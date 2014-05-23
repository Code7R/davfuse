/*
  davfuse: FUSE file systems as WebDAV servers
  Copyright (C) 2012, 2013 Rian Hunter <rian@alum.mit.edu>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation, either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

/*
  An async HTTP server
*/
#define _ISOC99_SOURCE

#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "c_util.h"
#include "coroutine.h"
#include "coroutine_io.h"
#include "event_loop.h"
#include "events.h"
#include "logging.h"
#include "util.h"
#include "util_event_loop.h"
#include "util_sockets.h"
#include "uthread.h"

#define _IS_HTTP_SERVER_C
#include "http_server.h"
#undef _IS_HTTP_SERVER_C

/* private structures */
typedef struct {
  http_request_handle_t request_context;
  event_handler_t cb;
  void *cb_ud;
} WriteResponseState;

/* public opaque structures */
typedef struct _http_request_context {
  struct _http_connection *conn;
  http_request_write_state_t write_state;
  http_request_read_state_t read_state;
  bool is_connection_close;
  bool is_no_content;
  size_t out_content_length;
  size_t bytes_written;
  bool is_chunked_request;
  union {
    struct chunked_read_persist_ctx {
      coroutine_position_t pos;
      char var_buf[4096];
      size_t chunk_size;
      size_t chunk_read;
      size_t amt_parsed;
      bool is_over;
    } chunked_coro_ctx;
    struct content_length_read_persist_ctx {
      size_t content_length;
      size_t bytes_read;
    } content_length_read;
  } persist_ctx;
  union {
    struct content_length_read_temp_ctx {
      event_handler_t cb;
      void *cb_ud;
    } content_length_read_ctx;
    WriteResponseState rws;
    struct chunked_read_temp_ctx {
      event_handler_t cb;
      void *cb_ud;
      void *input_buf;
      size_t input_nbyte;
      size_t input_buf_offset;
    } chunked_read_ctx;
  } sub;
} HTTPRequestContext;

typedef struct _http_connection {
  UTHR_CTX_BASE;
  struct _http_server *server;
  socket_t sock;
  int last_error_number;
  ReadBuffer f;
  unsigned client_generation;
  /* these might become per-request,
     right now we only do one request at a time,
     i.e. no pipe-lining */
  union {
    char buffer[OUT_BUF_SIZE];
    HTTPResponseHeaders rsp;
    HTTPRequestHeaders req;
    struct {
      event_loop_watch_key_t read_key;
      event_loop_watch_key_t stop_key;
      event_loop_timeout_key_t timeout_key;
    } wait_until;
  } spare;
  struct _http_request_context rctx;
} HTTPConnection;

typedef struct _http_server {
  event_loop_handle_t loop;
  socket_t sock;
  event_loop_watch_key_t accept_watch_key;
  event_handler_t handler;
  void *ud;
  bool shutting_down;
  size_t waiting_connections;
  socket_t stop_sockets[2];
  unsigned client_generation;
  bool client_handlers_should_wake_up;
} HTTPServer;

const char *const HTTP_HEADER_ALLOW = "Allow";
const char *const HTTP_HEADER_CONNECTION = "Connection";
const char *const HTTP_HEADER_CONTENT_LENGTH = "Content-Length";
const char *const HTTP_HEADER_CONTENT_TYPE = "Content-Type";
const char *const HTTP_HEADER_DATE = "Date";
const char *const HTTP_HEADER_HOST = "Host";
const char *const HTTP_HEADER_IF_MODIFIED_SINCE = "If-Modified-Since";
const char *const HTTP_HEADER_LAST_MODIFIED = "Last-Modified";
const char *const HTTP_HEADER_TRANSFER_ENCODING = "Transfer-Encoding";

/* static forward decls */
static
EVENT_HANDLER_DECLARE(accept_handler);
static
EVENT_HANDLER_DECLARE(client_coroutine);
static
UTHR_DECLARE(c_get_request);

/* TODO: make this runtime configurable, 5 seconds is a decent default */
enum {
  CONN_READ_TIMEOUT = 5,
};

static const EventLoopTimeout HTTP_READ_TIMEOUT = {CONN_READ_TIMEOUT, 0};
static const EventLoopTimeout CLIENT_STOP_WATCH_RETRY_TIMEOUT = {1, 0};

enum {
  STOP_SOCKET_RECV,
  STOP_SOCKET_SEND,
};

static PURE_FUNCTION const char *
_get_header_value(const struct _header_pair *headers, size_t num_headers, const char *header_name) {
  /* headers can only be ascii */
  for (size_t i = 0; i < num_headers; ++i) {
    if (ascii_strcaseequal(header_name, headers[i].name)) {
      return headers[i].value;
    }
  }

  return NULL;
}

/* small layer of indirection */
typedef UtilEventLoopSocketWriteDoneEvent HTTPConnectionWriteDoneEvent;

static void
_http_connection_read(HTTPConnection *conn, void *buf, size_t nbyte,
                      event_handler_t cb, void *ud) {
  return util_event_loop_socket_read(conn->server->loop, conn->sock,
                                     buf, nbyte, &HTTP_READ_TIMEOUT, cb, ud);
}

static void
_http_connection_write(HTTPConnection *conn, const void *buf, size_t nbyte,
                       event_handler_t cb, void *ud){
  return util_event_loop_socket_write(conn->server->loop,
                                      conn->sock,
                                      buf, nbyte, cb, ud);
}

static bool
_http_connection_close(HTTPConnection *conn) {
  return !closesocket(conn->sock);
}

static bool
_http_connection_is_close(HTTPConnection *conn) {
  return conn->rctx.is_connection_close;
}

static bool
_http_connection_has_error(HTTPConnection *conn) {
  return conn->last_error_number;
}

static bool
_http_connection_is_old(HTTPConnection *conn) {
  assert(conn->server->client_generation >= conn->client_generation);
  return conn->server->client_generation > conn->client_generation;
}

static bool
_http_connection_do_another_request(HTTPConnection *conn) {
  return (!_http_connection_has_error(conn) &&
          !_http_connection_is_close(conn) &&
          !_http_connection_is_old(conn) &&
          !conn->server->shutting_down);
}

static
EVENT_HANDLER_DEFINE(wait_until_ready_handler, ev_type, ev_, ud) {
  HTTPConnection *const conn = ud;

  assert(conn->spare.wait_until.stop_key &&
         conn->spare.wait_until.read_key &&
         conn->spare.wait_until.timeout_key);
  void *data_is_available = NULL;

  if (ev_type == EVENT_LOOP_SOCKET_EVENT) {
    EventLoopSocketEvent *const ev = ev_;

    /* we have to remove the opposite watch key since we're
       waiting for the first one to arrive */
    event_loop_watch_key_t to_remove = 0;
    if (ev->socket == conn->sock) {
      http_request_log_debug(&conn->rctx, "Client request socket has ready data!");
      to_remove = conn->spare.wait_until.stop_key;
      if (!ev->error) data_is_available = (void *) 0x1;
    }
    else {
      http_request_log_debug(&conn->rctx, "received server stop signal!!");
      assert(ev->socket == conn->server->stop_sockets[STOP_SOCKET_RECV]);
      to_remove = conn->spare.wait_until.read_key;
    }

    /* TODO: handle this better */
    bool success_remove =
      event_loop_watch_remove(conn->server->loop, to_remove);
    ASSERT_TRUE(success_remove);

    bool success_remove_timeout =
      event_loop_timeout_remove(conn->server->loop, conn->spare.wait_until.timeout_key);
    ASSERT_TRUE(success_remove_timeout);

    /* if there was an error waiting, close down the connection */
    if (ev->error) conn->last_error_number = 1;
  }
  else if (ev_type == EVENT_LOOP_TIMEOUT_EVENT) {
    bool success_remove =
      event_loop_watch_remove(conn->server->loop, conn->spare.wait_until.read_key);
    ASSERT_TRUE(success_remove);
    bool success_remove_2 =
      event_loop_watch_remove(conn->server->loop, conn->spare.wait_until.stop_key);
    ASSERT_TRUE(success_remove_2);

    /* read timeout ran out, we consider this an error */
    http_request_log_debug(&conn->rctx, "Timeout waiting for client, closing connection...");

    conn->last_error_number = 1;
  }
  else {
    /* should never happen */
    assert(false);
  }

  conn->spare.wait_until.stop_key = 0;
  conn->spare.wait_until.read_key = 0;
  conn->spare.wait_until.timeout_key = 0;

  assert(conn->server->waiting_connections > 0);
  conn->server->waiting_connections -= 1;

  /* read off signal data if there are no more waiting connections
     and the clients were signaled to wake up
   */
  if (!conn->server->waiting_connections &&
      conn->server->client_handlers_should_wake_up) {
    char toread;
    socket_ssize_t ret =
      recv(conn->server->stop_sockets[STOP_SOCKET_RECV], &toread, 1, 0);
    ASSERT_TRUE(ret == 1);
    conn->server->client_handlers_should_wake_up = false;
  }

  return client_coroutine(GENERIC_EVENT, data_is_available, conn);
}


static
EVENT_HANDLER_DEFINE(wait_until_ready_start_handler, ev_type, ev_, ud) {
  UNUSED(ev_type);
  UNUSED(ev_);

  HTTPConnection *const conn = ud;
  HTTPServer *const http = conn->server;

  /* busy-wait until waiting clients have woken up before waiting ourselves
     (since we only have one signal socket for triggering wake up,
      and we shouldn't immediately wake ourselves up)
  */
  if (conn->server->client_handlers_should_wake_up) {
    assert(conn->server->waiting_connections);
    const EventLoopTimeout yield_timeout = {0, 0};
    bool success_set_timeout =
      event_loop_timeout_add(conn->server->loop,
                             &yield_timeout,
                             wait_until_ready_start_handler, conn,
                             NULL);
    ASSERT_TRUE(success_set_timeout);
    return;
  }

  conn->spare.wait_until.read_key = 0;
  conn->spare.wait_until.stop_key = 0;
  conn->spare.wait_until.timeout_key = 0;

  const bool success_add_watch_1 =
    event_loop_socket_watch_add(http->loop,
                                conn->sock,
                                create_stream_events(true, false),
                                wait_until_ready_handler,
                                conn,
                                &conn->spare.wait_until.read_key);
  if (!success_add_watch_1) goto fail;

  const bool success_add_watch_2 =
    event_loop_socket_watch_add(http->loop,
                                http->stop_sockets[STOP_SOCKET_RECV],
                                create_stream_events(true, false),
                                wait_until_ready_handler,
                                conn,
                                &conn->spare.wait_until.stop_key);
  if (!success_add_watch_2) goto fail;

  const bool success_add_watch_3 =
    event_loop_timeout_add(http->loop,
                           &HTTP_READ_TIMEOUT,
                           wait_until_ready_handler,
                           conn,
                           &conn->spare.wait_until.timeout_key);
  if (!success_add_watch_3) goto fail;

  conn->server->waiting_connections += 1;

  return;

 fail:
  log_error("failed to add a watch, yielding and trying again later...");

  if (conn->spare.wait_until.read_key) {
    const bool success_remove_watch =
      event_loop_watch_remove(http->loop, conn->spare.wait_until.read_key);
    if (!success_remove_watch) log_error("Error removing read watch");
  }

  if (conn->spare.wait_until.stop_key) {
    const bool success_remove_watch =
      event_loop_watch_remove(http->loop, conn->spare.wait_until.stop_key);
    if (!success_remove_watch) log_error("Error removing stopwatch");
  }

  if (conn->spare.wait_until.timeout_key) {
    const bool success_remove_timeout =
      event_loop_timeout_remove(http->loop, conn->spare.wait_until.timeout_key);
    if (!success_remove_timeout) log_error("Error removing read timeout");
  }

  /* we failed to add a watch so yield and try again later */
  {
    const bool success_add_watch_4 =
      event_loop_timeout_add(http->loop,
			     &CLIENT_STOP_WATCH_RETRY_TIMEOUT,
			     wait_until_ready_start_handler,
			     conn,
			     NULL);
    if (!success_add_watch_4) {
      log_error("failed to add timeout, client coroutine will spin");
      client_coroutine(GENERIC_EVENT, NULL, conn);
    }
  }
}

void
_http_connection_wait_until_ready(HTTPConnection *conn) {
  return wait_until_ready_start_handler(GENERIC_EVENT, NULL, conn);
}

#define _HTTP_SERVER_ACCEPT_DONE_EVENT EVENT_LOOP_SOCKET_EVENT

static
socket_t
_http_server_sock_from_accept_event(const EventLoopSocketEvent *ev) {
  if (ev->error) return INVALID_SOCKET;

  socket_t ret = accept(ev->socket, NULL, NULL);
  if (ret == INVALID_SOCKET) return ret;

  bool success = set_socket_non_blocking(ret);
  if (!success) {
    closesocket(ret);
    return INVALID_SOCKET;
  }

  return ret;
}

static
bool
_http_server_accept(http_server_t http) {
  return event_loop_socket_watch_add(http->loop,
                                     http->sock,
                                     create_stream_events(true, false),
                                     accept_handler,
                                     http,
                                     &http->accept_watch_key);
}

static
bool
_http_server_stop_accept(http_server_t http) {
  if (!http->accept_watch_key) return true;

  bool success_watch_remove =
    event_loop_watch_remove(http->loop, http->accept_watch_key);
  if (success_watch_remove) http->accept_watch_key = 0;
  return success_watch_remove;
}

static
void
_http_server_destroy(http_server_t http) {
  for (unsigned i = 0; i < NELEMS(http->stop_sockets); ++i) {
    if (http->stop_sockets[i] != INVALID_SOCKET) {
      int ret_close = closesocket(http->stop_sockets[i]);
      if (ret_close == SOCKET_ERROR) {
        /* we don't fail hard here, we just leak a descriptor */
        log_error("Couldn't close socket: %ld: %s",
                  (long) http->stop_sockets[i], last_socket_error_message());
      }
    }
  }

  free(http);
}

static
void
_http_server_wake_up_sleeping_client_handlers(http_server_t http) {
  if (!http->waiting_connections) return;
  if (http->client_handlers_should_wake_up) return;

  const int ret =
    send(http->stop_sockets[STOP_SOCKET_SEND], "1", 1, 0);
  if (ret == SOCKET_ERROR) {
    log_error("Error while writing to stop socket: %s",
              last_socket_error_message());
    /* TODO: handle this */
    ASSERT_TRUE(false);
  }

  http->client_handlers_should_wake_up = true;
}

http_server_t
http_server_new(event_loop_handle_t loop,
                socket_t sock,
                event_handler_t handler,
                void *ud) {
  struct _http_server *const http = malloc(sizeof(*http));
  if (!http) return NULL;

  *http = (struct _http_server) {
    .loop = loop,
    .sock = sock,
    .handler = handler,
    .stop_sockets = {INVALID_SOCKET, INVALID_SOCKET},
    .ud = ud,
  };

  /* create stop signal listener for keep-alive
     client requests */
  int ret = localhost_socketpair(http->stop_sockets);
  if (ret) {
    _http_server_destroy(http);
    return NULL;
  }

  return http;
}

bool
http_server_start(http_server_t http) {
  return _http_server_accept(http);
}

bool
http_server_stop(http_server_t http) {
  const bool success_stop = _http_server_stop_accept(http);
  if (!success_stop) return false;

  http->shutting_down = true;

  /* write to the stop socket to wake connections up */
  _http_server_wake_up_sleeping_client_handlers(http);

  return true;
}

void
http_server_disconnect_existing_clients(http_server_t http) {
  http->client_generation += 1;
  _http_server_wake_up_sleeping_client_handlers(http);
}

bool
http_server_destroy(http_server_t http) {
  _http_server_destroy(http);
  return true;
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  http_request_handle_t rh;
  HTTPRequestHeaders *request_headers;
  event_handler_t cb;
  void *ud;
  /* state */
  int i;
  int c;
  time_t header_read_start;
  size_t ei;
  size_t parsed;
  char tmpbuf[1024];
  /* this is used for early exit on bad input headers,
     e.g. expect headers we don't understand */
  HTTPResponseHeaders *response_headers;
} GetRequestState;

void
http_request_read_headers(http_request_handle_t rh,
                          HTTPRequestHeaders *request_headers,
                          event_handler_t cb, void *cb_ud) {
  HTTPRequestContext *rctx = rh;

  UNUSED(rh);
  UNUSED(cb);
  UNUSED(cb_ud);
  UNUSED(request_headers);

  if (rctx->read_state != HTTP_REQUEST_READ_STATE_NONE) {
    HTTPRequestReadHeadersDoneEvent read_headers_ev = {
      .request_handle = rh,
      /* TODO set correct error */
      .err = HTTP_GENERIC_ERROR,
    };
    return cb(HTTP_REQUEST_READ_HEADERS_DONE_EVENT, &read_headers_ev, cb_ud);
  }

  http_request_log_debug(rctx, "Reading header");

  /* read out client http request */
  rctx->read_state = HTTP_REQUEST_READ_STATE_READING_HEADERS;

  UTHR_CALL4(c_get_request, GetRequestState,
             .rh = rh,
             .request_headers = request_headers,
             .cb = cb,
             .ud = cb_ud);
}

static
EVENT_HANDLER_DEFINE(_handle_request_read, ev_type, ev, ud) {
  UNUSED(ev_type);
  assert(ev_type == C_READ_DONE_EVENT);

  HTTPRequestContext *rctx = ud;
  CReadDoneEvent *c_read_done_ev = ev;

  /* update request state */
  rctx->persist_ctx.content_length_read.bytes_read += c_read_done_ev->nbyte;
  rctx->conn->last_error_number = c_read_done_ev->error_number;
  rctx->read_state = HTTP_REQUEST_READ_STATE_READ_HEADERS;

  HTTPRequestReadDoneEvent read_done_ev = {
    .err = c_read_done_ev->error_number ? HTTP_GENERIC_ERROR : HTTP_SUCCESS,
    .nbyte = c_read_done_ev->nbyte,
  };
  rctx->sub.content_length_read_ctx.cb(HTTP_REQUEST_READ_DONE_EVENT, &read_done_ev,
                                       rctx->sub.content_length_read_ctx.cb_ud);
}

static
EVENT_HANDLER_DEFINE(_chunked_request_coro, ev_type, ev, ud) {
  UNUSED(ev_type);

  HTTPRequestContext *const rctx = ud;
  struct chunked_read_persist_ctx *const cctx =
    &rctx->persist_ctx.chunked_coro_ctx;
  struct chunked_read_temp_ctx *const tctx =
    &rctx->sub.chunked_read_ctx;

  /* if this coroutine is running, it should be returning data to
     someone */
  assert(tctx->cb);

#define EXPECT(s)                                               \
  do {                                                          \
    assert(strlen(s) < sizeof(cctx->var_buf));                  \
    CRYIELD(cctx->pos,                                          \
            c_read(&rctx->conn->f,                              \
                   cctx->var_buf, strlen(s),                    \
                   _chunked_request_coro, ud));                 \
    assert(ev_type == C_READ_DONE_EVENT);                       \
    CReadDoneEvent *c_read_done_ev = ev;                        \
    if (c_read_done_ev->error_number ||                         \
        c_read_done_ev->nbyte != strlen(s) ||                   \
        memcmp(s, cctx->var_buf, strlen(s))) {                  \
      log_info("Was expecting: %s but didn't get it", s);       \
      goto error;                                               \
    }                                                           \
  }                                                             \
  while (false)

  CRBEGIN(cctx->pos);

  while (true) {
    /* read out hex digit */
    CRYIELD(cctx->pos,
            c_getwhile(&rctx->conn->f,
                       cctx->var_buf, sizeof(cctx->var_buf) - 1,
                       match_hex_digit,
                       &cctx->amt_parsed,
                       _chunked_request_coro, ud));
    assert(C_GETWHILE_DONE_EVENT == ev_type);
    if (!cctx->amt_parsed ||
        cctx->amt_parsed > sizeof(cctx->var_buf) - 1) {
      /* nothing was parsed, either EOF or wrong character */
      log_info("didn't parse enough to parsed too much");
      goto error;
    }

    cctx->var_buf[cctx->amt_parsed] = '\0';
    intmax_t chunk_size  = strtoll(cctx->var_buf, NULL, 16);
    /* since we used `match_hex_digit`, we couldn't have had
       an invalid input */
    assert(!(!chunk_size && errno == EINVAL));

    if (chunk_size < 0 || ((uintmax_t) chunk_size) > SIZE_MAX) {
      log_info("Chunk size is too large: %lu",
               (unsigned long) chunk_size);
      goto error;
    }

    cctx->chunk_size = (size_t) chunk_size;

    /* TODO: read 'chunk-extension' */

    /* read CRLF */
    EXPECT("\r\n");

    if (!cctx->chunk_size) {
      /* no more chunks */
      break;
    }

    cctx->chunk_read = 0;

    /* read chunk */
    while (cctx->chunk_read < cctx->chunk_size) {
      assert(tctx->input_buf_offset < tctx->input_nbyte);
      CRYIELD(cctx->pos,
              c_read(&rctx->conn->f,
                     tctx->input_buf + tctx->input_buf_offset,
                     min_size_t(tctx->input_nbyte - tctx->input_buf_offset,
                                cctx->chunk_size - cctx->chunk_read),
                     _chunked_request_coro, ud));
      assert(ev_type == C_READ_DONE_EVENT);
      CReadDoneEvent *c_read_done_ev = ev;
      if (c_read_done_ev->error_number) {
        log_info("Error while reading from buffer");
        goto error;
      }

      if (!c_read_done_ev->nbyte) {
        log_info("Premature EOF");
        goto error;
      }

      cctx->chunk_read += c_read_done_ev->nbyte;

      tctx->input_buf_offset += c_read_done_ev->nbyte;
      if (tctx->input_buf_offset == tctx->input_nbyte) {
        /* we read enough to satisfy the reader */
        rctx->read_state = HTTP_REQUEST_READ_STATE_READ_HEADERS;

        HTTPRequestReadDoneEvent read_done_ev = {
          .err = HTTP_SUCCESS,
          .nbyte = tctx->input_buf_offset,
        };
        CRYIELD(cctx->pos,
                tctx->cb(HTTP_REQUEST_READ_DONE_EVENT, &read_done_ev, tctx->cb_ud));
        assert(ev_type == GENERIC_EVENT);
        /* we're starting new */
        assert(!tctx->input_buf_offset);
      }
    }

    /* read CRLF */
    EXPECT("\r\n");
  }

  /* TODO: read trailing headers */

  EXPECT("\r\n");

  if (false) {
  error:
    /* there was an error, we are persistently in a bad state */
    while (true) {
      rctx->read_state = HTTP_REQUEST_READ_STATE_READ_HEADERS;

      HTTPRequestReadDoneEvent read_done_ev = {
        .err = HTTP_GENERIC_ERROR,
        .nbyte = 0,
      };

      rctx->conn->last_error_number = 1;
      CRYIELD(cctx->pos,
              tctx->cb(HTTP_REQUEST_READ_DONE_EVENT, &read_done_ev, tctx->cb_ud));
      assert(ev_type == GENERIC_EVENT);
      assert(!tctx->input_buf_offset);
    }
  }

  /* no more data, just keep returning EOF */
  log_debug("Chunked request is over");
  while (true) {
    cctx->is_over = true;
    rctx->read_state = HTTP_REQUEST_READ_STATE_READ_HEADERS;

    HTTPRequestReadDoneEvent read_done_ev = {
      .err = HTTP_SUCCESS,
      .nbyte = tctx->input_buf_offset,
    };
    CRYIELD(cctx->pos,
            tctx->cb(HTTP_REQUEST_READ_DONE_EVENT, &read_done_ev, tctx->cb_ud));
    assert(ev_type == GENERIC_EVENT);
    /* we're starting new */
    assert(!tctx->input_buf_offset);
  }

  CREND();

#undef EXPECT
}

void
http_request_read(http_request_handle_t rh,
                  void *buf, size_t nbyte,
                  event_handler_t cb, void *cb_ud) {
  HTTPRequestContext *rctx = rh;

  if (rctx->read_state != HTTP_REQUEST_READ_STATE_READ_HEADERS) {
    /* haven't yet read the headers, this was called out of order */
    HTTPRequestReadDoneEvent read_done_ev = {
      .err = HTTP_GENERIC_ERROR,
    };
    return cb(HTTP_REQUEST_READ_DONE_EVENT, &read_done_ev, cb_ud);
  }

  rctx->read_state = HTTP_REQUEST_READ_STATE_READING;

  if (rctx->is_chunked_request) {
    rctx->sub.chunked_read_ctx = (struct chunked_read_temp_ctx) {
      .cb = cb,
      .cb_ud = cb_ud,
      .input_buf = buf,
      .input_nbyte = nbyte,
      .input_buf_offset = 0,
    };

    return _chunked_request_coro(GENERIC_EVENT, NULL, rctx);
  }
  else {
    struct content_length_read_persist_ctx *cctx = &rctx->persist_ctx.content_length_read;
    assert(cctx->content_length >= cctx->bytes_read);
    nbyte = min_size_t(nbyte, cctx->content_length - cctx->bytes_read);

    rctx->sub.content_length_read_ctx = (struct content_length_read_temp_ctx) {
      .cb = cb,
      .cb_ud = cb_ud,
    };

    return c_read(&rctx->conn->f,
                  buf, nbyte,
                  _handle_request_read, rctx);
  }
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  const HTTPResponseHeaders *response_headers;
  struct _http_request_context *request_context;
  event_handler_t cb;
  void *cb_ud;
  /* state */
  size_t header_idx;
  char response_line[MAX_RESPONSE_LINE_SIZE];
} WriteHeadersState;

static
UTHR_DEFINE(_http_request_write_headers_coroutine) {
  UTHR_HEADER(WriteHeadersState, whs);

  int myerrno = 0;
  whs->request_context->write_state = HTTP_REQUEST_WRITE_STATE_WRITING_HEADERS;

#define EMITN(b, n)                                                     \
  do {                                                                  \
    UTHR_YIELD(whs,                                                     \
               _http_connection_write(whs->request_context->conn,       \
                                      b, n,                             \
                                      _http_request_write_headers_coroutine, \
                                      whs));                            \
    UTHR_RECEIVE_EVENT(HTTP_CONNECTION_WRITE_DONE_EVENT,                \
                       HTTPConnectionWriteDoneEvent, write_done_ev);    \
    myerrno = write_done_ev->error;                                     \
    if (myerrno) {                                                      \
      goto done;                                                        \
    }                                                                   \
  }                                                                     \
  while (false)

#define EMIT(c) EMITN(c, sizeof(c) - 1)
#define EMITS(c) EMITN(c, strnlen(c, sizeof(c)))

  /* output response code */
  const int ret = snprintf(whs->response_line,
                           sizeof(whs->response_line),
                           "HTTP/1.1 %d %s\r\n",
                           whs->response_headers->code,
                           whs->response_headers->message);
  if (ret < 0 || (size_t) ret >= sizeof(whs->response_line)) {
    myerrno = ENOMEM;
    goto done;
  }
  http_request_log_debug(whs->request_context,
                         "Writing HTTP response, %d %s",
                         whs->response_headers->code,
                         whs->response_headers->message);
  EMITN(whs->response_line, ret);

  /* add date header */
  const time_t tt = time(NULL);
  struct tm *const tm_ = gmtime(&tt);
  const char *const fmt = "Date: %a, %d %b %Y %H:%M:%S GMT\r\n";
  const int ret_sprint2 =
    strftime(whs->response_line, sizeof(whs->response_line), fmt, tm_);
  if (!ret_sprint2) {
    myerrno = ENOMEM;
    goto done;
  }
  http_request_log_debug(whs->request_context,
                         "Writing response header: %.*s",
                         ret_sprint2 - 2, whs->response_line);
  EMITN(whs->response_line, ret_sprint2);

  if (!_get_header_value(whs->response_headers->headers,
                         whs->response_headers->num_headers,
                         "Server")) {
    http_request_log_debug(whs->request_context,
                           "Writing response header: Server: Rian's HTTP Server");
    EMITS("Server: Rian's HTTP Server\r\n");
  }


  if (!_http_connection_do_another_request(whs->request_context->conn)) {
    http_request_log_debug(whs->request_context,
                           "Writing response header: Connection: close");
    EMITS("Connection: close\r\n");
  }
  else {
    /* TODO: only do this client sent "Connection: Keep-Alive",
       not harmful otherwise though, just unnecessary */
    http_request_log_debug(whs->request_context,
                           "Writing response header: Connection: Keep-Alive");
    EMITS("Connection: Keep-Alive\r\n");
    char out[256];
    int str_len = snprintf(out, sizeof(out), "Keep-Alive: timeout=%d\r\n",
                           CONN_READ_TIMEOUT);
    http_request_log_debug(whs->request_context,
                           "Writing response header: %s", out);
    EMITN(out, str_len);
  }

  /* output each header */
  for (whs->header_idx = 0; whs->header_idx < whs->response_headers->num_headers;
       ++whs->header_idx) {
    http_request_log_debug(whs->request_context,
                           "Writing response header: %s: %s",
                           whs->response_headers->headers[whs->header_idx].name,
                           whs->response_headers->headers[whs->header_idx].value);
    EMITS(whs->response_headers->headers[whs->header_idx].name);
    EMIT(": ");
    EMITS(whs->response_headers->headers[whs->header_idx].value);
    EMIT("\r\n");
  }

  /* finish headers */
  EMIT("\r\n");

 done:
  if (myerrno) {
    http_request_log_warning(whs->request_context,
                             "Error while writing headers to client");
  }

  whs->request_context->write_state = HTTP_REQUEST_WRITE_STATE_WROTE_HEADERS;
  HTTPRequestWriteHeadersDoneEvent write_headers_ev = {
    .request_handle = whs->request_context,
    .err = myerrno ? HTTP_GENERIC_ERROR : HTTP_SUCCESS,
  };
  whs->request_context->conn->last_error_number = myerrno;
  UTHR_RETURN(whs,
              whs->cb(HTTP_REQUEST_WRITE_HEADERS_DONE_EVENT,
                      &write_headers_ev, whs->cb_ud));

  UTHR_FOOTER();

#undef EMIT
#undef EMITN
#undef EMITS
}

http_error_code_t
http_request_force_connection_close(http_request_handle_t rh) {
  HTTPRequestContext *const rctx = rh;

  // TODO: this should possibly be an assert()
  // this must happen before anything is done on this connection
  if (rctx->write_state != HTTP_REQUEST_WRITE_STATE_NONE) {
    log_error("Must set connection close before anything!");
    return HTTP_GENERIC_ERROR;
  }

  rctx->is_connection_close = true;

  return HTTP_SUCCESS;
}

void
http_request_write_headers(http_request_handle_t rh,
                           const HTTPResponseHeaders *response_headers,
                           event_handler_t cb,
                           void *cb_ud) {
  HTTPRequestContext *rctx = rh;

  if (rctx->write_state != HTTP_REQUEST_WRITE_STATE_NONE) {
    log_error("Handler called write headers at strange time!");
    goto error;
  }

  rctx->is_no_content = response_headers->code == HTTP_STATUS_CODE_NO_CONTENT;

  /* check if the response has a "Content-Length" header
     this is used as a hint by the handlers to tell the server
     how much it's going to write, right now it's strictly necessary
     but we may relax this in the future (esp if we negotiate chunked encoding) */
  {
    const char *const content_length_str =
      _get_header_value(response_headers->headers,
                        response_headers->num_headers,
                        HTTP_HEADER_CONTENT_LENGTH);
    if (!rctx->is_no_content) {
      if (!content_length_str) {
        log_error("Handler did not use a valid content length string!");
        goto error;
      }

      long content_length = strtol(content_length_str, NULL, 10);
      if ((content_length == 0 && errno == EINVAL) ||
          content_length < 0) {
        log_error("Handler did not use a valid content length string!");
        goto error;
      }

      rctx->out_content_length = content_length;
    }
    else {
      if (content_length_str) {
        log_error("Handler had a content-length header"
                  "when the code was no-content");
        goto error;
      }
    }
  }

  if (response_headers->code == HTTP_STATUS_CODE_METHOD_NOT_ALLOWED &&
      !_get_header_value(response_headers->headers,
                         response_headers->num_headers,
                         HTTP_HEADER_ALLOW)) {
    log_error("Handler must specific an allow header with a "
              "method not allowed status code!");
    goto error;
  }

  if (_get_header_value(response_headers->headers,
                        response_headers->num_headers,
                        HTTP_HEADER_CONNECTION)) {
    log_error("Handler cannot specify a connection header!");
    goto error;
  }

  if (_get_header_value(response_headers->headers,
                        response_headers->num_headers,
                        HTTP_HEADER_DATE)) {
    log_error("Handler cannot specify a date header!");
    goto error;
  }

  if (false) {
    HTTPRequestWriteHeadersDoneEvent write_headers_ev;
  error:
    rctx->conn->last_error_number = 1;
    write_headers_ev = (HTTPRequestWriteHeadersDoneEvent) {
      .request_handle = rh,
      /* TODO set correct error */
      .err = HTTP_GENERIC_ERROR,
    };
    return cb(HTTP_REQUEST_WRITE_HEADERS_DONE_EVENT, &write_headers_ev, cb_ud);
  }

  UTHR_CALL4(_http_request_write_headers_coroutine, WriteHeadersState,
             .response_headers = response_headers,
             .request_context = rh,
             .cb = cb,
             .cb_ud = cb_ud);
}

EVENT_HANDLER_DEFINE(_handle_write_done, ev_type, ev, ud) {
  WriteResponseState *rws = ud;

  UNUSED(ev_type);
  assert(ev_type == HTTP_CONNECTION_WRITE_DONE_EVENT);
  HTTPConnectionWriteDoneEvent *write_all_done_event = ev;

  if (write_all_done_event->error) {
    http_request_log_warning(rws->request_context,
                             "http_request_write failed");
    rws->request_context->conn->last_error_number = 1;
  }
  else {
    rws->request_context->bytes_written += write_all_done_event->nbyte;
    rws->request_context->conn->last_error_number = 0;
  }

  rws->request_context->write_state = HTTP_REQUEST_WRITE_STATE_WROTE_HEADERS;
  HTTPRequestWriteDoneEvent write_ev = {
    .request_handle = rws->request_context,
    .err = write_all_done_event->error ? HTTP_GENERIC_ERROR : HTTP_SUCCESS,
  };
  rws->cb(HTTP_REQUEST_WRITE_DONE_EVENT, &write_ev, rws->cb_ud);
}

void
http_request_write(http_request_handle_t rh,
                   const void *buf, size_t nbyte,
                   event_handler_t cb, void *cb_ud) {
  HTTPRequestContext *rctx = rh;

  if (rctx->write_state != HTTP_REQUEST_WRITE_STATE_WROTE_HEADERS) {
    goto error;
  }

  if (rctx->is_no_content) {
    /* this response was no content */
    http_request_log_warning(rctx,
                             "http_request_write called on a no content response");
    goto error;
  }

  assert(rctx->out_content_length >= rctx->bytes_written);
  const size_t left_to_write = rctx->out_content_length - rctx->bytes_written;
  if (nbyte > left_to_write) {
    /* TODO: right now have no facility to do short writes,
       could return write amount when done
    */
    http_request_log_warning(rctx->conn,
                             "http_request_write will not do a short write, "
                             "request to write less. wanted to write %lu, "
                             "but there was only %lu left to write",
                             (unsigned long) nbyte,
                             (unsigned long) left_to_write);
    goto error;
  }

  if (false) {
    HTTPRequestWriteDoneEvent write_ev;
  error:
    write_ev = (HTTPRequestWriteDoneEvent) {
      .request_handle = rh,
      /* TODO set correct error */
      .err = HTTP_GENERIC_ERROR,
    };
    return cb(HTTP_REQUEST_WRITE_DONE_EVENT, &write_ev, cb_ud);
  }

  rctx->sub.rws = (WriteResponseState) {
    .request_context = rh,
    .cb = cb,
    .cb_ud = cb_ud,
  };

  rctx->write_state = HTTP_REQUEST_WRITE_STATE_WRITING;

  _http_connection_write(rctx->conn,
                         buf, nbyte,
                         _handle_write_done,
                         &rctx->sub.rws);
}

void
http_request_end(http_request_handle_t rh) {
  HTTPRequestContext *rctx = rh;

  UNUSED(rctx);
  assert(!(rctx->write_state == HTTP_REQUEST_WRITE_STATE_WRITING ||
           rctx->write_state == HTTP_REQUEST_WRITE_STATE_WRITING_HEADERS ||
           rctx->read_state == HTTP_REQUEST_READ_STATE_READING ||
           rctx->read_state == HTTP_REQUEST_READ_STATE_READING_HEADERS));

  client_coroutine(HTTP_END_REQUEST_EVENT, NULL, rh->conn);
}

const char *
http_get_header_value(const HTTPRequestHeaders *rhs, const char *header_name) {
  return _get_header_value(rhs->headers, rhs->num_headers, header_name);
}

static
EVENT_HANDLER_DEFINE(accept_handler, ev_type, ev, ud) {
  socket_t sock = INVALID_SOCKET;
  HTTPConnection *ctx = NULL;

  UNUSED(ev_type);
  assert(ev_type == _HTTP_SERVER_ACCEPT_DONE_EVENT);
  HTTPServer *const http = ud;
  assert(!http->shutting_down);

  /* our key has been invalidated */
  http->accept_watch_key = (event_loop_watch_key_t) 0;

  /* accept again before running client
     (which could stop the server) */
  const bool success_accept = _http_server_accept(http);
  if (!success_accept) {
    log_error("couldn't accept again, shutting down server!");
    bool success_http_stop = http_server_stop(http);
    /* TODO: handle more gracefully */
    ASSERT_TRUE(success_http_stop);
    return;
  }

  sock = _http_server_sock_from_accept_event(ev);
  if (sock == INVALID_SOCKET) goto error;

  ctx = malloc(sizeof(*ctx));
  if (!ctx) goto error;

  /* run client */
  *ctx = (HTTPConnection) {
    .sock = sock,
    .f = {
      .read_fn = (read_fn_t) _http_connection_read,
      .handle = ctx,
      .in_use = false,
    },
    .server = http,
    .client_generation = http->client_generation,
  };
  UTHR_RUN(client_coroutine, ctx);

  if (false) {
  error:
    log_error("Couldn't allocate resources for new client, dropping connection...");
    free(ctx);
    if (sock != INVALID_SOCKET) {
      int ret = closesocket(sock);
      if (ret == SOCKET_ERROR) {
        log_error("Couldnt' close socket %d, leaking", (int) sock);
      }
    }
  }
}

static void
_write_out_internal_server_error(http_request_handle_t rh,
                                 event_handler_t handler, void *ud) {
  HTTPRequestContext *rctx = rh;
  HTTPResponseHeaders *rsp = &rctx->conn->spare.rsp;

  http_response_set_code(rsp, HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR);
  http_response_add_header(rsp, HTTP_HEADER_CONTENT_LENGTH, "%d", 0);
  http_request_write_headers(rh, rsp, handler, ud);
}

static
UTHR_DEFINE(client_coroutine) {
  UTHR_HEADER(HTTPConnection, cc);

  http_request_log_debug(&cc->rctx, "new connection!");

  do {
    /* (re-)initialize the request context */
    cc->rctx = (HTTPRequestContext) {
      .conn = cc,
    };

    /* TODO: Prevent against "slowloris" style attacks
       with clients who send their headers very very slowly:
       give some timeout to total request processing
    */

    /* wait here until connection becomes read ready
       or we get the server stop signal */
    UTHR_YIELD(cc, _http_connection_wait_until_ready(cc));
    void *const data_is_available = UTHR_EVENT();
    if (!data_is_available) continue;

    /* create request event, we can do this on the stack
       because the handler shouldn't use this after */
    HTTPNewRequestEvent new_request_ev = {
      .server = cc->server,
      .request_handle = &cc->rctx,
    };
    http_request_log_debug(&cc->rctx, "starting request");
    UTHR_YIELD(cc,
               cc->server->handler(HTTP_NEW_REQUEST_EVENT,
                                   &new_request_ev,
                                   cc->server->ud));
    assert(UTHR_EVENT_TYPE() == HTTP_END_REQUEST_EVENT);
    http_request_log_debug(&cc->rctx, "request is over!");

    /* read headers if they were ignored */
    if (!_http_connection_has_error(cc) &&
        cc->rctx.read_state == HTTP_REQUEST_READ_STATE_NONE) {
      http_request_log_debug(&cc->rctx, "handler didn't read headers...");
      UTHR_YIELD(cc,
                 http_request_read_headers(&cc->rctx, &cc->spare.req,
                                           client_coroutine, cc));
      assert(UTHR_EVENT_TYPE() == HTTP_REQUEST_READ_HEADERS_DONE_EVENT);
    }

    /* read out all data if it was ignored */
    if (!_http_connection_has_error(cc) &&
        cc->rctx.read_state == HTTP_REQUEST_READ_STATE_READ_HEADERS) {
      if (cc->rctx.is_chunked_request
          ? !cc->rctx.persist_ctx.chunked_coro_ctx.is_over
          : (cc->rctx.persist_ctx.content_length_read.bytes_read <
             cc->rctx.persist_ctx.content_length_read.content_length)) {
        http_request_log_debug(&cc->rctx, "handler didn't read entire body...");
      }
      while (!_http_connection_has_error(cc)) {
        UTHR_YIELD(cc,
                   http_request_read(&cc->rctx, cc->spare.buffer,
                                     sizeof(cc->spare.buffer),
                                     client_coroutine, cc));
        assert(UTHR_EVENT_TYPE() == HTTP_REQUEST_READ_DONE_EVENT);
        HTTPRequestReadDoneEvent *read_done_ev = UTHR_EVENT();
        if (!read_done_ev->err && !read_done_ev->nbyte) {
          break;
        }
      }
    }

    /* clean up write side of request */
    if (!_http_connection_has_error(cc) &&
        cc->rctx.write_state == HTTP_REQUEST_WRITE_STATE_NONE) {
      http_request_log_debug(&cc->rctx, "handler didn't send a response...");
      UTHR_YIELD(cc,
                 _write_out_internal_server_error(&cc->rctx,
                                                  client_coroutine, cc));
      assert(UTHR_EVENT_TYPE() == HTTP_REQUEST_WRITE_HEADERS_DONE_EVENT);
    }

    /* write out rest of garbage if request ended prematurely */
    if (!_http_connection_has_error(cc) &&
        cc->rctx.write_state == HTTP_REQUEST_WRITE_STATE_WROTE_HEADERS &&
        !cc->rctx.is_no_content) {
      if (cc->rctx.bytes_written < cc->rctx.out_content_length) {
        http_request_log_debug(&cc->rctx, "handler didn't finish response");
      }
      while (!_http_connection_has_error(cc) &&
             cc->rctx.bytes_written < cc->rctx.out_content_length) {
        /* initted to zero because static */
        static char bytes[4096];
        /* just writing bytes */
        UTHR_YIELD(cc,
                   http_request_write(&cc->rctx, bytes,
                                      /* we must send the exact amount,
                                         because we don't support chunked responses yet */
                                      cc->rctx.out_content_length - cc->rctx.bytes_written,
                                      client_coroutine, cc));
        assert(UTHR_EVENT_TYPE() == HTTP_REQUEST_WRITE_DONE_EVENT);
      }
    }
  } while (_http_connection_do_another_request(cc));

  http_request_log_debug(&cc->rctx, "Client done, closing conn");
  bool success_close = _http_connection_close(cc);
  if (!success_close) {
    http_request_log_error(&cc->rctx, "error while closing client connection, leaking...");
  }

  UTHR_RETURN(cc, 0);

  UTHR_FOOTER();
}

static
UTHR_DEFINE(c_get_request) {
  UTHR_HEADER(GetRequestState, state);

#define PEEK()                                          \
  do {                                                  \
    if ((state->c = fbpeek(&state->rh->conn->f)) < 0) { \
      UTHR_YIELD(state,                                 \
                 c_fbpeek(&state->rh->conn->f,          \
                          &state->c,                    \
                          c_get_request, state));       \
      assert(UTHR_EVENT_TYPE() == C_FBPEEK_DONE_EVENT); \
    }                                                   \
    if (state->c == EOF) goto error;                    \
  }                                                     \
  while (false)

#define EXPECT(_c)                                              \
  do {                                                          \
    /* first check the synchronous interface, to avoid          \
       many layers of nesting */                                \
    if ((state->c = fbgetc(&state->rh->conn->f)) < 0) {         \
      UTHR_YIELD(state,                                         \
                 c_fbgetc(&state->rh->conn->f,                  \
                          &state->c,                            \
                          c_get_request, state));               \
      assert(UTHR_EVENT_TYPE() == C_FBGETC_DONE_EVENT);         \
    }                                                           \
    if ((char) state->c != (_c)) {                              \
      if (state->c == EOF) {                                    \
        log_error("Got EOF, while expecting '%c'", (_c));       \
      }                                                         \
      else {                                                    \
        log_error("Didn't get the character we "                \
                  "were expecting: '%c' vs '%c'",               \
                  state->c, (_c));                              \
      }                                                         \
      goto error;                                               \
    }                                                           \
  }                                                             \
  while (false)

#define EXPECTS(_s)                                                     \
  do {                                                                  \
    for (state->ei = 0; state->ei < sizeof(_s) - 1; ++state->ei) {      \
      EXPECT(_s[state->ei]);                                            \
    }                                                                   \
  }                                                                     \
  while (false)

#define PARSEVAR(var, fn)                                               \
  do {                                                                  \
    UTHR_YIELD(state,                                                   \
               c_getwhile(&state->rh->conn->f,                          \
                          var, sizeof(var) - 1, fn, &state->parsed,     \
                          c_get_request, state));                       \
    assert(UTHR_EVENT_TYPE() == C_GETWHILE_DONE_EVENT);                 \
    if (state->parsed > sizeof(var) - 1 ||                             \
        !state->parsed) {						\
      log_error("parsed too much or not enough!");                      \
      goto error;							\
    }									\
    /* we don't protect against there being a '\0' in the http */       \
    /* variable the worst that can happen is the var is cut  */         \
    /* short and fails */                                               \
    var[state->parsed] = '\0';                                          \
  }                                                                     \
  while (false)

#define PARSEINTVAR(var)                                        \
  do {                                                          \
    long _val;                                                  \
    PARSEVAR(state->tmpbuf, match_digit);                       \
    _val = strtol(state->tmpbuf, NULL, 10);                     \
    if ((_val == 0 && errno == EINVAL) ||                       \
        _val > INT_MAX || _val < INT_MIN) {                     \
      log_error("Didn't parse an integer: %s", state->tmpbuf);  \
      goto error;                                               \
    }                                                           \
    var = _val;                                                 \
  }                                                             \
  while (false)

  PARSEVAR(state->request_headers->method, match_token);

  EXPECT(' ');

  http_request_log_debug(state->rh, "Got method '%s'",
                         state->request_headers->method);

  /* request-uri = "*" | absoluteURI | abs_path | authority */
  /* we don't parse super intelligently here because
     http URIs aren't LL(1), authority and absoluteURI start with
     the same prefix string */
  PARSEVAR(state->request_headers->uri, match_non_null_or_space);
  EXPECT(' ');

  http_request_log_debug(state->rh, "Got uri '%s'",
                         state->request_headers->uri);

  EXPECTS("HTTP/");
  PARSEINTVAR(state->request_headers->major_version);
  EXPECT('.');
  PARSEINTVAR(state->request_headers->minor_version);
  EXPECTS("\r\n");

  http_request_log_debug(state->rh, "Got version '%d.%d'",
                         state->request_headers->major_version,
                         state->request_headers->minor_version);

  http_request_log_debug(state->rh, "Parsed request line");

  for (state->i = 0; state->i < (int) NELEMS(state->request_headers->headers);
       ++state->i) {
    PEEK();

    if (state->c == '\r') {
      break;
    }

    PARSEVAR(state->request_headers->headers[state->i].name,
             match_non_null_or_colon);
    EXPECT(':');

    /* TODO, turn this into PARSEFIELDVALUE
       which itself is quite complicated, we do the bare minimum
       and skip leading whitespace
    */
    /* skip lws */
    while (true) {
      PEEK();
      if (state->c == ' ') {
        EXPECT(' ');
      }
      else if (state->c == '\t') {
        EXPECT('\t');
      }
      else {
        break;
      }
    }

    PEEK();
    if (state->c != '\r') {
      PARSEVAR(state->request_headers->headers[state->i].value,
               match_non_null_or_carriage_return);
    }
    else {
      state->request_headers->headers[state->i].value[0] = '\0';
    }

    EXPECTS("\r\n");

    http_request_log_debug(state->rh, "Parsed header %s: %s",
                           state->request_headers->headers[state->i].name,
                           state->request_headers->headers[state->i].value);
  }
  state->request_headers->num_headers = state->i;

  EXPECTS("\r\n");

  int err = HTTP_SUCCESS;
  if (false) {
  error:
    /* i see what you did there */
    err = HTTP_GENERIC_ERROR;
  }

  if (!err &&
      !state->rh->is_connection_close) {
    const char *connection_header;
    state->rh->is_connection_close =
      ((connection_header =
        http_get_header_value(state->request_headers, HTTP_HEADER_CONNECTION)) &&
       str_case_equals(connection_header, "close"));
  }

  /* deal with the request headers that dictate how the request body is tranferred */
  if (!err) {
    /* okay at this point we have the headers, make sure it's something
       we support */
    const char *transfer_encoding_str = http_get_header_value(state->request_headers, HTTP_HEADER_TRANSFER_ENCODING);
    const char *content_length_str = http_get_header_value(state->request_headers, HTTP_HEADER_CONTENT_LENGTH);
    if (transfer_encoding_str && content_length_str) {
      log_info("Client specified both Transfer-Encoding header and Content-Length header");
      err = HTTP_GENERIC_ERROR;
    }
    else if (transfer_encoding_str) {
      if (!ascii_strcaseequal(transfer_encoding_str, "chunked")) {
        log_info("Server does not support \"%s\" encoding", transfer_encoding_str);
        err = HTTP_GENERIC_ERROR;
      }
      else {
        state->rh->is_chunked_request = true;
        state->rh->persist_ctx.chunked_coro_ctx.pos = CORO_POS_INIT;
      }
    }
    else {
      long converted_content_length;
      if (content_length_str) {
        /* get the "Content-Length" header */
        converted_content_length = strtol(content_length_str, NULL, 10);
      }
      else {
        /* if there is no data header, treat it as zero-length body */
        converted_content_length = 0;
        errno = 0;
      }

      if (converted_content_length > 0 ||
          (converted_content_length == 0 && errno != EINVAL)) {
        state->rh->is_chunked_request = false;
        state->rh->persist_ctx.content_length_read.content_length = converted_content_length;
        state->rh->persist_ctx.content_length_read.bytes_read = 0;
      }
      else {
        err = HTTP_GENERIC_ERROR;
      }
    }
  }

  /* deal with the "Expect" request header */
  if (!err) {
    const char *expect_str = http_get_header_value(state->request_headers, "expect");
    if (expect_str) {
      if (str_equals(expect_str, "100-continue")) {
        /* write out 100 continue response */
        UTHR_YIELD(state,
                   _http_connection_write(state->rh->conn,
                                          "HTTP/1.1 100 Continue\r\n",
                                          sizeof("HTTP/1.1 100 Continue\r\n") - 1,
                                          c_get_request,
                                          state));
        UTHR_RECEIVE_EVENT(HTTP_CONNECTION_WRITE_DONE_EVENT,
                           HTTPConnectionWriteDoneEvent, write_done_ev);
        err = write_done_ev->error
          ? HTTP_GENERIC_ERROR
          /* we have to reinitialize since we're potentially re-entering this scope
             after the yield thta has just happened */
          : HTTP_SUCCESS;
      }
      else {
        /* we don't understand this, have to send an 417 (Expectation Failed) */
        state->response_headers = malloc(sizeof(HTTPResponseHeaders));

        assert(state->response_headers);
        http_response_init(state->response_headers);
        bool ret = http_response_set_code(state->response_headers,
                                          HTTP_STATUS_CODE_EXPECTATION_FAILED);
        ASSERT_TRUE(ret);
        ret = http_response_add_header(state->response_headers,
                                       HTTP_HEADER_CONTENT_LENGTH, "%d", 0);
        ASSERT_TRUE(ret);

        UTHR_YIELD(state,
                   http_request_write_headers(state->rh, state->response_headers,
                                              c_get_request, state));

        free(state->response_headers);

        assert(UTHR_EVENT_TYPE() == HTTP_REQUEST_WRITE_HEADERS_DONE_EVENT);

        /* return an error to the user's handler so it stops processing */
        err = HTTP_GENERIC_ERROR;
      }
    }
  }

  state->rh->read_state = HTTP_REQUEST_READ_STATE_READ_HEADERS;
  /* NB: against convention and as a shortcut,
     we use HTTP_REQUEST_READ_HEADERS_DONE_EVENT,
     not C_GET_REQUEST_DONE_EVENT */
  HTTPRequestReadHeadersDoneEvent read_headers_events = {
    .err = err,
    .request_handle = state->rh,
  };
  /* TODO: use real error numbers or just pass http errors through
     last_error_number */
  state->rh->conn->last_error_number = err == HTTP_SUCCESS ? 0 : 1;
  UTHR_RETURN(state,
              state->cb(HTTP_REQUEST_READ_HEADERS_DONE_EVENT,
                        &read_headers_events,
                        state->ud));

#undef PARSEINTVAR
#undef PARSEVAR
#undef EXPECTS
#undef EXPECT

  UTHR_FOOTER();
}

bool
http_response_add_header(HTTPResponseHeaders *rsp,
                         const char *name, const char *value_fmt, ...) {
  if (NELEMS(rsp->headers) == rsp->num_headers) {
    return false;
  }

  size_t len = strlen(name);
  // hard code error check, fix later if we have to be more defensive
  assert(len <= (sizeof(rsp->headers[rsp->num_headers].name) - 1));
  memcpy(rsp->headers[rsp->num_headers].name, name, len);
  rsp->headers[rsp->num_headers].name[len] = '\0';

  va_list ap;
  va_start(ap, value_fmt);
  int best_string_size = vsnprintf(rsp->headers[rsp->num_headers].value,
                                   sizeof(rsp->headers[rsp->num_headers].value),
                                   value_fmt, ap);
  /* poor man's error handling */
  ASSERT_TRUE(best_string_size >= 0);
  ASSERT_TRUE((size_t) best_string_size <= (sizeof(rsp->headers[rsp->num_headers].value) - 1));
  va_end(ap);

  rsp->num_headers += 1;

  return true;
}

const char *
http_error_to_string(http_error_code_t e) {
#define _EV(e) case e: return #e
  switch (e) {
    _EV(HTTP_SUCCESS);
    _EV(HTTP_GENERIC_ERROR);
  default: assert(false); return NULL;
  }
#undef _EV
}
