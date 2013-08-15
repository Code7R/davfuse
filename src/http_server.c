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
#include "events.h"
#include "http_backend.h"
#include "logging.h"
#include "util.h"
#include "uthread.h"

#define _IS_HTTP_SERVER_C
#include "http_server.h"
#undef _IS_HTTP_SERVER_C

/* define opaque structures */
typedef struct _http_server {
  http_backend_t backend;
  event_handler_t handler;
  void *ud;
  bool shutting_down;
  size_t num_connections;
  event_handler_t stop_cb;
  void *stop_ud;
} HTTPServer;

typedef struct _http_request_context {
  struct _http_connection *conn;
  HTTPRequestHeaders rh;
  http_request_write_state_t write_state;
  http_request_read_state_t read_state;
  size_t out_content_length;
  size_t bytes_written;
  int last_error_number;
  bool is_chunked_request;
  union {
    struct chunked_read_persist_ctx {
      coroutine_position_t pos;
      char var_buf[4096];
      size_t chunk_size;
      size_t chunk_read;
      size_t amt_parsed;
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
  http_backend_handle_t handle;
  ReadBuffer f;
  struct _http_server *server;
  /* these might become per-request,
     right now we only do one request at a time,
     i.e. no pipe-lining */
  union {
    char buffer[OUT_BUF_SIZE];
    HTTPResponseHeaders rsp;
    HTTPRequestHeaders req;
  } spare;
  struct _http_request_context rctx;
} HTTPConnection;

const char *const HTTP_HEADER_CONNECTION = "Connection";
const char *const HTTP_HEADER_CONTENT_LENGTH = "Content-Length";
const char *const HTTP_HEADER_CONTENT_TYPE = "Content-Type";
const char *const HTTP_HEADER_DATE = "Date";
const char *const HTTP_HEADER_HOST = "Host";
const char *const HTTP_HEADER_TRANSFER_ENCODING = "Transfer-Encoding";

/* static forward decls */
static
EVENT_HANDLER_DECLARE(accept_handler);
static
EVENT_HANDLER_DECLARE(client_coroutine);
static
UTHR_DECLARE(c_get_request);


/* small layer of indirection */
typedef HttpBackendWriteDoneEvent HTTPConnectionWriteDoneEvent;

static void
_http_connection_read(HTTPConnection *conn, void *buf, size_t nbyte,
                      event_handler_t cb, void *ud) {
  return http_backend_read(conn->server->backend, conn->handle,
                           buf, nbyte, cb, ud);
}

static void
_http_connection_write(HTTPConnection *conn, const void *buf, size_t nbyte,
                       event_handler_t cb, void *ud){
  return http_backend_write(conn->server->backend, conn->handle,
                            buf, nbyte, cb, ud);
}

http_server_t
http_server_start(http_backend_t backend,
                  event_handler_t handler,
                  void *ud) {
  struct _http_server *http = malloc(sizeof(*http));
  if (!http) {
    return http;
  }

  *http = (struct _http_server) {
    .backend = backend,
    .handler = handler,
    .ud = ud,
  };

  http_backend_accept(backend, accept_handler, http);

  return http;
}

void
http_server_stop(http_server_t http,
                 event_handler_t cb, void *user_data) {
  http_backend_stop_accept(http->backend);

  http->shutting_down = true;
  http->stop_cb = cb;
  http->stop_ud = user_data;

  if (!http->num_connections) {
    /* no more connections, call callback immediately */
    free(http);
    cb(HTTP_SERVER_STOP_DONE_EVENT, NULL, user_data);
  }
}

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

  log_debug("FD %p Reading header", rctx->conn);

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
  rctx->last_error_number = c_read_done_ev->error_number;
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

  HTTPRequestContext *rctx = ud;
  struct chunked_read_persist_ctx *cctx = &rctx->persist_ctx.chunked_coro_ctx;
  struct chunked_read_temp_ctx *tctx = &rctx->sub.chunked_read_ctx;

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
    assert(cctx->amt_parsed <= sizeof(cctx->var_buf) - 1);

    if (!cctx->amt_parsed) {
      /* nothing was parsed, either EOF or wrong character */
      log_info("There was no chunk size to be parsed!");
      goto error;
    }

    cctx->var_buf[cctx->amt_parsed] = '\0';
    intmax_t chunk_size  = strtoll(cctx->var_buf, NULL, 16);
    /* since we used `match_hex_digit`, we couldn't have had
       an invalid input */
    assert(!(!chunk_size && errno == EINVAL));

    if (chunk_size < 0 || ((uintmax_t) chunk_size) > SIZE_MAX) {
      log_info("Chunk size is too large: %jd", chunk_size);
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

      rctx->last_error_number = 1;
      CRYIELD(cctx->pos,
              tctx->cb(HTTP_REQUEST_READ_DONE_EVENT, &read_done_ev, tctx->cb_ud));
      assert(ev_type == GENERIC_EVENT);
      assert(!tctx->input_buf_offset);
    }
  }

  /* no more data, just keep returning EOF */
  log_debug("Chunked request is over");
  while (true) {
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
  /* TODO: consider not using malloc/asprintf here */
  int ret = snprintf(whs->response_line,
		     sizeof(whs->response_line),
		     "HTTP/1.1 %d %s\r\n",
		     whs->response_headers->code,
		     whs->response_headers->message);
  if (ret < 0) {
    myerrno = ENOMEM;
    goto done;
  }
  log_debug("Writing response, code: %d, message: %s",
            whs->response_headers->code,
            whs->response_headers->message);
  EMITN(whs->response_line, ret);

  /* add date header */
  const time_t tt = time(NULL);
  struct tm *const tm_ = gmtime(&tt);
  const char *const fmt = "Date: %a, %d %b %Y %H:%M:%S GMT\r\n";
  const int ret_sprint2 =
    strftime(whs->response_line, sizeof(whs->response_line), fmt, tm_);
  if (ret_sprint2 < 0) {
    myerrno = ENOMEM;
    goto done;
  }
  EMITN(whs->response_line, ret_sprint2);

  /* TODO: support persistent connections */
  EMIT("Connection: close\r\n");

  /* output each header */
  for (whs->header_idx = 0; whs->header_idx < whs->response_headers->num_headers;
       ++whs->header_idx) {
    log_debug("Writing response header: %s: %s",
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
    log_warning("Error while writing headers to client %p",
                whs->request_context->conn);
  }

  whs->request_context->write_state = HTTP_REQUEST_WRITE_STATE_WROTE_HEADERS;
  HTTPRequestWriteHeadersDoneEvent write_headers_ev = {
    .request_handle = whs->request_context,
    .err = myerrno ? HTTP_GENERIC_ERROR : HTTP_SUCCESS,
  };
  whs->request_context->last_error_number = myerrno;
  UTHR_RETURN(whs,
              whs->cb(HTTP_REQUEST_WRITE_HEADERS_DONE_EVENT,
                      &write_headers_ev, whs->cb_ud));

  UTHR_FOOTER();

#undef EMIT
#undef EMITN
#undef EMITS
}

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

  /* check if the response has a "Content-Length" header
     this is used as a hint by the handlers to tell the server
     how much it's going to write, right now it's strictly necessary
     but we may relax this in the future (esp if we negotiate chunked encoding) */
  {
    const char *content_length_str = _get_header_value(response_headers->headers,
                                                       response_headers->num_headers,
                                                       HTTP_HEADER_CONTENT_LENGTH);
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
    rctx->last_error_number = 1;
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
    log_warning("ON conn: %p, http_request_write failed",
                rws->request_context->conn);
    rws->request_context->last_error_number = 1;
  }
  else {
    rws->request_context->bytes_written += write_all_done_event->nbyte;
    rws->request_context->last_error_number = 0;
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

  assert(rctx->out_content_length >= rctx->bytes_written);
  if (nbyte > rctx->out_content_length - rctx->bytes_written) {
    /* TODO: right now have no facility to do short writes,
       could return write amount when done
    */
    log_warning("ON conn: %p, "
                "http_request_write will not do a short write, "
                "request to write less. wanted to write %d, "
                "but there was only %d left to write",
                rctx->conn, nbyte,
                rctx->out_content_length - rctx->bytes_written);
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
  UNUSED(ev_type);
  assert(ev_type == HTTP_BACKEND_ACCEPT_DONE_EVENT);
  HttpBackendAcceptDoneEvent *accept_done_ev = ev;
  HTTPServer *http = ud;

  if (accept_done_ev->error) {
    log_error("accept() client connection failed!");
    return;
  }

  assert(!http->shutting_down);

  http->num_connections += 1;

  /* run client */
  HTTPConnection *ctx = malloc_or_abort(sizeof(*ctx));
  *ctx = (HTTPConnection) {
    .handle = accept_done_ev->handle,
    .f = {
      .read_fn = (read_fn_t) _http_connection_read,
      .handle = ctx,
      .in_use = false,
    },
    .server = http,
  };
  UTHR_RUN(client_coroutine, ctx);

  return http_backend_accept(http->backend, accept_handler, http);
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

  while (true) {
    /* initialize the request context */
    cc->rctx = (HTTPRequestContext) {
      .conn = cc,
      .read_state = HTTP_REQUEST_READ_STATE_NONE,
      .write_state = HTTP_REQUEST_WRITE_STATE_NONE,
      .last_error_number = 0,
    };

    /* TODO: Prevent against "slowloris" style attacks
       with clients who send their headers very very slowly:
       give some timeout to total request processing
     */

    /* create request event, we can do this on the stack
       because the handler shouldn't use this after */
    HTTPNewRequestEvent new_request_ev = {
      .server = cc->server,
      .request_handle = &cc->rctx,
    };
    UTHR_YIELD(cc,
               cc->server->handler(HTTP_NEW_REQUEST_EVENT,
                                   &new_request_ev,
                                   cc->server->ud));
    assert(UTHR_EVENT_TYPE() == HTTP_END_REQUEST_EVENT);
    /* we'll come back when `http_request_end` is called,
       or there is some error */

    /* read headers if they were ignored */
    if (!cc->rctx.last_error_number &&
        cc->rctx.read_state == HTTP_REQUEST_READ_STATE_NONE) {
      static HTTPRequestHeaders dirty_headers;
      UTHR_YIELD(cc,
                 http_request_read_headers(&cc->rctx, &dirty_headers,
                                           client_coroutine, cc));
      assert(UTHR_EVENT_TYPE() == HTTP_REQUEST_READ_HEADERS_DONE_EVENT);
    }

    /* read out all data if it was ignored */
    if (!cc->rctx.last_error_number &&
        cc->rctx.read_state == HTTP_REQUEST_READ_STATE_READ_HEADERS) {
      while (true) {
        UTHR_YIELD(cc,
                   http_request_read(&cc->rctx, cc->spare.buffer,
                                     sizeof(cc->spare.buffer),
                                     client_coroutine, cc));
        assert(UTHR_EVENT_TYPE() == HTTP_REQUEST_READ_DONE_EVENT);
        HTTPRequestReadDoneEvent *read_done_ev = UTHR_EVENT();
        if (read_done_ev->err || !read_done_ev->nbyte) {
          break;
        }
      }
    }

    /* clean up write side of request */
    if (!cc->rctx.last_error_number &&
        cc->rctx.write_state == HTTP_REQUEST_WRITE_STATE_NONE) {
      UTHR_YIELD(cc,
                 _write_out_internal_server_error(&cc->rctx,
                                                  client_coroutine, cc));
      assert(UTHR_EVENT_TYPE() == HTTP_REQUEST_WRITE_HEADERS_DONE_EVENT);
    }

    /* write out rest of garbage if request ended prematurely */
    if (!cc->rctx.last_error_number &&
        cc->rctx.write_state == HTTP_REQUEST_WRITE_STATE_WROTE_HEADERS) {
      while (cc->rctx.bytes_written < cc->rctx.out_content_length) {
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
        HTTPRequestWriteDoneEvent *write_done_ev = UTHR_EVENT();
        /* bytes_written is incremented in http_request_write */
        if (write_done_ev->err) {
          break;
        }
      }
    }

    /* TODO: support persistent connections */
    break;

    if (cc->rctx.last_error_number) {
      /* break if there was an error */
      break;
    }
    else {
      cc->rctx.read_state = HTTP_REQUEST_READ_STATE_DONE;
      cc->rctx.write_state = HTTP_REQUEST_WRITE_STATE_DONE;
    }
  }

  log_debug("Client done, closing conn %p", cc);
  bool success_close = http_backend_close(cc->server->backend, cc->handle);
  if (!success_close) {
    abort();
  }
  /* NB: ordinarily we'd call UTHR_RETURN, but we need
     to free the memory first before calling the stop handler */
  HTTPServer *server = cc->server;
  UTHR_FREE(cc);
  server->num_connections -= 1;
  if (!server->num_connections && server->shutting_down) {
    event_handler_t cb = server->stop_cb;
    void *ud = server->stop_ud;
    free(server);
    return cb(HTTP_SERVER_STOP_DONE_EVENT, NULL, ud);
  }
  else {
    return;
  }

  UTHR_FOOTER();
}

static
UTHR_DEFINE(c_get_request) {
  UTHR_HEADER(GetRequestState, state);

#define PEEK()                                                  \
  do {                                                          \
    if ((state->c = fbpeek(&state->rh->conn->f)) < 0) {          \
      UTHR_YIELD(state,                                         \
                 c_fbpeek(&state->rh->conn->f,                   \
                          &state->c,                            \
                          c_get_request, state));               \
      assert(UTHR_EVENT_TYPE() == C_FBPEEK_DONE_EVENT);         \
    }                                                           \
  }                                                             \
  while (false)

#define EXPECT(_c)                                              \
  do {                                                          \
    /* first check the synchronous interface, to avoid          \
       many layers of nesting */                                \
    if ((state->c = fbgetc(&state->rh->conn->f)) < 0) {             \
      UTHR_YIELD(state,                                            \
                 c_fbgetc(&state->rh->conn->f,                     \
                          &state->c,                               \
                          c_get_request, state));                  \
      assert(UTHR_EVENT_TYPE() == C_FBGETC_DONE_EVENT);            \
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
    assert(state->parsed <= sizeof(var) - 1);                           \
    if (!state->parsed) {						\
      log_error("Parsed empty var!");					\
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

  log_debug("Got method '%s'", state->request_headers->method);

  /* request-uri = "*" | absoluteURI | abs_path | authority */
  /* we don't parse super intelligently here because
     http URIs aren't LL(1), authority and absoluteURI start with
     the same prefix string */
  PARSEVAR(state->request_headers->uri, match_non_null_or_space);
  EXPECT(' ');

  log_debug("Got uri '%s'", state->request_headers->uri);

  EXPECTS("HTTP/");
  PARSEINTVAR(state->request_headers->major_version);
  EXPECT('.');
  PARSEINTVAR(state->request_headers->minor_version);
  EXPECTS("\r\n");

  log_debug("Got version '%d.%d'",
            state->request_headers->major_version,
            state->request_headers->minor_version);

  log_debug("conn %p, Parsed request line",
            state->rh->conn);

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

    log_debug("Conn %p, Parsed header %s: %s",
              state->rh->conn,
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
  state->rh->last_error_number = err == HTTP_SUCCESS ? 0 : 1;
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

NON_NULL_ARGS0() bool
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
