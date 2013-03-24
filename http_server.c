#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "c_util.h"
#include "coroutine.h"
#include "coroutine_io.h"
#include "events.h"
#include "fdevent.h"
#include "fd_utils.h"
#include "logging.h"
#include "util.h"
#include "uthread.h"

#define _IS_HTTP_SERVER_C
#include "http_server.h"
#undef _IS_HTTP_SERVER_C

enum {
  LISTEN_BACKLOG=5,
};

const char *HTTP_HEADER_CONTENT_LENGTH = "Content-Length";

/* static forward decls */
static
EVENT_HANDLER_DECLARE(accept_handler);
static
EVENT_HANDLER_DECLARE(client_coroutine);
static
UTHR_DECLARE(c_get_request);

bool
http_server_start(HTTPServer *http,
                  FDEventLoop *loop,
                  int fd,
                  event_handler_t handler,
                  void *ud) {
  /*
    we expect the fd to be capable of a couple things:
    1. you can call listen() on it
    1. you can call accept() on it
    2. you can get read readiness info on it

    at this point we own the fd
  */
  assert(http);
  assert(loop);
  assert(fd >= 0);

  memset(http, 0, sizeof(*http));

  if (listen(fd, LISTEN_BACKLOG)) {
    goto error;
  }

  if (!set_non_blocking(fd)) {
    goto error;
  }

  bool ret = fdevent_add_watch(loop, fd,
			       create_stream_events(true, false),
			       &accept_handler,
			       http,
			       &http->watch_key);
  if (!ret) {
    goto error;
  }

  http->fd = fd;
  http->handler = handler;
  http->loop = loop;
  http->ud = ud;

  return true;

 error:
  close(fd);
  http->fd = -1;
  http->watch_key = FD_EVENT_INVALID_WATCH_KEY;
  return false;
}

bool
http_server_stop(HTTPServer *http) {
  if (http->watch_key != FD_EVENT_INVALID_WATCH_KEY) {
    bool ret = fdevent_remove_watch(http->loop, http->watch_key);
    assert(ret);
    http->watch_key = FD_EVENT_INVALID_WATCH_KEY;
  }
  if (http->fd >= 0) {
    close(http->fd);
    http->fd = -1;
  }
  return true;
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

  log_debug("FD %d Reading header", rctx->conn->f.fd);

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

  ReadRequestState *rrs = ud;
  CReadDoneEvent *c_read_done_ev = ev;

  HTTPRequestReadDoneEvent read_done_ev = {
    .request_handle = rrs->request_context,
    .err = c_read_done_ev->error_number ? HTTP_GENERIC_ERROR : HTTP_SUCCESS,
    .nbyte = c_read_done_ev->nbyte,
  };
  rrs->request_context->bytes_read += c_read_done_ev->nbyte;
  rrs->request_context->last_error_number = c_read_done_ev->error_number;
  rrs->cb(HTTP_REQUEST_READ_DONE_EVENT, &read_done_ev, rrs->cb_ud);
}

void
http_request_read(http_request_handle_t rh,
                  void *buf, size_t nbyte,
                  event_handler_t cb, void *cb_ud) {
  HTTPRequestContext *rctx = rh;

  rctx->sub.rrs = (ReadRequestState) {
    .request_context = rh,
    .cb = cb,
    .cb_ud = cb_ud,
  };

  assert(rctx->content_length >= rctx->bytes_read);
  nbyte = MIN(nbyte, rctx->out_content_length - rctx->bytes_read);

  return c_read(rctx->conn->server->loop, &rctx->conn->f,
                buf, nbyte,
                _handle_request_read,
                &rctx->sub.rrs);
}

static
UTHR_DEFINE(_http_request_write_headers_coroutine) {
  UTHR_HEADER(WriteHeadersState, whs);

  int myerrno = 0;
  whs->request_context->write_state = HTTP_REQUEST_WRITE_STATE_WRITING_HEADERS;

#define EMITN(b, n)                                                     \
  do {                                                                  \
    UTHR_YIELD(whs,                                                     \
               c_write_all(whs->request_context->conn->server->loop,    \
                           whs->request_context->conn->f.fd,            \
                           b, n,                                        \
                           _http_request_write_headers_coroutine,       \
                           whs));                                       \
    assert(UTHR_EVENT_TYPE() == C_WRITEALL_DONE_EVENT);                 \
    myerrno = ((CWriteAllDoneEvent *) UTHR_EVENT())->error_number;      \
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
  EMITN(whs->response_line, ret);

  /* output each header */
  for (whs->header_idx = 0; whs->header_idx < whs->response_headers->num_headers;
       ++whs->header_idx) {
    EMITS(whs->response_headers->headers[whs->header_idx].name);
    EMIT(":");
    EMITS(whs->response_headers->headers[whs->header_idx].value);
    EMIT("\r\n");
  }

  /* finish headers */
  EMIT("\r\n");

 done:
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

static PURE_FUNCTION char
ascii_to_lower(char a) {
  return a + ((65 <= a && a <= 90) ? 33 : 0);
}

static PURE_FUNCTION bool
ascii_strcaseequal(const char *a, const char *b) {
  int i;
  for (i = 0;
       (ascii_to_lower(a[i]) == ascii_to_lower(b[i]) &&
        (a[i] != '\0' || b[i] != '\0'));
       ++i) {
  }
  return a[i] == '\0' && b[i] == '\0';
}

static PURE_FUNCTION const char *
_get_header_value(const struct _header_pair *headers, size_t num_headers, const char *header_name) {
  /* headers can only be ascii */
  for (size_t i = 0; i < num_headers; ++i) {
    if (ascii_strcaseequal(header_name, headers[i].name)) {
      return (char *) headers[i].value;
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
      goto error;
    }

    long content_length = strtol(content_length_str, NULL, 10);
    if ((content_length == 0 && errno) ||
        content_length < 0) {
      goto error;
    }

    rctx->out_content_length = content_length;
  }

  if (false) {
    HTTPRequestWriteHeadersDoneEvent write_headers_ev;
  error:
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
  assert(ev_type == C_WRITEALL_DONE_EVENT);
  CWriteAllDoneEvent *write_all_done_event = ev;

  rws->request_context->write_state = HTTP_REQUEST_WRITE_STATE_WROTE_HEADERS;
  HTTPRequestWriteDoneEvent write_ev = {
    .request_handle = rws->request_context,
    .err = write_all_done_event->error_number ? HTTP_GENERIC_ERROR : HTTP_SUCCESS,
  };
  rws->request_context->bytes_written += write_all_done_event->nbyte;
  rws->request_context->last_error_number = write_all_done_event->error_number;
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

  c_write_all(rctx->conn->server->loop,
              rctx->conn->f.fd,
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
  HTTPServer *http = (HTTPServer *) ud;
  int client_fd = -1;
  FDEvent *fdev = ev;

  UNUSED(ev_type);
  UNUSED(ud);

  assert(ev_type == FD_EVENT);
  assert(stream_events_are_equal(fdev->events,
                                 create_stream_events(true, false)));
  assert(http->loop == fdev->loop);
  assert(http->fd == fdev->fd);

  client_fd = accept(fdev->fd, NULL, NULL);
  if (client_fd < 0) {
    log_error("Couldn't accept client connnection: %s", strerror(errno));
    goto error;
  }

  log_debug("New client! %d", client_fd);

  /* wait for next client */
  /* NB: need to do this before calling the client handler because
     it could attempt to stop the http server */
  bool ret = fdevent_add_watch(http->loop, http->fd,
                               create_stream_events(true, false),
                               accept_handler, http, &http->watch_key);
  UNUSED(ret);
  assert(ret);

  if (set_non_blocking(client_fd) < 0) {
    log_error("Couldn't make client fd non-blocking: %s", strerror(errno));
    goto error;
  }

  /* run client */
  HTTPConnection ctx = {
    .f = {
      .fd = client_fd,
      .in_use = false,
    },
    .server = http,
  };
  UTHR_CALL(client_coroutine, HTTPConnection, ctx);

  return;

 error:
  if (client_fd >= 0) {
    close(client_fd);
  }
}

static void
_write_out_internal_server_error(http_request_handle_t rh,
                                 event_handler_t handler, void *ud) {
  HTTPRequestContext *rctx = rh;
  HTTPResponseHeaders *rsp = &rctx->conn->spare.rsp;

  const char msg[] = "Internal Server Error";

  rsp->code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
  strncpy(rsp->message, msg, sizeof(rsp->message));
  rsp->num_headers = 1;
  strncpy(rsp->headers[0].name, HTTP_HEADER_CONTENT_LENGTH, sizeof(rsp->headers[0].name));
  snprintf(rsp->headers[0].value, sizeof(rsp->headers[0].value), "%d", 0);

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
      .bytes_read = 0,
      .bytes_written = 0,
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
      while (!cc->rctx.last_error_number &&
             cc->rctx.bytes_read < cc->rctx.content_length) {
        UTHR_YIELD(cc,
                   http_request_read(&cc->rctx, cc->spare.buffer,
                                     MIN(cc->rctx.content_length - cc->rctx.bytes_read,
                                         sizeof(cc->spare.buffer)),
                                     client_coroutine, cc));
        assert(UTHR_EVENT_TYPE() == HTTP_REQUEST_READ_DONE_EVENT);
        /* cc->rctx.bytes_read is incremented in `http_request_read()` */
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
      while (!cc->rctx.last_error_number &&
             cc->rctx.bytes_written < cc->rctx.out_content_length) {
        /* initted to zero because static */
        static char bytes[4096];
        /* just writing bytes */
        UTHR_YIELD(cc,
                   http_request_write(&cc->rctx, bytes, sizeof(bytes),
                                      client_coroutine, cc));
        assert(UTHR_EVENT_TYPE() == HTTP_REQUEST_WRITE_DONE_EVENT);
        /* bytes_written is incremented in http_request_write */
      }
    }

    if (cc->rctx.last_error_number) {
      /* break if there was an error */
      break;
    }
    else {
      cc->rctx.read_state = HTTP_REQUEST_READ_STATE_DONE;
      cc->rctx.write_state = HTTP_REQUEST_WRITE_STATE_DONE;
    }
  }

  log_debug("Client done, closing descriptor %d", cc->f.fd);
  close(cc->f.fd);
  UTHR_RETURN(cc, 0);

  UTHR_FOOTER();
}

static
UTHR_DEFINE(c_get_request) {
  UTHR_HEADER(GetRequestState, state);

#define PEEK()                                                  \
  do {                                                          \
    if ((state->c = fbpeek(&state->rh->conn->f)) < 0) {          \
      UTHR_YIELD(state,                                         \
                 c_fbpeek(state->rh->conn->server->loop,        \
                          &state->rh->conn->f,                   \
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
                 c_fbpeek(state->rh->conn->server->loop,           \
                          &state->rh->conn->f,                     \
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
               c_getwhile(state->rh->conn->server->loop,                \
                          &state->rh->conn->f,                          \
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
    errno = 0;                                                  \
    _val = strtol(state->tmpbuf, NULL, 10);                     \
    if (errno || _val > INT_MAX || _val < INT_MIN) {            \
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

  log_debug("FD %d, Parsed request line", state->rh->conn->f.fd);

  for (state->i = 0; state->i < (int) NELEMS(state->request_headers->headers);
       ++state->i) {
    PEEK();

    if (state->c == '\r') {
      break;
    }

    PARSEVAR(state->request_headers->headers[state->i].name,
             match_non_null_or_colon);
    EXPECT(':');
    PARSEVAR(state->request_headers->headers[state->i].value,
             match_non_null_or_carriage_return);
    EXPECTS("\r\n");

    log_debug("FD %d, Parsed header %s:%s",
              state->rh->conn->f.fd,
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

  if (err == HTTP_SUCCESS) {
    /* okay at this point we have the headers, make sure it's something
       we support */
    if (!strcasecmp(state->request_headers->method, "POST") ||
        !strcasecmp(state->request_headers->method, "PUT")) {
      /* get the content-length header */
      /* TODO: support 'chunked' encoding */
      const char *content_length_str = http_get_header_value(state->request_headers, HTTP_HEADER_CONTENT_LENGTH);
      if (content_length_str) {
        long converted_content_length = strtol(content_length_str, NULL, 10);
        if (converted_content_length >= 0 && !errno) {
          state->rh->content_length = converted_content_length;
        }
        else {
          err = HTTP_GENERIC_ERROR;
        }
      }
      else {
        err = HTTP_GENERIC_ERROR;
      }
    }
    else {
      state->rh->content_length = 0;
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
  assert(best_string_size >= 0);
  assert((size_t) best_string_size <= (sizeof(rsp->headers[rsp->num_headers].value) - 1));
  va_end(ap);

  rsp->num_headers += 1;

  return true;
}

NON_NULL_ARGS3(1, 3, 4) void
http_request_simple_response(http_request_handle_t rh,
			     http_status_code_t code, const char *body,
			     event_handler_t cb, void *cb_ud) {
  /* not yet implemented */
  UNUSED(rh);
  UNUSED(code);
  UNUSED(body);
  UNUSED(cb);
  UNUSED(cb_ud);
  assert(false);
}

