#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "c_util.h"
#include "coroutine.h"
#include "coroutine_io.h"
#include "events.h"
#include "fdevent.h"
#include "fd_utils.h"
#include "http_server.h"
#include "logging.h"

#define LISTEN_BACKLOG 5

/* static forward decls */
static void
accept_handler(event_type_t, void *, void *);
static void
client_coroutine(event_type_t, void *, void *);
static void
init_c_get_request_state(GetRequestState *state,
                         http_request_handle_t rh,
                         FDEventLoop *loop,
                         FDBuffer *f,
                         HTTPRequestHeaders *rhs,
                         event_handler_t cb,
                         void *ud) {
  *state = (GetRequestState) {
    .rh = rh,
    .loop = loop,
    .f = f,
    .request_headers = rhs,
    .cb = cb,
    .ud = ud,
  };
}

static void
c_get_request(event_type_t, void *, void *);

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
  
  bool ret;
  ret = fdevent_add_watch(loop, fd,
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
  memset(http, 0, sizeof(*http));
  close(fd);
  return false;
}

bool
http_server_stop(HTTPServer *http) {
  /* TODO: implement */
  assert(false);
  UNUSED(http);
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

  if (rctx->state != HTTP_REQUEST_STATE_NONE) {
    return cb(HTTP_REQUEST_READ_HEADERS_DONE_EVENT, NULL, cb_ud);
  }

  log_debug("FD %d Reading header", rctx->conn->f.fd);

  /* read out client http request */

  init_c_get_request_state(&rctx->conn->sub.grs,
                           rh,
                           rctx->conn->server->loop,
                           &rctx->conn->f,
                           request_headers,
                           cb,
                           cb_ud);
  c_get_request(START_COROUTINE_EVENT, NULL, &rctx->conn->sub.grs);
}

void
http_request_read(http_request_handle_t rh,
                  void *buf, size_t nbyte,
                  event_handler_t cb, void *cb_ud) {
  UNUSED(rh);
  UNUSED(cb);
  UNUSED(cb_ud);
  UNUSED(buf);
  UNUSED(nbyte);

}

struct _write_headers_state {
  coroutine_position_t coropos;
  union {
    WriteAllState was;
  } sub;
  int header_idx;
  char tmpbuf[1024];
  size_t out_size;

  /* args */
  HTTPResponseHeaders *response_headers;
  HTTPRequestContext *request_context;
  event_handler_t cb;
  void *cb_ud;
};

static void
_http_request_write_headers_coroutine(event_type_t ev_type, void *ev, void *ud) {
  struct _write_headers_state *whs = ud;

  UNUSED(ev);

  CRBEGIN(whs->coropos);
  assert(ev_type == START_COROUTINE_EVENT);

#define EMITN(b, n)                                                     \
  do {                                                                  \
    init_c_write_all_state(&whs->sub.was,                               \
                           whs->request_context->conn->server->loop,    \
                           whs->request_context->conn->f.fd,            \
                           b, n,                                        \
                           _http_request_write_headers_coroutine,       \
                           whs);                                        \
    CRYIELD(whs->coropos,                                               \
            c_write_all(START_COROUTINE_EVENT, NULL, &whs->sub.was));   \
    assert(ev_type == C_WRITEALL_DONE_EVENT);                           \
  }                                                                     \
  while (false)

#define EMIT(c) EMITN(c, sizeof(c) - 1)

  /* output response code */
  whs->out_size = snprintf(whs->tmpbuf, sizeof(whs->tmpbuf),
                           "HTTP/1.1 %d %s\r\n",
                           whs->response_headers->code,
                           whs->response_headers->message);
  EMITN(whs->tmpbuf, whs->out_size);

  /* output each header */
  for (whs->header_idx = 0; (size_t) whs->header_idx < whs->response_headers->num_headers;
       ++whs->header_idx) {
    EMIT(whs->response_headers->headers[whs->header_idx].name);
    EMIT(":");
    EMIT(whs->response_headers->headers[whs->header_idx].value);
    EMIT("\r\n");
  }

  /* connection close for now */
  EMIT("Connection: close\r\n");

  /* finish headers */
  EMIT("\r\n");

  /* TODO: call callback */

  CREND();
}

void
http_request_write_headers(http_request_handle_t rh,
                           HTTPResponseHeaders *response_headers,
                           event_handler_t cb,
                           void *cb_ud) {
  UNUSED(rh);
  UNUSED(cb);
  UNUSED(cb_ud);
  UNUSED(response_headers);

  struct _write_headers_state *whs;
  whs = malloc(sizeof(*whs));
  /* TODO: handle gracefully */
  assert(whs);

  *whs = (struct _write_headers_state) {
    .coropos = CORO_POS_INIT,
    .response_headers = response_headers,
    .request_context = rh,
    .cb = cb,
    .cb_ud = cb_ud,
  };

  _http_request_write_headers_coroutine(START_COROUTINE_EVENT, NULL, whs);
}


#if 0


    EMITN(cc->outbuffer, cc->out_size);
    EMIT("\r\n");

#undef EMIT
#undef EMITN

#endif
}

void
http_request_write(http_request_handle_t rh,
                   const void *buf, size_t nbyte,
                   event_handler_t cb, void *cb_ud) {
  UNUSED(rh);
  UNUSED(cb);
  UNUSED(cb_ud);
  UNUSED(buf);
  UNUSED(nbyte);
}

void
http_request_end(http_request_handle_t rh,
                 event_handler_t cb, void *cb_ud) {
  UNUSED(rh);
  UNUSED(cb);
  UNUSED(cb_ud);
}

static CONST_FUNCTION char
ascii_to_lower(char a) {
  return a + ((65 <= a && a <= 90) ? 33 : 0);
}

static CONST_FUNCTION bool
ascii_strcaseequal(const char *a, const char *b) {
  int i;
  for (i = 0;
       (ascii_to_lower(a[i]) == ascii_to_lower(b[i]) &&
        (a[i] != '\0' || b[i] != '\0'));
       ++i) {
  }
  return a[i] == '\0' && b[i] == '\0';
}

char *
http_get_header_value(HTTPRequestHeaders *rhs, const char *header_name) {
  UNUSED(rhs);
  UNUSED(header_name);

  /* headers can only be ascii */
  for (unsigned i = 0; i < rhs->num_headers; ++i) {
    if (ascii_strcaseequal(header_name, rhs->headers[i].name)) {
      return rhs->headers[i].value;
    }
  }

  return NULL;
}

static void
accept_handler(event_type_t ev_type, void *ev, void *ud) {
  HTTPServer *http = (HTTPServer *) ud;
  HTTPConnection *cc = NULL;
  int client_fd = -1;
  FDEvent *fdev = ev;

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

  if (set_non_blocking(client_fd) < 0) {
    log_error("Couldn't make client fd non-blocking: %s", strerror(errno));
    goto error;
  }

  cc = malloc(sizeof(*cc));
  if (!cc) {
    log_error("Couldn't allocate memory for new client");
    goto error;
  }

  *cc = (HTTPConnection) {.f = {.fd = client_fd},
                          .server = http,
                          .coropos = CORO_POS_INIT};

  /* run client */
  client_coroutine(START_COROUTINE_EVENT, NULL, cc);

  return;

 error:
  if (client_fd >= 0) {
    close(client_fd);
  }

  if (cc) {
    free(cc);
  }
}

static void
client_coroutine(event_type_t ev_type, void *ev, void *ud) {
  HTTPConnection *cc = ud;

  UNUSED(ev);
  
  CRBEGIN(cc->coropos);

  assert(ev_type == START_COROUTINE_EVENT);

  while (true) {
    /* initialize the request context */
    cc->rctx = (HTTPRequestContext) {
      .conn = cc,
      .state = HTTP_REQUEST_STATE_NONE,
    };

    /* create request event, we can do this on the stack
       because the handler shouldn't use this after */
    HTTPNewRequestEvent new_request_ev = {
      .request_handle = &cc->rctx,
    };
    CRYIELD(cc->coropos, 
            cc->server->handler(HTTP_NEW_REQUEST_EVENT,
                                &new_request_ev,
                                cc->server->ud));
    /* we'll come back when `http_request_end` is called,
       or there is some error */

    /* only connection close for now */
    break;
  }

  close(cc->f.fd);
  CRRETURN(cc->coropos, 0);

  CREND();
}

static void
c_get_request(event_type_t ev_type, void *ev, void *ud) {
  /* do this before CRBEGIN jumps away */
  GetRequestState *state = ud;
  UNUSED(ev);

  CRBEGIN(state->coropos);
  assert(ev_type == START_COROUTINE_EVENT);

#define PEEK()                                                  \
  do {                                                          \
    if ((state->c = fbpeek(state->f)) < 0) {                    \
      init_c_fbpeek_state(&state->sub.peek_state,               \
                          state->loop, state->f, &state->c,     \
                          c_get_request, state);                \
      CRYIELD(state->coropos,                                   \
              c_fbpeek(START_COROUTINE_EVENT, NULL,             \
                       &state->sub.peek_state));                \
      assert(ev_type == C_FBPEEK_DONE_EVENT);                   \
    }                                                           \
  }                                                             \
  while (false)

#define EXPECT(_c)                                              \
  do {                                                          \
    /* first check the synchronous interface, to avoid          \
       many layers of nesting */                                \
    if ((state->c = fbgetc(state->f)) < 0) {                   \
      init_c_fbgetc_state(&state->sub.getc_state,               \
                          state->loop, state->f, &state->c,     \
                          c_get_request, state);                \
      CRYIELD(state->coropos,                                   \
              c_fbgetc(START_COROUTINE_EVENT, NULL,             \
                       &state->sub.getc_state));                \
      assert(ev_type == C_FBGETC_DONE_EVENT);                   \
    }                                                           \
    if ((char) state->c != (_c)) {                              \
      log_error("Didn't get the character we "                  \
                "were expecting: '%c' vs '%c'",                 \
                state->c, (_c));                                \
      goto error;                                               \
    }                                                           \
  }                                                             \
  while (false)

#define EXPECTS(_s)                                                     \
  do {                                                                  \
    for (state->ei = 0; state->ei < (int) sizeof(_s) - 1; ++state->ei) { \
      EXPECT(_s[state->ei]);                                            \
    }                                                                   \
  }                                                                     \
  while (false)

#define PARSEVAR(var, fn)                                               \
  do {                                                                  \
    init_c_getwhile_state(&state->sub.getwhile_state, state->loop,      \
                          state->f,                                     \
                          var, sizeof(var) - 1, fn, &state->parsed,     \
                          c_get_request, state);                        \
    CRYIELD(state->coropos,                                             \
            c_getwhile(START_COROUTINE_EVENT, NULL,                     \
                       &state->sub.getwhile_state));                    \
    assert(ev_type == C_GETWHILE_DONE_EVENT);                           \
    assert(state->parsed <= sizeof(var) - 1);                           \
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

  log_debug("FD %d, Parsed request line", state->f->fd);

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
              state->f->fd,
              state->request_headers->headers[state->i].name,
              state->request_headers->headers[state->i].value);
  }
  state->request_headers->num_headers = state->i;

  EXPECTS("\r\n");

  int err = 0;
  if (false) {
  error:
    /* i see what you did there */
    err = 1;
  }

  /* NB: against convention and as a shortcut,
     we use HTTP_REQUEST_READ_HEADERS_DONE_EVENT,
     not C_GET_REQUEST_DONE_EVENT */
  HTTPRequestReadHeadersDoneEvent read_headers_events = {
    .err = err,
    .request_handle = state->rh,
  };
  CRRETURN(state->coropos,
           state->cb(HTTP_REQUEST_READ_HEADERS_DONE_EVENT,
                     &read_headers_events, 
                     state->ud));

  CREND();

#undef PARSEINTVAR
#undef PARSEVAR
#undef EXPECTS
#undef EXPECT
}
