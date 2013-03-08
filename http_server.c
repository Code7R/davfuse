#include <stdbool.h>

#include "c_util.h"
#include "coroutine.h"
#include "coroutine_io.h"
#include "fdevent.h"
#incldue "fd_utils.h"
#include "http_server.h"
#include "logging.h"

#define LISTEN_BACKLOG 5

bool
http_server_start(HTTPServer *http,
		  FDEventLoop *loop,
		  int fd,
		  http_handler handler, 
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
  assert(accept_fn);

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
}

static void
accept_handler(int fd, StreamEvents events, void *ud) {
  ClientConnection *cc = NULL;
  HTTPServer *http = (HTTPServer *) ud;
  int client_fd = -1;
  bool ret;

  UNUSED(fd);
  UNUSED(events);
  UNUSED(ud);

  client_fd = accept(fd, NULL, NULL);
  if (client_fd < 0) {
    log_error("Couldn't accept client connnection: %s", strerror(errno));
    goto error;
  }

  if (set_non_blocking(client_fd) < 0) {
    log_error("Couldn't make client fd non-blocking: %s", strerror(errno));
    goto error;
  }

  cc = malloc(sizeof(*cc));
  if (!cc) {
    log_error("Couldn't allocate memory for new client");
    goto error;
  }

  *cc = {.f = {.fd = client_fd},
	 .server = http,
	 .coropos = CORO_POS_INIT};

  /* the client is read to accept connections! */
  ret = fdevent_add_watch(http->loop, cc->f.fd,
			  create_stream_events(true, false),
                          client_handler, cc, &cc->watch_key);
  if (!ret) {
    log_error("Couldn't add fd watch for new client!");
    goto error;
  }

  log_debug("New client! %d", client_fd);

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
client_handler(int fd, StreamEvents events, void *ud) {
  ClientConnection *cc = ud;

  UNUSED(fd);
  UNUSED(events);

  if (!client_coroutine(cc)) {
    if (cc->watch_key) {
      fdevent_remove_watch(cc->server->loop, cc->watch_key);
      cc->watch_key = 0;
    }
    close_client(cc->f.fd);
    free(cc);
  }
  else {
    bool ret;
    StreamEvents new_wanted_events;

    new_wanted_events = {.read = cc->want_read,
			 .write = cc->want_write};

    if (new_wanted_events.read || new_wanted_events.write) {
      if (!cc->watch_key) {
        ret = fdevent_add_watch(cc->server->loop, cc->f.fd,
                                new_wanted_events, &client_handler,
                                ud, &cc->watch_key);
      }
      else {
        ret = fdevent_modify_watch(cc->server->loop, cc->watch_key,
                                   new_wanted_events, &client_handler,
                                   ud);
        if (!ret) {
          log_error("Failed to modify watch!");
          return;
        }
      }
    }
    else if (cc->watch_key) {
      ret = fdevent_remove_watch(cc->server->loop, cc->watch_key);
      if (!ret) {
        log_error("Failed to remove watch during wait");
        return;
      }
      cc->watch_key = 0;
    }
  }
}

#define CRCALL(state, fn, state2, ...)                      \
  do {                                                      \
    memset(state2, 0, sizeof(*state2));                     \
    while (fn(state2, __VA_ARGS__)) {                       \
      CRYIELD((state)->coropos);                            \
    }                                                       \
  } while (false)

static bool
client_coroutine(ClientConnection *cc) {
  CRBEGIN(cc->coropos);

#define EMITN(b, n)                                                     \
  do {                                                                  \
    ssize_t ret;                                                        \
    CRCALL(cc, c_write_all, &cc->sub.was, cc->f.fd, b, n,               \
           &ret);                                                       \
    if (ret) {                                                          \
      CRHALT(cc->coropos);                                              \
    }                                                                   \
  }                                                                     \
  while (false)

#define EMIT(c) EMITN(c, sizeof(c) - 1)

  while (true) {
    bool success;

    log_debug("FD %d Reading header", cc->f.fd);

    /* read out client http request */
    cc->want_read = true;
    CRCALL(cc, c_get_request, &cc->sub.grs, &cc->f, &success, &cc->request);
    cc->want_read = false;
    if (!success) {
      /* TODO: propagate error */
      CRHALT(cc->coropos);
    }

    log_debug("FD %d Parsed header, sending request to working thread",
              cc->f.fd);

    /* okay write out the request pointer to the fuse thread */
    while (true) {
      assert(sizeof(cc) <= PIPE_BUF);

      ssize_t ret = write(cc->server->out_pipe, &cc, sizeof(cc));
      if (ret < 0 && errno == EAGAIN) {
        /* TODO: want_write for this fd */
        assert(false);
        continue;
      }
      else if (ret != sizeof(cc)) {
        if (ret < 0) {
          log_debug("FD %d Error writing to out-pipe: %s", cc->f.fd,
                    strerror(errno));
        }
        else {
          log_debug("FD %d Error super rare partial write!", cc->f.fd);
        }
        CRHALT(cc->coropos);
      }

      break;
    }

    while (!cc->response.code) {
      CRYIELD(cc->coropos);
    }

    cc->server

    /* now write out our response */
    /* hardcoded to failure for now */
    cc->want_write = true;
    cc->out_size = snprintf(cc->outbuffer, sizeof(cc->outbuffer),
                            "HTTP/1.1 %d Stuff\r\n", cc->response.code);
    EMITN(cc->outbuffer, cc->out_size);
    EMIT("\r\n");
    cc->want_write = false;
    break;
  }

  /* TODO: if we want to read out more, we have to pull the bits out of
     `cc->grs.gls.buf` */

  CREND();

#undef EMIT
#undef EMITN
}

static bool
c_get_request(GetRequestState *state, FDBuffer *f,
              bool *success, HTTPRequestHeaders *rh) {
  CRBEGIN(state->coropos);

  /* success is initialized to false */
  *success = false;

#define PEEK()                                                          \
  CRCALL(state, c_fbpeek, &state->sub.peek_state, f, &state->c)

#define EXPECT(_c)                                                      \
  do {                                                                  \
    CRCALL(state, c_fbgetc, &state->sub.getc_state, f, &state->c);      \
    if ((char) state->c != (_c)) {                                      \
      log_error("Didn't get the character we "                          \
                "were expecting: '%c' vs '%c'",                         \
                state->c, (_c));                                        \
      CRHALT(state->coropos);                                           \
    }                                                                   \
  }                                                                     \
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
    CRCALL(state, c_getwhile, &state->sub.getwhile_state, f,            \
           var, sizeof(var) - 1, fn, &state->parsed);                   \
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
      CRHALT(state->coropos);                                   \
    }                                                           \
    var = _val;                                                 \
  }                                                             \
  while (false)

  PARSEVAR(rh->method, match_token);
  EXPECT(' ');

  log_debug("Got method '%s'", rh->method);

  /* request-uri = "*" | absoluteURI | abs_path | authority */
  /* we don't parse super intelligently here because
     http URIs aren't LL(1), authority and absoluteURI start with
     the same prefix string */
  PARSEVAR(rh->uri, match_non_null_or_space);
  EXPECT(' ');

  log_debug("Got uri '%s'", rh->uri);

  EXPECTS("HTTP/");
  PARSEINTVAR(rh->major_version);
  EXPECT('.');
  PARSEINTVAR(rh->minor_version);
  EXPECTS("\r\n");

  log_debug("Got version '%d.%d'", rh->major_version, rh->minor_version);

  log_debug("FD %d, Parsed request line", f->fd);

  for (state->i = 0; state->i < (int) NELEMS(rh->headers); ++state->i) {
    PEEK();

    if (state->c == '\r') {
      break;
    }

    PARSEVAR(rh->headers[state->i].name, match_non_null_or_colon);
    EXPECT(':');
    PARSEVAR(rh->headers[state->i].value, match_non_null_or_carriage_return);
    EXPECTS("\r\n");

    log_debug("FD %d, Parsed header %s:%s",
              f->fd,
              rh->headers[state->i].name,
              rh->headers[state->i].value);
  }


  EXPECTS("\r\n");

  *success = true;
  CREND();

#undef PARSEINTVAR
#undef PARSEVAR
#undef EXPECTS
#undef EXPECT
}
