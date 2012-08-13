/* We have to do this since we're strict ANSI C99 */
#define _XOPEN_SOURCE
#define _FILE_OFFSET_BITS 64

/* POSIX includes */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

/* C Standard includes */
#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* We import the public FUSE header because we interact
   with code that uses the public API */
#define FUSE_USE_VERSION 26
#include "fuse.h"

/* local includes */
#include "coroutine.h"
#include "fdevent.h"
#include "logging.h"

#define DEFAULT_LISTEN_BACKLOG 5
#define MAX_LINE_SIZE 1024
#define MAX_METHOD_SIZE 16
#define MAX_URI_SIZE 1024
#define MAX_VERSION_SIZE 8
#define MAX_HEADER_NAME_SIZE 64
#define MAX_HEADER_VALUE_SIZE 128
#define MAX_NUM_HEADERS 16

#define UNUSED(x) (void)(x)
#define NELEMS(arr) (sizeof(arr) / sizeof(arr[0]))

#define CRCALL(state, fn, state2, ...)                      \
  do {                                                      \
    (state2)->coropos = CORO_POS_INIT;                      \
    while (fn(state2, __VA_ARGS__)) {                       \
      CRYIELD((state)->coropos);                            \
    }                                                       \
  } while (false)

typedef struct {
  bool singlethread : 1;
} FuseOptions;

typedef struct {
  log_level_t log_level;
} DavOptions;

typedef struct {
  coroutine_position_t coropos;
} GetCState;

typedef GetCState PeekState;

typedef struct {
  coroutine_position_t coropos;
  char *init_buf;
  size_t init_buf_size;
  char *buf_end;
  GetCState getc_state;
} GetWhileState;

typedef struct {
  coroutine_position_t coropos;
  const void *buf_loc;
  size_t count_left;
} WriteAllState;

typedef struct {
  union {
    GetWhileState getwhile_state;
    GetCState getc_state;
    PeekState peek_state;
  } sub;
  int i;
  int c;
  char tmp;
  size_t parsed;
  char tmpbuf[1024];
  coroutine_position_t coropos;
} GetRequestState;

typedef struct {
  FDEventLoop *loop;
} ServerContext;

typedef struct {
  char method[MAX_METHOD_SIZE];
  char uri[MAX_URI_SIZE];
  int major_version;
  int minor_version;
  size_t num_headers;
  struct {
    char name[MAX_HEADER_NAME_SIZE];
    char value[MAX_HEADER_VALUE_SIZE];
  } headers[MAX_NUM_HEADERS];
} HTTPRequestHeaders;

typedef struct {
  int fd;
  char *buf_start;
  char *buf_end;
  char buf[4096];
} FDBuffer;

typedef struct {
  FDBuffer f;
  FDEventLoop *loop;
  FDEventWatchKey watch_key;
  coroutine_position_t coropos;
  union {
    GetRequestState grs;
    WriteAllState was;
  } sub;
  HTTPRequestHeaders request;
  bool want_read : 1;
  bool want_write : 1;
} ClientConnection;

static int
parse_command_line(int argc, char *argv[], FuseOptions *options) {
  int i;

  for (i = 1; i < argc; ++i) {
    char *arg = argv[i];

    /* don't case about non options for now */
    if (arg[0] != '-') {
      continue;
    }

    switch (arg[1]) {
    case 's':
      options->singlethread = true;
      break;
    default:
      break;
    }
  }

  return 0;
}

static int
parse_environment(DavOptions *options) {
  /* default for now */
  options->log_level = LOG_DEBUG;
  return 0;
}

static int
create_server_socket(DavOptions *options) {
  int listen_backlog = DEFAULT_LISTEN_BACKLOG;
  int ret;
  int socket_fd = -1;
  int reuse = 1;
  struct sockaddr_in listen_addr;

  UNUSED(options);

  memset(&listen_addr, 0, sizeof(listen_addr));

  /* TODO: use `options` */
  listen_addr.sin_family = AF_INET;
  listen_addr.sin_port = htons(8080);
  listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd < 0) {
    goto fail;
  }

  ret = setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
  if (ret) {
    goto fail;
  }

  ret = bind(socket_fd, (struct sockaddr *) &listen_addr,
             sizeof(listen_addr));
  if (ret) {
    goto fail;
  }

  ret = listen(socket_fd, listen_backlog);
  if (ret) {
    goto fail;
  }

  return socket_fd;

 fail:
  if (socket_fd >= 0) {
    close(socket_fd);
  }

  return -1;
}

static int
accept_client(int server_socket) {
  struct sockaddr_in client_addr;
  socklen_t size = sizeof(client_addr);
  return accept(server_socket, (struct sockaddr *) &client_addr, &size);
}

static int
close_client(int client_socket) {
  return close(client_socket);
}

static int
set_non_blocking(int fd) {
  int flags;

  flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    log_warning("Couldn't read file flags: %s, setting 0", strerror(errno));
    flags = 0;
  }

  return fcntl(fd, F_SETFL, (long) flags | O_NONBLOCK);
}

#define _C_FBPEEK(coropos, f, out, peek)                       \
  do {                                                         \
    ssize_t ret;                                               \
                                                               \
    if (f->buf_start < f->buf_end) {                           \
      out = (unsigned char) *f->buf_start;                     \
      f->buf_start += peek ? 1 : 0;                            \
      break;                                                   \
    }                                                          \
                                                               \
    assert(f->buf_start == f->buf_end);                        \
    assert(sizeof(f->buf));                                    \
                                                               \
    ret = read(f->fd, f->buf, sizeof(f->buf));                 \
    if (ret < 0 && errno == EAGAIN) {                          \
      /* TODO: register for read events */                     \
      CRYIELD(coropos);                                        \
      continue;                                                \
    }                                                          \
    else if (ret <= 0) {                                       \
      out = EOF;                                               \
      break;                                                   \
    }                                                          \
                                                               \
    f->buf_start = f->buf;                                     \
    f->buf_end = f->buf + ret;                                 \
  }                                                            \
  while (true)

#define C_FBPEEK(coropos, f, out) _C_FBPEEK(coropos, f, out, 0)
#define C_FBGETC(coropos, f, out) _C_FBPEEK(coropos, f, out, 1)

static bool
c_fbgetc(GetCState *state, FDBuffer *f, int *out) {
  CRBEGIN(state->coropos);
  C_FBGETC(state->coropos, f, *out);
  CREND();
}

static bool
c_fbpeek(PeekState *state, FDBuffer *f, int *out) {
  CRBEGIN(state->coropos);
  C_FBPEEK(state->coropos, f, *out);
  CREND();
}

static void
fbungetc(FDBuffer *f, int c) {
  /* not implemented */
  UNUSED(f);
  UNUSED(c);
  assert(false);
}

static bool
c_getwhile(GetWhileState *state, FDBuffer *f,
           char *buf, size_t buf_size,
           bool (*fn)(char),
           size_t *out) {
  /* always do these asserts first */
  assert(buf);
  assert(buf_size);
  assert(!state->init_buf || state->init_buf == buf);
  assert(!state->init_buf_size || state->init_buf_size == buf_size);

  CRBEGIN(state->coropos);

  state->init_buf = buf;
  state->init_buf_size = buf_size;
  state->buf_end = buf;

  /* find terminator in existing buffer */
  do {
    int c;

    /* we only call fbgetc in one place here, so we force an inline */
    C_FBGETC(state->coropos, f, c);

    if (c == EOF) {
      log_error("Error while expecting a character: %s", strerror(errno));
      break;
    }

    /* pain! we make an indirect function call here to accomodate multiple uses
       it definitely slows done this loop,
       maybe we can optimized this in the future */
    if (!(*fn)(c)) {
      fbungetc(f, c);
      break;
    }

    *(state->buf_end++) = (char) c;
  }
  while (state->buf_end < (state->init_buf + state->init_buf_size));

  *out = state->buf_end - state->init_buf;
  CREND();
}

static bool
c_write_all(WriteAllState *state, int fd,
            const void *buf, size_t count, ssize_t *ret) {
  CRBEGIN(state->coropos);

  state->buf_loc = buf;
  state->count_left = count;

  while (state->count_left) {
    ssize_t ret2;
    ret2 = write(fd, state->buf_loc, state->count_left);
    if (ret2 < 0) {
      if (errno == EAGAIN) {
        CRYIELD(state->coropos);
        continue;
      }
      else {
        assert(count >= state->count_left);
        *ret = count - state->count_left;
      }
    }

    assert(state->count_left >= ret2);
    state->count_left -= ret2;
    state->buf_loc += ret2;
  }

  *ret = 0;

  CREND();
}

static bool
__attribute__((const))
match_seperator(char c) {
#define N(l) l == c ||
  /* these are lots of independent checks but the CPU should plow through
     this since it's not a loop and doesn't access memory */
  return (N('(') N(')') N('<') N('>') N('@') N(',') N(';') N(':')
          N('\\') N('/') N('[') N(']') N('?') N('=') N('{') N('}')
          N(' ') '\t' == c);
#undef N
}

static bool
__attribute__((const))
match_token(char c) {
  /* token          = 1*<any CHAR except CTLs or separators> */
  return (32 < c && c < 127 && !match_seperator(c));
}

static bool
__attribute__((const))
match_non_null_or_space(char c) {
  return c && c != ' ';
}

static bool
__attribute__((const))
match_non_null_or_colon(char c) {
  return c && c != ':';
}

static bool
__attribute__((const))
match_non_null_or_carriage_return(char c) {
  return c && c != '\r';
}

static bool
__attribute__((const))
match_digit(char c) {
  return '0' <= c && c <= '9';
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
    for (state->i = 0; state->i < (int) sizeof(_s) - 1; ++state->i) {   \
      EXPECT(_s[state->i]);                                             \
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

    log_debug("FD %d, Parsed header %s, %s",
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

static bool
client_coroutine(ClientConnection *cc) {
  CRBEGIN(cc->coropos);

#define EMIT(b)                                                         \
  do {                                                                  \
    ssize_t ret;                                                        \
    CRCALL(cc, c_write_all, &cc->sub.was, cc->f.fd, b, sizeof(b) - 1,   \
           &ret);                                                       \
    if (ret) {                                                          \
      CRHALT(cc->coropos);                                              \
    }                                                                   \
  }                                                                     \
  while (0)

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

    log_debug("FD %d Parsed header, sending respond", cc->f.fd);

    /* now write out our response */
    /* hardcoded to failure for now */
    cc->want_write = true;
    EMIT("HTTP/1.1 404 Not Found\r\n");
    EMIT("\r\n");
    cc->want_write = false;
    break;
  }

  /* TODO: if we want to read out more, we have to pull the bits out of
     `cc->grs.gls.buf` */

  CREND();
}

static void
client_handler(int fd, StreamEvents events, void *ud) {
  ClientConnection *cc = ud;
  UNUSED(fd);
  UNUSED(events);

  if (!client_coroutine(ud)) {
    fdevent_remove_watch(cc->loop, cc->watch_key);
    close_client(fd);
  }
  else {
    bool ret;
    ret = fdevent_remove_watch(cc->loop, cc->watch_key);
    if (!ret) {
      log_error("Failed to remove watch!");
      return;
    }
    ret = fdevent_add_watch(cc->loop, fd,
                            (StreamEvents) {.read = cc->want_read,
                                .write = cc->want_write},
                            client_handler, ud,
                            &cc->watch_key);
    if (!ret) {
      log_error("Failed to add watch!");
      return;
    }
  }
}

static void
accept_handler(int fd, StreamEvents events, void *ud) {
  ServerContext *sc = (ServerContext *) ud;
  int client_fd = -1;
  ClientConnection *cc = NULL;
  bool ret;

  UNUSED(fd);
  UNUSED(events);
  UNUSED(ud);

  client_fd = accept_client(fd);
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

  *cc = (ClientConnection) {.f = (FDBuffer) {.fd = client_fd},
                            .loop = sc->loop,
                            .coropos = CORO_POS_INIT};

  /* the client is read to accept connections! */
  ret = fdevent_add_watch(sc->loop, cc->f.fd,
                          (StreamEvents) {.read = true, .write = false},
                          client_handler, cc, &cc->watch_key);
  if (!ret) {
    log_error("Couldn't add fd watch for new client!");
    goto error;
  }

  log_debug("New client! %d", client_fd);

  return;

 error:
  if (client_fd >= 0) {
    close_client(client_fd);
  }

  if (cc) {
    free(cc);
  }
}

/* From "fuse_versionscript" the version of this symbol is FUSE_2.6 */
int fuse_main_real(int argc, char *argv[], const struct fuse_operations *op,
                   size_t op_size, void *user_data) {
  DavOptions dav_options;
  FuseOptions fuse_options;
  int ret;
  int server_fd;
  FDEventLoop loop;
  FDEventWatchKey server_watch_key;
  ServerContext sc;

  UNUSED(op);
  UNUSED(op_size);
  UNUSED(user_data);

  /* Initialize options to 0 */
  memset(&fuse_options, 0, sizeof(fuse_options));
  memset(&dav_options, 0, sizeof(dav_options));

  ret = parse_environment(&dav_options);
  if (ret) {
    log_critical("Error parsing DAVFUSE_OPTIONS environment variable");
    return -1;
  }

  init_logging(stderr, dav_options.log_level);

  ret = parse_command_line(argc, argv, &fuse_options);
  if (ret) {
    log_critical("Error parsing command line");
    return -1;
  }

  if (!fuse_options.singlethread) {
    log_critical("We only support single threaded mode right now");
    return -1;
  }

  server_fd = create_server_socket(&dav_options);
  if (server_fd < 0) {
    log_critical("Couldn't create server socket: %s", strerror(errno));
    return -1;
  }

  {
    bool ret;

    ret = fdevent_init(&loop);
    if (!ret) {
      log_critical("Couldn't initialize fdevent loop: %s", strerror(errno));
      return -1;
    }
  }

  sc.loop = &loop;

  {
    bool ret;

    ret = fdevent_add_watch(&loop, server_fd,
                            (StreamEvents) {.read = true, .write = false},
                            accept_handler, &sc, &server_watch_key);
    if (!ret) {
      log_critical("Couldn't watch server socket");
      return -1;
    }
  }

  log_info("Starting main loop");

  /* this currently runs forever,
     only returns if there is an error watching sockets */
  fdevent_main_loop(&loop);

  return -1;
}
