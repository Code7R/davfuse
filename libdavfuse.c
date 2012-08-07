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

#define UNUSED(x) (void)(x)

typedef struct {
  bool singlethread : 1;
} FuseOptions;

typedef struct {
  log_level_t log_level;
} DavOptions;

typedef struct {
  char buf[MAX_LINE_SIZE];
  char *buf_start;
  char *buf_end;
  coroutine_position_t coropos;
} GetLineState;

typedef struct {
  FDEventLoop *loop;
} ServerContext;

typedef struct {
  int fd;
  FDEventWatchKey watch_key;
  coroutine_position_t coropos;
  GetLineState gls;
  char *line;
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
  struct sockaddr_in listen_addr;

  UNUSED(options);

  memset(&listen_addr, 0, sizeof(listen_addr));

  /* TODO: use `options` */
  listen_addr.sin_family = AF_INET;
  listen_addr.sin_port = htons(80);
  listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd < 0) {
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


static void
init_getline(GetLineState *gls) {
  gls->buf_start = gls->buf;
  gls->buf_end = gls->buf_start;
  gls->coropos = CORO_POS_INIT;
}

/* like strchr, except doesn't care about '\0' and uses `n` */
static char *
find_chr(const char *str, int c, size_t n) {
  unsigned int i;

  for (i = 0; i < n; i++) {
    if (str[i] == c) {
      return (char *) &(str[i]);
    }
  }

  return NULL;
}

static bool
c_getline(int fd, GetLineState *gls, char **out) {
  CRBEGIN(gls->coropos);

  /* realign buffer to beginning */
  memmove(gls->buf, gls->buf_start, gls->buf_end - gls->buf_start);
  gls->buf_end = gls->buf + (gls->buf_end - gls->buf_start);
  gls->buf_start = gls->buf;

  while (true) {
    char *newline_ptr;
    ssize_t ret;

    /* if we've read too much data without seeing a newline
       that's an error */
    if (gls->buf_end >= (gls->buf + sizeof(gls->buf))) {
      break;
    }

    ret = read(fd, gls->buf_end, (gls->buf + sizeof(gls->buf)) - gls->buf_end);
    if (ret < 0) {
      break;
    }

    /* search the new buffer for a newline */
    newline_ptr = find_chr(gls->buf_end, '\n', ret);
    gls->buf_end += ret;

    if (newline_ptr) {
      *newline_ptr = '\0';
      gls->buf_start = newline_ptr + 1;
      *out = gls->buf_start;
      CRHALT(gls->coropos);
    }
  }

  *out = NULL;
  CREND();
}

static bool
client_coroutine(ClientConnection *cc) {
#define GETLINE() do {                                            \
    init_getline(&cc->gls);                                       \
    CRLOOP(c_getline(cc->fd, &cc->gls, &cc->line), cc->coropos);  \
    if (!cc->line) {                                              \
      log_error("Line expected but didn't get one!");             \
    }                                                             \
  } while (0)

  CRBEGIN(cc->coropos);

  /* read out client http request */

  /* first read the http version string */
  GETLINE();
  {
    char *saveptr;
    char *token;

    token = strtok_r(cc->line, " \t", &saveptr);

    UNUSED(token);
  }

  CREND();
#undef GETLINE
}

static void
client_handler(int fd, StreamEvents events, void *ud) {
  UNUSED(fd);
  UNUSED(events);

  /* TODO: check return code to see if done */
  client_coroutine(ud);
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

  cc = malloc(sizeof(*cc));
  if (!cc) {
    log_error("Couldn't allocate memory for new client");
    goto error;
  }

  *cc = (ClientConnection) {.fd = client_fd,
                            .coropos = CORO_POS_INIT};

  /* the client is read to accept connections! */
  ret = fdevent_add_watch(sc->loop, cc->fd,
                          (StreamEvents) {.read = true, .write = false},
                          client_handler, cc, &cc->watch_key);
  if (!ret) {
    log_error("Couldn't add fd watch for new client!");
    goto error;
  }

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
    log_critical("Couldn't create server socket");
    return -1;
  }

  {
    bool ret;

    ret = fdevent_init(&loop);
    if (!ret) {
      log_critical("Couldn't initialize fdevent loop!");
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

  /* this currently runs forever,
     only returns if there is an error watching sockets */
  fdevent_main_loop(&loop);

  return -1;
}
