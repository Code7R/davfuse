/* We have to do this since we're strict ANSI C99 */
#define _XOPEN_SOURCE
#define _FILE_OFFSET_BITS 64

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* We import the public FUSE header because we interact
   with code that uses the public API */
#define FUSE_USE_VERSION 26
#include "fuse.h"

#include "fdevent.h"

#define DEFAULT_LISTEN_BACKLOG 5
#define MAX_LINE_LENGTH 1024

#define UNUSED(x) (void)(x)

typedef struct {
  unsigned int singlethread : 1;
} FuseOptions;

typedef struct {
  int dummy;
} DavOptions;

typedef struct {
  char buf[MAX_LINE_LENGTH];
  char *buf_start;
  char *buf_end;
} GetLineState;

static int parse_command_line(int argc, char *argv[], FuseOptions *options) {
  int i;

  for (i = 1; i < argc; ++i) {
    char *arg = argv[i];

    /* don't case about non options for now */
    if (arg[0] != '-') {
      continue;
    }

    switch (arg[1]) {
    case 's':
      options->singlethread = 1;
      break;
    default:
      break;
    }
  }

  return 0;
}

static int parse_environment(DavOptions *options) {
  /* nothing for now */
  UNUSED(options);
  return 0;
}

/* TODO: support varargs */
static void print_error(const char *err) {
  fprintf(stderr, err);
  fprintf(stderr, "\n");
}

static int create_server_socket(DavOptions *options) {
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

#if 0
static int accept_client(int server_socket) {
  struct sockaddr_in client_addr;
  socklen_t size = sizeof(client_addr);
  return accept(server_socket, (struct sockaddr *) &client_addr, &size);
}

static void init_get_line_state(GetLineState *gls) {
  gls->buf_start = gls->buf;
  gls->buf_end = gls->buf_start;
}

/* like strchr, except doesn't care about '\0' and uses `n` */
static char *find_chr(const char *str, int c, size_t n) {
  unsigned int i;

  for (i = 0; i < n; i++) {
    if (str[i] == c) {
      return (char *) &(str[i]);
    }
  }

  return NULL;
}

static char *my_getline(int fd, GetLineState *gls) {
  /* realign buffer to beginning */
  memmove(gls->buf, gls->buf_start, gls->buf_end - gls->buf_start);
  gls->buf_end = gls->buf + (gls->buf_end - gls->buf_start);
  gls->buf_start = gls->buf;

  while (1) {
    char *newline_ptr;
    ssize_t ret;

    /* if we've read too much data without seeing a newline
       that's an error */
    if (gls->buf_end >= (gls->buf + sizeof(gls->buf))) {
      return NULL;
    }

    ret = read(fd, gls->buf_end, (gls->buf + sizeof(gls->buf)) - gls->buf_end);
    if (ret < 0) {
      return NULL;
    }

    /* search the new buffer for a newline */
    newline_ptr = find_chr(gls->buf_end, '\n', ret);
    gls->buf_end += ret;

    if (newline_ptr) {
      *newline_ptr = '\0';
      gls->buf_start = newline_ptr + 1;
      return gls->buf;
    }
  }

  /* NOTREACHED */
  return NULL;
}
#endif

static void connect_handler(int fd, StreamEvents events, void *ud) {
  UNUSED(fd);
  UNUSED(events);
  UNUSED(ud);
  printf("new connect!\n");
}

/* From "fuse_versionscript" the version of this symbol is FUSE_2.6 */
int fuse_main_real(int argc, char *argv[], const struct fuse_operations *op,
                   size_t op_size, void *user_data) {
  DavOptions dav_options;
  FuseOptions fuse_options;
  int ret;
  int server_fd;
  FDEventLoop loop;

  UNUSED(op);
  UNUSED(op_size);
  UNUSED(user_data);

  /* Initialize options to 0 */
  memset(&fuse_options, 0, sizeof(fuse_options));
  memset(&dav_options, 0, sizeof(dav_options));

  ret = parse_command_line(argc, argv, &fuse_options);
  if (ret) {
    print_error("Error parsing command line");
    return -1;
  }

  if (!fuse_options.singlethread) {
    print_error("We only support single threaded mode right now");
    return -1;
  }

  ret = parse_environment(&dav_options);
  if (ret) {
    print_error("Error parsing DAVFUSE_OPTIONS environment variable");
    return -1;
  }

  server_fd = create_server_socket(&dav_options);
  if (server_fd < 0) {
    print_error("Couldn't create server socket");
    return -1;
  }

  fdevent_init(&loop);

  FDEventWatchKey key;
  bool ret1;
  ret1 = fdevent_add_watch(&loop, server_fd,
                           (StreamEvents) {.read = true, .write = false},
                           connect_handler, NULL, &key);

  if (ret1) {
    printf("success!\n");
    fdevent_main_loop(&loop);
  }

#if 0

  /* We currently only handle one client at a time */
  while (1) {
    const char *line;
    GetLineState line_state;
    int client_socket = -1;

    client_socket = accept_client(server_fd);
    if (client_socket < 0) {
      print_error("Bad client socket!");
      goto request_cleanup;
    }

    init_get_line_state(&line_state);

    /* read request */
    line = my_getline(client_socket, &line_state);
    if (!line) {
      goto request_cleanup;
    }

    /* TODO check HTTP version */
    if (line[0] == 'H') {
    }

  request_cleanup:
    if (client_socket >= 0) {
      close(client_socket);
    }
  }
#endif

  return 0;
}
