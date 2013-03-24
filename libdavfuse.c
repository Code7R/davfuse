/* We have to do this since we're strict ANSI C99 */
#define _XOPEN_SOURCE
#define _FILE_OFFSET_BITS 64

/* POSIX includes */
#include <errno.h>
#include <pthread.h>
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
#include "c_util.h"
#include "coroutine.h"
#include "fd_utils.h"
#include "fdevent.h"
#include "http_server.h"
#include "logging.h"

typedef union {
  int all[2];
  struct {
    int in;
    int out;
  } named;
} Pipes;

typedef struct {
  bool singlethread : 1;
} FuseOptions;

typedef struct {
  log_level_t log_level;
} DavOptions;

typedef struct {
  int in_pipe;
  int out_pipe;
  struct fuse_operations *op;
  void *user_data;
} ThreadContext;

typedef struct {
  int to_main;
  fd_event_watch_key_t watch_key;
} HandlerContext;

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

int
create_server_socket(DavOptions *options) {
  UNUSED(options);

  /* TODO: use `options` */
  return create_ipv4_bound_socket(8080);
}

static void
in_pipe_handler(FDEventLoop *loop, int fd, StreamEvents events, void *ud) {
  UNUSED(events);
  UNUSED(ud);

  while (true) {
    HandlerContext *hc;
    assert(sizeof(hc) <= PIPE_BUF);

    ssize_t ret = read(fd, &hc, sizeof(hc));
    if (ret < 0 && errno == EAGAIN) {
      /* nothing */
      break;
    }

    /* TODO: handle ret < size(hc) case more gracefully */
    assert(sizeof(hc) == ret);
    
    log_debug("Got response from worker thread: %p", hc);

    run_request_coroutine(hc);
  }

  /* re-register watch */
  bool ret = fdevent_add_watch(loop, fd,
			       create_stream_events(true, false),
			       in_pipe_handler, NULL, NULL);
  /* handle error more gracefully */
  assert(ret);
}

static void
handle_request(http_request_handle_t rh, void *ud) {
  HandlerContext *hc = (HandlerContext *) ud;
  UNUSED(rh);
  run_request_coroutine(hc);
}

static void
run_request_coroutine(HandlerContext *hc) {
  /* TODO: do cleanup */
  request_coroutine(hc);
}

static void
request_coroutine(HandlerContext *hc) {

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
        /* this could be an assert, but i feel weird assert()ing on
           a result of an external interface */
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

    /* wait for response from other threads */
    while (!cc->response.code) {
      CRYIELD(cc->coropos);
    }

    cc->server
}

static void *
http_thread(void *ud) {
  FDEventLoop loop;
  HandlerContext hc;
  HTTPServer http;
  Pipes *pipes = (Pipes *) ud;
  bool ret;
  int server_fd;

  hc.to_main = pipes->named.out;

  for (int i = 0; i < NELEMS(pipes->all); ++i) {
    if (set_non_blocking(pipes->all[i]) < 0) {
      log_critical_errno("Couldn't make pipe non-blocking");
      goto error;
    }
  }

  /* create event loop */
  ret = fdevent_init(&loop);
  if (!ret) {
    log_critical_errno("Couldn't initialize fdevent loop");
    goto error;
  }

  /* register pipe handler */
  ret = fdevent_add_watch(&loop, pipes->named.in,
                          create_stream_events(true, false),
                          in_pipe_handler, NULL, NULL);
  if (!ret) {
    log_critical("Couldn't add watch for pipe");
    goto error;
  }

  /* create server socket */
  server_fd = create_server_socket(&dav_options);
  if (server_fd < 0) {
    log_critical_errno("Couldn't create server socket");
    goto error;
  }

  /* start http server */
  ret = http_server_start(&http, &loop, server_fd,
			  handle_request, &hc);
  if (!ret) {
    log_critical_errno("Couldn't start http server");
    goto error;
  }

  /* this currently runs forever,
     only returns if there is an error watching sockets */
  fdevent_main_loop(&loop);

  return NULL;

 error:
  /* TODO: handle errors */
  assert(false);
}

/* From "fuse_versionscript" the version of this symbol is FUSE_2.6 */
int 
fuse_main_real(int argc,
	       char *argv[],
	       const struct fuse_operations *op,
	       size_t op_size,
	       void *user_data) {
  DavOptions dav_options;
  FuseOptions fuse_options;
  int ret;
  ThreadContext tc;
  int pipefds[2];
  Pipes http_thread_pipes;

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

  if (pipe(pipefds) < 0) {
    log_critical("Couldn't create to-thread pipe: %s", strerror(errno));
    /* TODO: close server socket? */
    return -1;
  }

  tc.in_pipe = pipefds[0];
  http_thread_pipes.named.out = pipefds[1];

  if (pipe(pipefds) < 0) {
    log_critical("Couldn't create from-thread pipe: %s", strerror(errno));
    /* TODO: close server socket? */
    return -1;
  }

  http_thread_pipes.named.in = pipefds[0];
  tc.out_pipe = pipefds[1];

  log_info("Starting main loop");

  pthread_t new_thread;
  pthread_create(&new_thread, NULL, http_thread, &http_thread_pipes);

  log_info("Starting fuse worker");

  while (true) {
    ssize_t ret;
    ClientConnection *cc;

    assert(sizeof(cc) <= PIPE_BUF);

    log_debug("Waiting for worker request");
    ret = read(tc.in_pipe, &cc, sizeof(cc));
    if (ret < 0) {
      break;
    }

    /* TODO: handle this more gracefully */
    assert(sizeof(cc) == ret);

    log_debug("Got request from %p", cc);

    /* all fails */
    cc->response.code = 404;

    ret = write(tc.out_pipe, &cc, sizeof(cc));
    /* TODO: handle this more gracefully */
    assert(sizeof(cc) == ret);
  }

  /* wakeup server thread */

  pthread_join(new_thread, NULL);

  return -1;
}




