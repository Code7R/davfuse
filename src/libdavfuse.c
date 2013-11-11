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
 * Implements a WebDAV server using a set of FUSE callbacks
 */
#define _BSD_SOURCE
#define _ISOC99_SOURCE
#define _POSIX_C_SOURCE 200112L

#include <pthread.h>
#include <unistd.h>

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c_util.h"

/* We import the public FUSE header because we interact
   with code that uses the public API */
#define FUSE_USE_VERSION 26
#define FUSE_SHARED_DECL DYNAMICALLY_LINKED_FUNCTION_ATTR
#include "fuse.h"
#undef FUSE_USE_VERSION

#include "event_loop.h"
#include "iface_util.h"
#include "logging.h"
#include "log_printer.h"
#include "log_printer_stdio.h"
#include "webdav_backend.h"
#include "webdav_backend_async_fuse.h"
#include "webdav_server.h"
#include "util.h"
#include "util_sockets.h"

ASSERT_SAME_IMPL(LOG_PRINTER_IMPL, LOG_PRINTER_STDIO_IMPL);
ASSERT_SAME_IMPL(WEBDAV_BACKEND_IMPL, WEBDAV_BACKEND_ASYNC_FUSE_IMPL);

typedef struct {
  bool singlethread : 1;
} FuseOptions;

typedef struct {
  log_level_t log_level;
  char *listen_str;
  char *public_uri_root;
  char *internal_root;
} DavOptions;

typedef struct {
  async_fuse_fs_t async_fuse_fs;
  char *listen_str;
  char *public_uri_root;
  char *internal_root;
  event_loop_handle_t loop;
} HTTPThreadArguments;

static bool
parse_command_line(int argc, char *argv[], FuseOptions *options) {
  for (int i = 1; i < argc; ++i) {
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

  return true;
}

static bool
parse_environment(DavOptions *options) {
  /* default for now */
  options->log_level = LOG_DEBUG;
  options->listen_str = NULL;
  options->public_uri_root = davfuse_util_strdup("http://localhost:8080/");
  options->internal_root = davfuse_util_strdup("/");

  return true;
}

static void
free_dav_options(DavOptions *options) {
  free(options->public_uri_root);
  free(options->listen_str);
  free(options->internal_root);
}

static void *
http_thread(void *ud) {
  HTTPThreadArguments *args = (HTTPThreadArguments *) ud;
  webdav_backend_async_fuse_t webdav_backend = 0;
  webdav_server_t wd_serv = 0;
  socket_t listen_sock = INVALID_SOCKET;

  if (args->listen_str) {
    log_critical("Specified listen host/port is not yet supported");
    abort();
  }

  /* create listen socket */
  port_t port = 8080;
  log_info("Create listen socket");
  struct sockaddr_in listen_addr;
  init_sockaddr_in(&listen_addr, LOCALHOST_IP, port);
  listen_sock = create_bound_socket((struct sockaddr *) &listen_addr,
                                    sizeof(listen_addr));
  if (listen_sock == INVALID_SOCKET) {
    log_critical("Couldn't listen on socket");
    goto done;
  }

  /* create webdav backend */
  log_info("Create webdav server backend");
  webdav_backend = webdav_backend_async_fuse_new(args->async_fuse_fs);
  if (!webdav_backend) {
    log_critical("Couldn't create WebDAV backend");
    goto done;
  }

  /* start webdav server */
  log_info("Create webdav server");
  wd_serv = webdav_server_new(args->loop,
                              listen_sock,
                              args->public_uri_root,
                              args->internal_root,
                              webdav_backend);
  /* the server owns the fd now */
  if (!wd_serv) {
    log_critical("Couldn't start webdav server!");
    goto done;
  }

  bool success_server_start = webdav_server_start(wd_serv);
  if (!success_server_start) {
    log_critical("Couldn't start webdav server");
    goto done;
  }

  log_info("Starting WebDAV server loop");

  bool success_main_loop = event_loop_main_loop(args->loop);
  if (!success_main_loop) log_error("Main loop stopped prematurely");

  /* this will end if a handler stops the server */
  log_info("Ending WebDAV server loop");

 done:
  if (wd_serv) {
    log_info("Destroying webdav server");
    webdav_server_destroy(wd_serv);
  }

  if (webdav_backend) {
    log_info("Destroying webdav backend");
    webdav_backend_async_fuse_destroy(webdav_backend);
  }

  if (listen_sock != INVALID_SOCKET) {
    log_info("Closing listen socket");
    closesocket(listen_sock);
  }

  /* okay tell the main thread we're done here */
  log_info("Signaling for main thread to stop");
  bool success_async_fuse_fs_stop_blocking =
    async_fuse_fs_stop_blocking(args->async_fuse_fs);
  if (!success_async_fuse_fs_stop_blocking) {
    log_critical("Can't stop fuse fs thread");
    abort();
  }

  return NULL;
}

static pthread_key_t fuse_context_key;
static pthread_mutex_t fuse_context_lock = PTHREAD_MUTEX_INITIALIZER;
static int fuse_context_ref;

DYNAMICALLY_LINKED_FUNCTION_ATTR struct fuse_context *
fuse_get_context(void) {
  struct fuse_context *c = pthread_getspecific(fuse_context_key);
  if (!c) {
    c = calloc(1, sizeof(*c));
    if (!c) {
      /* This is hard to deal with properly, so just
         abort.  If memory is so low that the
         context cannot be allocated, there's not
         much hope for the filesystem anyway */
      log_critical("fuse: failed to allocate thread specific data");
      abort();
    }
    pthread_setspecific(fuse_context_key, c);
  }
  return c;
}

static void
fuse_freecontext(void *data) {
  free(data);
}

static int
fuse_create_context_key(void) {
  int err = 0;
  pthread_mutex_lock(&fuse_context_lock);
  if (!fuse_context_ref) {
    err = pthread_key_create(&fuse_context_key, fuse_freecontext);
    if (err) {
      fprintf(stderr, "fuse: failed to create thread specific key: %s\n",
              strerror(err));
      pthread_mutex_unlock(&fuse_context_lock);
      return -1;
    }
  }
  fuse_context_ref++;
  pthread_mutex_unlock(&fuse_context_lock);
  return 0;
}

static void
fuse_delete_context_key(void) {
  pthread_mutex_lock(&fuse_context_lock);
  fuse_context_ref--;
  if (!fuse_context_ref) {
    fuse_freecontext(pthread_getspecific(fuse_context_key));
    pthread_key_delete(fuse_context_key);
  }
  pthread_mutex_unlock(&fuse_context_lock);
}

/* From "fuse_versionscript" the version of this symbol is FUSE_2.6 */
DYNAMICALLY_LINKED_FUNCTION_ATTR int
fuse_main_real(int argc,
	       char *argv[],
	       const struct fuse_operations *op,
	       size_t op_size,
	       void *user_data) {
  DavOptions dav_options = { .log_level = 0, };
  FuseOptions fuse_options = { .singlethread = 0 };
  async_fuse_fs_t async_fuse_fs = 0;
  event_loop_handle_t loop = 0;
  bool initted_logging = false;
  int ret_create_context = -1;
  bool success_init_sockets = false;

  /* this code makes this module become POSIX */
  char *const term_env = getenv("TERM");
  FILE *const logging_output = stderr;
  const bool show_colors = (isatty(fileno(logging_output)) &&
                            term_env && !str_equals(term_env, "dumb"));
  initted_logging = log_printer_stdio_init(logging_output, show_colors);
  if (!initted_logging) {
    log_critical("Error initting logging");
    goto error;
  }

  const bool success_parse_environment = parse_environment(&dav_options);
  if (!success_parse_environment) {
    log_critical("Error parsing DAVFUSE_OPTIONS environment variable");
    goto error;
  }

  logging_set_global_level(dav_options.log_level);

  /* create fuse context structure */
  log_info("Creating context");
  ret_create_context = fuse_create_context_key();
  if (ret_create_context < 0) {
    log_critical("Couldn't create fuse context");
    goto error;
  }

  /* init socket subsystem */
  success_init_sockets = init_socket_subsystem();
  if (!success_init_sockets) {
    log_critical("Couldn't init socket subsystem");
    goto error;
  }

  /* ignore SIGPIPE */
  log_info("Ignoring sigpipe");
  const bool success_ignore = ignore_sigpipe();
  if (!success_ignore) {
    log_critical("Couldn't ignore SIGPIPE");
    goto error;
  }

  /* parse command line */
  log_info("Parsing command line");
  const bool success_parse_command_line = parse_command_line(argc, argv, &fuse_options);
  if (!success_parse_command_line) {
    log_critical("Error parsing command line");
    goto error;
  }

  if (!fuse_options.singlethread) {
    log_critical("We only support single threaded mode right now");
    goto error;
  }

  /* create event loop */
  log_info("Creating event loop");
  loop = event_loop_default_new();
  if (!loop) {
    log_critical_errno("Couldn't initialize event loop");
    goto error;
  }

  /* create async fuse system */
  log_info("Creating async fuse fs");
  async_fuse_fs = async_fuse_fs_new(loop);
  if (!async_fuse_fs){
    log_critical("Couldn't create async fuse fs");
    goto error;
  }

  /* create webdav server thread */
  log_info("Starting WebDAV server thread");
  HTTPThreadArguments http_thread_args = {
    .async_fuse_fs = async_fuse_fs,
    .loop = loop,
    .listen_str = dav_options.listen_str,
    .public_uri_root = dav_options.public_uri_root,
    .internal_root = dav_options.internal_root,
  };
  pthread_t new_thread;
  const int ret_pthread_create =
    pthread_create(&new_thread, NULL, http_thread, &http_thread_args);
  if (ret_pthread_create) {
    log_critical("Couldn't create http thread: %s",
                 strerror(ret_pthread_create));
    goto error;
  }

  /* start fuse worker thread */
  log_info("Starting async FUSE worker main loop");
  async_fuse_worker_main_loop(async_fuse_fs, op, op_size, user_data);
  log_info("FUSE main loop is done");

  /* wait on server thread to complete */
  log_info("Waiting for server thread to die...");
  pthread_join(new_thread, NULL);

  int toret = 0;
  if (false) {
  error:
    toret = -1;
  }

  log_info("Freeing dav_options memory");
  free_dav_options(&dav_options);

  if (async_fuse_fs) {
    log_info("Destroying async fuse fs");
    async_fuse_fs_destroy(async_fuse_fs);
  }

  if (loop) {
    log_info("Destroying event loop");
    event_loop_destroy(loop);
  }

  if (success_init_sockets) {
    log_info("Shutting down socket subsystem");
    shutdown_socket_subsystem();
  }

  if (!ret_create_context) {
    log_info("Destroying fuse context");
    fuse_delete_context_key();
  }

  if (initted_logging) {
    log_info("Shutting down logging, bye!");
    log_printer_stdio_shutdown();
  }

  return toret;
}

DYNAMICALLY_LINKED_FUNCTION_ATTR void
fuse_unmount_compat22(const char *mountpoint, struct fuse_chan *ch) {
  /* TODO: implement */
  UNUSED(mountpoint);
  UNUSED(ch);
  abort();
}
