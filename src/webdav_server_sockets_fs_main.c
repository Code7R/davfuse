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
  A WebDAV server that uses sockets at the frontend and a file system for its backend.
 */
#define _ISOC99_SOURCE

#ifndef _WIN32
#define _POSIX_C_SOURCE 200112L
#include <unistd.h>
#endif

#include <assert.h>
#include <errno.h>
#include <signal.h>

#include "c_util.h"
#include "http_backend_sockets_fdevent.h"
#include "http_backend_sockets_fdevent_fdevent.h"
#include "iface_util.h"
#include "logging.h"
#include "logging_log_printer.h"
#include "webdav_backend_fs.h"
#include "webdav_backend_fs_fs.h"
#include "webdav_server.h"
#include "webdav_server_xml.h"
#include "uthread.h"
#include "util.h"
#include "util_sockets.h"

#ifndef _WIN32
#include "log_printer_stdio.h"
ASSERT_SAME_IMPL(LOGGING_LOG_PRINTER_IMPL, LOG_PRINTER_STDIO_IMPL);
#endif

ASSERT_SAME_IMPL(HTTP_SERVER_HTTP_BACKEND_IMPL, HTTP_BACKEND_SOCKETS_FDEVENT_IMPL);
ASSERT_SAME_IMPL(WEBDAV_SERVER_WEBDAV_BACKEND_IMPL, WEBDAV_BACKEND_FS_IMPL);

int
main(int argc, char *argv[]) {
  /* init logging */
#ifndef _WIN32
  /* this code makes this module become POSIX */
  char *const term_env = getenv("TERM");
  FILE *const logging_output = stderr;
  const bool show_colors = (isatty(fileno(logging_output)) &&
                            term_env && !str_equals(term_env, "dumb"));
  log_printer_stdio_init(logging_output, show_colors);
#else
  log_printer_default_init();
#endif

  logging_set_global_level(LOG_DEBUG);
  log_info("Logging initted.");

  ASSERT_TRUE(argc > 4);

  /* parse command line */

  /* get listen address */
  /* TODO: accept other listen addresses, not just ports */
  long to_port = strtol(argv[1], NULL, 10);
  if ((to_port == 0 && errno) ||
      to_port < 0 ||
      to_port > MAX_PORT) {
    log_critical("Bad port: %s", argv[1]);
    return -1;
  }
  struct sockaddr_in listen_addr;
  init_sockaddr_in(&listen_addr, to_port);

  /* get public uri root */
  /* TODO: handle bad input paths, or sanitize them, you know DWIM... */
  const char *public_uri_root = argv[2];

  /* get internal root */
  /* TODO: handle bad input paths, or sanitize them, you know DWIM... */
  const char *internal_root = argv[3];

  /* get local path */
  /* TODO: handle bad input paths, or sanitize them, you know DWIM... */
  char *base_path = argv[4];

  /* init sockets */
  bool success_init_sockets = init_socket_subsystem();
  ASSERT_TRUE(success_init_sockets);

  /* ignore SIGPIPE */
  bool success_ignore = ignore_sigpipe();
  ASSERT_TRUE(success_ignore);

  /* create event loop (implemented by file descriptors) */
  fdevent_loop_t loop = fdevent_default_new();
  ASSERT_TRUE(loop);

  /* create network IO backend (implemented by the Socket API) */
  http_backend_sockets_fdevent_t http_backend =
    http_backend_sockets_fdevent_new(loop,
                                     (struct sockaddr *) &listen_addr,
                                     sizeof(listen_addr));
  ASSERT_TRUE(http_backend);

  /* create fs (implementation is compile-time configurable) */
  fs_t fs = fs_default_new();
  ASSERT_TRUE(fs);

  /* create storage backend (implemented by the file system) */
  webdav_backend_fs_t wd_backend = webdav_backend_fs_new(fs, base_path);
  ASSERT_TRUE(wd_backend);

  /* init xml parser */
  init_xml_parser();

  /* start webdav server */
  webdav_server_t ws = webdav_server_start(http_backend,
                                           public_uri_root,
                                           internal_root,
                                           wd_backend);
  ASSERT_TRUE(ws);

  log_info("Starting main loop");
  fdevent_main_loop(loop);
  log_info("Server stopped");

  log_info("Shutting down xml parser");
  shutdown_xml_parser();

  log_info("Destroying webdav storage backend");
  webdav_backend_fs_destroy(wd_backend);

  log_info("Destroying file system");
  fs_destroy(fs);

  log_info("Destroying http network IO backend");
  http_backend_sockets_fdevent_destroy(http_backend);

  log_info("Destroying event loop");
  fdevent_destroy(loop);

  log_info("Shutting down socket subsystem");
  shutdown_socket_subsystem();

  log_info("Shutting down logging, bye!");
  log_printer_shutdown();

  return 0;
}
