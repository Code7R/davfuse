/*
  A WebDAV server that uses sockets at the frontend and a file system for its backend.
 */
#define _ISOC99_SOURCE

#include <assert.h>
#include <errno.h>
#include <signal.h>

#include "c_util.h"
#include "fdevent.h"
#include "http_backend_sockets_fdevent.h"
#include "logging.h"
#include "webdav_backend_fs.h"
#include "webdav_server.h"
#include "webdav_server_xml.h"
#include "uthread.h"
#include "util.h"
#include "util_sockets.h"

int
main(int argc, char *argv[]) {
  /* init logging */
  init_logging(stdout, LOG_DEBUG);
  log_info("Logging initted.");

  /* parse command line */
  port_t port;
  if (argc > 1) {
    long to_port = strtol(argv[1], NULL, 10);
    if ((to_port == 0 && errno) ||
	to_port < 0 ||
	to_port > MAX_PORT) {
      log_critical("Bad port: %s", argv[1]);
      return -1;
    }
    port = (port_t) to_port;
  }
  else {
    port = 8080;
  }

  const char *public_prefix = argc > 2
    ? argv[2]
    : "http://localhost:8080/";

  char *base_path = argc > 3
    ? strdup(argv[3])
    : getcwd(NULL, 0);
  ASSERT_NOT_NULL(base_path);

  /* init sockets */
  bool success_init_sockets = init_socket_subsystem();
  ASSERT_TRUE(success_init_sockets);

  /* ignore SIGPIPE */
  bool success_ignore = ignore_sigpipe();
  ASSERT_TRUE(success_ignore);

  /* create event loop (implemented by file descriptors) */
  fdevent_loop_t loop = fdevent_new();
  ASSERT_TRUE(loop);

  /* create network IO backend (implemented by the Socket API) */
  /* TODO: accept other listen addresses */
  struct sockaddr_in listen_addr;
  init_sockaddr_in(&listen_addr, port);

  http_backend_t http_backend =
    http_backend_sockets_fdevent_new(loop,
                                     (struct sockaddr *) &listen_addr,
                                     sizeof(listen_addr));
  ASSERT_TRUE(http_backend);

  /* create fs (implementation is compile-time configurable) */
  fs_t fs = fs_blank_new();
  ASSERT_TRUE(fs);

  /* create storage backend (implemented by the file system) */
  webdav_backend_t wd_backend = webdav_backend_fs_new(fs, base_path);
  ASSERT_TRUE(wd_backend);

  /* init xml parser */
  init_xml_parser();

  /* start webdav server*/
  webdav_server_t ws = webdav_server_start(http_backend, public_prefix, wd_backend);
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

  log_info("Freeing base path");
  free(base_path);

  log_info("Shutting down logging, bye!");
  shutdown_logging();

  return 0;
}
