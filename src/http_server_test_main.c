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
  A test HTTP server that uses sockets at the frontend
 */
#define _ISOC99_SOURCE

#ifndef _WIN32
#define _POSIX_C_SOURCE 200112L
#include <unistd.h>
#endif

#include <assert.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>

#include "event_loop.h"
#include "events.h"
#include "http_server.h"
#include "iface_util.h"
#include "logging.h"
#include "log_printer.h"
#include "sockets.h"
#include "util.h"
#include "util_sockets.h"

#ifndef _WIN32
#include "log_printer_stdio.h"
ASSERT_SAME_IMPL(LOG_PRINTER_IMPL, LOG_PRINTER_STDIO_IMPL);
#endif

enum {
  BUF_SIZE=4096,
};

struct handler_context {
  coroutine_position_t pos;
  HTTPRequestHeaders rhs;
  HTTPResponseHeaders resp;
  size_t bytes_read;
  char buf[BUF_SIZE];
  size_t content_length;
  http_request_handle_t rh;
};

static void
handle_request(event_type_t ev_type, void *ev, void *ud) {
  struct handler_context *hc = ud;

  /* because asserts might get compiled out */
  UNUSED(ev_type);

  if (!hc) {
    assert(ev_type == HTTP_NEW_REQUEST_EVENT);
    hc = malloc(sizeof(*hc));
    assert(hc);
    *hc = (struct handler_context) {
      .pos = CORO_POS_INIT,
    };
  }

  CRBEGIN(hc->pos);
  assert(ev_type == HTTP_NEW_REQUEST_EVENT);
  HTTPNewRequestEvent *new_request_ev = ev;
  hc->rh = new_request_ev->request_handle;

  log_info("New request!");

  /* read out headers */
  CRYIELD(hc->pos,
          http_request_read_headers(hc->rh,
                                    &hc->rhs, handle_request, hc));
  assert(ev_type == HTTP_REQUEST_READ_HEADERS_DONE_EVENT);
  HTTPRequestReadHeadersDoneEvent *read_headers_ev = ev;
  UNUSED(read_headers_ev);
  assert(read_headers_ev->request_handle == hc->rh);
  if (read_headers_ev->err != HTTP_SUCCESS) {
    goto error;
  }

  log_info("Received headers:");
  log_info("Method: %s", hc->rhs.method);
  log_info("URI: %s", hc->rhs.uri);
  log_info("HTTP Version: %d.%d", hc->rhs.major_version, hc->rhs.minor_version);
  for (unsigned i = 0; i < hc->rhs.num_headers; ++i) {
    log_info("Header %s: %s",
             hc->rhs.headers[i].name,
             hc->rhs.headers[i].value);
  }

  /* now read out body */
  /* TODO: we shouldn't have to worry about content-length or chunked
     or any of that, but for now we assume content-length */

  const char *content_length_str = http_get_header_value(&hc->rhs, "content-length");
  if (content_length_str) {
    long converted_content_length = strtol(content_length_str, NULL, 10);
    assert(converted_content_length >= 0 && !errno);

    hc->content_length = converted_content_length;
    hc->bytes_read = 0;
    while (hc->bytes_read <= hc->content_length) {
      CRYIELD(hc->pos,
              http_request_read(hc->rh, hc->buf,
                                MIN(hc->content_length - hc->bytes_read, sizeof(hc->buf)),
                                handle_request, hc));
      HTTPRequestReadDoneEvent *read_ev = ev;
      assert(ev_type == HTTP_REQUEST_READ_DONE_EVENT);
      if (read_ev->err != HTTP_SUCCESS) {
        goto error;
      }

      hc->bytes_read += read_ev->nbyte;
    }
  }

  static const char toret[] = "SORRY BRO";

  /* now write out headers */
  hc->resp.code = 404;
  strncpy(hc->resp.message, "Not Found", sizeof(hc->resp.message));
  hc->resp.num_headers = 1;
  strncpy(hc->resp.headers[0].name, "Content-Length", sizeof(hc->resp.headers[0].name));
  assert(sizeof(toret) - 1 <= UINT_MAX);
  int ret_snprintf =
    snprintf(hc->resp.headers[0].value, sizeof(hc->resp.headers[0].value),
             "%lu", (unsigned long) (sizeof(toret) - 1));
  if (ret_snprintf < 0 || (size_t) ret_snprintf >= sizeof(hc->resp.headers[0].value)) {
    goto error;
  }

  CRYIELD(hc->pos,
          http_request_write_headers(hc->rh, &hc->resp,
                                     handle_request, hc));
  assert(ev_type == HTTP_REQUEST_WRITE_HEADERS_DONE_EVENT);
  HTTPRequestWriteHeadersDoneEvent *write_headers_ev = ev;
  /* because asserts might get compiled out */
  UNUSED(write_headers_ev);
  assert(write_headers_ev->request_handle == hc->rh);
  if (write_headers_ev->err != HTTP_SUCCESS) {
    goto error;
  }

  CRYIELD(hc->pos,
          http_request_write(hc->rh, toret, sizeof(toret) - 1,
                             handle_request, hc));
  assert(ev_type == HTTP_REQUEST_WRITE_DONE_EVENT);
  HTTPRequestWriteDoneEvent *write_ev = ev;
  UNUSED(write_ev);
  assert(write_ev->request_handle == hc->rh);
  if (write_ev->err != HTTP_SUCCESS) {
    goto error;
  }

 error:
  CRRETURN(hc->pos,
           (http_request_end(hc->rh),
            free(hc)));

  CREND();
}

int main() {
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

  /* init sockets */
  bool success_init_sockets = init_socket_subsystem();
  ASSERT_TRUE(success_init_sockets);

  /* ignore SIGPIPE */
  bool success_ignore = ignore_sigpipe();
  ASSERT_TRUE(success_ignore);

  /* create event loop */
  event_loop_handle_t loop = event_loop_default_new();
  ASSERT_TRUE(loop);

  /* create listen socket */
  struct sockaddr_in listen_addr;
  init_sockaddr_in(&listen_addr, INADDR_ANY, 8080);
  socket_t sock = create_bound_socket((struct sockaddr *) &listen_addr,
                                      sizeof(listen_addr));
  ASSERT_TRUE(sock != INVALID_SOCKET);

  /* create http server */
  http_server_t server = http_server_new(loop, sock, handle_request, NULL);
  ASSERT_TRUE(server);

  /* start http server */
  bool started = http_server_start(server);
  ASSERT_TRUE(started);

  log_info("Starting main loop");
  event_loop_main_loop(loop);

  return 0;
}
