#include <assert.h>
#include <signal.h>
#include <stdlib.h>


#include "events.h"
#include "fdevent.h"
#include "fd_utils.h"
#include "http_server.h"
#include "logging.h"

#define BUF_SIZE 4096

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

  char *content_length_str = http_get_header_value(&hc->rhs, "content-length");
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
      assert(read_ev->request_handle == hc->rh);
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
  snprintf(hc->resp.headers[0].value, sizeof(hc->resp.headers[0].value),
           "%zu", sizeof(toret) - 1);

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
  init_logging(stdout, LOG_DEBUG);
  log_info("Logging initted.");

  /* ignore SIGPIPE */
  signal(SIGPIPE, SIG_IGN);

  /* create server socket */
  int server_fd = create_ipv4_bound_socket(8080);
  assert(server_fd >= 0);

  /* create event loop */
  FDEventLoop loop;
  bool ret = fdevent_init(&loop);
  assert(ret);

  /* start http server */
  HTTPServer http;
  ret = http_server_start(&http, &loop, server_fd,
			  handle_request, NULL);
  assert(ret);

  log_info("Starting main loop");
  fdevent_main_loop(&loop);

  return 0;
}
