/*
  A simple file server out of the current directory
 */

#include <fcntl.h>
#include <unistd.h>

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
  FDEventLoop *loop;
  HTTPRequestHeaders rhs;
  HTTPResponseHeaders resp;
  http_error_code_t err;
  size_t bytes_read;
  char buf[BUF_SIZE];
  size_t content_length;
  http_request_handle_t rh;
  int fd;
};

static void
handle_request(event_type_t ev_type, void *ev, void *ud) {
  struct handler_context *hc = ud;

  /* because asserts might get compiled out */
  UNUSED(ev_type);

  if (ev_type == HTTP_NEW_REQUEST_EVENT) {
    hc = malloc(sizeof(*hc));
    assert(hc);
    *hc = (struct handler_context) {
      .pos = CORO_POS_INIT,
      .loop = ud,
      .fd = -1,
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

  /* now read out body */
  /* TODO: we shouldn't have to worry about content-length or chunked
     or even reading this out for the sake of it,
     but we do it now so the request/connection is sane
     TODO: the server should take care of stuff like this (half-read connections)
     but for now we assume content-length */
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

  log_debug("done reading body");

  static const char toret[] = "SORRY BRO";

  size_t content_length;
  off_t pos;
  const char *msg;
  hc->fd = open(&hc->rhs.uri[1], O_RDONLY | O_NONBLOCK);
  if (hc->fd >= 0 &&
      (pos = lseek(hc->fd, 0, SEEK_END)) >= 0) {
    hc->resp.code = 200;
    content_length = pos;
    msg = "Found";
  }
  else {
    /* we couldn't open find just respond */
    hc->resp.code = 404;
    msg = "Not Found";
    content_length = sizeof(toret) - 1;
  }
  
  strncpy(hc->resp.message, msg, sizeof(hc->resp.message));
  hc->resp.num_headers = 1;
  strncpy(hc->resp.headers[0].name, "Content-Length", sizeof(hc->resp.headers[0].name));
  /* now write out headers */
  snprintf(hc->resp.headers[0].value, sizeof(hc->resp.headers[0].value),
           "%zu", content_length);

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

  log_debug("Sent headers!");

  if (hc->resp.code == 200) {
    log_debug("Sending file %s, length: %s", &hc->rhs.uri[1], hc->resp.headers[0].value);

    /* seek back to beginning of file */
    int ret = lseek(hc->fd, 0, SEEK_SET);
    UNUSED(ret);
    assert(!ret);
    /* TODO: must be send up to the content-length we sent */
    while (true) {
      ssize_t amt_read = read(hc->fd, hc->buf, sizeof(hc->buf));
      if (amt_read < 0 && errno == EAGAIN) {
        bool ret = fdevent_add_watch(hc->loop, hc->fd,
                                     create_stream_events(true, false),
                                     handle_request, hc,
                                     NULL);
        UNUSED(ret);
        assert(ret);
        CRYIELD(hc->pos, 0);
        assert(ev_type == FD_EVENT);
        continue;
      }
      else if (amt_read < 0) {
        log_error_errno("Error while read()ing file");
        /* error while reading the file */
        goto error;
      }
      else if (!amt_read) {
        /* EOF */
        log_debug("EOF done reading file; %zu", sizeof(hc->buf));
        break;
      }

      log_debug("Sending %zd bytes", amt_read);

      /* now write to socket */
      CRYIELD(hc->pos,
              http_request_write(hc->rh, hc->buf, amt_read,
                                 handle_request, hc));
      assert(ev_type == HTTP_REQUEST_WRITE_DONE_EVENT);
      HTTPRequestWriteDoneEvent *write_ev = ev;
      UNUSED(write_ev);
      assert(write_ev->request_handle == hc->rh);
      if (write_ev->err != HTTP_SUCCESS) {
        goto error;
      }
    }
  }
  else {
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
  }

 error:
  if (hc->fd >= 0) {
    close(hc->fd);
  }
  
  CRRETURN(hc->pos,
           (http_request_end(hc->rh),
            free(hc)));

  CREND();
}

int main() {
  log_level_t log_level = LOG_NOTHING;

  init_logging(stdout, log_level);
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
			  handle_request, &loop);
  assert(ret);

  log_info("Starting main loop");
  fdevent_main_loop(&loop);

  return 0;
}

