#include <stddef.h>

#include "http_server.h"
#include "logging.h"
#include "uthread.h"

#include "http_helpers.h"

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  http_request_handle_t request_handle;
  http_status_code_t code;
  const char *body;
  size_t body_len;
  const char *content_type;
  event_handler_t cb;
  void *ud;
  /* ctx */
  HTTPResponseHeaders resp;
} SimpleResponseCtx;

static
UTHR_DEFINE(_simple_response_uthr) {
  UTHR_HEADER(SimpleResponseCtx, ctx);

  http_response_init(&ctx->resp);

  /* send headers */
  bool ret = http_response_set_code(&ctx->resp, ctx->code);
  assert(ret);

  ret = http_response_add_header(&ctx->resp, HTTP_HEADER_CONTENT_LENGTH,
                                 "%zu", ctx->body_len);
  assert(ret);

  if (ctx->body_len) {
    ret = http_response_add_header(&ctx->resp, HTTP_HEADER_CONTENT_TYPE,
                                   "%s", ctx->content_type);
    assert(ret);
  }

  UTHR_YIELD(ctx,
             http_request_write_headers(ctx->request_handle,
                                        &ctx->resp,
                                        _simple_response_uthr, ctx));
  assert(UTHR_EVENT_TYPE() == HTTP_REQUEST_WRITE_HEADERS_DONE_EVENT);
  HTTPRequestWriteHeadersDoneEvent *write_headers_ev = UTHR_EVENT();
  assert(write_headers_ev->request_handle == ctx->request_handle);
  if (write_headers_ev->err != HTTP_SUCCESS) {
    log_info("Writing headers failed!");
    goto error;
  }

  if (ctx->body_len) {
    UTHR_YIELD(ctx,
               http_request_write(ctx->request_handle,
                                  ctx->body,
                                  ctx->body_len,
                                  _simple_response_uthr, ctx));
    assert(UTHR_EVENT_TYPE() == HTTP_REQUEST_WRITE_DONE_EVENT);
    HTTPRequestWriteDoneEvent *write_ev = UTHR_EVENT();
    assert(write_ev->request_handle == ctx->request_handle);
    if (write_ev->err != HTTP_SUCCESS) {
      log_info("Writing response body failed!");
      goto error;
    }
  }

  HTTPRequestSimpleResponseDoneEvent sev;
  if (false) {
  error:
    sev.error = true;
  }
  else {
    sev.error = false;
  }

  UTHR_RETURN(ctx,
              ctx->cb(GENERIC_EVENT, &sev, ctx->ud));

  UTHR_FOOTER();
}


NON_NULL_ARGS4(1, 3, 5, 6) void
http_request_simple_response(http_request_handle_t rh,
			     http_status_code_t code,
                             const char *body, size_t body_len,
                             const char *content_type,
			     event_handler_t cb, void *ud) {
  UTHR_CALL7(_simple_response_uthr, SimpleResponseCtx,
             .request_handle = rh,
             .code = code,
             .body = body,
             .body_len = body_len,
             .content_type = content_type,
             .cb = cb,
             .ud = ud,
             );
}

NON_NULL_ARGS3(1, 3, 4) void
http_request_string_response(http_request_handle_t rh,
                             http_status_code_t code,
                             const char *body,
                             event_handler_t cb, void *cb_ud) {
  http_request_simple_response(rh, code, body, strlen(body), "text/plain", cb, cb_ud);
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  http_request_handle_t request_handle;
  bool store_body;
  event_handler_t cb;
  void *ud;
  /* state */
  char scratch_buf[4096];
  char *buf;
  size_t buf_size;
  size_t buf_used;
} ReadRequestBody;

static
UTHR_DEFINE(_read_request_body) {
  UTHR_HEADER(ReadRequestBody, ctx);

  while (true) {
    UTHR_YIELD(ctx,
               http_request_read(ctx->request_handle,
                                 ctx->scratch_buf,
                                 sizeof(ctx->scratch_buf),
                                 _read_request_body, ctx));
    assert(UTHR_EVENT_TYPE() == HTTP_REQUEST_READ_DONE_EVENT);
    HTTPRequestReadDoneEvent *read_done_ev = UTHR_EVENT();
    assert(read_done_ev->request_handle = ctx->request_handle);
    if (!read_done_ev->nbyte) {
      /* EOF */
      break;
    }

    if (ctx->store_body) {
      if (ctx->buf_size - ctx->buf_used < read_done_ev->nbyte) {
        size_t new_buf_size = MAX(1, ctx->buf_size);
        while (new_buf_size - ctx->buf_used < read_done_ev->nbyte) {
          new_buf_size *= 2;
        }

        void *new_ptr = realloc(ctx->buf, new_buf_size);
        if (!new_ptr) {
          goto error;
        }

        ctx->buf = new_ptr;
        ctx->buf_size = new_buf_size;
      }

      memcpy(ctx->buf + ctx->buf_used,
             ctx->scratch_buf, read_done_ev->nbyte);
    }

    ctx->buf_used += read_done_ev->nbyte;
  }

  HTTPRequestReadBodyDoneEvent ev;
  if (false) {
  error:
    free(ctx->buf);
    ev = (HTTPRequestReadBodyDoneEvent) {
      .error = true,
    };
  }
  else {
    ev = (HTTPRequestReadBodyDoneEvent) {
      .body = ctx->buf,
      .length = ctx->buf_used,
    };
  }

  UTHR_RETURN(ctx,
              ctx->cb(GENERIC_EVENT, &ev, ctx->ud));

  UTHR_FOOTER();
}

void
http_request_read_body(http_request_handle_t rh,
                       event_handler_t cb,
                       void *ud) {
  UTHR_CALL4(_read_request_body, ReadRequestBody,
             .request_handle = rh,
             .store_body = true,
             .cb = cb,
             .ud = ud);
}

void
http_request_ignore_body(http_request_handle_t rh,
                         event_handler_t cb,
                         void *ud) {
  UTHR_CALL4(_read_request_body, ReadRequestBody,
             .request_handle = rh,
             .store_body = false,
             .cb = cb,
             .ud = ud);
}

