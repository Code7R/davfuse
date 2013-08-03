#define _ISOC99_SOURCE

#include <assert.h>
#include <stddef.h>

#include "coroutine_io.h"
#include "http_server.h"
#include "logging.h"
#include "uthread.h"
#include "util.h"

#include "http_helpers.h"

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  http_request_handle_t request_handle;
  http_status_code_t code;
  const char *body;
  size_t body_len;
  const char *content_type;
  linked_list_t extra_headers;
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
  ASSERT_TRUE(ret);

  ret = http_response_add_header(&ctx->resp, HTTP_HEADER_CONTENT_LENGTH,
                                 "%zu", ctx->body_len);
  ASSERT_TRUE(ret);

  if (ctx->body_len) {
    ret = http_response_add_header(&ctx->resp, HTTP_HEADER_CONTENT_TYPE,
                                   "%s", ctx->content_type);
    assert(ret);
  }

  LINKED_LIST_FOR(HeaderPair, elt, ctx->extra_headers) {
    ret = http_response_add_header(&ctx->resp, elt->name, "%s", elt->value);
    assert(ret);
  }

  UTHR_YIELD(ctx,
             http_request_write_headers(ctx->request_handle,
                                        &ctx->resp,
                                        _simple_response_uthr, ctx));
  assert(UTHR_EVENT_TYPE() == HTTP_REQUEST_WRITE_HEADERS_DONE_EVENT);
  HTTPRequestWriteHeadersDoneEvent *write_headers_ev = UTHR_EVENT();
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


NON_NULL_ARGS4(1, 3, 5, 7) void
http_request_simple_response(http_request_handle_t rh,
			     http_status_code_t code,
                             const char *body, size_t body_len,
                             const char *content_type,
                             linked_list_t extra_headers,
			     event_handler_t cb, void *ud) {
  UTHR_CALL7(_simple_response_uthr, SimpleResponseCtx,
             .request_handle = rh,
             .code = code,
             .body = body,
             .body_len = body_len,
             .content_type = content_type,
             .extra_headers = extra_headers,
             .cb = cb,
             .ud = ud,
             );
}

NON_NULL_ARGS3(1, 3, 4) void
http_request_string_response(http_request_handle_t rh,
                             http_status_code_t code,
                             const char *body,
                             event_handler_t cb, void *cb_ud) {
  http_request_simple_response(rh, code, body, strlen(body), "text/plain",
                               LINKED_LIST_INITIALIZER, cb, cb_ud);
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

  ctx->buf = NULL;
  ctx->buf_size = 0;
  ctx->buf_used = 0;

  while (true) {
    UTHR_YIELD(ctx,
               http_request_read(ctx->request_handle,
                                 ctx->scratch_buf,
                                 sizeof(ctx->scratch_buf),
                                 _read_request_body, ctx));
    assert(UTHR_EVENT_TYPE() == HTTP_REQUEST_READ_DONE_EVENT);
    HTTPRequestReadDoneEvent *read_done_ev = UTHR_EVENT();
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

char *
decode_urlpath(const char *urlpath, size_t len) {
  /* TODO: remove params from /path_segment;param/ */
  assert(str_startswith(urlpath, "/"));

  /* first figure out length of new string */
  size_t new_size = 0;
  for (size_t i = 0; i < len; ++new_size) {
    /* this should definitely not include any query component,
       TODO: we should expand this assert
     */
    assert(urlpath[i] != '?' && urlpath[i] != ';');
    i += (urlpath[i] == '%' &&
          match_hex_digit(urlpath[i + 1]) &&
          match_hex_digit(urlpath[i + 2]))
      ? 3
      : 1;
  }

  /* allocate necessary memory */
  char *toret = malloc(new_size + 1);
  if (!toret) {
    return NULL;
  }

  /* now actually decode */
  size_t j = 0;
  for (size_t i = 0; i < len; ++j) {
    if (urlpath[i] == '%' &&
        match_hex_digit(urlpath[i + 1]) &&
        match_hex_digit(urlpath[i + 2])) {
      char hex_temp[3] = {urlpath[i + 1], urlpath[i + 2], '\0'};
      long char_code = strtol(hex_temp, NULL, 16);
      assert(char_code >= 0 && char_code < 256);
      toret[j] = (unsigned char) char_code;
      i += 3;
    }
    else {
      toret[j] = urlpath[i];
      i += 1;
    }
  }

  assert(j == new_size);
  toret[new_size] = '\0';
  return toret;
}

static bool
match_valid_urlpath_set(char c) {
  static const char unreserved_url_chars[] = "-_.!~*'()/";
  for (size_t i = 0; i < sizeof(unreserved_url_chars) - 1; ++i) {
    if (c == unreserved_url_chars[i]) {
      return true;
    }
  }

  return (('A' <= c && c <= 'Z') ||
          ('a' <= c && c <= 'z') ||
          ('0' <= c && c <= '9'));
}

static char
to_hex_digit(char c) {
  /* you should def know what you're doing
     if you use this function */
  assert(c >= 0 && c <= 15);
  if (c < 10) {
    return '0' + c;
  }
  else {
    return 'a' + (c - 10);
  }
}

char *
encode_urlpath(const char *urlpath, size_t len) {
  assert(str_startswith(urlpath, "/"));
  /* this encodes the path to be usable in the HTTP request line,
     this only allows: "-" | "_" | "." | "!" | "~" | "*" | "'" | "(" | ")"
     and: alphanum (A-Z,a-z,0-9)
     (reserved characters, ":" | "@" | "&" | "=" | "+" | "$" | ",",
     are technically allowed but not in the path component of a url)
   */

  size_t new_size = 0;
  for (size_t i = 0; i < len; ++i) {
    new_size += match_valid_urlpath_set(urlpath[i]) ? 1 : 3;
  }

  char *toret = malloc(new_size + 1);
  if (!toret) {
    return NULL;
  }

  size_t new_pos = 0;
  for (size_t i = 0; i < len; ++i) {
    assert(new_pos < new_size);
    if (match_valid_urlpath_set(urlpath[i])) {
      toret[new_pos++] = urlpath[i];
    }
    else {
      toret[new_pos++] = '%';
      toret[new_pos++] = to_hex_digit(((unsigned char) urlpath[i]) / 16);
      toret[new_pos++] = to_hex_digit(((unsigned char) urlpath[i]) % 16);
    }
  }

  assert(new_pos == new_size);
  toret[new_pos] = '\0';
  return toret;
}
