#ifndef HTTP_HELPERS_H

#include <stddef.h>

#include "events.h"
#include "http_server.h"
#include "util.h"

typedef struct {
  bool error;
} HTTPRequestSimpleResponseDoneEvent;

typedef struct {
  char *name;
  char *value;
} HeaderPair;

NON_NULL_ARGS4(1, 3, 5, 7) void
http_request_simple_response(http_request_handle_t rh,
			     http_status_code_t code,
                             const char *body, size_t body_len,
                             const char *content_type,
                             linked_list_t extra_headers,
			     event_handler_t cb, void *cb_ud);

NON_NULL_ARGS3(1, 3, 4) void
http_request_string_response(http_request_handle_t rh,
                             http_status_code_t code,
                             const char *body,
                             event_handler_t cb, void *cb_ud);

typedef struct {
  bool error;
  char *body;
  size_t length;
} HTTPRequestReadBodyDoneEvent;

void
http_request_read_body(http_request_handle_t rh,
                       event_handler_t cb,
                       void *ud);

void
http_request_ignore_body(http_request_handle_t rh,
                         event_handler_t cb,
                         void *ud);

#endif /* HTTP_HELPERS_H */
