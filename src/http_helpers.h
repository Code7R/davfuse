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

#ifndef HTTP_HELPERS_H

#ifdef __cplusplus
extern "C" {
#endif

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

NON_NULL_ARGS3(1, 5, 7) void
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

char *
decode_urlpath(const char *urlpath, size_t len);

char *
encode_urlpath(const char *urlpath, size_t len);

bool
generate_http_date(char *buf, size_t buf_size, time_t time);

bool
parse_http_date(const char *buf, time_t *time);

#ifdef __cplusplus
}
#endif

#endif /* HTTP_HELPERS_H */
