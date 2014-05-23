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

#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <stdint.h>
#include <time.h>

#include "c_util.h"
#include "event_loop.h"
#include "events.h"
#include "sockets.h"
#include "uthread.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _IS_HTTP_SERVER__C
extern const char *const HTTP_HEADER_CONTENT_LENGTH;
extern const char *const HTTP_HEADER_CONTENT_TYPE;
extern const char *const HTTP_HEADER_LAST_MODIFIED;
extern const char *const HTTP_HEADER_HOST;
extern const char *const HTTP_HEADER_IF_MODIFIED_SINCE;
#endif

enum {
  IN_BUF_SIZE=4096,
  MAX_LINE_SIZE=1024,
  MAX_METHOD_SIZE=16,
  MAX_URI_SIZE=1024,
  MAX_VERSION_SIZE=8,
  MAX_HEADER_NAME_SIZE=64,
  MAX_HEADER_VALUE_SIZE=256,
  MAX_NUM_HEADERS=16,
  MAX_MESSAGE_SIZE=64,
  OUT_BUF_SIZE=4096,
  MAX_RESPONSE_LINE_SIZE=128,
};

/* forward decl */
struct _http_server;
struct _http_request_context;

typedef struct _http_server *http_server_t;
typedef struct _http_request_context *http_request_handle_t;

struct _header_pair {
  char name[MAX_HEADER_NAME_SIZE];
  char value[MAX_HEADER_VALUE_SIZE];
};

typedef struct {
  char method[MAX_METHOD_SIZE];
  char uri[MAX_URI_SIZE];
  int major_version;
  int minor_version;
  size_t num_headers;
  struct _header_pair headers[MAX_NUM_HEADERS];
} HTTPRequestHeaders;

typedef enum {
  HTTP_SUCCESS,
  HTTP_GENERIC_ERROR,
} http_error_code_t;

typedef enum {
  HTTP_STATUS_CODE___INVALID,
  HTTP_STATUS_CODE_OK=200,
  HTTP_STATUS_CODE_CREATED=201,
  HTTP_STATUS_CODE_NO_CONTENT=204,
  HTTP_STATUS_CODE_MULTI_STATUS=207,
  HTTP_STATUS_CODE_MOVED_PERMANENTLY=301,
  HTTP_STATUS_CODE_NOT_MODIFIED=304,
  HTTP_STATUS_CODE_BAD_REQUEST=400,
  HTTP_STATUS_CODE_FORBIDDEN=403,
  HTTP_STATUS_CODE_NOT_FOUND=404,
  HTTP_STATUS_CODE_METHOD_NOT_ALLOWED=405,
  HTTP_STATUS_CODE_CONFLICT=409,
  HTTP_STATUS_CODE_PRECONDITION_FAILED=412,
  HTTP_STATUS_CODE_UNSUPPORTED_MEDIA_TYPE=415,
  HTTP_STATUS_CODE_EXPECTATION_FAILED=417,
  HTTP_STATUS_CODE_LOCKED=423,
  HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR=500,
  HTTP_STATUS_CODE_NOT_IMPLEMENTED=501,
  HTTP_STATUS_CODE_INSUFFICIENT_STORAGE=507,
} http_status_code_t;

typedef struct {
  http_status_code_t code;
  char message[MAX_MESSAGE_SIZE];
  size_t num_headers;
  struct _header_pair headers[MAX_NUM_HEADERS];
} HTTPResponseHeaders;

typedef enum {
  HTTP_REQUEST_READ_STATE_NONE,
  HTTP_REQUEST_READ_STATE_READING_HEADERS,
  HTTP_REQUEST_READ_STATE_READ_HEADERS,
  HTTP_REQUEST_READ_STATE_READING,
} http_request_read_state_t;

typedef enum {
  HTTP_REQUEST_WRITE_STATE_NONE,
  HTTP_REQUEST_WRITE_STATE_WRITING_HEADERS,
  HTTP_REQUEST_WRITE_STATE_WROTE_HEADERS,
  HTTP_REQUEST_WRITE_STATE_WRITING,
} http_request_write_state_t;

typedef struct {
  http_request_handle_t request_handle;
  http_error_code_t err;
} _SimpleRequestActionDoneEvent;

typedef struct {
  http_request_handle_t request_handle;
  struct _http_server *server;
} HTTPNewRequestEvent;

typedef _SimpleRequestActionDoneEvent HTTPRequestReadHeadersDoneEvent;
typedef _SimpleRequestActionDoneEvent HTTPRequestWriteHeadersDoneEvent;
typedef _SimpleRequestActionDoneEvent HTTPRequestWriteDoneEvent;

typedef struct {
  unsigned err;
  size_t nbyte;
} HTTPRequestReadDoneEvent;

NON_NULL_ARGS2(1, 3)
http_server_t
http_server_new(event_loop_handle_t loop,
                socket_t sock,
                event_handler_t handler,
                void *ud);

NON_NULL_ARGS1(1)
bool
http_server_destroy(http_server_t http);

NON_NULL_ARGS1(1)
bool
http_server_start(http_server_t http);

NON_NULL_ARGS1(1)
bool
http_server_stop(http_server_t http);

NON_NULL_ARGS1(1)
void
http_server_disconnect_existing_clients(http_server_t http);

NON_NULL_ARGS3(1, 2, 3) void
http_request_read_headers(http_request_handle_t rh,
			  HTTPRequestHeaders *request_headers,
			  event_handler_t cb,
			  void *cb_ud);

NON_NULL_ARGS3(1, 2, 4) void
http_request_read(http_request_handle_t rh,
		  void *buf, size_t nbyte,
		  event_handler_t cb, void *cb_ud);

NON_NULL_ARGS1(1)
http_error_code_t
http_request_force_connection_close(http_request_handle_t rh);

NON_NULL_ARGS3(1, 2, 3) void
http_request_write_headers(http_request_handle_t rh,
			   const HTTPResponseHeaders *response_headers,
			   event_handler_t cb,
			   void *cb_ud);

NON_NULL_ARGS3(1, 2, 4) void
http_request_write(http_request_handle_t rh,
		   const void *buf, size_t nbyte,
		   event_handler_t cb, void *cb_ud);

NON_NULL_ARGS() void
http_request_end(http_request_handle_t rh);

NON_NULL_ARGS() const char *
http_get_header_value(const HTTPRequestHeaders *rhs, const char *header_name);

HEADER_FUNCTION NON_NULL_ARGS1(1) bool
http_response_init(HTTPResponseHeaders *rsp) {
  rsp->num_headers = 0;
  return true;
}

NON_NULL_ARGS3(1, 2, 3) bool
http_response_add_header(HTTPResponseHeaders *rsp, const char *name,
                         const char *value_fmt, ...);

HEADER_FUNCTION NON_NULL_ARGS1(1) bool
http_response_set_code(HTTPResponseHeaders *rsp, http_status_code_t code) {
  rsp->code = code;

  size_t msg_size;
  const char *msg;
#define SCS(code, msg_)				\
  case code:                                    \
    do {                                        \
      msg_size = sizeof(msg_);			\
      msg = msg_;                               \
    }						\
    while (false);                              \
  break

  switch (code) {
    SCS(HTTP_STATUS_CODE_OK, "OK");
    SCS(HTTP_STATUS_CODE_CREATED, "Created");
    SCS(HTTP_STATUS_CODE_NO_CONTENT, "No Content");
    SCS(HTTP_STATUS_CODE_MULTI_STATUS, "Multi-Status");
    SCS(HTTP_STATUS_CODE_MOVED_PERMANENTLY, "Moved Permanently");
    SCS(HTTP_STATUS_CODE_NOT_MODIFIED, "Not Modified");
    SCS(HTTP_STATUS_CODE_BAD_REQUEST, "Bad Request");
    SCS(HTTP_STATUS_CODE_FORBIDDEN, "Forbidden");
    SCS(HTTP_STATUS_CODE_NOT_FOUND, "Not Found");
    SCS(HTTP_STATUS_CODE_METHOD_NOT_ALLOWED, "Method Not Allowed");
    SCS(HTTP_STATUS_CODE_CONFLICT, "Conflict");
    SCS(HTTP_STATUS_CODE_PRECONDITION_FAILED, "Precondition Failed");
    SCS(HTTP_STATUS_CODE_UNSUPPORTED_MEDIA_TYPE, "Unsupported Media Type");
    SCS(HTTP_STATUS_CODE_EXPECTATION_FAILED, "Expectation Failed");
    SCS(HTTP_STATUS_CODE_LOCKED, "Locked");
    SCS(HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR, "Internal Server Error");
    SCS(HTTP_STATUS_CODE_NOT_IMPLEMENTED, "Not Implemented");
  default: return false; break;
  }

  memcpy(rsp->message, msg, MIN(sizeof(rsp->message), msg_size));

  return true;
#undef SET_MSG
}

const char *
http_error_to_string(http_error_code_t e);

/* we use the ##__VA_ARGS__ GCC extension here,
   if not supported you have to implement http_request_log differently
   (probably as a static header function) */
#define http_request_log(rh, level, fmt, ...)                           \
  logging_log(level, "HTTP %p " fmt, rh, ##__VA_ARGS__)

#define http_request_log_error(rh, ...) http_request_log(rh, LOG_ERROR, __VA_ARGS__)
#define http_request_log_warning(rh, ...) http_request_log(rh, LOG_WARNING, __VA_ARGS__)
#define http_request_log_info(rh, ...) http_request_log(rh, LOG_INFO, __VA_ARGS__)
#define http_request_log_debug(rh, ...) http_request_log(rh, LOG_DEBUG, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* HTTP_SERVER_H */
