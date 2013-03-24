#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <stdint.h>

#include "c_util.h"
#include "coroutine.h"
#include "coroutine_io.h"
#include "events.h"
#include "fdevent.h"
#include "uthread.h"

#ifndef _IS_HTTP_SERVER__C
extern const char *HTTP_HEADER_CONTENT_LENGTH;
#endif

enum {
  IN_BUF_SIZE=4096,
  MAX_LINE_SIZE=1024,
  MAX_METHOD_SIZE=16,
  MAX_URI_SIZE=1024,
  MAX_VERSION_SIZE=8,
  MAX_HEADER_NAME_SIZE=64,
  MAX_HEADER_VALUE_SIZE=128,
  MAX_NUM_HEADERS=16,
  MAX_MESSAGE_SIZE=64,
  OUT_BUF_SIZE=4096,
  MAX_RESPONSE_LINE_SIZE=128,
};

/* forward decl */
struct _http_server;
typedef struct _http_server HTTPServer;
struct _http_connection;
typedef struct _http_connection HTTPConnection;

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
  HTTP_STATUS_CODE_OK=200,
  HTTP_STATUS_CODE_NOT_FOUND=404,
  HTTP_STATUS_CODE_METHOD_NOT_ALLOWED=405,
  HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR=500,
} http_status_code_t;

typedef struct {
  http_status_code_t code;
  char message[MAX_MESSAGE_SIZE];
  size_t num_headers;
  struct _header_pair headers[MAX_NUM_HEADERS];
} HTTPResponseHeaders;

struct _http_request_context;
typedef struct _http_request_context HTTPRequestContext;
typedef HTTPRequestContext *http_request_handle_t;

struct _http_server {
  FDEventLoop *loop;
  int fd;
  fd_event_watch_key_t watch_key;
  event_handler_t handler;
  void *ud;
};

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  http_request_handle_t rh;
  HTTPRequestHeaders *request_headers;
  event_handler_t cb;
  void *ud;
  /* state */
  int i;
  int c;
  size_t ei;
  size_t parsed;
  char tmpbuf[1024];
} GetRequestState;

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  const HTTPResponseHeaders *response_headers;
  HTTPRequestContext *request_context;
  event_handler_t cb;
  void *cb_ud;
  /* state */
  size_t header_idx;
  char response_line[MAX_RESPONSE_LINE_SIZE];
} WriteHeadersState;

typedef struct {
  http_request_handle_t request_context;
  event_handler_t cb;
  void *cb_ud;
} WriteResponseState;

typedef struct {
  http_request_handle_t request_context;
  event_handler_t cb;
  void *cb_ud;
} ReadRequestState;

typedef enum {
  HTTP_REQUEST_READ_STATE_NONE,
  HTTP_REQUEST_READ_STATE_READING_HEADERS,
  HTTP_REQUEST_READ_STATE_READ_HEADERS,
  HTTP_REQUEST_READ_STATE_READING,
  HTTP_REQUEST_READ_STATE_DONE,
} http_request_read_state_t;

typedef enum {
  HTTP_REQUEST_WRITE_STATE_NONE,
  HTTP_REQUEST_WRITE_STATE_WRITING_HEADERS,
  HTTP_REQUEST_WRITE_STATE_WROTE_HEADERS,
  HTTP_REQUEST_WRITE_STATE_WRITING,
  HTTP_REQUEST_WRITE_STATE_DONE,
} http_request_write_state_t;

struct _http_request_context {
  HTTPConnection *conn;
  HTTPRequestHeaders rh;
  http_request_write_state_t write_state;
  http_request_read_state_t read_state;
  size_t content_length;
  size_t bytes_read;
  size_t out_content_length;
  size_t bytes_written;
  int last_error_number;
  union {
    ReadRequestState rrs;
    WriteResponseState rws;
  } sub;
};

struct _http_connection {
  UTHR_CTX_BASE;
  FDBuffer f;
  HTTPServer *server;
  /* these might become per-request,
     right now we only do one request at a time,
     i.e. no pipe-lining */
  union {
    char buffer[OUT_BUF_SIZE];
    HTTPResponseHeaders rsp;
    HTTPRequestHeaders req;
  } spare;
  HTTPRequestContext rctx;
};

typedef struct {
  http_request_handle_t request_handle;
  int err;
} _SimpleRequestActionDoneEvent;

typedef struct {
  http_request_handle_t request_handle;
  HTTPServer *server;
} HTTPNewRequestEvent;

typedef _SimpleRequestActionDoneEvent HTTPRequestReadHeadersDoneEvent;
typedef _SimpleRequestActionDoneEvent HTTPRHTTPRequestWriteHeadersDoneEvent;
typedef _SimpleRequestActionDoneEvent HTTPRequestWriteHeadersDoneEvent;
typedef _SimpleRequestActionDoneEvent HTTPRequestWriteDoneEvent;

typedef struct {
  http_request_handle_t request_handle;
  int err;
  size_t nbyte;
} HTTPRequestReadDoneEvent;

NON_NULL_ARGS3(1, 2, 4) bool
http_server_start(HTTPServer *http,
		  FDEventLoop *loop,
		  int fd,
		  event_handler_t handler,
		  void *ud);

NON_NULL_ARGS0() bool
http_server_stop(HTTPServer *http);

NON_NULL_ARGS3(1, 2, 3) void
http_request_read_headers(http_request_handle_t rh,
			  HTTPRequestHeaders *request_headers,
			  event_handler_t cb,
			  void *cb_ud);

NON_NULL_ARGS3(1, 2, 4) void
http_request_read(http_request_handle_t rh,
		  void *buf, size_t nbyte,
		  event_handler_t cb, void *cb_ud);

NON_NULL_ARGS3(1, 2, 3) void
http_request_write_headers(http_request_handle_t rh,
			   const HTTPResponseHeaders *response_headers,
			   event_handler_t cb,
			   void *cb_ud);

NON_NULL_ARGS3(1, 2, 4) void
http_request_write(http_request_handle_t rh,
		   const void *buf, size_t nbyte,
		   event_handler_t cb, void *cb_ud);

NON_NULL_ARGS0() void
http_request_end(http_request_handle_t rh);

NON_NULL_ARGS0() const char *
http_get_header_value(const HTTPRequestHeaders *rhs, const char *header_name);

NON_NULL_ARGS3(1, 3, 4) void
http_request_simple_response(http_request_handle_t rh,
			     http_status_code_t code, const char *body,
			     event_handler_t cb, void *cb_ud);

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
#define SET_MSG(msg_)				\
  do {						\
    msg_size = sizeof(msg_);			\
    msg = msg_;					\
  }						\
  while (false)
  switch (code) {
  case HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR: SET_MSG("Internal Server Error"); break;
  case HTTP_STATUS_CODE_OK: SET_MSG("OK"); break;
  case HTTP_STATUS_CODE_NOT_FOUND: SET_MSG("Not Found"); break;
  case HTTP_STATUS_CODE_METHOD_NOT_ALLOWED: SET_MSG("Method Not Allowed"); break;
  default: return false; break;
  }

  memcpy(rsp->message, msg, MIN(sizeof(rsp->message), msg_size));

  return true;
}

#endif /* HTTP_SERVER_H */
