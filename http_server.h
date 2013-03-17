#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include "c_util.h"
#include "coroutine.h"
#include "coroutine_io.h"
#include "events.h"
#include "fdevent.h"

enum {
  IN_BUF_SIZE=4096,
  MAX_LINE_SIZE=1024,
  MAX_METHOD_SIZE=16,
  MAX_URI_SIZE=1024,
  MAX_VERSION_SIZE=8,
  MAX_HEADER_NAME_SIZE=64,
  MAX_HEADER_VALUE_SIZE=128,
  MAX_NUM_HEADERS=16,
  MAX_MESSAGE_SIZE=16,
  OUT_BUF_SIZE=4096,
};

/* forward decl */
struct _http_server;
typedef struct _http_server HTTPServer;
struct _http_connection;
typedef struct _http_connection HTTPConnection;

typedef struct {
  char method[MAX_METHOD_SIZE];
  char uri[MAX_URI_SIZE];
  int major_version;
  int minor_version;
  size_t num_headers;
  struct {
    char name[MAX_HEADER_NAME_SIZE];
    char value[MAX_HEADER_VALUE_SIZE];
  } headers[MAX_NUM_HEADERS];
} HTTPRequestHeaders;

typedef enum {
  HTTP_SUCCESS, 
  HTTP_GENERIC_ERROR,
} http_error_code_t;

typedef enum {
  HTTP_STATUS_CODE_OK=200,
  HTTP_STATUS_CODE_NOT_FOUND=404,
  HTTP_STATUS_CODE_METHOD_NOT_ALLOWED=405,
} http_status_code_t;

typedef struct {
  http_status_code_t code;
  char message[MAX_MESSAGE_SIZE];
  size_t num_headers;
  struct {
    char name[MAX_HEADER_NAME_SIZE];
    char value[MAX_HEADER_VALUE_SIZE];
  } headers[MAX_NUM_HEADERS];
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
  union {
    GetWhileState getwhile_state;
    GetCState getc_state;
    PeekState peek_state;
  } sub;
  int i;
  int ei;
  int c;
  size_t parsed;
  char tmpbuf[1024];
  coroutine_position_t coropos;
  /* args */
  http_request_handle_t rh;
  FDEventLoop *loop;
  FDBuffer *f;
  HTTPRequestHeaders *request_headers;
  event_handler_t cb;
  void *ud;
} GetRequestState;

typedef struct {
  coroutine_position_t coropos;
  union {
    WriteAllState was;
  } sub;
  int header_idx;
  char tmpbuf[1024];
  size_t out_size;

  /* args */
  const HTTPResponseHeaders *response_headers;
  HTTPRequestContext *request_context;
  event_handler_t cb;
  void *cb_ud;
} WriteHeadersState;

typedef struct {
  union {
    WriteAllState was;
  } sub;
  http_request_handle_t request_context;
  event_handler_t cb;
  void *cb_ud;
} WriteResponseState;

typedef struct {
  union {
    CReadState crs;
  } sub;
  http_request_handle_t request_context;
  event_handler_t cb;
  void *cb_ud;
} ReadRequestState;

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

struct _http_request_context {
  HTTPConnection *conn;
  HTTPRequestHeaders rh;
  http_request_write_state_t write_state;
  http_request_read_state_t read_state;
  int last_error_number;
  union {
    WriteHeadersState whs;
    WriteResponseState rws;
    ReadRequestState rrs;
  } sub;
};

struct _http_connection {
  FDBuffer f;
  char outbuffer[OUT_BUF_SIZE];
  int out_size;
  HTTPServer *server;
  coroutine_position_t coropos;
  union {
    GetRequestState grs;
    WriteAllState was;
  } sub;
  /* right now we only do one request at a time,
     i.e. no pipe-lining */
  HTTPRequestContext rctx;
};

typedef struct {
  http_request_handle_t request_handle;
  int err;
} _SimpleRequestActionDoneEvent;

typedef struct {
  http_request_handle_t request_handle;
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

NON_NULL_ARGS0() char *
http_get_header_value(HTTPRequestHeaders *rhs, const char *header_name);

NON_NULL_ARGS2(1, 3)  void
http_request_simple_response(http_request_handle_t rh,
			     http_status_code_t code, const char *body,
			     event_handler_t cb, void *cb_ud);

#endif /* HTTP_SERVER_H */
