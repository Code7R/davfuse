#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include "coroutine.h"
#include "coroutine_io.h"
#include "events.h"
#include "fdevent.h"

#define IN_BUF_SIZE 4096
#define MAX_LINE_SIZE 1024
#define MAX_METHOD_SIZE 16
#define MAX_URI_SIZE 1024
#define MAX_VERSION_SIZE 8
#define MAX_HEADER_NAME_SIZE 64
#define MAX_HEADER_VALUE_SIZE 128
#define MAX_NUM_HEADERS 16
#define OUT_BUF_SIZE 4096

typedef void (*callback_t)(void *);

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
  HTTP_REQUEST_STATE_NONE,
  HTTP_REQUEST_STATE_READ_HEADERS,
  HTTP_REQUEST_STATE_WROTE_HEADERS,
  HTTP_REQUEST_STATE_DONE,
} http_request_state_t;

typedef enum {
  HTTP_SUCCESS, 
  HTTP_GENERIC_ERROR,
} http_error_code_t;

typedef struct {
  HTTPConnection *conn;
  http_request_state_t state;
  HTTPRequestHeaders rh;
} HTTPRequestContext;

typedef struct {
} HTTPResponseHeaders;

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
  FDEventLoop *loop;
  FDBuffer *f;
  bool *success;
  HTTPRequestHeaders *request_headers;
  int *error;
  event_handler_t cb;
  void *ud;
} GetRequestState;

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
} HTTPNewRequestEvent;

typedef struct {
  http_request_handle_t request_handle;
  int err;
} HTTPRequestReadHeadersDoneEvent;

typedef struct {
  http_request_handle_t request_handle;
  int err;
  size_t nbyte;
} HTTPRequestReadDoneEvent;

bool
http_server_start(HTTPServer *http,
		  FDEventLoop *loop,
		  int fd,
		  event_handler_t handler, 
		  void *ud);

bool
http_server_stop(HTTPServer *http);

void
http_request_read_headers(http_request_handle_t rh,
			  HTTPRequestHeaders *request_headers,
			  event_handler_t cb,
			  void *);

void
http_request_read(http_request_handle_t rh,
		  void *buf, size_t nbyte,
		  event_handler_t cb, void *cb_ud);

void
http_request_write_headers(http_request_handle_t rh,
			   HTTPResponseHeaders *response_headers,
			   event_handler_t cb,
			   void *cb_ud);

void
http_request_write(http_request_handle_t rh,
		   const void *buf, size_t nbyte,
		   event_handler_t cb, void *cb_ud);

void
http_request_end(http_request_handle_t rh,
		 event_handler_t cb, void *cb_ud);

char *
http_get_header_value(HTTPRequestHeaders *rhs, char *header_name);

#endif /* HTTP_SERVER_H */
