#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include "coroutine_io.h"

#define IN_BUF_SIZE 4096
#define MAX_LINE_SIZE 1024
#define MAX_METHOD_SIZE 16
#define MAX_URI_SIZE 1024
#define MAX_VERSION_SIZE 8
#define MAX_HEADER_NAME_SIZE 64
#define MAX_HEADER_VALUE_SIZE 128
#define MAX_NUM_HEADERS 16
#define OUT_BUF_SIZE 4096

typedef struct {
  FDEventLoop *loop;
  http_accept_handler cur_handler;
  int fd;
  FDEventWatchKey watch_key;
  void *ud;
} HTTPServer;

typedef struct {
  union {
    GetWhileState getwhile_state;
    GetCState getc_state;
    PeekState peek_state;
  } sub;
  int i;
  int ei;
  int c;
  char tmp;
  size_t parsed;
  char tmpbuf[1024];
  coroutine_position_t coropos;
} GetRequestState;

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

typedef struct {
  int code;
} HTTPResponse;

typedef struct {
  FDBuffer f;
  char outbuffer[OUT_BUF_SIZE];
  int out_size;
  HTTPServer *server;
  FDEventWatchKey watch_key;
  coroutine_position_t coropos;
  union {
    GetRequestState grs;
    WriteAllState was;
  } sub;
  HTTPRequestHeaders request;
  HTTPResponse response;
  bool want_read : 1;
  bool want_write : 1;
} ClientConnection;

typedef void (*HTTPHandler)(HTTPRequestHeaders *,
			    HTTPRequestContext,
			    void *);

/* TODO: define different callbacks */

void
http_server_start(HTTPServer *http,
		  FDEventLoop *loop,
		  int fd,
		  HTTPHandler handler, 
		  void *ud,
		  Callback cb,
		  void *cb_ud);

void
http_server_stop(HTTPServer *http,
		 Callback cb, void *cb_ud);

void
http_request_read(HTTPRequestContext rctx,
		  void *buf, size_t nbyte,
		  Callback cb, void *cb_ud) {
}

void
http_request_start_headers(HTTPRequestContext rctx,
			   RequestHeader request_headers,
			   Callback cb, void *cb_ud) {
}

void
http_request_write(HTTPRequestContext rctx,
		   const void *buf, size_t nbyte,
		   Callback cb, void *cb_ud) {
}

void
http_request_end(HTTPRequestContext rctx,
		 Callback cb, void *cb_ud) {
}

#endif /* HTTP_SERVER_H */
