#ifndef __WEBDAV_SERVER_PRIVATE_TYPES_H
#define __WEBDAV_SERVER_PRIVATE_TYPES_H

#include "http_server.h"
#include "uthread.h"
#include "util.h"
#include "_webdav_server_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* this can be implemented in any way, that's why it's a void * */
typedef void *owner_xml_t;

typedef unsigned webdav_timeout_t;

/* private events */

typedef struct {
  const void *buf;
  size_t nbyte;
  event_handler_t cb;
  void *cb_ud;
} WebdavGetRequestWriteEvent;

typedef struct {
  webdav_error_t error;
} WebdavGetRequestEndEvent;

typedef struct {
  void *buf;
  size_t nbyte;
  event_handler_t cb;
  void *cb_ud;
} WebdavPutRequestReadEvent;

typedef struct {
  webdav_error_t error;
  bool resource_existed;
} WebdavPutRequestEndEvent;

/* private structures */

typedef struct {
  char *element_name;
  char *ns_href;
} WebdavProperty;

typedef struct {
  char *path;
  webdav_depth_t depth;
  bool is_exclusive;
  owner_xml_t owner_xml;
  char *lock_token;
  webdav_timeout_t timeout_in_seconds;
} WebdavLockDescriptor;

typedef enum {
  WEBDAV_PROPPATCH_DIRECTIVE_SET,
  WEBDAV_PROPPATCH_DIRECTIVE_REMOVE,
} webdav_proppatch_directive_type_t;

typedef struct {
  webdav_proppatch_directive_type_t type;
  char *name;
  char *ns_href;
  char *value;
} WebdavProppatchDirective;

/* public, yet opaque structures */

struct webdav_propfind_entry {
  char *relative_uri;
  webdav_file_time_t modified_time;
  webdav_file_time_t creation_time;
  bool is_collection;
  size_t length;
};

struct webdav_backend {
  const WebdavBackendOperations *op;
  void *user_data;
};

struct webdav_server {
  HTTPServer http;
  FDEventLoop *loop;
  linked_list_t locks;
  webdav_backend_t fs;
  char *public_prefix;
  event_handler_t stop_cb;
  void *stop_ud;
};

struct handler_context {
  UTHR_CTX_BASE;
  struct webdav_server *serv;
  HTTPRequestHeaders rhs;
  HTTPResponseHeaders resp;
  http_request_handle_t rh;
  event_handler_t handler;
  union {
    struct copy_context {
      coroutine_position_t pos;
      bool is_move;
      webdav_depth_t depth;
      char *response_body;
      size_t response_body_len;
      char *dst_relative_uri;
      char *src_relative_uri;
      bool dst_existed;
    } copy;
    struct delete_context {
      coroutine_position_t pos;
      char *response_body;
      size_t response_body_len;
      char *request_relative_uri;
    } delete_x;
    struct get_context {
      coroutine_position_t pos;
      char *resource_uri;
      bool set_size_hint;
      bool sent_headers;
      WebdavGetRequestWriteEvent rwev;
    } get;
    struct lock_context {
      coroutine_position_t pos;
      char *response_body;
      size_t response_body_len;
      char *request_body;
      size_t request_body_len;
      linked_list_t headers;
      char *file_path;
      owner_xml_t owner_xml;
      char *resource_tag;
      char *resource_tag_path;
      char *refresh_uri;
      bool is_locked;
      const char *lock_token;
      const char *status_path;
      bool is_exclusive;
      webdav_depth_t depth;
      bool created;
      webdav_timeout_t timeout_in_seconds;
    } lock;
    struct mkcol_context {
      coroutine_position_t pos;
      char *request_relative_uri;
    } mkcol;
    struct propfind_context {
      coroutine_position_t pos;
      char *request_relative_uri;
      char *buf;
      size_t buf_used, buf_size;
      char *out_buf;
      size_t out_buf_size;
      linked_list_t props_to_get;
      webdav_propfind_req_type_t propfind_req_type;
    } propfind;
    struct proppatch_context {
      coroutine_position_t pos;
      char *request_body;
      size_t request_body_size;
      char *response_body;
      size_t response_body_size;
    } proppatch;
    struct put_context {
      coroutine_position_t pos;
      WebdavPutRequestReadEvent read_ev;
      char *request_relative_uri;
      char *response_body;
      size_t response_body_len;
    } put;
  } sub;
};

#ifdef __cplusplus
}
#endif

#endif
