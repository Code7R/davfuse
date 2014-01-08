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

#ifndef __WEBDAV_SERVER_PRIVATE_TYPES_H
#define __WEBDAV_SERVER_PRIVATE_TYPES_H

#include "http_server.h"
#include "uthread.h"
#include "util.h"
#include "webdav_backend.h"
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
  bool is_collection;
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
  webdav_resource_time_t modified_time;
  webdav_resource_time_t creation_time;
  bool is_collection;
  webdav_resource_size_t length;
};

struct webdav_server {
  http_server_t http;
  linked_list_t locks;
  webdav_backend_t fs;
  char *public_uri_root;
  char *internal_root;
};

struct handler_context {
  UTHR_CTX_BASE;
  struct webdav_server *serv;
  HTTPRequestHeaders rhs;
  HTTPResponseHeaders resp;
  http_request_handle_t rh;
  struct header_context {
    event_handler_t handler;
  } header;
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
      size_t amt_sent;
      struct webdav_propfind_entry entry;
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
      bool is_collection;
      owner_xml_t owner_xml;
      char *resource_tag;
      char *resource_tag_path;
      char *refresh_uri;
      bool is_locked;
      const char *lock_token;
      const char *status_path;
      bool status_path_is_collection;
      bool is_exclusive;
      webdav_depth_t depth;
      bool created;
      webdav_timeout_t timeout_in_seconds;
    } lock;
    struct mkcol_context {
      coroutine_position_t pos;
      char *request_relative_uri;
    } mkcol;
    struct options_context {
      coroutine_position_t pos;
      bool uri_is_collection;
      char allow_header[256];
    } options;
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

WebdavProperty *
create_webdav_property(const char *element_name, const char *ns_href);

void
free_webdav_property(WebdavProperty *wp);

WebdavProppatchDirective *
create_webdav_proppatch_directive(webdav_proppatch_directive_type_t type,
                                  const char *name,
                                  const char *ns_href,
                                  const char *value);

void
free_webdav_proppatch_directive(WebdavProppatchDirective *wp);

#ifdef __cplusplus
}
#endif

#endif
