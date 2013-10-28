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

#ifndef __WEBDAV_SERVER_TYPES_H
#define __WEBDAV_SERVER_TYPES_H

#include <limits.h>
#include <stdint.h>

#include "c_util.h"
#include "events.h"

#ifdef __cplusplus
/* not defined in C++ */
#ifndef SIZE_MAX
#define SIZE_MAX ((size_t) -1)
#define __DEFINED_SIZE_MAX
#endif

extern "C" {
#endif

typedef enum {
  DEPTH_0,
  DEPTH_1,
  DEPTH_INF,
  DEPTH_INVALID,
} webdav_depth_t;

typedef enum {
  WEBDAV_PROPFIND_PROP,
  WEBDAV_PROPFIND_ALLPROP,
  WEBDAV_PROPFIND_PROPNAME,
} webdav_propfind_req_type_t;

typedef enum {
  WEBDAV_ERROR_NONE,
  WEBDAV_ERROR_GENERAL,
  WEBDAV_ERROR_NO_MEM,
  WEBDAV_ERROR_IS_COL,
  WEBDAV_ERROR_DOES_NOT_EXIST,
  WEBDAV_ERROR_NOT_COLLECTION,
  WEBDAV_ERROR_DESTINATION_DOES_NOT_EXIST,
  WEBDAV_ERROR_DESTINATION_NOT_COLLECTION,
  WEBDAV_ERROR_DESTINATION_EXISTS,
  WEBDAV_ERROR_PERM,
  WEBDAV_ERROR_NO_SPACE,
  WEBDAV_ERROR_EXISTS,
} webdav_error_t;

typedef long long webdav_resource_time_t;
typedef size_t webdav_resource_size_t;

/* NB: not totally sure about defining constants like this,
   a #define might be better */
HEADER_CONST const
webdav_resource_time_t INVALID_WEBDAV_RESOURCE_TIME = LLONG_MAX;
HEADER_CONST const
webdav_resource_size_t INVALID_WEBDAV_RESOURCE_SIZE = SIZE_MAX;

/* opaque forward decls */
struct webdav_propfind_entry;
struct webdav_server;
struct handler_context;

typedef struct webdav_server *webdav_server_t;
typedef struct webdav_propfind_entry *webdav_propfind_entry_t;
typedef struct handler_context *webdav_get_request_ctx_t;
typedef struct handler_context *webdav_put_request_ctx_t;

webdav_propfind_entry_t
webdav_new_propfind_entry(const char *relative_uri,
                          webdav_resource_time_t modified_time,
                          webdav_resource_time_t creation_time,
                          bool is_collection,
                          webdav_resource_size_t length);

void
webdav_destroy_propfind_entry(webdav_propfind_entry_t pfe);

#ifdef __cplusplus
}

#ifdef __DEFINED_SIZE_MAX
#undef __DEFINED_SIZE_MAX
#undef SIZE_MAX
#endif

#endif

#endif
