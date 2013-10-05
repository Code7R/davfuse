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

#ifndef _WEBDAV_BACKEND_ASYNC_FUSE_H
#define _WEBDAV_BACKEND_ASYNC_FUSE_H

#include "async_fuse_fs.h"
#include "iface_util.h"
#include "_webdav_server_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct _webdav_backend_async_fuse;

typedef struct _webdav_backend_async_fuse *webdav_backend_async_fuse_t;

webdav_backend_async_fuse_t
webdav_backend_async_fuse_new(async_fuse_fs_t fs);

bool
webdav_backend_async_fuse_destroy(webdav_backend_async_fuse_t backend);

void
webdav_backend_async_fuse_get(webdav_backend_async_fuse_t backend,
                              const char *relative_uri,
                              webdav_get_request_ctx_t get_ctx);

void
webdav_backend_async_fuse_put(webdav_backend_async_fuse_t backend,
                              const char *relative_uri,
                              webdav_put_request_ctx_t put_ctx);

void
webdav_backend_async_fuse_touch(webdav_backend_async_fuse_t backend,
                                const char *relative_uri,
                                event_handler_t cb, void *cb_ud);

void
webdav_backend_async_fuse_propfind(webdav_backend_async_fuse_t backend,
                                   const char *relative_uri, webdav_depth_t depth,
                                   webdav_propfind_req_type_t propfind_req_type,
                                   event_handler_t cb, void *cb_ud);

void
webdav_backend_async_fuse_mkcol(webdav_backend_async_fuse_t backend,
                                const char *relative_uri,
                                event_handler_t cb, void *cb_ud);

void
webdav_backend_async_fuse_delete(webdav_backend_async_fuse_t backend,
                                 const char *relative_uri,
                                 event_handler_t cb, void *cb_ud);

void
webdav_backend_async_fuse_move(webdav_backend_async_fuse_t backend,
                               const char *src_relative_uri, const char *dst_relative_uri,
                               bool overwrite,
                               event_handler_t cb, void *cb_ud);

void
webdav_backend_async_fuse_copy(webdav_backend_async_fuse_t backend,
                               const char *src_relative_uri, const char *dst_relative_uri,
                               bool overwrite, webdav_depth_t depth,
                               event_handler_t cb, void *cb_ud);

CREATE_IMPL_TAG(WEBDAV_BACKEND_ASYNC_FUSE_IMPL);

#ifdef __cplusplus
}
#endif

#endif
