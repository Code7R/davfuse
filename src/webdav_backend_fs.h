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

#ifndef _WEBDAV_BACKEND_FS_H
#define _WEBDAV_BACKEND_FS_H

#include "iface_util.h"
#include "fs.h"
#include "_webdav_server_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct _webdav_backend_fs;

typedef struct _webdav_backend_fs *webdav_backend_fs_t;

webdav_backend_fs_t
webdav_backend_fs_new(fs_handle_t fs, const char *root);

void
webdav_backend_fs_destroy(webdav_backend_fs_t backend);

void
webdav_backend_fs_get(webdav_backend_fs_t backend,
                      const char *relative_uri,
                      webdav_get_request_ctx_t get_ctx);

void
webdav_backend_fs_put(webdav_backend_fs_t backend,
                      const char *relative_uri,
                      webdav_put_request_ctx_t put_ctx);

void
webdav_backend_fs_touch(webdav_backend_fs_t backend,
                        const char *relative_uri,
                        event_handler_t cb, void *cb_ud);

void
webdav_backend_fs_propfind(webdav_backend_fs_t backend,
                           const char *relative_uri, webdav_depth_t depth,
                           webdav_propfind_req_type_t propfind_req_type,
                           event_handler_t cb, void *cb_ud);

void
webdav_backend_fs_mkcol(webdav_backend_fs_t backend,
                        const char *relative_uri,
                        event_handler_t cb, void *cb_ud);

void
webdav_backend_fs_delete(webdav_backend_fs_t backend,
                         const char *relative_uri,
                         event_handler_t cb, void *cb_ud);

void
webdav_backend_fs_move(webdav_backend_fs_t backend,
                       const char *src_relative_uri, const char *dst_relative_uri,
                       bool overwrite,
                       event_handler_t cb, void *cb_ud);

void
webdav_backend_fs_copy(webdav_backend_fs_t backend,
                       const char *src_relative_uri, const char *dst_relative_uri,
                       bool overwrite, webdav_depth_t depth,
                       event_handler_t cb, void *cb_ud);

CREATE_IMPL_TAG(WEBDAV_BACKEND_FS_IMPL);

#ifdef __cplusplus
}
#endif

#endif
