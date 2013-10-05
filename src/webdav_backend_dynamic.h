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

typedef struct webdav_backend *webdav_backend_t;

typedef struct {
  void (*copy)(void *backend_user_data,
	       const char *src_uri, const char *dst_uri,
	       bool overwrite, webdav_depth_t depth,
	       event_handler_t cb, void *ud);
  void (*delete_x)(void *backend_user_data,
                 const char *relative_uri,
                 event_handler_t cb, void *ud);
  void (*get)(void *backend_user_data,
              const char *relative_uri,
              webdav_get_request_ctx_t get_ctx);
  void (*mkcol)(void *backend_user_data,
                const char *relative_uri,
                event_handler_t cb, void *ud);
  void (*move)(void *backend_user_data,
               const char *src_uri, const char *dst_uri,
	       bool overwrite,
	       event_handler_t cb, void *ud);
  void (*propfind)(void *backend_user_data,
                   const char *relative_uri, webdav_depth_t depth,
                   webdav_propfind_req_type_t propfind_req_type,
                   event_handler_t cb, void *user_data);
  void (*put)(void *backend_user_data,
              const char *relative_uri,
              webdav_put_request_ctx_t put_ctx);
  /* for LOCK */
  void (*touch)(void *backend_user_data,
                const char *relative_uri,
                event_handler_t cb, void *user_data);

} WebdavBackendOperations;
