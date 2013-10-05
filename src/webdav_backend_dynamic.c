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

struct webdav_backend {
  const WebdavBackendOperations *op;
  void *user_data;
};

webdav_backend_t
webdav_backend_new(const WebdavBackendOperations *op,
              size_t op_size,
              void *user_data) {
  UNUSED(op_size);

  struct webdav_backend *toret = malloc(sizeof(*toret));
  if (!toret) {
    return NULL;
  }

  *toret = (struct webdav_backend) {
    .op = op,
    .user_data = user_data,
  };

  return toret;
}

void
webdav_backend_destroy(webdav_backend_t fs) {
  free(fs);
}

void
webdav_backend_get(webdav_backend_t fs,
                   const char *relative_uri,
                   webdav_get_request_ctx_t get_ctx) {
  return fs->op->get(fs->user_data, relative_uri, get_ctx);
}

void
webdav_backend_put(webdav_backend_t fs,
                   const char *relative_uri,
                   webdav_put_request_ctx_t put_ctx) {
  return fs->op->put(fs->user_data, relative_uri, put_ctx);
}

void
webdav_backend_touch(webdav_backend_t fs,
                     const char *relative_uri,
                     event_handler_t cb, void *cb_ud) {
  return fs->op->touch(fs->user_data,
                       relative_uri,
                       cb, cb_ud);
}

void
webdav_backend_propfind(webdav_backend_t fs,
                        const char *relative_uri, webdav_depth_t depth,
                        webdav_propfind_req_type_t propfind_req_type,
                        event_handler_t cb, void *cb_ud) {
  return fs->op->propfind(fs->user_data,
                          relative_uri, depth,
                          propfind_req_type,
                          cb, cb_ud);
}

void
webdav_backend_mkcol(webdav_backend_t fs,
                     const char *relative_uri,
                     event_handler_t cb, void *cb_ud) {
  return fs->op->mkcol(fs->user_data, relative_uri, cb, cb_ud);
}

void
webdav_backend_delete(webdav_backend_t fs,
                      const char *relative_uri,
                      event_handler_t cb, void *cb_ud) {
  return fs->op->delete_x(fs->user_data, relative_uri, cb, cb_ud);
}

void
webdav_backend_move(webdav_backend_t fs,
                    const char *src_relative_uri, const char *dst_relative_uri,
                    bool overwrite,
                    event_handler_t cb, void *cb_ud) {
  return fs->op->move(fs->user_data,
                      src_relative_uri, dst_relative_uri,
                      overwrite,
                      cb, cb_ud);
}

void
webdav_backend_copy(webdav_backend_t fs,
                    const char *src_relative_uri, const char *dst_relative_uri,
                    bool overwrite, webdav_depth_t depth,
                    event_handler_t cb, void *cb_ud) {
  return fs->op->copy(fs->user_data,
                      src_relative_uri, dst_relative_uri,
                      overwrite, depth,
                      cb, cb_ud);
}
