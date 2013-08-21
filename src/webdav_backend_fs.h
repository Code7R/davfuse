#ifndef _WEBDAV_BACKEND_FS_H
#define _WEBDAV_BACKEND_FS_H

#include "iface_util.h"
#include "webdav_backend_fs_fs.h"
#include "_webdav_server_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct _webdav_backend_fs;

typedef struct _webdav_backend_fs *webdav_backend_fs_t;

webdav_backend_fs_t
webdav_backend_fs_new(fs_t fs, const char *root);

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
