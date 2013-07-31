#ifndef __WEBDAV_SERVER_TYPES_H
#define __WEBDAV_SERVER_TYPES_H

#include "events.h"

#ifdef __cplusplus
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

typedef long long webdav_file_time_t;

/* opaque forward decls */
struct webdav_propfind_entry;
struct webdav_backend;
struct webdav_server;
struct handler_context;

typedef struct webdav_backend *webdav_backend_t;
typedef struct webdav_server *webdav_server_t;
typedef struct webdav_propfind_entry *webdav_propfind_entry_t;
typedef struct handler_context *webdav_get_request_ctx_t;
typedef struct handler_context *webdav_put_request_ctx_t;

typedef struct {
  void (*copy)(void *backend_user_data,
	       const char *src_uri, const char *dst_uri,
	       bool overwrite, webdav_depth_t depth,
	       event_handler_t cb, void *ud);
  void (*delete)(void *backend_user_data,
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

#ifdef __cplusplus
}
#endif

#endif
