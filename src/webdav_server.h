#ifndef WEBDAV_SERVER_H
#define WEBDAV_SERVER_H

#include "events.h"
#include "util.h"

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

enum {
  MAX_FILE_NAME_LENGTH=256,
};

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

typedef struct {
  webdav_error_t error;
} _WebdavGenericDoneEvent;

typedef struct {
  webdav_error_t error;
  linked_list_t failed_to_delete;
} WebdavDeleteDoneEvent;

typedef struct {
  webdav_error_t error;
  linked_list_t failed_to_move;
  bool dst_existed;
} WebdavMoveDoneEvent;

typedef struct {
  webdav_error_t error;
  linked_list_t failed_to_copy;
  bool dst_existed;
} WebdavCopyDoneEvent;

typedef struct {
  webdav_error_t error;
  bool resource_existed;
} WebdavTouchDoneEvent;

typedef struct {
  webdav_error_t error;
  linked_list_t entries;
} WebdavPropfindDoneEvent;

typedef _WebdavGenericDoneEvent WebdavMkcolDoneEvent;
typedef _WebdavGenericDoneEvent WebdavCloseDoneEvent;

/* backend method helper done events */
typedef _WebdavGenericDoneEvent WebdavGetRequestSizeHintDoneEvent;
typedef _WebdavGenericDoneEvent WebdavGetRequestWriteDoneEvent;

typedef struct {
  webdav_error_t error;;
  size_t nbyte;
} WebdavPutRequestReadDoneEvent;


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

webdav_propfind_entry_t
webdav_new_propfind_entry(const char *relative_uri,
                             webdav_file_time_t modified_time,
                             webdav_file_time_t creation_time,
                             bool is_collection,
                             size_t length);

void
webdav_destroy_propfind_entry(webdav_propfind_entry_t pfe);

webdav_server_t
webdav_server_start(FDEventLoop *loop,
		    int server_fd,
		    const char *public_prefix,
		    webdav_backend_t fs);

void
webdav_server_stop(webdav_server_t ws,
                   event_handler_t cb, void *user_data);

void
webdav_get_request_size_hint(webdav_get_request_ctx_t get_ctx,
                             size_t size,
                             event_handler_t cb, void *cb_ud);

void
webdav_get_request_write(webdav_get_request_ctx_t get_ctx,
                         const void *buf, size_t nbyte,
                         event_handler_t cb, void *cb_ud);

void
webdav_get_request_end(webdav_get_request_ctx_t get_ctx, webdav_error_t error);

void
webdav_put_request_read(webdav_put_request_ctx_t put_ctx,
                        void *buf, size_t nbyte,
                        event_handler_t cb, void *cb_ud);

void
webdav_put_request_end(webdav_get_request_ctx_t put_ctx,
                       webdav_error_t error,
                       bool resource_existed);

webdav_backend_t
webdav_backend_new(const WebdavBackendOperations *op, size_t op_size, void *user_data);

void
webdav_backend_destroy(webdav_backend_t);

void
webdav_backend_get(webdav_backend_t fs,
                   const char *relative_uri,
                   webdav_get_request_ctx_t get_ctx);

void
webdav_backend_put(webdav_backend_t fs,
                   const char *relative_uri,
                   webdav_put_request_ctx_t put_ctx);

void
webdav_backend_touch(webdav_backend_t fs,
                     const char *relative_uri,
                     event_handler_t cb, void *cb_ud);

void
webdav_backend_propfind(webdav_backend_t fs,
                        const char *relative_uri, webdav_depth_t depth,
                        webdav_propfind_req_type_t propfind_req_type,
                        event_handler_t cb, void *cb_ud);

void
webdav_backend_mkcol(webdav_backend_t fs,
                     const char *relative_uri,
                     event_handler_t cb, void *cb_ud);

void
webdav_backend_delete(webdav_backend_t fs,
                      const char *relative_uri,
                      event_handler_t cb, void *cb_ud);

void
webdav_backend_move(webdav_backend_t fs,
                    const char *src_relative_uri, const char *dst_relative_uri,
                    bool overwrite,
                    event_handler_t cb, void *cb_ud);

void
webdav_backend_copy(webdav_backend_t fs,
                    const char *src_relative_uri, const char *dst_relative_uri,
                    bool overwrite, webdav_depth_t depth,
                    event_handler_t cb, void *cb_ud);

#endif
