#ifndef WEBDAV_SERVER_H
#define WEBDAV_SERVER_H

#include "events.h"
#include "util.h"

typedef long long webdav_file_time_t;

enum {
  MAX_FILE_NAME_LENGTH=256,
};

typedef enum {
  DEPTH_0,
  DEPTH_1,
  DEPTH_INF,
  DEPTH_INVALID,
} webdav_depth_t;

typedef struct {
  webdav_file_time_t modified_time;
  webdav_file_time_t creation_time;
  bool is_collection;
  size_t length;
} WebdavFileInfo;

typedef struct {
  WebdavFileInfo file_info;
  char name[MAX_FILE_NAME_LENGTH];
} WebdavCollectionEntry;

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
  void *file_handle;
} WebdavOpenDoneEvent;

typedef struct {
  webdav_error_t error;
  WebdavFileInfo file_info;
} WebdavFstatDoneEvent;

typedef struct {
  webdav_error_t error;
  size_t nbyte;
} WebdavReadDoneEvent;

typedef struct {
  webdav_error_t error;
  size_t nbyte;
} WebdavWriteDoneEvent;

typedef struct {
  webdav_error_t error;
  size_t nread;
} WebdavReadcolDoneEvent;

typedef struct {
  webdav_error_t error;
  linked_list_t failed_to_delete;
} WebdavDeleteDoneEvent;

typedef struct {
  webdav_error_t error;
  linked_list_t failed_to_move;
} WebdavMoveDoneEvent;

typedef struct {
  webdav_error_t error;
  linked_list_t failed_to_copy;
} WebdavCopyDoneEvent;

typedef struct {
  webdav_error_t error;
} _WebdavGenericDoneEvent;

typedef _WebdavGenericDoneEvent WebdavMkcolDoneEvent;
typedef _WebdavGenericDoneEvent WebdavCloseDoneEvent;
typedef _WebdavGenericDoneEvent WebdavGetRequestSizeHintDoneEvent;
typedef _WebdavGenericDoneEvent WebdavGetRequestWriteDoneEvent;

struct webdav_backend;
struct webdav_server;
struct handler_context;

typedef struct webdav_backend *webdav_backend_t;
typedef struct webdav_server *webdav_server_t;

typedef struct handler_context *webdav_get_request_ctx_t;

typedef struct {
  /* for GET / PUT / PROPFIND */
  void (*get)(void *backend_user_data,
              const char *relative_uri,
              webdav_get_request_ctx_t get_ctx);
  void (*open)(void *backend_user_data, const char *, bool, event_handler_t, void *);
  void (*fstat)(void *backend_user_data, void *, event_handler_t, void *);
  void (*read)(void *backend_user_data, void *, void *, size_t, event_handler_t, void *);
  void (*write)(void *backend_user_data, void *, const void *, size_t, event_handler_t, void *);
  void (*readcol)(void *backend_user_data,
                  void *, WebdavCollectionEntry *, size_t, event_handler_t, void *);
  void (*close)(void *backend_user_data,
                void *, event_handler_t, void *);
  void (*mkcol)(void *backend_user_data,
                const char *relative_uri,
                event_handler_t cb, void *ud);
  void (*delete)(void *backend_user_data,
                 const char *relative_uri,
                 event_handler_t cb, void *ud);
  void (*copy)(void *backend_user_data,
	       const char *src_uri, const char *dst_uri,
	       bool overwrite, webdav_depth_t depth,
	       event_handler_t cb, void *ud);
  void (*move)(void *backend_user_data,
               const char *src_uri, const char *dst_uri,
	       bool overwrite,
	       event_handler_t cb, void *ud);
} WebdavBackendOperations;


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

webdav_backend_t
webdav_backend_new(const WebdavBackendOperations *op, size_t op_size, void *user_data);

void
webdav_backend_destroy(webdav_backend_t);

void
webdav_backend_get(webdav_backend_t fs,
                   const char *relative_uri,
                   webdav_get_request_ctx_t get_ctx);

void
webdav_backend_open(webdav_backend_t fs,
                    const char *relative_uri,
                    bool create,
                    event_handler_t cb, void *cb_ud);

void
webdav_backend_fstat(webdav_backend_t fs,
                     void *file_handle,
                     event_handler_t cb, void *cb_ud);

void
webdav_backend_read(webdav_backend_t fs, void *file_handle,
                    void *buf, size_t buf_size,
                    event_handler_t cb, void *cb_ud);

void
webdav_backend_write(webdav_backend_t fs, void *file_handle,
                     const void *buf, size_t buf_size,
                     event_handler_t cb, void *cb_ud);

void
webdav_backend_readcol(webdav_backend_t fs,
                       void *col_handle,
                       WebdavCollectionEntry *ce, size_t nentries,
                       event_handler_t cb, void *ud);

void
webdav_backend_close(webdav_backend_t fs,
                     void *file_handle,
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
