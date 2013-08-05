#ifndef WEBDAV_SERVER_H
#define WEBDAV_SERVER_H

#include "events.h"
#include "http_backend.h"
#include "util.h"
#include "webdav_backend.h"

#include "_webdav_server_types.h"

enum {
  MAX_FILE_NAME_LENGTH=256,
};

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

webdav_propfind_entry_t
webdav_new_propfind_entry(const char *relative_uri,
                          webdav_file_time_t modified_time,
                          webdav_file_time_t creation_time,
                          bool is_collection,
                          size_t length);

void
webdav_destroy_propfind_entry(webdav_propfind_entry_t pfe);

webdav_server_t
webdav_server_start(http_backend_t http_backend,
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

#endif
