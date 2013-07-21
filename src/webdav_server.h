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
typedef _WebdavGenericDoneEvent WebdavRemoveDoneEvent;

typedef struct {
  /* for GET / PUT / PROPFIND */
  void (*open)(void *, const char *relative_uri, bool, event_handler_t, void *);
  void (*fstat)(void *, void *, event_handler_t, void *);
  void (*read)(void *, void *, void *, size_t, event_handler_t, void *);
  void (*write)(void *, void *, const void *, size_t, event_handler_t, void *);
  /* for PROPFIND */
  void (*readcol)(void *, void *, WebdavCollectionEntry *, size_t, event_handler_t, void *);
  void (*close)(void *, void *, event_handler_t, void *);
  /* for MKCOL */
  void (*mkcol)(void *, const char *relative_uri, event_handler_t, void *);
  /* for DELETE */
  void (*delete)(void *, const char *relative_uri, event_handler_t, void *);
  /* for COPY  */
  void (*copy)(void *,
	       const char *src_uri, const char *dst_uri,
	       bool overwrite, webdav_depth_t depth,
	       event_handler_t, void *);
  /* for MOVE  */
  void (*move)(void *, const char *src_uri, const char *dst_uri,
	       bool overwrite,
	       event_handler_t, void *);
} WebdavOperations;

struct webdav_fs;
struct webdav_server;

typedef struct webdav_fs *webdav_fs_t;
typedef struct webdav_server *webdav_server_t;

webdav_server_t
webdav_server_start(FDEventLoop *loop,
		    int server_fd,
		    const char *public_prefix,
		    webdav_fs_t fs);

void
webdav_server_stop(webdav_server_t ws,
                   event_handler_t cb, void *user_data);

webdav_fs_t
webdav_fs_new(const WebdavOperations *op, size_t op_size, void *user_data);

void
webdav_fs_destroy(webdav_fs_t);

void
webdav_fs_open(webdav_fs_t fs,
	       const char *relative_uri,
	       bool create,
	       event_handler_t cb, void *cb_ud);

void
webdav_fs_fstat(webdav_fs_t fs,
		void *file_handle,
		event_handler_t cb, void *cb_ud);

void
webdav_fs_read(webdav_fs_t fs, void *file_handle,
	       void *buf, size_t buf_size,
	       event_handler_t cb, void *cb_ud);

void
webdav_fs_write(webdav_fs_t fs, void *file_handle,
		const void *buf, size_t buf_size,
		event_handler_t cb, void *cb_ud);

void
webdav_fs_readcol(webdav_fs_t fs,
		  void *col_handle,
		  WebdavCollectionEntry *ce, size_t nentries,
		  event_handler_t cb, void *ud);

void
webdav_fs_close(webdav_fs_t fs,
		void *file_handle,
		event_handler_t cb, void *cb_ud);

void
webdav_fs_mkcol(webdav_fs_t fs,
		const char *relative_uri,
		event_handler_t cb, void *cb_ud);

void
webdav_fs_delete(webdav_fs_t fs,
		 const char *relative_uri,
		 event_handler_t cb, void *cb_ud);

void
webdav_fs_move(webdav_fs_t fs,
	       const char *src_relative_uri, const char *dst_relative_uri,
	       bool overwrite,
	       event_handler_t cb, void *cb_ud);

void
webdav_fs_copy(webdav_fs_t fs,
	       const char *src_relative_uri, const char *dst_relative_uri,
	       bool overwrite, webdav_depth_t depth,
	       event_handler_t cb, void *cb_ud);

#endif
