#ifndef EVENTS_H
#define EVENTS_H

/* all events types go here,
   the benefits of writing all your own code */

typedef enum {
  GENERIC_EVENT,
  HTTP_NEW_REQUEST_EVENT,
  HTTP_REQUEST_READ_HEADERS_DONE_EVENT,
  HTTP_REQUEST_READ_DONE_EVENT,
  HTTP_REQUEST_WRITE_HEADERS_DONE_EVENT,
  HTTP_REQUEST_WRITE_DONE_EVENT,
  HTTP_END_REQUEST_EVENT,
  START_COROUTINE_EVENT,
  C_FBGETC_DONE_EVENT,
  C_FBPEEK_DONE_EVENT,
  C_GETWHILE_DONE_EVENT,
  FD_EVENT,
  C_WRITEALL_DONE_EVENT,
  C_READ_DONE_EVENT,
  WEBDAV_MKCOL_DONE_EVENT,
  RUN_PROPFIND_DONE_EVENT,
  WEBDAV_REMOVE_DONE_EVENT,
  WEBDAV_DELETE_DONE_EVENT,
  WEBDAV_MOVE_DONE_EVENT,
  WEBDAV_COPY_DONE_EVENT,
  WEBDAV_TOUCH_DONE_EVENT,
  HTTP_SERVER_STOP_DONE_EVENT,
  SEND_MESSAGE_DONE_EVENT,
  RECEIVE_REPLY_MESSAGE_DONE_EVENT,
  ASYNC_FUSE_FS_OPEN_DONE_EVENT,
  ASYNC_FUSE_FS_FGETATTR_DONE_EVENT,
  ASYNC_FUSE_FS_READ_DONE_EVENT,
  ASYNC_FUSE_FS_WRITE_DONE_EVENT,
  ASYNC_FUSE_FS_OPENDIR_DONE_EVENT,
  WEBDAV_GET_REQUEST_SIZE_HINT_DONE_EVENT,
  WEBDAV_GET_REQUEST_WRITE_DONE_EVENT,
  WEBDAV_GET_REQUEST_WRITE_EVENT,
  WEBDAV_GET_REQUEST_END_EVENT,
  WEBDAV_PUT_REQUEST_READ_EVENT,
  WEBDAV_PUT_REQUEST_READ_DONE_EVENT,
  WEBDAV_PUT_REQUEST_END_EVENT,
  WEBDAV_PROPFIND_DONE_EVENT,
  ASYNC_RDWR_DESTROY_DONE_EVENT,
  ASYNC_RDWR_WRITE_LOCK_DONE_EVENT,
  ASYNC_RDWR_READ_LOCK_DONE_EVENT,
} event_type_t;

#define EVENT_HANDLER_DEFINE(handler, a, b, c) void handler(event_type_t a, void *b, void *c)
#define EVENT_HANDLER_DECLARE(handler) EVENT_HANDLER_DEFINE(handler, a, b, c)

typedef EVENT_HANDLER_DECLARE((*event_handler_t));

#endif /* EVENTS_H */
