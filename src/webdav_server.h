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

#ifndef WEBDAV_SERVER_H
#define WEBDAV_SERVER_H

#include "events.h"
#include "http_server_http_backend.h"
#include "util.h"
#include "webdav_server_webdav_backend.h"

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

/* backend method helper done events */
typedef _WebdavGenericDoneEvent WebdavGetRequestSizeHintDoneEvent;
typedef _WebdavGenericDoneEvent WebdavGetRequestWriteDoneEvent;

typedef struct {
  webdav_error_t error;
  size_t nbyte;
} WebdavPutRequestReadDoneEvent;

webdav_server_t
webdav_server_start(http_backend_t http_backend,
                    const char *public_uri_root,
                    const char *internal_root,
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
