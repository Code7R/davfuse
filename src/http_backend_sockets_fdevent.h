/*
  davfuse: FUSE file systems as WebDAV servers
  Copyright (C) 2012, 2013 Rian Hunter <rian@alum.mit.edu>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lessage General Public License as published by
  the Free Software Foundation, either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#ifndef _HTTP_BACKEND_FDEVENT_H
#define _HTTP_BACKEND_FDEVENT_H

#include "coroutine_io.h"
#include "http_backend_sockets_fdevent_fdevent.h"
#include "http_backend_sockets_fdevent_sockets.h"
#include "iface_util.h"

#ifdef __cplusplus
extern "C" {
#endif

struct _http_backend;

typedef struct _http_backend *http_backend_sockets_fdevent_t;
typedef fd_t http_backend_sockets_fdevent_handle_t;
typedef io_error_t http_backend_sockets_fdevent_error_t;

typedef struct {
  http_backend_sockets_fdevent_error_t error;
  http_backend_sockets_fdevent_handle_t handle;
} HttpBackendSocketsFdeventAcceptDoneEvent;

typedef ReadFnDoneEvent HttpBackendSocketsFdeventReadDoneEvent;
typedef WriteFnDoneEvent HttpBackendSocketsFdeventWriteDoneEvent;

enum {
  HTTP_BACKEND_SOCKETS_FDEVENT_ERROR_NONE=IO_ERROR_NONE,
  HTTP_BACKEND_SOCKETS_FDEVENT_ERROR_UNKNOWN=IO_ERROR_GENERAL,
};

http_backend_sockets_fdevent_t
http_backend_sockets_fdevent_new(fdevent_loop_t loop,
                                 const struct sockaddr *addr, socklen_t addr_len);

void
http_backend_sockets_fdevent_destroy(http_backend_sockets_fdevent_t backend);


void
http_backend_sockets_fdevent_accept(http_backend_sockets_fdevent_t backend,
                                    event_handler_t cb,
                                    void *ud);

void
http_backend_sockets_fdevent_stop_accept(http_backend_sockets_fdevent_t backend);

void
http_backend_sockets_fdevent_read(http_backend_sockets_fdevent_t backend,
                                  http_backend_sockets_fdevent_handle_t handle,
                                  void *buf, size_t nbyte,
                                  event_handler_t cb,
                                  void *ud);

void
http_backend_sockets_fdevent_write(http_backend_sockets_fdevent_t backend,
                                   http_backend_sockets_fdevent_handle_t handle,
                                   const void *buf, size_t nbyte,
                                   event_handler_t cb,
                                   void *ud);

bool
http_backend_sockets_fdevent_close(http_backend_sockets_fdevent_t backend,
                                   http_backend_sockets_fdevent_handle_t handle);

CREATE_IMPL_TAG(HTTP_BACKEND_SOCKETS_FDEVENT_IMPL);

#ifdef __cplusplus
}
#endif

#endif
