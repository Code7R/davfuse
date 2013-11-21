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

#ifndef _UTIL_EVENT_LOOP_H
#define _UTIL_EVENT_LOOP_H

#include "coroutine_io.h"
#include "event_loop.h"
#include "sockets.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef ReadFnDoneEvent UtilEventLoopSocketReadDoneEvent;
typedef WriteFnDoneEvent UtilEventLoopSocketWriteDoneEvent;

void
util_event_loop_socket_read(event_loop_handle_t loop,
                            socket_t sock,
                            void *buf, size_t nbyte,
                            const EventLoopTimeout *timeout,
                            event_handler_t cb,
                            void *cb_ud);

void
util_event_loop_socket_write(event_loop_handle_t loop,
                             socket_t sock,
                             const void *buf, size_t nbyte,
                             event_handler_t cb,
                             void *cb_ud);

#ifdef __cplusplus
}
#endif

#endif
