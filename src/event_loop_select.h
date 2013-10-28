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

#ifndef _EVENT_LOOP_SELECT_H
#define _EVENT_LOOP_SELECT_H

#include <stdbool.h>

#include "c_util.h"
#include "events.h"
#include "iface_util.h"
#include "sockets.h"

#ifdef __cplusplus
extern "C" {
#endif

/* event subsystem */

/* forward decl */
struct _event_loop_select_handle;
struct _event_loop_select_link;

typedef struct _event_loop_select_handle *event_loop_select_handle_t;
typedef struct _event_loop_select_link *event_loop_select_watch_key_t;

#define _INCLUDE_EVENT_LOOP_COMMON_H
#include "_event_loop_common.h"
#undef _INCLUDE_EVENT_LOOP_COMMON_H

typedef struct {
  event_loop_select_handle_t loop;
  socket_t socket;
  StreamEvents events;
} EventLoopSelectSocketEvent;

event_loop_select_handle_t
event_loop_select_default_new();

bool
event_loop_select_socket_watch_add(event_loop_select_handle_t loop,
                                   socket_t fd,
                                   StreamEvents events,
                                   event_handler_t handler,
                                   void *ud,
                                   event_loop_select_watch_key_t *key);

bool
event_loop_select_fd_watch_add(event_loop_select_handle_t loop,
                               int fd,
                               StreamEvents events,
                               event_handler_t handler,
                               void *ud,
                               event_loop_select_watch_key_t *key);

bool
event_loop_select_watch_remove(event_loop_select_handle_t wt,
                               event_loop_select_watch_key_t key);

bool
event_loop_select_main_loop(event_loop_select_handle_t loop);

bool
event_loop_select_destroy(event_loop_select_handle_t loop);

CREATE_IMPL_TAG(EVENT_LOOP_SELECT_IMPL);

#ifdef __cplusplus
}
#endif

#endif
