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

#ifndef FDEVENT_EPOLL_H
#define FDEVENT_EPOLL_H

#include <stdbool.h>
#include <stdint.h>

#include "events.h"

/* event subsystem */

/* forward decl */
struct _fdwaiter_link;
struct _fd_event_loop;

#define FDEVENT_LOOP struct _fd_event_loop
#include "_fdevent_common.h"
#undef FDEVENT_LOOP

#define WATCHER_LIST_MAGIC 0x86820485
#define WATCHER_MAGIC 0x78122876

typedef struct _fd_event_watcher {
  uint32_t magic;
  StreamEvents events;
  StreamEventHandler handler;
  void *ud;
  struct _fdwaiter_link *wll;
  struct _fd_event_watcher *next;
} FDEventWatcher;

typedef struct _fdwaiter_link {
  uint32_t magic;
  int fd;
  uint32_t epoll_events;
  FDEventWatcher *watchers;
  struct _fdwaiter_link *prev;
  struct _fdwaiter_link *next;
} FDEventWatcherList;

/* event watcher/dispatcher bookkeeping */
typedef struct _fd_event_loop {
  int epollfd;
  int fd_to_watcher_size;
  /* this is a hash table */
  FDEventWatcherList **fd_to_watchers;
} FDEventLoop;

typedef FDEventWatcher *FDEventWatchKey;

bool
fdevent_init(FDEventLoop *loop);

bool
fdevent_add_watch(FDEventLoop *loop,
                  int fd,
                  StreamEvents events,
                  event_handler_t handler,
                  void *ud,
                  FDEventWatchKey *key);

bool
fdevent_remove_watch(FDEventLoop *loop,
                     FDEventWatchKey key);

bool
fdevent_main_loop(FDEventLoop *loop);
#endif
