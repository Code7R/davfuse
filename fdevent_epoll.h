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
