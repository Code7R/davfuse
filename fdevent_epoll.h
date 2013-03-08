#ifndef FDEVENT_EPOLL_H
#define FDEVENT_EPOLL_H

#include <stdbool.h>

/* event subsystem */

typedef struct {
  bool read : 1;
  bool write : 1;
} StreamEvents;

/* Make this is a macro if too slow */
static StreamEvents
create_stream_events(bool read, bool write) {
  return (StreamEvents) {.read = read, .write = write}
}

typedef void (*StreamEventHandler)(int, StreamEvents, void *);

typedef struct _fd_event_watcher {
  int fd;
  void *ud;
  StreamEvents events;
  StreamEventHandler handler;
  struct _fd_event_watcher *next;
} FDEventWatcher;

typedef struct _fdwaiter_link {
  FDEventWatcher *watchers;
  struct _fdwaiter_link *prev;
  struct _fdwaiter_link *next;
} FDEventWatcherList;

/* event watcher/dispatcher bookkeeping */
typedef struct {
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
                  StreamEventHandler handler,
                  void *ud,
                  FDEventWatchKey *key);

bool
fdevent_modify_watch(FDEventLoop *loop,
                     FDEventWatchKey key,
                     StreamEvents new_events,
                     StreamEventHandler handler,
                     void *ud);

bool
fdevent_remove_watch(FDEventLoop *wt,
                     FDEventWatchKey key);

bool
fdevent_main_loop(FDEventLoop *loop);
#endif
