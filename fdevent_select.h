#ifndef FDEVENT_SELECT_H
#define FDEVENT_SELECT_H

#include <stdbool.h>

/* event subsystem */

typedef struct {
  bool read : 1;
  bool write : 1;
} StreamEvents;

typedef void (*StreamEventHandler)(int, StreamEvents, void *);

typedef struct {
  int fd;
  void *ud;
  StreamEvents events;
  StreamEventHandler handler;
} FDEventWatcher;

typedef struct _fdevent_link {
  FDEventWatcher ew;
  struct _fdevent_link *prev;
  struct _fdevent_link *next;
} FDEventLink;

typedef FDEventLink *FDEventWatchKey;

/* event watcher/dispatcher bookkeeping */
typedef struct {
  FDEventLink *ll;
} FDEventLoop;

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
fdevent_remove_watch(FDEventLoop *wt,
                     FDEventWatchKey key);

bool
fdevent_main_loop(FDEventLoop *loop);

#endif
