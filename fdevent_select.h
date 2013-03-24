#ifndef FDEVENT_SELECT_H
#define FDEVENT_SELECT_H

#include <stdbool.h>

#include "c_util.h"
#include "events.h"

/* event subsystem */

/* forward decl */
struct _fd_event_loop;

#define FDEVENT_LOOP struct _fd_event_loop
#include "_fdevent_common.h"
#undef FDEVENT_LOOP

typedef struct {
  int fd;
  void *ud;
  StreamEvents events;
  event_handler_t handler;
} FDEventWatcher;

typedef struct _fdevent_link {
  FDEventWatcher ew;
  struct _fdevent_link *prev;
  struct _fdevent_link *next;
} FDEventLink;

typedef FDEventLink *fd_event_watch_key_t;
#define FD_EVENT_INVALID_WATCH_KEY NULL

typedef struct _fd_event_loop {
  FDEventLink *ll;
} FDEventLoop;

bool
fdevent_init(FDEventLoop *loop);

bool
fdevent_add_watch(FDEventLoop *loop,
                  int fd,
                  StreamEvents events,
                  event_handler_t handler,
                  void *ud,
                  fd_event_watch_key_t *key);

bool
fdevent_remove_watch(FDEventLoop *wt,
                     fd_event_watch_key_t key);

bool
fdevent_main_loop(FDEventLoop *loop);

#endif
