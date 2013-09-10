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

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

#include "c_util.h"
#include "events.h"
#include "fdevent_select_sockets.h"
#include "logging.h"
#include "util_sockets.h"

#include "fdevent_select.h"

enum {
  /* set to false to cause program to spin
     instead of waiting on select */
  ACTUALLY_WAIT_ON_SELECT=true,
};

/* opaque structures */
typedef struct {
  fd_t fd;
  void *ud;
  StreamEvents events;
  event_handler_t handler;
} FDEventWatcher;

typedef struct _fdevent_link {
  FDEventWatcher ew;
  struct _fdevent_link *prev;
  struct _fdevent_link *next;
  bool active;
} FDEventLink;

typedef struct _fd_event_loop {
  FDEventLink *ll;
} FDEventLoop;

NON_NULL_ARGS0() fdevent_select_loop_t
fdevent_select_default_new(void) {
  FDEventLoop *loop = malloc(sizeof(*loop));
  if (!loop) {
    return NULL;
  }

  loop->ll = NULL;
  return loop;
}

bool
fdevent_select_destroy(fdevent_select_loop_t a) {
  assert(!a->ll);
  free(a);
  return true;
}

NON_NULL_ARGS2(1, 4) bool
fdevent_select_add_watch(fdevent_select_loop_t loop,
                         fd_t fd,
                         StreamEvents events,
                         event_handler_t handler,
                         void *ud,
                         fdevent_select_watch_key_t *key) {
  FDEventLink *ew;

  assert(loop);
  assert(handler);

  ew = malloc(sizeof(*ew));
  if (!ew) {
    *key = FDEVENT_SELECT_INVALID_WATCH_KEY;
    return false;
  }

  *ew = (FDEventLink) {
    .ew = {fd, ud, events, handler},
    .prev = NULL,
    .next = NULL,
    .active = true,
  };

  if (loop->ll) {
    ew->next = loop->ll;
    loop->ll->prev = ew;
    loop->ll = ew;
  }
  else {
    loop->ll = ew;
  }

  if (key) {
    *key = ew;
  }

  return true;
}

NON_NULL_ARGS0() bool
fdevent_select_remove_watch(fdevent_select_loop_t loop,
                            fdevent_select_watch_key_t key) {
  UNUSED(loop);

  /* fdevent_select_watch_key_t types are actually pointers to FDEventLink types */
  FDEventLink *ll = key;

  assert(loop);
  assert(loop->ll);
  assert(key);

  ll->active = false;

  return true;
}

static void
_actually_free_link(FDEventLoop *loop, FDEventLink *ll) {
  if (ll->prev) {
    ll->prev->next = ll->next;
  }

  if (ll->next) {
    ll->next->prev = ll->prev;
  }

  if (ll == loop->ll) {
    assert(!ll->prev);
    loop->ll = ll->next;
  }

  free(ll);
}

bool
fdevent_select_main_loop(fdevent_select_loop_t loop) {
  log_info("fdevent select main loop started");

  while (true) {
    fd_set readfds, writefds;
    int nfds = -1;
    unsigned readfds_watched = 0;
    unsigned writefds_watched = 0;
    FDEventLink *ll = loop->ll;

    log_debug("Looping...");

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    while (ll) {
      if (!ll->active) {
        FDEventLink *tmpll = ll->next;
        _actually_free_link(loop, ll);
        ll = tmpll;
        continue;
      }

      if (ll->ew.events.read && !FD_ISSET(ll->ew.fd, &readfds)) {
        log_debug("Adding fd %d to read set", ll->ew.fd);
	FD_SET(ll->ew.fd, &readfds);
        readfds_watched += 1;
      }

      if (ll->ew.events.write && !FD_ISSET(ll->ew.fd, &writefds)) {
        log_debug("Adding fd %d to write set", ll->ew.fd);
	FD_SET(ll->ew.fd, &writefds);
        writefds_watched += 1;
      }

      if ((int) ll->ew.fd > nfds) {
	nfds = ll->ew.fd;
      }

      ll = ll->next;
    }

    if (writefds_watched >= FD_SETSIZE) {
      log_critical("Too many write fds being watched: %d vs MAX %d",
                   writefds_watched, FD_SETSIZE);
      abort();
    }

    if (readfds_watched >= FD_SETSIZE) {
      log_critical("Too many read fds being watched: %d vs MAX %d",
                   readfds_watched, FD_SETSIZE);
      abort();
    }

    /* if there is nothing to select for, then stop the main loop */
    if (!readfds_watched && !writefds_watched) {
      return true;
    }

    log_debug("before select");
    if (ACTUALLY_WAIT_ON_SELECT) {
      fd_set *readfds_ptr = readfds_watched
        ? &readfds
        : NULL;
      fd_set *writefds_ptr = writefds_watched
        ? &writefds
        : NULL;
      while (true) {
        int ret_select =
          select(nfds + 1, readfds_ptr, writefds_ptr, NULL, NULL);
        if (ret_select != SOCKET_ERROR) {
          break;
        }

        if (last_socket_error() != SOCKET_EINTR) {
          log_error("Error while doing select(): %s",
                    last_socket_error_message());
          return false;
        }

        log_info("select() interrupted!");
      }
    }
    log_debug("after select");

    /* now dispatch on events */
    ll = loop->ll;
    while (ll) {
      StreamEvents events;

      if (ll->active) {
        events = create_stream_events(FD_ISSET(ll->ew.fd, &readfds),
                                      FD_ISSET(ll->ew.fd, &writefds));
        if ((events.read && ll->ew.events.read) ||
            (events.write && ll->ew.events.write)) {
          event_handler_t h = ll->ew.handler;
          fd_t fd = ll->ew.fd;
          void *ud = ll->ew.ud;
          FdeventSelectEvent e = (FdeventSelectEvent) {
            .loop = loop,
            .fd = fd,
            .events = events,
          };
          fdevent_select_remove_watch(loop, ll);
          h(FD_EVENT, &e, ud);
        }
      }

      ll = ll->next;
    }
  }
}
