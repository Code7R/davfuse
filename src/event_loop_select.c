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

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

#include "c_util.h"
#include "events.h"
#include "logging.h"
#include "sockets.h"
#include "util_sockets.h"

#include "event_loop_select.h"

/* workaround undefined behavior bug in darwin...
   https://groups.google.com/forum/#!topic/darwin-dev/xNf5wDSqhLk
 */
#ifdef __DARWIN_FD_ISSET
static int
__my_darwin_fd_isset(int _n, const struct fd_set *_p) {
  return (_p->fds_bits[(unsigned long)_n/__DARWIN_NFDBITS] &
          ((int32_t)(((unsigned long)1)<<((unsigned long)_n % __DARWIN_NFDBITS))));
}

#define MY_FD_ISSET(n, p) __my_darwin_fd_isset(n, p)
#define MY_FD_SET(n, p) do { int __fd = (n); ((p)->fds_bits[__fd/__DARWIN_NFDBITS] |= ((unsigned long)1<<(__fd % __DARWIN_NFDBITS))); } while(0)
#else
#define MY_FD_ISSET(n, p) FD_ISSET(n, p)
#define MY_FD_SET(n, p) FD_SET(n, p)
#endif

enum {
  /* set to false to cause program to spin
     instead of waiting on select */
  ACTUALLY_WAIT_ON_SELECT=true,
};

/* opaque structures */
typedef struct {
  bool is_fd_watch;
  socket_t sock;
  void *ud;
  StreamEvents events;
  event_handler_t handler;
} EventLoopSelectWatcher;

typedef struct _event_loop_select_link {
  EventLoopSelectWatcher ew;
  struct _event_loop_select_link *prev;
  struct _event_loop_select_link *next;
  bool active;
} EventLoopSelectLink;

typedef struct _event_loop_select_handle {
  EventLoopSelectLink *ll;
} EventLoopSelectLoop;

event_loop_select_handle_t
event_loop_select_default_new(void) {
  EventLoopSelectLoop *loop = malloc(sizeof(*loop));
  if (!loop) {
    return NULL;
  }

  loop->ll = NULL;
  return loop;
}

bool
event_loop_select_destroy(event_loop_select_handle_t a) {
  assert(!a->ll);
  free(a);
  return true;
}

static
bool
_event_loop_select_watch_add(event_loop_select_handle_t loop,
                             bool is_fd_watch,
                             socket_t sock,
                             StreamEvents events,
                             event_handler_t handler,
                             void *ud,
                             event_loop_select_watch_key_t *key) {
  EventLoopSelectLink *ew;

  assert(loop);
  assert(handler);

  ew = malloc(sizeof(*ew));
  if (!ew) {
    *key = 0;
    return false;
  }

  *ew = (EventLoopSelectLink) {
    .ew = {
      .is_fd_watch = is_fd_watch,
      .sock = sock,
      .ud = ud,
      .events = events,
      .handler = handler
    },
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

bool
event_loop_select_socket_watch_add(event_loop_select_handle_t loop,
                                   socket_t sock,
                                   StreamEvents events,
                                   event_handler_t handler,
                                   void *ud,
                                   event_loop_select_watch_key_t *key) {
  return _event_loop_select_watch_add(loop, false, sock, events, handler, ud, key);
}

bool
event_loop_select_fd_watch_add(event_loop_select_handle_t loop,
                               int fd,
                               StreamEvents events,
                               event_handler_t handler,
                               void *ud,
                               event_loop_select_watch_key_t *key) {
  socket_t socket = socket_from_fd(fd);
  if (socket == INVALID_SOCKET) return false;
  return _event_loop_select_watch_add(loop, true, socket, events, handler,
                                      ud, key);
}

NON_NULL_ARGS0() bool
event_loop_select_watch_remove(event_loop_select_handle_t loop,
                               event_loop_select_watch_key_t key) {
  UNUSED(loop);

  /* event_loop_select_watch_key_t types are actually pointers to EventLoopSelectLink types */
  EventLoopSelectLink *ll = key;

  assert(loop);
  assert(loop->ll);
  assert(key);

  ll->active = false;

  return true;
}

static void
_actually_free_link(EventLoopSelectLoop *loop, EventLoopSelectLink *ll) {
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
event_loop_select_main_loop(event_loop_select_handle_t loop) {
  log_info("fdevent select main loop started");

  while (true) {
    fd_set readfds, writefds, errorfds;
    int nfds = -1;
    unsigned readfds_watched = 0;
    unsigned writefds_watched = 0;
    EventLoopSelectLink *ll = loop->ll;

    log_debug("Looping...");

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&errorfds);

    while (ll) {
      if (!ll->active) {
        EventLoopSelectLink *tmpll = ll->next;
        _actually_free_link(loop, ll);
        ll = tmpll;
        continue;
      }

      if (ll->ew.events.read && !MY_FD_ISSET(ll->ew.sock, &readfds)) {
        log_debug("Adding fd %d to read set", ll->ew.sock);
        MY_FD_SET(ll->ew.sock, &readfds);
        MY_FD_SET(ll->ew.sock, &errorfds);
        readfds_watched += 1;
      }

      if (ll->ew.events.write && !MY_FD_ISSET(ll->ew.sock, &writefds)) {
        log_debug("Adding fd %d to write set", ll->ew.sock);
        MY_FD_SET(ll->ew.sock, &writefds);
        MY_FD_SET(ll->ew.sock, &errorfds);
        writefds_watched += 1;
      }

      if ((int) ll->ew.sock > nfds) {
        nfds = ll->ew.sock;
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
    bool select_error = false;
    if (ACTUALLY_WAIT_ON_SELECT) {
      while (true) {
        int ret_select =
          select(nfds + 1, &readfds, &writefds, &errorfds, NULL);

        if (ret_select == SOCKET_ERROR &&
            last_socket_error() == SOCKET_EINTR) {
          log_info("select() interrupted!");
          continue;
        }

        if (ret_select == SOCKET_ERROR) {
          log_error("Error while doing select(): %s",
                    last_socket_error_message());
          select_error = true;
        }

        break;
      }
    }
    log_debug("after select");

    /* now dispatch on events */
    for (ll = loop->ll; ll; ll = ll->next) {
      if (ll->active) {
        const bool sock_error = (select_error ||
                                 MY_FD_ISSET(ll->ew.sock, &errorfds));
        const StreamEvents events = sock_error
          ? create_stream_events(false, false)
          : create_stream_events(MY_FD_ISSET(ll->ew.sock, &readfds),
                                 MY_FD_ISSET(ll->ew.sock, &writefds));

        if (sock_error ||
            (events.read && ll->ew.events.read) ||
            (events.write && ll->ew.events.write)) {
          /* NB: this just marks removal, doesn't actually free */
          event_loop_select_watch_remove(loop, ll);

          if (ll->ew.is_fd_watch) {
            EventLoopSelectFdEvent e = {
              .loop = loop,
              .fd = fd_from_socket(ll->ew.sock),
              .events = events,
              .error = sock_error,
            };
            assert(e.fd >= 0);
            ll->ew.handler(EVENT_LOOP_FD_EVENT, &e, ll->ew.ud);
          }
          else {
            EventLoopSelectSocketEvent e = {
              .loop = loop,
              .socket = ll->ew.sock,
              .events = events,
              .error = sock_error,
            };
            ll->ew.handler(EVENT_LOOP_SOCKET_EVENT, &e, ll->ew.ud);
          }
        }
      }
    }
  }
}
