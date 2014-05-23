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
#include "uptime.h"
#include "util.h"
#include "util_sockets.h"

#include "event_loop_select.h"

/* workaround undefined behavior bug in darwin...
   https://groups.google.com/forum/#!topic/darwin-dev/xNf5wDSqhLk
 */
#ifdef __DARWIN_FD_ISSET
static int
__my_darwin_fd_isset(int _n, const struct fd_set *_p) {
  assert(_n >= 0);
  return (_p->fds_bits[_n/__DARWIN_NFDBITS] &
          (1U<<(_n % __DARWIN_NFDBITS)));
}

#define MY_FD_ISSET(n, p) __my_darwin_fd_isset(n, p)
#define MY_FD_SET(n, p) do { assert((n) >= 0); int __fd = (n); ((p)->fds_bits[__fd/__DARWIN_NFDBITS] |= (1U<<(__fd % __DARWIN_NFDBITS))); } while(0)
#else
#define MY_FD_ISSET(n, p) FD_ISSET(n, p)
#define MY_FD_SET(n, p) FD_SET(n, p)
#endif

/* opaque structures */
typedef struct {
  bool is_fd_watch;
  socket_t sock;
  StreamEvents events;
  event_handler_t handler;
  void *ud;
} EventLoopSelectWatcher;

typedef struct {
  uint64_t end_clock;
  event_handler_t handler;
  void *ud;
} EventLoopSelectTimeoutCtx;

#define DEFINE_LL(_name, inner_type, inner_name)        \
  struct _name {                                        \
    inner_type inner_name;                              \
    struct _name *prev;                                 \
    struct _name *next;                                 \
    bool is_active;                                     \
  }

DEFINE_LL(_event_loop_select_watch_link,
          EventLoopSelectWatcher, watch);
DEFINE_LL(_event_loop_select_timeout_link,
          EventLoopSelectTimeoutCtx, timeout);

typedef struct _event_loop_select_watch_link EventLoopSelectLink;
typedef struct _event_loop_select_timeout_link EventLoopSelectTimeoutLink;

typedef struct _event_loop_select_handle {
  EventLoopSelectLink *ll;
  EventLoopSelectTimeoutLink *timeout_ll;
} EventLoopSelectLoop;

#define DEFINE_ADD_LL_FN(name, LINK_TYPE, INNER_TYPE, INNER_NAME)  \
  bool                                                  \
  name(const INNER_TYPE *data, LINK_TYPE **root_ptr, LINK_TYPE **key) { \
    LINK_TYPE *timeout_ll;                              \
    timeout_ll = malloc(sizeof(*timeout_ll));           \
    if (!timeout_ll) return false;                      \
                                                        \
    *timeout_ll = (LINK_TYPE) {                         \
      .INNER_NAME = *data,                              \
      .prev = NULL,                                     \
      .next = NULL,                                     \
      .is_active = true,                                \
    };                                                  \
                                                        \
    if (*root_ptr) {                                                    \
      (*root_ptr)->prev = timeout_ll;                                   \
      timeout_ll->next = *root_ptr;                                     \
    }                                                                   \
                                                                        \
    *root_ptr = timeout_ll;                                             \
                                                                        \
    if (key) *key = timeout_ll;                                         \
                                                                        \
    return true;                                                        \
  }

static
DEFINE_ADD_LL_FN(_add_watch_link, EventLoopSelectLink,
                 EventLoopSelectWatcher, watch);

static
DEFINE_ADD_LL_FN(_add_timeout_link, EventLoopSelectTimeoutLink,
                 EventLoopSelectTimeoutCtx, timeout);

#define FREE_LINK(root_ptr, link_ptr) \
  do {                                \
    if ((link_ptr)->prev) {           \
      ll->prev->next = ll->next;      \
    }                                 \
                                      \
    if ((link_ptr)->next) {           \
      ll->next->prev = ll->prev;      \
    }                                 \
                                      \
    if ((link_ptr) == *(root_ptr)) {          \
      assert(!(link_ptr)->prev);              \
      *(root_ptr) = (link_ptr)->next;         \
    }                                 \
                                      \
    free(link_ptr);                   \
  }                                   \
  while (false)

static
bool
timeout_is_triggered(EventLoopSelectTimeoutCtx *timeout_ctx,
                     uint64_t curclock) {
  return timeout_ctx->end_clock <= curclock;
}

static
bool
uptime_in_seconds(uint64_t *out) {
  UptimeTimespec uptime;
  bool success_time = uptime_time(&uptime);
  if (!success_time) return false;
  *out = uptime.seconds;
  return true;
}

event_loop_select_handle_t
event_loop_select_default_new(void) {
  return calloc(1, sizeof(EventLoopSelectLoop));
}

bool
event_loop_select_destroy(event_loop_select_handle_t a) {
  assert(!a->ll);
  free(a);
  return true;
}

static
void
_count_watched(event_loop_select_handle_t loop,
	       size_t *new_reads_watched,
	       size_t *new_writes_watched,
	       socket_t sock, StreamEvents events) {
  assert(loop && new_reads_watched && new_writes_watched);

  fd_set readfds, writefds;

  FD_ZERO(&readfds);
  FD_ZERO(&writefds);

  for (EventLoopSelectLink *ll = loop->ll; ll; ll = ll->next) {
    if (!ll->is_active) continue;

    if (ll->watch.events.read &&
	!MY_FD_ISSET(ll->watch.sock, &readfds)) {
      *new_reads_watched += 1;
      MY_FD_SET(ll->watch.sock, &readfds);
    }

    if (ll->watch.events.write &&
	!MY_FD_ISSET(ll->watch.sock, &writefds)) {
      *new_writes_watched += 1;
      MY_FD_SET(ll->watch.sock, &writefds);
    }
  }

  if (events.read && !MY_FD_ISSET(sock, &readfds)) {
    *new_reads_watched += 1;
  }

  if (events.write && !MY_FD_ISSET(sock, &writefds)) {
    *new_writes_watched += 1;
  }
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
  assert(loop);
  assert(handler);

  size_t new_reads_watched = 0, new_writes_watched = 0;
  _count_watched(loop, &new_reads_watched, &new_writes_watched,
		 sock, events);

  if (new_reads_watched >= FD_SETSIZE ||
      new_writes_watched >= FD_SETSIZE) {
    return false;
  }

  EventLoopSelectWatcher watch = {
    .is_fd_watch = is_fd_watch,
    .sock = sock,
    .ud = ud,
    .events = events,
    .handler = handler
  };

  return _add_watch_link(&watch, &loop->ll, key);
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

bool
event_loop_select_watch_remove(event_loop_select_handle_t loop,
                               event_loop_select_watch_key_t key) {
  UNUSED(loop);
  assert(loop);
  assert(loop->ll);
  assert(key);
  assert(key->is_active);
  /* TODO: assert that this watch is apart of this loop */
  key->is_active = false;
  return true;
}

bool
event_loop_select_timeout_add(event_loop_select_handle_t loop,
                              const EventLoopSelectTimeout *timeout,
                              event_handler_t handler,
                              void *ud,
                              event_loop_select_timeout_key_t *key) {
  assert(loop);
  assert(timeout);
  assert(handler);

  uint64_t cur_clock;
  bool success_uptime = uptime_in_seconds(&cur_clock);
  if (!success_uptime) return false;

  EventLoopSelectTimeoutCtx timeout_ctx = {
    .end_clock = timeout->sec + cur_clock,
    .handler = handler,
    .ud = ud,
  };

  return _add_timeout_link(&timeout_ctx, &loop->timeout_ll, key);
}

bool
event_loop_select_timeout_remove(event_loop_select_handle_t loop,
                                 event_loop_select_timeout_key_t key) {
  UNUSED(loop);
  assert(loop->ll);
  assert(key);
  assert(key->is_active);
  /* TODO: assert that this timeout is apart of this loop */
  key->is_active = false;
  return true;
}

bool
event_loop_select_main_loop(event_loop_select_handle_t loop) {
  log_info("fdevent select main loop started");

  while (true) {
    //    log_debug("Looping...");

    /* first clear out inactive timeouts and
       find select wait time
     */
    bool select_stop_clock_is_enabled = false;
    uint64_t select_stop_clock = UINT64_MAX;
    for (EventLoopSelectTimeoutLink *ll = loop->timeout_ll; ll;) {
      if (ll->is_active) {
        select_stop_clock = MIN(ll->timeout.end_clock, select_stop_clock);
        if (!select_stop_clock_is_enabled) select_stop_clock_is_enabled = true;
        ll = ll->next;
      }
      else {
        EventLoopSelectTimeoutLink *tmpll = ll->next;
        FREE_LINK(&loop->timeout_ll, ll);
        ll = tmpll;
      }
    }

    fd_set readfds, writefds, errorfds;
    int nfds = -1;
    unsigned readfds_watched = 0;
    unsigned writefds_watched = 0;

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&errorfds);

    for (EventLoopSelectLink *ll = loop->ll; ll;) {
      if (!ll->is_active) {
        EventLoopSelectLink *tmpll = ll->next;
        FREE_LINK(&loop->ll, ll);
        ll = tmpll;
        continue;
      }

      if (ll->watch.events.read && !MY_FD_ISSET(ll->watch.sock, &readfds)) {
        //        log_debug("Adding fd %d to read set", (int) ll->watch.sock);
        MY_FD_SET(ll->watch.sock, &readfds);
        MY_FD_SET(ll->watch.sock, &errorfds);
        readfds_watched += 1;
      }

      if (ll->watch.events.write && !MY_FD_ISSET(ll->watch.sock, &writefds)) {
        //        log_debug("Adding fd %d to write set", (int) ll->watch.sock);
        MY_FD_SET(ll->watch.sock, &writefds);
        MY_FD_SET(ll->watch.sock, &errorfds);
        writefds_watched += 1;
      }

      if ((int) ll->watch.sock > nfds) {
        nfds = ll->watch.sock;
      }

      ll = ll->next;
    }

    /* if there is nothing to select for, then stop the main loop */
    if (!readfds_watched && !writefds_watched && !select_stop_clock_is_enabled) {
      return true;
    }

    //    log_debug("before select");
    bool select_error = false;
    while (true) {
      struct timeval *select_timeout_p;
      struct timeval select_timeout;
      if (select_stop_clock_is_enabled) {
        uint64_t curclock;
        bool success_uptime = uptime_in_seconds(&curclock);
        if (!success_uptime) {
          log_error("uptime_in_seconds() failed, just polling...");
          select_timeout = (struct timeval) {0, 0};
        }
        else {
          select_timeout = (struct timeval) {
            (select_stop_clock > curclock
             ? select_stop_clock - curclock
             : 0),
            0,
          };
        }
        //        log_debug("Select will wait for %lu seconds",
        //                  (long unsigned) select_timeout.tv_sec);
        select_timeout_p = &select_timeout;
      }
      else select_timeout_p = NULL;

      /* NB: Winsock requires these pointers to be NULL
         if no FD has been set */
      fd_set *const readfds_p = readfds_watched
        ? &readfds
        : NULL;
      fd_set *const writefds_p = writefds_watched
        ? &writefds
        : NULL;
      fd_set *const errorfds_p = writefds_watched || readfds_watched
        ? &errorfds
        : NULL;

      int ret_select =
        select(nfds + 1, readfds_p, writefds_p, errorfds_p, select_timeout_p);

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
    //    log_debug("after select");

    /* dispatch io events */
    for (EventLoopSelectLink *ll = loop->ll; ll; ll = ll->next) {
      if (!ll->is_active) continue;

      const bool sock_error = (select_error ||
                               MY_FD_ISSET(ll->watch.sock, &errorfds));
      const StreamEvents events = sock_error
        ? create_stream_events(false, false)
        : create_stream_events(MY_FD_ISSET(ll->watch.sock, &readfds),
                               MY_FD_ISSET(ll->watch.sock, &writefds));

      /* if the io event was not triggered, continue */
      if (!sock_error &&
          !(events.read && ll->watch.events.read) &&
          !(events.write && ll->watch.events.write)) continue;

      /* before triggering the handler, mark it inactive
         (all watches are one-shot) */
      ll->is_active = false;

      if (ll->watch.is_fd_watch) {
        EventLoopSelectFdEvent e = {
          .loop = loop,
          .fd = fd_from_socket(ll->watch.sock),
          .events = events,
          .error = sock_error,
        };
        assert(e.fd >= 0);
        ll->watch.handler(EVENT_LOOP_FD_EVENT, &e, ll->watch.ud);
      }
      else {
        EventLoopSelectSocketEvent e = {
          .loop = loop,
          .socket = ll->watch.sock,
          .events = events,
          .error = sock_error,
        };
        ll->watch.handler(EVENT_LOOP_SOCKET_EVENT, &e, ll->watch.ud);
      }
    }

    /* trigger timeouts that have activated,
       we intentionally do this after socket dispatch
     */
    uint64_t curclock;
    bool success_uptime = uptime_in_seconds(&curclock);
    /* TODO: handle this error */
    ASSERT_TRUE(success_uptime);
    for (EventLoopSelectTimeoutLink *ll = loop->timeout_ll; ll; ll = ll->next) {
      if (!ll->is_active) continue;
      if (!timeout_is_triggered(&ll->timeout, curclock)) continue;

      ll->is_active = false;
      ll->timeout.handler(EVENT_LOOP_TIMEOUT_EVENT, NULL, ll->timeout.ud);
    }
  }
}
