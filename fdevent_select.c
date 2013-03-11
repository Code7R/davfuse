#include <errno.h>
#include <sys/select.h>

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

#include "c_util.h"
#include "events.h"
#include "fdevent_select.h"

NON_NULL_ARGS0() bool
fdevent_init(FDEventLoop *loop) {
  assert(loop);
  loop->ll = NULL;
  return true;
}

NON_NULL_ARGS2(1, 4) bool
fdevent_add_watch(FDEventLoop *loop,
                  int fd,
                  StreamEvents events,
                  event_handler_t handler,
                  void *ud,
                  fd_event_watch_key_t *key) {
  FDEventLink *ew;

  assert(loop);
  assert(handler);

  ew = malloc(sizeof(*ew));
  if (!ew) {
    return false;
  }

  *ew = (FDEventLink) {
    .ew = {fd, ud, events, handler},
    .prev = NULL,
    .next = NULL,
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
fdevent_remove_watch(FDEventLoop *loop,
                     fd_event_watch_key_t key) {
  /* fd_event_watch_key_t types are actually pointers to FDEventLink types */
  FDEventLink *ll = key;

  assert(loop);
  assert(loop->ll);
  assert(key);

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

  free(key);

  return true;
}

bool
fdevent_main_loop(FDEventLoop *loop) {
  fd_set readfds, writefds;

  FD_ZERO(&readfds);
  FD_ZERO(&writefds);

  while (true) {
    FDEventLink *ll = loop->ll;
    int nfds;

    while (ll) {
      if (ll->ew.events.read) {
	FD_SET(ll->ew.fd, &readfds);
      }

      if (ll->ew.events.write) {
	FD_SET(ll->ew.fd, &writefds);
      }

      if (ll->ew.fd > nfds) {
	nfds = ll->ew.fd;
      }

      ll = ll->next;
    }

    while (select(nfds + 1, &readfds, &writefds, NULL, NULL) < 0) {
      if (errno != EINTR) {
        return false;
      }
    }

    /* now dispatch on events */
    ll = loop->ll;
    while (ll) {
      FDEventLink *tmpll;
      StreamEvents events;

      /* do this first in case this link gets removed
         while calling `handler() `*/
      tmpll = ll->next;

      events = create_stream_events(FD_ISSET(ll->ew.fd, &readfds),
				    FD_ISSET(ll->ew.fd, &writefds));

      if ((events.read && ll->ew.events.read) ||
          (events.write && ll->ew.events.write)) {
	event_handler_t h = ll->ew.handler;
	int fd = ll->ew.fd;
	void *ud = ll->ew.ud;
	FDEvent e = (FDEvent) {
	  .loop = loop,
	  .fd = fd,
	  .events = events,
	};
	fdevent_remove_watch(loop, ll);
        h(FD_EVENT, &e, ud);
      }

      ll = tmpll;
    }
  }
}
