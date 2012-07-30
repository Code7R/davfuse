#include <errno.h>
#include <sys/select.h>

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

#include "fdevent_select.h"

bool
fdevent_init(FDEventLoop *loop) {
  assert(loop);
  loop->ll = NULL;
  return true;
}

bool
fdevent_add_watch(FDEventLoop *loop,
                  int fd,
                  StreamEvents events,
                  StreamEventHandler handler,
                  void *ud,
                  FDEventWatchKey *key) {
  FDEventLink *ew;

  assert(loop);
  assert(key);

  ew = malloc(sizeof(*ew));
  if (!ew) {
    return false;
  }

  *ew = (FDEventLink){((FDEventWatcher) {fd, ud, events, handler}),
                      NULL, NULL};

  if (loop->ll) {
    ew->next = loop->ll;
    loop->ll->prev = ew;
    loop->ll = ew;
  }
  else {
    loop->ll = ew;
  }

  *key = ew;

  return true;
}

bool
fdevent_remove_watch(FDEventLoop *loop,
                     FDEventWatchKey key) {
  /* FDEventWatchKey types are actually pointers to FDEventLink types */
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

      events = (StreamEvents) {.read = FD_ISSET(ll->ew.fd, &readfds),
                               .write = FD_ISSET(ll->ew.fd, &writefds)};

      if ((events.read && ll->events.read) ||
          (events.write && ll->events.write)) {
        ll->ew.handler(ll->ew.fd, events, ll->ew.ud);
      }

      ll = tmpll;
    }
  }
}
