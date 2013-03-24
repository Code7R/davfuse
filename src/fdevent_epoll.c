#include <errno.h>
#include <sys/epoll.h>

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

#include "c_util.h"
#include "fdevent_epoll.h"
#include "logging.h"

#define DEFAULT_WATCHER_TABLE_SIZE 10
#define EVENTS_PER_LOOP 10

static PURE_FUNCTION uint32_t
stream_event_to_event_set(StreamEvents events) {
  return ((events.read ? EPOLLIN : 0) |
          (events.write ? EPOLLOUT : 0));
}

static PURE_FUNCTION NON_NULL_ARGS() uint32_t
compute_event_set_for_fd(FDEventWatcher *ll) {
  uint32_t event_set = 0;

  do {
    event_set |= stream_event_to_event_set(ll->events);
    ll = ll->next;
  }
  while (event_set != (EPOLLIN | EPOLLOUT) && ll);

  return event_set;
}

static CONST_FUNCTION NON_NULL_ARGS() FDEventWatcherList *
watcher_list_for_fd(FDEventLoop *loop, int fd) {
  FDEventWatcherList *wll;

  wll = loop->fd_to_watchers[fd % loop->fd_to_watcher_size];
  while (wll) {
    if (wll->fd == fd) {
      break;
    }
    wll = wll->next;
  }

  return wll;
}

static void
free_watcher(FDEventWatcher *wl) {
  /* clear out magic */
  wl->magic = 0;
  free(wl);
}

static void
free_watcher_list(FDEventWatcherList *wll) {
  /* clear out magic */
  wll->magic = 0;
  free(wll);
}

bool
fdevent_init(FDEventLoop *loop) {
  assert(loop);

  loop->epollfd = epoll_create(DEFAULT_WATCHER_TABLE_SIZE);
  if (loop->epollfd < 0) {
    return false;
  }

  loop->fd_to_watcher_size = DEFAULT_WATCHER_TABLE_SIZE;
  /* TODO: grow this hash table as it gets full / empty */
  loop->fd_to_watchers = calloc(DEFAULT_WATCHER_TABLE_SIZE,
                                sizeof(loop->fd_to_watchers[0]));
  if (!loop->fd_to_watchers) {
    return false;
  }

  return true;
}

bool
fdevent_add_watch(FDEventLoop *loop,
                  int fd,
                  StreamEvents events,
                  StreamEventHandler handler,
                  void *ud,
                  FDEventWatchKey *key) {
  FDEventWatcher *wl = NULL;
  FDEventWatcherList *wll = NULL;

  assert(loop);
  assert(fd >= 0);
  assert(handler);

  wl = malloc(sizeof(*wl));
  if (!wl) {
    goto error;
  }

  wll = watcher_list_for_fd(loop, fd);
  if (!wll) {
    FDEventWatcherList *fdstart;

    /* there was no hash mapping for this fd, we have to create one */
    wll = malloc(sizeof(*wll));
    if (!wll) {
      goto error;
    }

    fdstart = loop->fd_to_watchers[fd % loop->fd_to_watcher_size];
    if (fdstart) {
      fdstart->prev = wll;
    }

    *wll = (FDEventWatcherList) {
      .magic = WATCHER_LIST_MAGIC,
      .fd = fd,
      .watchers = NULL,
      .prev = NULL,
      .next = fdstart,
    };
    loop->fd_to_watchers[fd % loop->fd_to_watcher_size] = wll;
  }

  *wl = (FDEventWatcher) {
    .magic = WATCHER_MAGIC,
    .events = events,
    .handler = handler,
    .ud = ud,
    .wll = wll,
    .next = wll->watchers,
  };
  wll->watchers = wl;

  {
    struct epoll_event ev;
    int op;

    ev.events = compute_event_set_for_fd(wl) | EPOLLET;
    ev.data.ptr = wll;

    op = wl->next ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;

    if (epoll_ctl(loop->epollfd, op, fd, &ev) < 0) {
      goto error;
    }

    wll->epoll_events = ev.events;
  }

  if (key) {
    *key = wl;
  }

  log_debug("adding watch for fd %d, key %p, events: read %d, write %d",
            fd, wl, events.read, events.write);

  return true;

 error:
  if (wl) {
    free_watcher(wl);
  }

  if (wll) {
    free_watcher_list(wll);
  }

  return false;
}

bool
fdevent_remove_watch(FDEventLoop *loop,
                     FDEventWatchKey key) {
  /* FDEventWatchKey types are actually pointers to FDWatcherLink types */
  FDEventWatcherList *wll;
  FDEventWatcher *ll = key, *before_ll = NULL;
  bool last_watch_for_fd;
  int fd;

  assert(loop);
  assert(loop->epollfd >= 0);
  assert(loop->fd_to_watcher_size);
  assert(loop->fd_to_watchers);
  assert(key);

  if (ll->magic != WATCHER_MAGIC) {
    /* this was a bad key */
    return false;
  }

  wll = ll->wll;
  assert(wll->magic == WATCHER_LIST_MAGIC);


  log_debug("removing watch for fd %d, key %p", wll->fd, key);
  last_watch_for_fd = wll->watchers == ll && !ll->next;

  /* first attempt to modify epoll */
  {
    struct epoll_event ev, *ev_set;
    int op;

    if (last_watch_for_fd) {
      /* last fd in an fd list */
      op = EPOLL_CTL_DEL;
      ev_set = NULL;
    }
    else {
      FDEventWatcher *ll1;

      /* compute the new event set for this fd */
      ev.events = 0;
      do {
        if (ll1 != ll) {
          ev.events |= stream_event_to_event_set(ll1->events);
        }

        if (ll1->next == ll) {
          before_ll = ll1;
        }

        ll1 = ll1->next;
      }
      /* stop if we're waiting for possible events or
	 there is no more to iterate over */
      while (ev.events != (EPOLLIN | EPOLLOUT) && ll1);

      op = EPOLL_CTL_MOD;
      ev.events |= EPOLLET;
      ev.data.ptr = wll;
      ev_set = &ev;
    }

    if ((op == EPOLL_CTL_DEL ||
	 ev.events != wll->epoll_events) &&
	epoll_ctl(loop->epollfd, op, wll->fd, ev_set) < 0) {
      return false;
    }

    if (op != EPOLL_CTL_DEL) {
      wll->epoll_events = ev.event;
    }
  }

  /* now remove the watch from the watcher list,
     we do this after `epoll_ctl` because that is more likely to fail
   */
  if (before_ll) {
    assert(wll->watchers != ll);
    before_ll->next = ll->next;
  }
  else if (wll->watchers == ll) {
    wll->watchers = ll->next;
  }

  free_watcher(ll);

  /* if this watcher list is dead, remove it from the hash table */
  if (!wll->watchers) {
    if (wll->prev) {
      wll->prev->next = wll->next;
    }
    else {
      /* if prev wasn't set, it was the first in the list */
      loop->fd_to_watchers[fd % loop->fd_to_watcher_size] = wll->next;
    }

    if (wll->next) {
      wll->next->prev = wll->prev;
    }

    free_watcher_list(wll);
  }

  return true;
}

static void
dump_loop(FDEventLoop *loop) {
  log_debug("Beginning dump");

  for (int i = 0; i < loop->fd_to_watcher_size; ++i) {
    FDEventWatcherList *ll = loop->fd_to_watchers[i];

    while (ll) {
      FDEventWatcher *watchers = ll->watchers;

      log_debug("Watch list: magic: %x, fd %d, epoll_events %x",
		ll->magic,
		ll->fd,
		ll->epoll_events);

      while (watchers) {
        log_debug("Watcher: key %p, magic: %x, wll: %p, events: read %d, write %d, handler: %p",
                  watchers,
		  watchers->magic,
                  watchers->wll, watchers->events.read, watchers->events.write,
                  watchers->handler);

        watchers = watchers->next;
      }

      ll = ll->next;
    }
  }

  log_debug("Done dump");
}

bool
fdevent_main_loop(FDEventLoop *loop) {
  while (true) {
    int nfds;
    struct epoll_event events[EVENTS_PER_LOOP];

    dump_loop(loop);

    while ((nfds = epoll_wait(loop->epollfd, events, NELEMS(events), -1)) < 0) {
      if (errno != EINTR) {
        return false;
      }
    }

    for (int i = 0; i < nfds; ++i) {
      FDEventWatcherList *wll = (FDEventWatcherList *) events[i].data.ptr;

      if (!wll || wll->magic != WATCHER_LIST_MAGIC) {
        /* not sure whose at fault here, either
           epoll gave us a bad fd or our internal data structures
           are corrupted */
        log_warning("epoll_wait() gave us a bad watcher list, magic: %p, %x",
		    wll, wll->magic);
        continue;
      }

      {
	FDEventWatcher *ll = wll->watchers;
	StreamEvents stream_events = {
	  .read = events[i].events & EPOLLIN,
	  .write = events[i].events & EPOLLOUT
	};
	/* save this in case wll gets free'd */
	int fd = wll->fd;
	
	while (ll) {
	  /* the linked-list might get modified while calling the handler,
	     but that's okay because:
	     * if we remove a link, we won't iterate to it
	     * when we add links, they go to the front
	     */
	  FDEventWatcher *lltmp = ll->next;
	  
	  if ((stream_events.read && ll->events.read) ||
	      (stream_events.write && ll->events.write)) {
	    /* these are one-shot,
	       save this info
	       remove the watch, and go
	    */
	    StreamEventHandler h = ll->handler;
	    void *ud = ll->ud;
	    fdevent_remove_watch(loop, ll);
	    h(loop, fd, stream_events, ud);
	  }
	  
	  ll = lltmp;
	}
      }
    }
  }
}
