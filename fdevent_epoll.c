#include <errno.h>
#include <sys/epoll.h>

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

#include "fdevent_epoll.h"
#include "logging.h"

#define DEFAULT_WATCHER_TABLE_SIZE 10
#define EVENTS_PER_LOOP 10
#define NELEMS(arr) (sizeof(arr) / sizeof(arr[0]))

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

static uint32_t
stream_event_to_event_set(StreamEvents events) {
  return ((events.read ? EPOLLIN : 0) |
          (events.write ? EPOLLOUT : 0));
}

static uint32_t
compute_event_set_for_fd(FDEventWatcher *ll) {
  uint32_t event_set = 0;

  do {
    event_set |= stream_event_to_event_set(ll->events);
    ll = ll->next;
  }
  while (event_set != (EPOLLIN | EPOLLOUT) && ll);

  return event_set;
}

static FDEventWatcherList *
watcher_list_for_fd(FDEventLoop *loop, int fd) {
  FDEventWatcherList *wll;

  wll = loop->fd_to_watchers[fd % loop->fd_to_watcher_size];
  while (wll) {
    if (wll->watchers->fd == fd) {
      break;
    }
    wll = wll->next;
  }

  return wll;
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
  assert(key);

  wl = malloc(sizeof(*wl));
  if (!wl) {
    goto fail;
  }

  wll = watcher_list_for_fd(loop, fd);
  if (!wll) {
    FDEventWatcherList *fdstart;

    /* there was no hash mapping for this fd, we have to create one */
    wll = malloc(sizeof(*wll));
    if (!wll) {
      goto fail;
    }

    fdstart = loop->fd_to_watchers[fd % loop->fd_to_watcher_size];
    if (fdstart) {
      fdstart->prev = wll;
    }

    *wll = (FDEventWatcherList) {.watchers = NULL,
                                 .prev = NULL,
                                 .next = fdstart};
    loop->fd_to_watchers[fd % loop->fd_to_watcher_size] = wll;
  }

  *wl = (FDEventWatcher) {.fd = fd,
                          .ud = ud,
                          .events = events,
                          .handler = handler,
                          .next = wll->watchers};
  wll->watchers = wl;

  {
    struct epoll_event ev;
    int op;

    ev.events = compute_event_set_for_fd(wl) | EPOLLET;
    ev.data.fd = fd;

    op = wl->next ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;

    if (epoll_ctl(loop->epollfd, op, fd, &ev) < 0) {
      goto fail;
    }
  }

  *key = wl;
  return true;

 fail:
  if (wl) {
    free(wl);
  }

  if (wll) {
    free(wll);
  }

  return false;
}

static bool
stream_events_are_equal(StreamEvents a, StreamEvents b) {
  return a.read == b.read && a.write == b.write;
}

bool
fdevent_modify_watch(FDEventLoop *loop,
                     FDEventWatchKey key,
                     StreamEvents new_events,
                     StreamEventHandler handler,
                     void *ud) {
  assert(loop);
  assert(loop->epollfd >= 0);
  assert(loop->fd_to_watcher_size);
  assert(loop->fd_to_watchers);
  assert(key);

  FDEventWatcher *watcher = key;

  if (!stream_events_are_equal(watcher->events, new_events)) {
    /* save a copy of the old one in case there is an error */
    StreamEvents old_events = watcher->events;

    watcher->events = new_events;

    /* recompute the events we're waiting on */
    FDEventWatcherList *watcher_list = watcher_list_for_fd(loop, watcher->fd);
    struct epoll_event ev;
    ev.events = compute_event_set_for_fd(watcher_list->watchers);
    ev.data.fd = watcher->fd;

    if (epoll_ctl(loop->epollfd, EPOLL_CTL_MOD, watcher->fd, &ev) < 0) {
      /* restore old events since this failed */
      watcher->events = old_events;
      return false;
    }
  }

  /* set the rest of the variables */
  if (handler != watcher->handler) {
    watcher->handler = handler;
  }

  if (watcher->ud != ud) {
    watcher->ud = ud;
  }

  return true;
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

  fd = ll->fd;
  wll = watcher_list_for_fd(loop, fd);
  last_watch_for_fd = wll->watchers == ll;

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

      ll1 = wll->watchers;
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
      while (ev.events != (EPOLLIN | EPOLLOUT) && ll1);

      op = EPOLL_CTL_MOD;
      ev.events |= EPOLLET;
      ev.data.fd = fd;
      ev_set = &ev;
    }

    if (epoll_ctl(loop->epollfd, op, fd, ev_set) < 0) {
      return false;
    }
  }

  /* now remove the watch from our data structure */
  if (before_ll) {
    before_ll->next = ll->next;
  }
  else {
    assert(last_watch_for_fd);
  }

  free(ll);

  if (last_watch_for_fd) {
    loop->fd_to_watchers[fd % loop->fd_to_watcher_size] = NULL;
    free(wll);
  }

  return true;
}

bool
fdevent_main_loop(FDEventLoop *loop) {
  while (true) {
    int i, nfds;
    struct epoll_event events[EVENTS_PER_LOOP];

    while ((nfds = epoll_wait(loop->epollfd, events, NELEMS(events), -1)) < 0) {
      if (errno != EINTR) {
        return false;
      }
    }

    for (i = 0; i < nfds; ++i) {
      FDEventWatcherList *wll;
      FDEventWatcher *ll;
      StreamEvents stream_events;

      wll = watcher_list_for_fd(loop, events[i].data.fd);
      if (!wll) {
        /* not sure whose at fault here, either
           epoll gave us a bad fd or our internal data structures
           are corrupted */
        log_warning("epoll_wait() gave us a bad fd: %d", events[i].data.fd);
        continue;
      }

      stream_events = (StreamEvents) {.read = events[i].events & EPOLLIN,
                                      .write = events[i].events & EPOLLOUT};

      ll = wll->watchers;
      while (ll) {
        FDEventWatcher *lltmp;

        lltmp = ll->next;

        if ((stream_events.read && ll->events.read) ||
            (stream_events.write && ll->events.write)) {
          ll->handler(ll->fd, stream_events, ll->ud);
        }

        ll = lltmp;
      }
    }
  }
}
