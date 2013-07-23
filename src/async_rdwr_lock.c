#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

#include "c_util.h"
#include "events.h"
#include "util.h"

#include "async_rdwr_lock.h"

typedef struct {
  event_handler_t cb;
  void *cb_ud;
} Callback;

static Callback *
callback_new(event_handler_t cb, void *cb_ud) {
  Callback *toret = malloc(sizeof(*toret));
  if (!toret) {
    return NULL;
  }

  *toret = (Callback) {
    .cb = cb,
    .cb_ud = cb_ud,
  };

  return toret;
}

struct async_rdwr_lock {
  bool has_write_lock;
  int num_readers;
  linked_list_t waiting_on_write_lock;
  linked_list_t waiting_on_read_lock;
  event_handler_t waiting_for_destroy_cb;
  void *waiting_for_destroy_ud;
};

UNUSED_FUNCTION_ATTR PURE_FUNCTION static bool
_is_valid_state(struct async_rdwr_lock *lock) {
  if (!lock->has_write_lock && !lock->num_readers &&
      (lock->waiting_on_write_lock || lock->waiting_on_read_lock)) {
    return false;
  }

  if (lock->waiting_on_read_lock && !lock->waiting_on_write_lock) {
    return false;
  }

  return true;
}

async_rdwr_lock_t
async_rdwr_new() {
  return calloc(1, sizeof(struct async_rdwr_lock));
}

void
async_rdwr_destroy(async_rdwr_lock_t lock,
                   event_handler_t cb, void *ud) {
  assert(_is_valid_state(lock));

  if (lock->waiting_for_destroy_cb) {
    /* someone is using this incorrectly */
    abort();
  }

  if (lock->has_write_lock || lock->num_readers > 0) {
    lock->waiting_for_destroy_cb = cb;
    lock->waiting_for_destroy_ud = ud;
    return;
  }

  return cb(ASYNC_RDWR_DESTROY_DONE_EVENT, NULL, ud);
}

void
async_rdwr_write_lock(async_rdwr_lock_t lock,
                      event_handler_t cb, void *ud) {
  assert(_is_valid_state(lock));
  AsyncRdwrWriteLockDoneEvent ev;

  if (lock->has_write_lock ||
      lock->num_readers) {
    Callback *callback = callback_new(cb, ud);
    if (!callback) {
      ev.success = false;
      goto out;
    }

    /* TODO: limit number of waiters */
    lock->waiting_on_write_lock =
      linked_list_prepend(lock->waiting_on_write_lock, callback);

    return;
  }

  lock->has_write_lock = true;
  ev.success = true;

 out:
  return cb(ASYNC_RDWR_WRITE_LOCK_DONE_EVENT, &ev, ud);
}

void
async_rdwr_write_unlock(async_rdwr_lock_t lock) {
  assert(_is_valid_state(lock));
  assert(lock->has_write_lock);
  assert(!lock->num_readers);

  lock->has_write_lock = false;

  /* give preference to readers here, since a writer just had the lock,
     when the read lock is given up, a writer will get it
   */
  Callback *read_callback;
  lock->waiting_on_read_lock =
    linked_list_popleft(lock->waiting_on_read_lock, (void **) &read_callback);
  if (read_callback) {
    event_handler_t cb = read_callback->cb;
    void *ud = read_callback->cb_ud;
    free(read_callback);
    AsyncRdwrReadLockDoneEvent ev = {.success = true};
    lock->num_readers += 1;
    return cb(ASYNC_RDWR_READ_LOCK_DONE_EVENT, &ev, ud);
  }

  Callback *write_callback;
  lock->waiting_on_write_lock =
    linked_list_popleft(lock->waiting_on_write_lock, (void **) &write_callback);

  if (write_callback) {
    event_handler_t cb = write_callback->cb;
    void *ud = write_callback->cb_ud;
    free(write_callback);
    AsyncRdwrWriteLockDoneEvent ev = {.success = true};
    lock->has_write_lock = true;
    return cb(ASYNC_RDWR_WRITE_LOCK_DONE_EVENT, &ev, ud);
  }
}

void
async_rdwr_read_lock(async_rdwr_lock_t lock,
                     event_handler_t cb, void *ud) {
  assert(_is_valid_state(lock));
  AsyncRdwrReadLockDoneEvent ev;

  if (lock->has_write_lock ||
      /* add to waiting list if ppl are waiting on the write lock,
         just so we don't starve writers */
      lock->waiting_on_write_lock) {
    Callback *callback = callback_new(cb, ud);
    if (!callback) {
      ev.success = false;
      goto out;
    }

    /* TODO: limit number of readers */
    lock->waiting_on_read_lock =
      linked_list_prepend(lock->waiting_on_read_lock, callback);

    return;
  }

  lock->num_readers += 1;
  ev.success = true;

 out:
  return cb(ASYNC_RDWR_READ_LOCK_DONE_EVENT, &ev, ud);
}

void
async_rdwr_read_unlock(async_rdwr_lock_t lock) {
  assert(_is_valid_state(lock));
  assert(!lock->has_write_lock);
  assert(lock->num_readers > 0);

  lock->num_readers -= 1;

  /* if there are no more readers, then start up the writers */
  if (!lock->num_readers) {
    Callback *write_callback;
    lock->waiting_on_write_lock =
      linked_list_popleft(lock->waiting_on_write_lock, (void **) &write_callback);

    if (write_callback) {
      event_handler_t cb = write_callback->cb;
      void *ud = write_callback->cb_ud;
      free(write_callback);
      AsyncRdwrWriteLockDoneEvent ev = {.success = true};
      lock->has_write_lock = true;
      return cb(ASYNC_RDWR_WRITE_LOCK_DONE_EVENT, &ev, ud);
    }
  }
}

