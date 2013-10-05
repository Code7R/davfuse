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
#include <stdbool.h>
#include <stdlib.h>

#include "c_util.h"
#include "events.h"
#include "util.h"

#include "async_rdwr_lock.h"

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

  if (lock->num_readers &&
      !lock->waiting_on_write_lock &&
      lock->waiting_on_read_lock) {
    return false;
  }

  return true;
}

static void
_call_write_callback(struct async_rdwr_lock *lock, Callback *write_callback) {
  event_handler_t cb;
  void *ud;
  callback_deconstruct(write_callback, &cb, &ud);
  AsyncRdwrWriteLockDoneEvent ev = {.success = true};
  lock->has_write_lock = true;
  return cb(ASYNC_RDWR_WRITE_LOCK_DONE_EVENT, &ev, ud);
}

static void
_call_read_callback(struct async_rdwr_lock *lock, Callback *read_callback) {
  event_handler_t cb;
  void *ud;
  callback_deconstruct(read_callback, &cb, &ud);
  AsyncRdwrReadLockDoneEvent ev = {.success = true};
  lock->num_readers += 1;
  return cb(ASYNC_RDWR_READ_LOCK_DONE_EVENT, &ev, ud);
}


static void
_call_destroy_callback(struct async_rdwr_lock *lock) {
  event_handler_t cb = lock->waiting_for_destroy_ud;
  assert(cb);
  void *ud = lock->waiting_for_destroy_ud;
  free(lock);
  return cb(ASYNC_RDWR_DESTROY_DONE_EVENT, NULL, ud);
}

async_rdwr_lock_t
async_rdwr_new() {
  return calloc(1, sizeof(struct async_rdwr_lock));
}

bool
async_rdwr_destroy_sync(async_rdwr_lock_t lock) {
  assert(_is_valid_state(lock));

  if (lock->has_write_lock || lock->num_readers > 0) {
    return false;
  }

  free(lock);

  return true;
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

  free(lock);

  return cb(ASYNC_RDWR_DESTROY_DONE_EVENT, NULL, ud);
}

void
async_rdwr_write_lock(async_rdwr_lock_t lock,
                      event_handler_t cb, void *ud) {
  assert(_is_valid_state(lock));
  AsyncRdwrWriteLockDoneEvent ev;

  if (lock->has_write_lock || lock->num_readers) {
    Callback *callback = callback_construct(cb, ud);
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
    return _call_read_callback(lock, read_callback);
  }

  Callback *write_callback;
  lock->waiting_on_write_lock =
    linked_list_popleft(lock->waiting_on_write_lock, (void **) &write_callback);
  if (write_callback) {
    return _call_write_callback(lock, write_callback);
  }

  /* nothing was waiting on the lock, call the destroy callback */
  if (lock->waiting_for_destroy_cb) {
    return _call_destroy_callback(lock);
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
    Callback *callback = callback_construct(cb, ud);
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
      return _call_write_callback(lock, write_callback);
    }

    assert(!lock->waiting_on_read_lock);

    /* nothing was waiting on the lock, call the destroy callback */
    if (lock->waiting_for_destroy_cb) {
      return _call_destroy_callback(lock);
    }
  }
}
