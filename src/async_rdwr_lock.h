#ifndef ASYNC_RDWR_LOCK_H
#define ASYNC_RDWR_LOCK_H

#include <stdbool.h>

#include "events.h"

typedef struct {
  bool success;
} AsyncRdwrWriteLockDoneEvent;

typedef AsyncRdwrWriteLockDoneEvent AsyncRdwrReadLockDoneEvent;

struct async_rdwr_lock;

typedef struct async_rdwr_lock *async_rdwr_lock_t;

async_rdwr_lock_t
async_rdwr_new();

void
async_rdwr_destroy(async_rdwr_lock_t lock,
                   event_handler_t cb, void *ud);

void
async_rdwr_write_lock(async_rdwr_lock_t lock,
                      event_handler_t cb, void *ud);

void
async_rdwr_write_unlock(async_rdwr_lock_t lock);

void
async_rdwr_read_lock(async_rdwr_lock_t lock,
                     event_handler_t cb, void *ud);

void
async_rdwr_read_unlock(async_rdwr_lock_t lock);

#endif
