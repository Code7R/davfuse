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

bool
async_rdwr_destroy_sync(async_rdwr_lock_t lock);


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
