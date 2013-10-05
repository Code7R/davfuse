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

#ifndef ASYNC_FUSE_FS_HELPERS_H
#define ASYNC_FUSE_FS_HELPERS_H

#include <stdbool.h>

#include "async_fuse_fs.h"
#include "util.h"

typedef struct {
  bool error;
  linked_list_t failed_to_copy;
} AsyncFuseFsCopytreeDoneEvent;

typedef struct {
  linked_list_t failed_to_delete;
} AsyncFuseFsRmtreeDoneEvent;

void
async_fuse_fs_rmtree(async_fuse_fs_t fs,
                     const char *path,
                     event_handler_t cb, void *ud);

void
async_fuse_fs_copytree(async_fuse_fs_t fs,
                       const char *src, const char *dst,
                       bool is_move,
                       event_handler_t cb, void *ud);

void
async_fuse_fs_copyfile(async_fuse_fs_t fs,
                       const char *src, const char *dst,
                       event_handler_t cb, void *ud);

#endif
