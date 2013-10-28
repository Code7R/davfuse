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

#ifndef ASYNC_FUSE_FS_H
#define ASYNC_FUSE_FS_H

#define FUSE_USE_VERSION 26
#include "fuse.h"
#undef FUSE_USE_VERSION

#include "events.h"
#include "event_loop.h"

struct async_fuse_fs;

typedef struct async_fuse_fs *async_fuse_fs_t;

typedef struct {
  int ret;
} FuseFsOpDoneEvent;

async_fuse_fs_t
async_fuse_fs_new(event_loop_handle_t loop);

void
async_fuse_fs_open(async_fuse_fs_t fs,
                   const char *path, struct fuse_file_info *fi,
                   event_handler_t cb, void *cb_ud);

void
async_fuse_fs_fgetattr(async_fuse_fs_t fs,
                       const char *path, struct stat *buf,
                       struct fuse_file_info *fi,
                       event_handler_t cb, void *cb_ud);

void
async_fuse_fs_read(async_fuse_fs_t fs,
                   const char *path, char *buf, size_t size,
                   off_t off, struct fuse_file_info *fi,
                   event_handler_t cb, void *cb_ud);

void
async_fuse_fs_write(async_fuse_fs_t fs,
                    const char *path, const char *buf,
                    size_t size, off_t off, struct fuse_file_info *fi,
                    event_handler_t cb, void *cb_ud);

void
async_fuse_fs_getdir(async_fuse_fs_t fs,
                     const char *path, fuse_dirh_t h, fuse_dirfil_t fn,
                     event_handler_t cb, void *cb_ud);

void
async_fuse_fs_unlink(async_fuse_fs_t fs,
                     const char *path,
                     event_handler_t cb, void *cb_ud);

void
async_fuse_fs_rmdir(async_fuse_fs_t fs,
                    const char *path,
                    event_handler_t cb, void *cb_ud);

void
async_fuse_fs_mkdir(async_fuse_fs_t fs,
                    const char *path,
                    mode_t mode,
                    event_handler_t cb, void *cb_ud);

void
async_fuse_fs_getattr(async_fuse_fs_t fs,
                      const char *path, struct stat *buf,
                      event_handler_t cb, void *cb_ud);

void
async_fuse_fs_rename(async_fuse_fs_t fs,
                     const char *src, const char *dst,
                     event_handler_t cb, void *cb_ud);

void
async_fuse_fs_mknod(async_fuse_fs_t fs,
                    const char *path, mode_t mode, dev_t dev,
                    event_handler_t cb, void *cb_ud);

void
async_fuse_fs_release(async_fuse_fs_t fs,
                      const char *path, struct fuse_file_info *fi,
                      event_handler_t cb, void *cb_ud);

void
async_fuse_worker_main_loop(async_fuse_fs_t fs,
                            const struct fuse_operations *op,
                            size_t op_size,
                            void *user_data);

bool
async_fuse_fs_stop_blocking(async_fuse_fs_t fs);

bool
async_fuse_fs_destroy(async_fuse_fs_t fs);

#endif
