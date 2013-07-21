#ifndef ASYNC_FUSE_FS_H
#define ASYNC_FUSE_FS_H

#define FUSE_USE_VERSION 26
#include "fuse.h"
#undef FUSE_USE_VERSION

#include "events.h"
#include "fdevent.h"

struct async_fuse_fs;

typedef struct async_fuse_fs *async_fuse_fs_t;

typedef struct {
  int ret;
} FuseFsOpDoneEvent;

async_fuse_fs_t
async_fuse_fs_new(FDEventLoop *loop);

void
async_fuse_fs_open(async_fuse_fs_t fs,
                   const char *path, struct fuse_file_info *fi,
                   event_handler_t cb, void *cb_ud);

void
async_fuse_fs_read(async_fuse_fs_t fs,
                   const char *path, char *buf, size_t size,
                   off_t off, struct fuse_file_info *fi,
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
