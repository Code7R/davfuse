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
