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

#define _ISOC99_SOURCE
#define _POSIX_C_SOURCE 199309L
#define _BSD_SOURCE

#include <sys/stat.h>

#include <string.h>

#define FUSE_USE_VERSION 26
#include "fuse.h"
#undef FUSE_USE_VERSION

#include "async_tree.h"
#include "events.h"
#include "uthread.h"
#include "util.h"

#include "async_fuse_fs_helpers.h"

enum {
  TRANSFER_BUF_SIZE = 4096,
};


typedef struct {
  UTHR_CTX_BASE;
  /* args */
  async_fuse_fs_t fuse_fs;
  linked_list_t stack;
  char *path;
  event_handler_t cb;
  void *ud;
  /* ctx */
  size_t path_len;
} AsyncFuseExpandCtx;

static int
_async_fuse_expand_dirfil_fn(fuse_dirh_t h,
                             const char *name,
                             int type,
                             ino_t ino) {
  /* NOTE THAT THIS COULD BE CALLED ON ANOTHER THREAD,
     it's okay because nothing should be using these data structures
     on the webdav thread
   */
  if (str_equals(name, "..") ||
      str_equals(name, ".")) {
    return 0;
  }

  AsyncFuseExpandCtx *ctx = (AsyncFuseExpandCtx *) h;
  UNUSED(type);
  UNUSED(ino);

  /* add new path */
  size_t name_len = strlen(name);
  char *new_path = malloc_or_abort(ctx->path_len + 1 + name_len + 1);
  memcpy(new_path, ctx->path, ctx->path_len);
  new_path[ctx->path_len] = '/';
  memcpy(new_path + ctx->path_len + 1, name, name_len);
  new_path[ctx->path_len + 1 + name_len] = '\0';

  ctx->stack = linked_list_prepend(ctx->stack, new_path);

  return 0;
}

static
UTHR_DEFINE(_async_fuse_expand_uthr) {
  UTHR_HEADER(AsyncFuseExpandCtx, ctx);

  /* NB: we just use the fuse getdir method because
     that's what encfs implements */
  ctx->path_len = strlen(ctx->path);
  UTHR_YIELD(ctx,
             async_fuse_fs_getdir(ctx->fuse_fs,
                                  ctx->path, (void *) ctx,
                                  _async_fuse_expand_dirfil_fn,
                                  _async_fuse_expand_uthr, ctx));
  UTHR_RECEIVE_EVENT(ASYNC_FUSE_FS_GETDIR_DONE_EVENT,
                     FuseFsOpDoneEvent,
                     getdir_done_ev);
  /* TODO: use this */
  UNUSED(getdir_done_ev);

  AsyncTreeExpandFnDoneEvent ev = {
    /* TODO: permanently false for now */
    .error = false,
    .new_stack = ctx->stack,
  };

  UTHR_RETURN(ctx,
              ctx->cb(ASYNC_TREE_EXPAND_FN_DONE_EVENT, &ev, ctx->ud));

  UTHR_FOOTER();
}

static void
_async_fuse_expand(void *user_data, linked_list_t stack, void *elt,
                   event_handler_t cb, void *ud) {
  UTHR_CALL4(_async_fuse_expand_uthr, AsyncFuseExpandCtx,
             .fuse_fs = user_data,
             .stack = stack,
             .path = elt,
             .cb = cb,
             .ud = ud);
}

typedef struct {
  async_fuse_fs_t fuse_fs;
  linked_list_t failed_to_delete;
  event_handler_t cb;
  void *cb_ud;
} AsyncFuseFsRmtreeCtx;

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  AsyncFuseFsRmtreeCtx *top;
  char *path;
  event_handler_t cb;
  void *ud;
  /* ctx */
  int ret;
} AsyncFuseApplyRmtreeCtx;

static
UTHR_DEFINE(_async_fuse_apply_rmtree_uthr) {
  UTHR_HEADER(AsyncFuseApplyRmtreeCtx, ctx);

  UTHR_YIELD(ctx,
             async_fuse_fs_unlink(ctx->top->fuse_fs, ctx->path,
                                  _async_fuse_apply_rmtree_uthr, ctx));
  UTHR_RECEIVE_EVENT(ASYNC_FUSE_FS_UNLINK_DONE_EVENT,
                     FuseFsOpDoneEvent, unlink_done_ev);
  ctx->ret = unlink_done_ev->ret;
  if (-ctx->ret == EPERM ||
      /* posix says to return EPERM when unlink() is called on a directory
         linux returns EISDIR */
      -ctx->ret == EISDIR) {
    /* failed cuz it was a directory, try rmdir */
    UTHR_YIELD(ctx,
               async_fuse_fs_rmdir(ctx->top->fuse_fs, ctx->path,
                                   _async_fuse_apply_rmtree_uthr, ctx));
    UTHR_RECEIVE_EVENT(ASYNC_FUSE_FS_RMDIR_DONE_EVENT,
                       FuseFsOpDoneEvent, rmdir_done_ev);
    ctx->ret = rmdir_done_ev->ret;
  }

  if (ctx->ret < 0) {
    ctx->top->failed_to_delete =
      linked_list_prepend(ctx->top->failed_to_delete,
                          ctx->path);
    log_debug("Error while deleting \"%s\": \%s",
              ctx->path, strerror(-ctx->ret));
  }
  else {
    free(ctx->path);
  }

  AsyncTreeApplyFnDoneEvent ev = {.error = ctx->ret};
  UTHR_RETURN(ctx,
              ctx->cb(ASYNC_TREE_APPLY_FN_DONE_EVENT, &ev, ctx->ud));

  UTHR_FOOTER();
}

static void
_async_fuse_apply_rmtree(void *user_data, void *elt,
                         event_handler_t cb, void *ud) {
  UTHR_CALL4(_async_fuse_apply_rmtree_uthr, AsyncFuseApplyRmtreeCtx,
             .top = user_data,
             .path = elt,
             .cb = cb,
             .ud = ud);
}

static void
_async_fuse_expand_rmtree(void *user_data, linked_list_t stack, void *elt,
                          event_handler_t cb, void *ud) {
  AsyncFuseFsRmtreeCtx *ctx = user_data;
  return _async_fuse_expand(ctx->fuse_fs, stack, elt, cb, ud);
}

static
EVENT_HANDLER_DEFINE(_async_fuse_fs_rmtree_done, ev_type, ev, ud) {
  UNUSED(ev);
  UNUSED(ev_type);
  assert(ev_type == ASYNC_TREE_APPLY_DONE_EVENT);
  AsyncFuseFsRmtreeCtx *ctx = ud;
  event_handler_t cb = ctx->cb;
  void *cb_ud = ctx->cb_ud;
  AsyncFuseFsRmtreeDoneEvent ev_out = {
    .failed_to_delete = ctx->failed_to_delete,
  };
  free(ctx);
  cb(ASYNC_FUSE_FS_RMTREE_DONE_EVENT, &ev_out, cb_ud);
}

void
async_fuse_fs_rmtree(async_fuse_fs_t fs,
                     const char *path,
                     event_handler_t cb, void *cb_ud) {
  AsyncFuseFsRmtreeCtx *ctx = malloc_or_abort(sizeof(*ctx));
  *ctx = (AsyncFuseFsRmtreeCtx) {
    .fuse_fs = fs,
    .failed_to_delete = LINKED_LIST_INITIALIZER,
    .cb = cb,
    .cb_ud = cb_ud,
  };

  bool is_postorder = true;
  char *init_path = davfuse_util_strdup(path);
  ASSERT_NOT_NULL(init_path);
  return async_tree_apply(ctx,
                          _async_fuse_apply_rmtree,
                          _async_fuse_expand_rmtree,
                          (void *) init_path,
                          is_postorder,
                          _async_fuse_fs_rmtree_done, ctx);
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  async_fuse_fs_t fs;
  const char *src;
  const char *dst;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
  off_t src_offset;
  bool src_opened;
  bool dst_opened;
  struct fuse_file_info fi_src;
  struct fuse_file_info fi_dst;
  char buf[TRANSFER_BUF_SIZE];
  FuseFsOpDoneEvent ev;
} AsyncFuseFsCopyfileCtx;

static
UTHR_DEFINE(_async_fuse_fs_copyfile_uthr) {
  UTHR_HEADER(AsyncFuseFsCopyfileCtx, ctx);

  ctx->fi_src.flags = O_RDONLY;
  UTHR_SUBCALL(ctx,
               async_fuse_fs_open(ctx->fs,
                                  ctx->src, &ctx->fi_src,
                                  _async_fuse_fs_copyfile_uthr, ctx),
               ASYNC_FUSE_FS_OPEN_DONE_EVENT,
               FuseFsOpDoneEvent,
               open_done_ev);
  if (open_done_ev->ret < 0) {
    ctx->ev.ret = open_done_ev->ret;
    goto done;
  }
  ctx->src_opened = true;


  UTHR_SUBCALL(ctx,
               async_fuse_fs_mknod(ctx->fs,
                                   ctx->dst, S_IFREG | 0666, 0,
                                   _async_fuse_fs_copyfile_uthr, ctx),
               ASYNC_FUSE_FS_MKNOD_DONE_EVENT,
               FuseFsOpDoneEvent,
               mknod_done_ev);

  if (mknod_done_ev->ret < 0 &&
      -mknod_done_ev->ret != EEXIST) {
    ctx->ev.ret = mknod_done_ev->ret;
    goto done;
  }

  ctx->fi_dst.flags = O_WRONLY;
  UTHR_SUBCALL(ctx,
               async_fuse_fs_open(ctx->fs,
                                  ctx->dst, &ctx->fi_dst,
                                  _async_fuse_fs_copyfile_uthr, ctx),
               ASYNC_FUSE_FS_OPEN_DONE_EVENT,
               FuseFsOpDoneEvent,
               open_done_ev_2);
  if (open_done_ev_2->ret < 0) {
    ctx->ev.ret = open_done_ev_2->ret;
    goto done;
  }
  ctx->dst_opened = true;

  ctx->src_offset = 0;
  while (true) {
    UTHR_SUBCALL(ctx,
                 async_fuse_fs_read(ctx->fs,
                                    ctx->src, ctx->buf, sizeof(ctx->buf),
                                    ctx->src_offset, &ctx->fi_src,
                                    _async_fuse_fs_copyfile_uthr, ctx),
                 ASYNC_FUSE_FS_READ_DONE_EVENT,
                 FuseFsOpDoneEvent,
                 read_done_ev);
    if (read_done_ev->ret < 0) {
      ctx->ev.ret = read_done_ev->ret;
      goto done;
    }
    else if (!read_done_ev->ret) {
      break;
    }

    UTHR_SUBCALL(ctx,
                 async_fuse_fs_write(ctx->fs,
                                     ctx->dst, ctx->buf, read_done_ev->ret,
                                     ctx->src_offset, &ctx->fi_dst,
                                     _async_fuse_fs_copyfile_uthr, ctx),
                 ASYNC_FUSE_FS_WRITE_DONE_EVENT,
                 FuseFsOpDoneEvent,
                 write_done_ev);
    if (write_done_ev->ret < 0) {
      ctx->ev.ret = write_done_ev->ret;
      goto done;
    }

    ctx->src_offset += write_done_ev->ret;
  }

  ctx->ev.ret = 0;

 done:
  if (ctx->src_opened) {
    UTHR_SUBCALL(ctx,
                 async_fuse_fs_release(ctx->fs,
                                       ctx->src, &ctx->fi_src,
                                       _async_fuse_fs_copyfile_uthr, ctx),
                 ASYNC_FUSE_FS_RELEASE_DONE_EVENT,
                 FuseFsOpDoneEvent,
                 release_done_ev);
    if (release_done_ev->ret < 0) {
      /* the return value of release is always ignored in the FUSE API,
         but we log on it, just in case
       */
      log_warning("Error while releasing \"%s\": %s",
                  ctx->src, strerror(-release_done_ev->ret));
    }

    UNUSED(release_done_ev);
  }

  if (ctx->dst_opened) {
    UTHR_SUBCALL(ctx,
                 async_fuse_fs_release(ctx->fs,
                                       ctx->dst, &ctx->fi_dst,
                                       _async_fuse_fs_copyfile_uthr, ctx),
                 ASYNC_FUSE_FS_RELEASE_DONE_EVENT,
                 FuseFsOpDoneEvent,
                 release_done_ev);
    /* the return value of release is always ignored in the FUSE API */
    if (release_done_ev->ret < 0) {
      log_warning("Error while releasing \"%s\": %s",
                  ctx->dst, strerror(-release_done_ev->ret));
    }
  }

  UTHR_RETURN(ctx,
              ctx->cb(ASYNC_FUSE_FS_COPYFILE_DONE_EVENT,
                      &ctx->ev,
                      ctx->cb_ud));


  UTHR_FOOTER();
}

void
async_fuse_fs_copyfile(async_fuse_fs_t fs,
                       const char *src, const char *dst,
                       event_handler_t cb, void *cb_ud) {
  UTHR_CALL5(_async_fuse_fs_copyfile_uthr, AsyncFuseFsCopyfileCtx,
             .fs = fs,
             .src = src,
             .dst = dst,
             .cb = cb,
             .cb_ud = cb_ud);
}

typedef struct {
  async_fuse_fs_t fs;
  const char *src;
  const char *dst;
  bool is_move;
  event_handler_t cb;
  void *cb_ud;
} AsyncFuseFsCopytreeCtx;

typedef struct{
  UTHR_CTX_BASE;
  /* args */
  AsyncFuseFsCopytreeCtx *top;
  char *path;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
  char *dest_path;
  struct stat st;
  AsyncTreeApplyFnDoneEvent ev;
} AsyncFuseFsCopytreeUthrCtx;

static char *
reparent_path(const char *from_path, const char *to_path,
              const char *to_transform) {
  /* we only accept absolute paths */
  assert(str_startswith(from_path, "/"));
  assert(str_startswith(to_path, "/"));
  assert(str_startswith(to_transform, "/"));

  if (str_equals(from_path, to_transform)) {
    return davfuse_util_strdup(to_path);
  }

  assert(str_startswith(to_transform, from_path));
  size_t from_path_len = strlen(from_path);
  assert(to_transform[from_path_len] == '/');

  size_t to_path_len = strlen(to_path);
  size_t appendage_len = strlen(to_transform + from_path_len);
  char *new_str = malloc(to_path_len + appendage_len + 1);
  memcpy(new_str, to_path, to_path_len);
  memcpy(new_str + to_path_len, to_transform + from_path_len, appendage_len);
  new_str[to_path_len + appendage_len] = '\0';

  return new_str;
}

static
UTHR_DEFINE(_async_fuse_apply_copytree_uthr) {
  UTHR_HEADER(AsyncFuseFsCopytreeUthrCtx, ctx);

  ctx->dest_path = NULL;

  UTHR_SUBCALL(ctx,
               async_fuse_fs_getattr(ctx->top->fs,
                                     ctx->path, &ctx->st,
                                     _async_fuse_apply_copytree_uthr, ctx),
               ASYNC_FUSE_FS_GETATTR_DONE_EVENT,
               FuseFsOpDoneEvent,
               getattr_done_ev);
  if (getattr_done_ev->ret < 0) {
    ctx->ev.error = true;
    goto done;
  }

  ctx->dest_path = reparent_path(ctx->top->src, ctx->top->dst, ctx->path);
  log_debug("Copying %s to %s", ctx->path, ctx->dest_path);

  if (S_ISDIR(ctx->st.st_mode)) {
    UTHR_SUBCALL(ctx,
                 async_fuse_fs_mkdir(ctx->top->fs,
                                     ctx->dest_path, 0777,
                                     _async_fuse_apply_copytree_uthr, ctx),
                 ASYNC_FUSE_FS_MKDIR_DONE_EVENT,
                 FuseFsOpDoneEvent,
                 mkdir_done_ev);
    ctx->ev.error = mkdir_done_ev->ret < 0;
  }
  else {
    UTHR_SUBCALL(ctx,
                 async_fuse_fs_copyfile(ctx->top->fs,
                                        ctx->path, ctx->dest_path,
                                        _async_fuse_apply_copytree_uthr, ctx),
                 ASYNC_FUSE_FS_COPYFILE_DONE_EVENT,
                 FuseFsOpDoneEvent,
                 copyfile_done_ev);
    ctx->ev.error = copyfile_done_ev->ret < 0;
    if (!ctx->ev.error && ctx->top->is_move) {
      /* eagerly delete this entry */
      UTHR_SUBCALL(ctx,
                   async_fuse_fs_unlink(ctx->top->fs,
                                        ctx->path,
                                        _async_fuse_apply_copytree_uthr, ctx),
                   ASYNC_FUSE_FS_UNLINK_DONE_EVENT,
                   FuseFsOpDoneEvent,
                   unlink_done_ev);
      if (unlink_done_ev->ret < 0 && -unlink_done_ev->ret != ENOENT) {
        log_warning("Failed to delete %s after copying: %s",
                    ctx->path, strerror(-unlink_done_ev->ret));
      }
    }
  }

 done:
  if (ctx->ev.error) {
    log_info("Error copying %s to %s", ctx->path, ctx->dest_path);
  }

  free(ctx->dest_path);
  free(ctx->path);

  UTHR_RETURN(ctx,
              ctx->cb(ASYNC_TREE_APPLY_FN_DONE_EVENT, &ctx->ev, ctx->cb_ud));

  UTHR_FOOTER();
}

static void
_async_fuse_apply_copytree(void *user_data, void *elt,
                           event_handler_t cb, void *cb_ud) {
  UTHR_CALL4(_async_fuse_apply_copytree_uthr, AsyncFuseFsCopytreeUthrCtx,
             .top = user_data,
             .path = elt,
             .cb = cb,
             .cb_ud = cb_ud);
}

static void
_async_fuse_expand_copytree(void *user_data, linked_list_t stack, void *elt,
                            event_handler_t cb, void *cb_ud) {
  AsyncFuseFsCopytreeCtx *ctx = user_data;
  return _async_fuse_expand(ctx->fs, stack, elt, cb, cb_ud);
}

static
EVENT_HANDLER_DEFINE(_async_fuse_fs_copytree_done, ev_type, ev, ud) {
  UNUSED(ev);
  UNUSED(ev_type);
  assert(ev_type == ASYNC_TREE_APPLY_DONE_EVENT);
  AsyncFuseFsCopytreeCtx *ctx = ud;
  event_handler_t cb = ctx->cb;
  void *cb_ud = ctx->cb_ud;
  free(ctx);
  /* TODO: fix error return */
  AsyncFuseFsCopytreeDoneEvent out_ev = {.error = false};
  cb(ASYNC_FUSE_FS_COPYTREE_DONE_EVENT, &out_ev, cb_ud);
}

void
async_fuse_fs_copytree(async_fuse_fs_t fs,
                       const char *src, const char *dst,
                       bool is_move,
                       event_handler_t cb, void *cb_ud) {
  AsyncFuseFsCopytreeCtx *ctx = malloc_or_abort(sizeof(*ctx));
  *ctx = (AsyncFuseFsCopytreeCtx) {
    .fs = fs,
    .src = src,
    .dst = dst,
    .is_move = is_move,
    .cb = cb,
    .cb_ud = cb_ud,
  };

  bool is_postorder = false;
  char *init_path = davfuse_util_strdup(src);
  ASSERT_NOT_NULL(init_path);
  return async_tree_apply(ctx,
                          _async_fuse_apply_copytree,
                          _async_fuse_expand_copytree,
                          (void *) init_path,
                          is_postorder,
                          _async_fuse_fs_copytree_done, ctx);
}
