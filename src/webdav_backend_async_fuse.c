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
#define _BSD_SOURCE

#include <libgen.h>

#include "async_fuse_fs.h"
#include "async_fuse_fs_helpers.h"
#include "uthread.h"
#include "util.h"
#include "webdav_server.h"

#include "webdav_backend_async_fuse.h"

enum {
  TRANSFER_BUF_SIZE = 4096,
};

typedef struct _webdav_backend_async_fuse {
  async_fuse_fs_t fuse_fs;
} WebdavBackendAsyncFuse;

static char *
path_from_uri(WebdavBackendAsyncFuse *ctx, const char *relative_uri) {
  UNUSED(ctx);
  /* TODO: no translation seems necessary yet */
  return davfuse_util_strdup(relative_uri);
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  WebdavBackendAsyncFuse *fbctx;
  bool is_move : 1;
  bool overwrite : 1;
  const char *src_relative_uri;
  const char *dst_relative_uri;
  webdav_depth_t depth;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
  char *file_path;
  char *destination_path;
  char *destination_path_copy;
  struct stat src_stat;
  struct stat dst_stat;
  bool dst_existed : 1;
  bool copy_failed : 1;
} FuseCopyMoveCtx;

UTHR_DEFINE(_fuse_copy_move_uthr) {
  UTHR_HEADER(FuseCopyMoveCtx, ctx);

  assert(ctx->depth == DEPTH_INF ||
	 (ctx->depth == DEPTH_0 && !ctx->is_move));

  webdav_error_t err;

  ctx->file_path = path_from_uri(ctx->fbctx, ctx->src_relative_uri);
  ctx->destination_path = path_from_uri(ctx->fbctx, ctx->dst_relative_uri);

  ctx->destination_path_copy = davfuse_util_strdup(ctx->destination_path);
  char *destination_path_dirname = dirname(ctx->destination_path_copy);

  /* check if destination directory exists */
  UTHR_YIELD(ctx,
             async_fuse_fs_getattr(ctx->fbctx->fuse_fs, destination_path_dirname,
                                   &ctx->src_stat,
                                   _fuse_copy_move_uthr, ctx));
  UTHR_RECEIVE_EVENT(ASYNC_FUSE_FS_GETATTR_DONE_EVENT,
                     FuseFsOpDoneEvent, getattr_done_ev);
  if (getattr_done_ev->ret) {
    err = getattr_done_ev->ret == -ENOENT
      ? WEBDAV_ERROR_DESTINATION_DOES_NOT_EXIST
      : WEBDAV_ERROR_GENERAL;
    goto done;
  }

  /* check if source exists */
  UTHR_YIELD(ctx,
             async_fuse_fs_getattr(ctx->fbctx->fuse_fs, ctx->file_path,
                                   &ctx->src_stat,
                                   _fuse_copy_move_uthr, ctx));
  UTHR_RECEIVE_EVENT(ASYNC_FUSE_FS_GETATTR_DONE_EVENT,
                     FuseFsOpDoneEvent, getattr_done_ev_2);
  if (getattr_done_ev_2->ret) {
    if (-getattr_done_ev_2->ret != ENOENT) {
      log_info("Error while calling stat(\"%s\"): %s",
	       ctx->file_path, strerror(-getattr_done_ev_2->ret));
      err = WEBDAV_ERROR_GENERAL;
    }
    else {
      err = WEBDAV_ERROR_DOES_NOT_EXIST;
    }
    goto done;
  }

  /* check if destination exists */
  UTHR_YIELD(ctx,
             async_fuse_fs_getattr(ctx->fbctx->fuse_fs, ctx->destination_path,
                                   &ctx->dst_stat,
                                   _fuse_copy_move_uthr, ctx));
  UTHR_RECEIVE_EVENT(ASYNC_FUSE_FS_GETATTR_DONE_EVENT,
                     FuseFsOpDoneEvent, getattr_done_ev_3);
  if (getattr_done_ev_3->ret && -getattr_done_ev_3->ret != ENOENT) {
    log_info("Error while calling stat(\"%s\"): %s",
	     ctx->destination_path, strerror(-getattr_done_ev_3->ret));
    err = WEBDAV_ERROR_GENERAL;
    goto done;
  }
  ctx->dst_existed = !getattr_done_ev_3->ret;

  /* kill directory if we're overwriting it */
  if (ctx->dst_existed) {
    if (!ctx->overwrite) {
      err = WEBDAV_ERROR_DESTINATION_EXISTS;
      goto done;
    }

    UTHR_YIELD(ctx,
               async_fuse_fs_rmtree(ctx->fbctx->fuse_fs, ctx->destination_path,
                                    _fuse_copy_move_uthr, ctx));
    UTHR_RECEIVE_EVENT(ASYNC_FUSE_FS_RMTREE_DONE_EVENT, void, _throw_away_ev);
    /* we ignore the error here because we rely on a subsequent failure */
    UNUSED(_throw_away_ev);
  }

  ctx->copy_failed = true;
  if (ctx->is_move) {
    /* first try moving */
    UTHR_SUBCALL(ctx,
                 async_fuse_fs_rename(ctx->fbctx->fuse_fs,
                                      ctx->file_path, ctx->destination_path,
                                      _fuse_copy_move_uthr, ctx),
                 ASYNC_FUSE_FS_RENAME_DONE_EVENT,
                 FuseFsOpDoneEvent,
                 rename_done_ev);

    if (rename_done_ev->ret < 0 && -rename_done_ev->ret != EXDEV) {
      log_info("Error while calling rename(\"%s\", \"%s\"): %s",
	       ctx->file_path, ctx->destination_path,
	       strerror(-rename_done_ev->ret));
      err = WEBDAV_ERROR_GENERAL;
      goto done;
    }

    ctx->copy_failed = rename_done_ev->ret < 0;
  }

  if (ctx->copy_failed) {
    if (ctx->depth == DEPTH_0) {
      if (S_ISDIR(ctx->src_stat.st_mode)) {
        UTHR_SUBCALL(ctx,
                     async_fuse_fs_mkdir(ctx->fbctx->fuse_fs,
                                         ctx->destination_path, 0777,
                                         _fuse_copy_move_uthr, ctx),
                     ASYNC_FUSE_FS_MKDIR_DONE_EVENT,
                     FuseFsOpDoneEvent, mkdir_done_ev);
	if (mkdir_done_ev->ret < 0) {
	  log_info("Failure to mkdir(\"%s\"): %s",
		   ctx->destination_path, strerror(-mkdir_done_ev->ret));
	  err = WEBDAV_ERROR_GENERAL;
	  goto done;
	}
      }
      else {
        UTHR_SUBCALL(ctx,
                     async_fuse_fs_copyfile(ctx->fbctx->fuse_fs,
                                            ctx->file_path, ctx->destination_path,
                                            _fuse_copy_move_uthr, ctx),
                     ASYNC_FUSE_FS_COPYFILE_DONE_EVENT,
                     FuseFsOpDoneEvent, copyfile_done_ev);
	if (copyfile_done_ev->ret < 0) {
	  log_info("Failure to copyfile(\"%s\", \"%s\"): %s",
		   ctx->file_path, ctx->destination_path,
                   strerror(-copyfile_done_ev->ret));
	  err = WEBDAV_ERROR_GENERAL;
	  goto done;
	}
      }
    }
    else {
      UTHR_SUBCALL(ctx,
                   async_fuse_fs_copytree(ctx->fbctx->fuse_fs,
                                          ctx->file_path, ctx->destination_path,
                                          ctx->is_move,
                                          _fuse_copy_move_uthr, ctx),
                   ASYNC_FUSE_FS_COPYTREE_DONE_EVENT,
                   AsyncFuseFsCopytreeDoneEvent, copytree_done_ev);
      /* we don't handle errors here yet */
      ASSERT_TRUE(!copytree_done_ev->error);
    }
  }

  err = WEBDAV_ERROR_NONE;

 done:
  free(ctx->file_path);
  free(ctx->destination_path);
  free(ctx->destination_path_copy);

  if (ctx->is_move) {
    WebdavMoveDoneEvent move_done_ev = {
      .error = err,
      /* TODO: implement */
      .failed_to_move = LINKED_LIST_INITIALIZER,
      .dst_existed = ctx->dst_existed,
    };
    UTHR_RETURN(ctx,
                ctx->cb(WEBDAV_MOVE_DONE_EVENT, &move_done_ev, ctx->cb_ud));
  }
  else {
    WebdavCopyDoneEvent copy_done_ev = {
      .error = err,
      /* TODO: implement */
      .failed_to_copy = LINKED_LIST_INITIALIZER,
      .dst_existed = ctx->dst_existed,
    };
    UTHR_RETURN(ctx,
                ctx->cb(WEBDAV_COPY_DONE_EVENT, &copy_done_ev, ctx->cb_ud));
  }

  UTHR_FOOTER();
}


void
webdav_backend_async_fuse_copy(webdav_backend_async_fuse_t backend_ctx,
                               const char *src_relative_uri, const char *dst_relative_uri,
                               bool overwrite, webdav_depth_t depth,
                               event_handler_t cb, void *cb_ud) {
  UTHR_CALL8(_fuse_copy_move_uthr, FuseCopyMoveCtx,
             .is_move = false,
             .fbctx = backend_ctx,
             .src_relative_uri = src_relative_uri,
             .dst_relative_uri = dst_relative_uri,
             .overwrite = overwrite,
             .depth = depth,
             .cb = cb,
             .cb_ud = cb_ud);
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  WebdavBackendAsyncFuse *fbctx;
  const char *relative_uri;
  event_handler_t cb;
  void *ud;
  /* ctx */
  struct stat st;
  WebdavDeleteDoneEvent ev;
  char *file_path;
} FuseDeleteCtx;

static
UTHR_DEFINE(_fuse_delete_uthr) {
  UTHR_HEADER(FuseDeleteCtx, ctx);


  ctx->file_path = path_from_uri(ctx->fbctx, ctx->relative_uri);
  if (!ctx->file_path) {
    ctx->ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  UTHR_SUBCALL(ctx,
               async_fuse_fs_getattr(ctx->fbctx->fuse_fs,
                                     ctx->file_path, &ctx->st,
                                     _fuse_delete_uthr, ctx),
               ASYNC_FUSE_FS_GETATTR_DONE_EVENT,
               FuseFsOpDoneEvent,
               getattr_done_ev);
  if (getattr_done_ev->ret < 0) {
    ctx->ev.error = -getattr_done_ev->ret == ENOENT
      ? WEBDAV_ERROR_DOES_NOT_EXIST
      : WEBDAV_ERROR_GENERAL;
    goto done;
  }

  UTHR_SUBCALL(ctx,
               async_fuse_fs_rmtree(ctx->fbctx->fuse_fs,
                                    ctx->file_path,
                                    _fuse_delete_uthr, ctx),
               ASYNC_FUSE_FS_RMTREE_DONE_EVENT,
               AsyncFuseFsRmtreeDoneEvent, rmtree_done_ev);
  ctx->ev = (WebdavDeleteDoneEvent) {
    .error = (rmtree_done_ev->failed_to_delete
              ? WEBDAV_ERROR_GENERAL
              : WEBDAV_ERROR_NONE),
    .failed_to_delete = rmtree_done_ev->failed_to_delete,
  };

 done:
  free(ctx->file_path);

  UTHR_RETURN(ctx,
              ctx->cb(WEBDAV_DELETE_DONE_EVENT, &ctx->ev, ctx->ud));

  UTHR_FOOTER();
}

void
webdav_backend_async_fuse_delete(webdav_backend_async_fuse_t backend_ctx,
                                 const char *relative_uri,
                                 event_handler_t cb, void *ud) {
  UTHR_CALL4(_fuse_delete_uthr, FuseDeleteCtx,
             .fbctx = backend_ctx,
             .relative_uri = relative_uri,
             .cb = cb,
             .ud = ud);
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  WebdavBackendAsyncFuse *fbctx;
  const char *relative_uri;
  webdav_get_request_ctx_t get_ctx;
  /* ctx */
  struct fuse_file_info fi;
  bool opened_file;
  char *path;
  webdav_error_t error;
  struct stat st;
  char buf[TRANSFER_BUF_SIZE];
  off_t offset;
  int amount_read;
} FuseGetCtx;

static
UTHR_DEFINE(_fuse_get_uthr) {
  UTHR_HEADER(FuseGetCtx, ctx);

  ctx->path = path_from_uri(ctx->fbctx, ctx->relative_uri);
  if (!ctx->path) {
    ctx->error = WEBDAV_ERROR_NO_MEM;
    goto done;
  }

  UTHR_SUBCALL(ctx,
               async_fuse_fs_open(ctx->fbctx->fuse_fs,
                                  ctx->path, &ctx->fi,
                                  _fuse_get_uthr, ctx),
               ASYNC_FUSE_FS_OPEN_DONE_EVENT,
               FuseFsOpDoneEvent, open_done_ev);
  if (open_done_ev->ret < 0) {
    if (-open_done_ev->ret != ENOENT) {
      log_warning("Error during open(\"%s\"): %s",
                  ctx->path, strerror(-open_done_ev->ret));
      ctx->error = WEBDAV_ERROR_GENERAL;
    }
    else {
      ctx->error =WEBDAV_ERROR_DOES_NOT_EXIST;
    }
    goto done;
  }

  ctx->opened_file = true;

  UTHR_SUBCALL(ctx,
               async_fuse_fs_fgetattr(ctx->fbctx->fuse_fs,
                                      ctx->path, &ctx->st,
                                      &ctx->fi,
                                      _fuse_get_uthr, ctx),
               ASYNC_FUSE_FS_FGETATTR_DONE_EVENT,
               FuseFsOpDoneEvent, fgetattr_done_ev);
  if (fgetattr_done_ev->ret < 0) {
    log_warning("Error during fgetattr(\"%s\"): %s",
                ctx->path, strerror(-fgetattr_done_ev->ret));
    ctx->error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  if (S_ISDIR(ctx->st.st_mode)) {
    ctx->error = WEBDAV_ERROR_IS_COL;
    goto done;
  }

  log_debug("We plan to send %jd bytes during GET",
            (intmax_t) ctx->st.st_size);
  assert(ctx->st.st_size >= 0);
  UTHR_SUBCALL(ctx,
               webdav_get_request_size_hint(ctx->get_ctx, ctx->st.st_size,
                                            _fuse_get_uthr, ctx),
               WEBDAV_GET_REQUEST_SIZE_HINT_DONE_EVENT,
               WebdavGetRequestSizeHintDoneEvent, size_hint_done_ev);
  if (size_hint_done_ev->error) {
    ctx->error = size_hint_done_ev->error;
    goto done;
  }

  ctx->offset = 0;
  while (true) {
    UTHR_SUBCALL(ctx,
                 async_fuse_fs_read(ctx->fbctx->fuse_fs,
                                    ctx->path,
                                    ctx->buf, sizeof(ctx->buf),
                                    ctx->offset, &ctx->fi,
                                    _fuse_get_uthr, ctx),
                 ASYNC_FUSE_FS_READ_DONE_EVENT,
                 FuseFsOpDoneEvent, read_done_ev);
    log_debug("During get, read got %d bytes", read_done_ev->ret);
    if (read_done_ev->ret < 0) {
      log_warning("Error while doing read from fuse file system: %s",
                  strerror(-read_done_ev->ret));
      ctx->error = WEBDAV_ERROR_GENERAL;
      goto done;
    }
    else if (!read_done_ev->ret) {
      break;
    }

    ctx->amount_read = read_done_ev->ret;
    UTHR_SUBCALL(ctx,
                 webdav_get_request_write(ctx->get_ctx,
                                          ctx->buf, ctx->amount_read,
                                          _fuse_get_uthr, ctx),
                 WEBDAV_GET_REQUEST_WRITE_DONE_EVENT,
                 WebdavGetRequestWriteDoneEvent, write_done_ev);
    if (write_done_ev->error) {
      log_warning("Error while sending data to client");
      ctx->error = write_done_ev->error;
      goto done;
    }

    ctx->offset += ctx->amount_read;
  }

  log_debug("We sent a total of %jd bytes", (intmax_t) ctx->offset);
  ctx->error = WEBDAV_ERROR_NONE;

 done:
  if (ctx->opened_file) {
    UTHR_SUBCALL(ctx,
                 async_fuse_fs_release(ctx->fbctx->fuse_fs,
                                       ctx->path, &ctx->fi,
                                       _fuse_get_uthr, ctx),
                 ASYNC_FUSE_FS_RELEASE_DONE_EVENT,
                 FuseFsOpDoneEvent,
                 release_done_ev);
    if (release_done_ev->ret < 0) {
      /* the return value of release is always ignored in the FUSE API,
         but just in case
      */
      log_warning("Error while releasing \"%s\": %s",
                  ctx->path, strerror(-release_done_ev->ret));
    }
  }

  log_debug("Fuse Put Request is over: %s", ctx->path);

  free(ctx->path);

  UTHR_RETURN(ctx,
              webdav_get_request_end(ctx->get_ctx, ctx->error));


  UTHR_FOOTER();
}

void
webdav_backend_async_fuse_get(webdav_backend_async_fuse_t backend_ctx,
                              const char *relative_uri,
                              webdav_get_request_ctx_t get_ctx) {
  UTHR_CALL3(_fuse_get_uthr, FuseGetCtx,
             .fbctx = backend_ctx,
             .relative_uri = relative_uri,
             .get_ctx = get_ctx);
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  WebdavBackendAsyncFuse *fbctx;
  const char *relative_uri;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
  char *path;
  WebdavMkcolDoneEvent ev;
} FuseMkcolCtx;

static
UTHR_DEFINE(_fuse_mkcol_uthr) {
  UTHR_HEADER(FuseMkcolCtx, ctx);

  ctx->path = path_from_uri(ctx->fbctx, ctx->relative_uri);
  if (!ctx->path) {
    ctx->ev.error = WEBDAV_ERROR_NO_MEM;
    goto done;
  }

  UTHR_SUBCALL(ctx,
               async_fuse_fs_mkdir(ctx->fbctx->fuse_fs,
                                   ctx->path, 0777,
                                   _fuse_mkcol_uthr, ctx),
               ASYNC_FUSE_FS_MKDIR_DONE_EVENT,
               FuseFsOpDoneEvent,
               mkdir_done_ev);
  if (!mkdir_done_ev->ret) {
    ctx->ev.error = WEBDAV_ERROR_NONE;
  }
  else if (-mkdir_done_ev->ret == ENOENT) {
    ctx->ev.error = WEBDAV_ERROR_DOES_NOT_EXIST;
  }
  else if (-mkdir_done_ev->ret == ENOSPC ||
           -mkdir_done_ev->ret == EDQUOT) {
    ctx->ev.error = WEBDAV_ERROR_NO_SPACE;
  }
  else if (-mkdir_done_ev->ret == ENOTDIR) {
    ctx->ev.error = WEBDAV_ERROR_NOT_COLLECTION;
  }
  else if (-mkdir_done_ev->ret == EACCES) {
    ctx->ev.error = WEBDAV_ERROR_PERM;
  }
  else if (-mkdir_done_ev->ret == EEXIST) {
    ctx->ev.error = WEBDAV_ERROR_EXISTS;
  }
  else {
    ctx->ev.error = WEBDAV_ERROR_GENERAL;
  }

 done:
  free(ctx->path);

  UTHR_RETURN(ctx,
              ctx->cb(WEBDAV_MKCOL_DONE_EVENT, &ctx->ev, ctx->cb_ud));

  UTHR_FOOTER();
}

void
webdav_backend_async_fuse_mkcol(webdav_backend_async_fuse_t backend_ctx,
                                const char *relative_uri,
                                event_handler_t cb, void *cb_ud) {
  UTHR_CALL4(_fuse_mkcol_uthr, FuseMkcolCtx,
             .fbctx = backend_ctx,
             .relative_uri = relative_uri,
             .cb = cb,
             .cb_ud = cb_ud);
}

void
webdav_backend_async_fuse_move(webdav_backend_async_fuse_t backend_ctx,
                               const char *src_relative_uri, const char *dst_relative_uri,
                               bool overwrite,
                               event_handler_t cb, void *cb_ud) {
  UTHR_CALL8(_fuse_copy_move_uthr, FuseCopyMoveCtx,
             .is_move = true,
             .depth = DEPTH_INF,
             .fbctx = backend_ctx,
             .src_relative_uri = src_relative_uri,
             .dst_relative_uri = dst_relative_uri,
             .overwrite = overwrite,
             .cb = cb,
             .cb_ud = cb_ud);
}

static webdav_propfind_entry_t
create_propfind_entry_from_stat(const char *relative_uri, struct stat *st) {
  return webdav_new_propfind_entry(relative_uri,
                                   st->st_mtime,
                                   /* mod_dav from apache also uses mtime as creation time */
                                   st->st_mtime,
                                   S_ISDIR(st->st_mode),
                                   st->st_size);
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  WebdavBackendAsyncFuse *fbctx;
  const char *relative_uri;
  webdav_depth_t depth;
  webdav_propfind_req_type_t propfind_req_type;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
  bool is_dir : 1;
  bool valid_handle : 1;
  WebdavPropfindDoneEvent ev;
  linked_list_t to_getattr;
  linked_list_t to_getattr_iter;
  linked_list_t entries;
  char *file_path;
  size_t file_path_len;
  struct stat scratch_st;
} FusePropfindCtx;

static int
_fuse_propfind_dirfil_fn(fuse_dirh_t h,
                         const char *name,
                         int type,
                         ino_t ino) {
  UNUSED(type);
  UNUSED(ino);

  if (str_equals(name, "..") ||
      str_equals(name, ".")) {
    return 0;
  }

  FusePropfindCtx *ctx = (FusePropfindCtx *) h;

  size_t name_len = strlen(name);
  assert(name_len);

  assert(ctx->file_path_len);

  char *new_uri;
  if (str_equals(ctx->file_path, "/")) {
    new_uri = malloc_or_abort(1 + name_len + 1);
    new_uri[0] = '/';
    memcpy(&new_uri[1], name, name_len);
    new_uri[name_len + 1] = '\0';
  }
  else {
    /* NB: intentionally don't use `asprintf()` */
    new_uri = malloc_or_abort(ctx->file_path_len + 1 + name_len + 1);
    memcpy(new_uri, ctx->file_path, ctx->file_path_len);
    new_uri[ctx->file_path_len] = '/';
    memcpy(new_uri + ctx->file_path_len + 1, name, name_len);
    new_uri[ctx->file_path_len + 1 + name_len] = '\0';
  }

  ctx->to_getattr = linked_list_prepend(ctx->to_getattr, new_uri);

  return 0;
}

static
UTHR_DEFINE(_fuse_propfind_uthr) {
  UTHR_HEADER(FusePropfindCtx, ctx);

  /* TODO: support this */
  if (ctx->depth == DEPTH_INF) {
    log_info("We don't support infinity propfind requests");
    ctx->ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  /* TODO: support this */
  if (ctx->propfind_req_type != WEBDAV_PROPFIND_PROP &&
      ctx->propfind_req_type != WEBDAV_PROPFIND_ALLPROP) {
    log_info("We don't support 'propname' requests");
    ctx->ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  ctx->file_path = path_from_uri(ctx->fbctx, ctx->relative_uri);
  if (!ctx->file_path) {
    log_info("Couldn't make file path from \"%s\'", ctx->file_path);
    ctx->ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  ctx->file_path_len = strlen(ctx->file_path);

  ctx->to_getattr = linked_list_prepend(ctx->to_getattr, ctx->file_path);

  if (ctx->depth == DEPTH_1) {
    /* add more things to ctx->to_getattr if the client is
       interested in more depth */
    UTHR_SUBCALL(ctx,
                 async_fuse_fs_getdir(ctx->fbctx->fuse_fs,
                                      ctx->file_path, (void *) ctx,
                                      _fuse_propfind_dirfil_fn,
                                      _fuse_propfind_uthr, ctx),
                 ASYNC_FUSE_FS_GETDIR_DONE_EVENT,
                 FuseFsOpDoneEvent,
                 getdir_done_ev);
    if (getdir_done_ev->ret < 0 && -getdir_done_ev->ret != ENOTDIR) {
      log_info("Couldn't do getdir on \"%s\": %s",
               ctx->file_path, strerror(-getdir_done_ev->ret));
      ctx->ev.error = -getdir_done_ev->ret == ENOENT
        ? WEBDAV_ERROR_DOES_NOT_EXIST
        : WEBDAV_ERROR_GENERAL;
      goto done;
    }

    /* now everything in `to_getattr` should exist,
       errors while doing getattr are unexpected */

    /* now for every path in ctx->to_getattr, add the info */
    for (ctx->to_getattr_iter = ctx->to_getattr; ctx->to_getattr_iter;
         ctx->to_getattr_iter = ctx->to_getattr_iter->next) {
      UTHR_SUBCALL(ctx,
                   async_fuse_fs_getattr(ctx->fbctx->fuse_fs,
                                         ctx->to_getattr_iter->elt,
                                         &ctx->scratch_st,
                                         _fuse_propfind_uthr, ctx),
                   ASYNC_FUSE_FS_GETATTR_DONE_EVENT,
                   FuseFsOpDoneEvent,
                   getattr_done_ev);
      if (getattr_done_ev->ret < 0) {
        log_info("Couldn't do getattr on \"%s\": %s",
                 (char *) ctx->to_getattr_iter->elt,
                 strerror(-getattr_done_ev->ret));
        ctx->ev.error = WEBDAV_ERROR_GENERAL;
        goto done;
      }

      webdav_propfind_entry_t pfe =
        create_propfind_entry_from_stat(ctx->to_getattr_iter->elt,
                                        &ctx->scratch_st);
      ASSERT_TRUE(pfe);
      ctx->ev.entries = linked_list_prepend(ctx->ev.entries, pfe);
    }
  }
  else {
    /* if no depth is request, then just check this one path */
    UTHR_SUBCALL(ctx,
                 async_fuse_fs_getattr(ctx->fbctx->fuse_fs,
                                       ctx->file_path,
                                       &ctx->scratch_st,
                                       _fuse_propfind_uthr, ctx),
                 ASYNC_FUSE_FS_GETATTR_DONE_EVENT,
                 FuseFsOpDoneEvent,
                 getattr_done_ev);
    if (getattr_done_ev->ret < 0) {
      log_info("Couldn't do getattr on \"%s\": %s",
               ctx->file_path, strerror(-getattr_done_ev->ret));
      ctx->ev.error = -getattr_done_ev->ret == ENOENT
        ? WEBDAV_ERROR_DOES_NOT_EXIST
        : WEBDAV_ERROR_GENERAL;
      goto done;
    }

    webdav_propfind_entry_t pfe =
      create_propfind_entry_from_stat(ctx->file_path,
                                      &ctx->scratch_st);
    ASSERT_TRUE(pfe);
    ctx->ev.entries = linked_list_prepend(ctx->ev.entries, pfe);
  }

  ctx->ev.error = WEBDAV_ERROR_NONE;

 done:
  linked_list_free(ctx->to_getattr, free);
  /* don't need to do this cuz  this happens in the previous line: */
  /*  free(ctx->file_path); */

  if (ctx->ev.error) {
    linked_list_free(ctx->ev.entries,
                     (linked_list_elt_handler_t) webdav_destroy_propfind_entry);
  }


  UTHR_RETURN(ctx,
              ctx->cb(WEBDAV_PROPFIND_DONE_EVENT, &ctx->ev, ctx->cb_ud));

  UTHR_FOOTER();
}

void
webdav_backend_async_fuse_propfind(webdav_backend_async_fuse_t backend_ctx,
                                   const char *relative_uri, webdav_depth_t depth,
                                   webdav_propfind_req_type_t propfind_req_type,
                                   event_handler_t cb, void *cb_ud) {
  UTHR_CALL6(_fuse_propfind_uthr, FusePropfindCtx,
             .fbctx = backend_ctx,
             .relative_uri = relative_uri,
             .depth = depth,
             .propfind_req_type = propfind_req_type,
             .cb = cb,
             .cb_ud = cb_ud);
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  WebdavBackendAsyncFuse *fbctx;
  const char *relative_uri;
  webdav_put_request_ctx_t put_ctx;
  /* ctx */
  bool opened_file : 1;
  bool resource_existed : 1;
  webdav_error_t error;
  struct fuse_file_info fi;
  char *file_path;
  size_t amount_read;
  size_t amount_written;
  size_t total_amount_transferred;
  char buf[TRANSFER_BUF_SIZE];
} FusePutCtx;

UTHR_DEFINE(_fuse_put_uthr) {
  UTHR_HEADER(FusePutCtx, ctx);

  ctx->file_path = path_from_uri(ctx->fbctx, ctx->relative_uri);
  if (!ctx->file_path) {
    ctx->error = WEBDAV_ERROR_NO_MEM;;
    goto done;
  }

  /* first try to create the file normally, if it already exists nbd */
  UTHR_SUBCALL(ctx,
               async_fuse_fs_mknod(ctx->fbctx->fuse_fs,
                                   ctx->file_path, S_IFREG | 0666, 0,
                                   _fuse_put_uthr, ctx),
               ASYNC_FUSE_FS_MKNOD_DONE_EVENT,
               FuseFsOpDoneEvent, mknod_done_ev);
  if (mknod_done_ev->ret < 0 &&
      -mknod_done_ev->ret != EEXIST) {
    ctx->error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  ctx->resource_existed = mknod_done_ev->ret;

  ctx->fi.flags = O_WRONLY | O_TRUNC;
  UTHR_SUBCALL(ctx,
               async_fuse_fs_open(ctx->fbctx->fuse_fs,
                                  ctx->file_path, &ctx->fi,
                                  _fuse_put_uthr, ctx),
               ASYNC_FUSE_FS_OPEN_DONE_EVENT,
               FuseFsOpDoneEvent, open_done_ev);
  if (open_done_ev->ret < 0) {
    log_info("Error opening \"%s\" (%s)",
             ctx->file_path, strerror(-open_done_ev->ret));
    switch (errno) {
    case ENOENT: ctx->error = WEBDAV_ERROR_DOES_NOT_EXIST; break;
    case ENOTDIR: ctx->error = WEBDAV_ERROR_NOT_COLLECTION; break;
    case EISDIR: ctx->error = WEBDAV_ERROR_IS_COL; break;
    default: ctx->error = WEBDAV_ERROR_GENERAL; break;
    }
    goto done;
  }

  ctx->opened_file = true;

  ctx->total_amount_transferred = 0;
  while (true) {
    log_debug("put: waiting on read");
    UTHR_SUBCALL(ctx,
                 webdav_put_request_read(ctx->put_ctx,
                                         ctx->buf, sizeof(ctx->buf),
                                         _fuse_put_uthr, ctx),
                 WEBDAV_PUT_REQUEST_READ_DONE_EVENT,
                 WebdavPutRequestReadDoneEvent, read_done_ev);
    if (read_done_ev->error) {
      log_error("Error while reading the webdav request!");
      ctx->error = read_done_ev->error;
      goto done;
    }

    /* EOF */
    if (!read_done_ev->nbyte) {
      break;
    }

    log_debug("put: waiting on write");
    UTHR_SUBCALL(ctx,
                 async_fuse_fs_write(ctx->fbctx->fuse_fs,
                                     ctx->file_path, ctx->buf, read_done_ev->nbyte,
                                     ctx->total_amount_transferred, &ctx->fi,
                                     _fuse_put_uthr, ctx),
                 ASYNC_FUSE_FS_WRITE_DONE_EVENT,
                 FuseFsOpDoneEvent, write_done_ev);
    if (write_done_ev->ret < 0) {
      log_error("Couldn't write to resource \"%s\": %s",
                ctx->file_path, strerror(-write_done_ev->ret));
      ctx->error = WEBDAV_ERROR_GENERAL;
      goto done;
    }

    ctx->total_amount_transferred += write_done_ev->ret;
  }

  log_info("Resource \"%s\" created with %zu bytes",
           ctx->file_path, ctx->total_amount_transferred);
  ctx->error = WEBDAV_ERROR_NONE;

 done:
  if (ctx->opened_file) {
    UTHR_SUBCALL(ctx,
                 async_fuse_fs_release(ctx->fbctx->fuse_fs,
                                       ctx->file_path, &ctx->fi,
                                       _fuse_put_uthr, ctx),
                 ASYNC_FUSE_FS_RELEASE_DONE_EVENT,
                 FuseFsOpDoneEvent,
                 release_done_ev);
    if (release_done_ev->ret < 0) {
      /* the return value of release is always ignored in the FUSE API,
         but just in case
      */
      log_warning("Error while releasing \"%s\": %s",
                  ctx->file_path, strerror(-release_done_ev->ret));
    }
  }

  free(ctx->file_path);

  UTHR_RETURN(ctx,
              webdav_put_request_end(ctx->put_ctx, ctx->error, ctx->resource_existed));

  UTHR_FOOTER();
}

void
webdav_backend_async_fuse_put(webdav_backend_async_fuse_t backend_ctx,
                              const char *relative_uri,
                              webdav_put_request_ctx_t put_ctx) {
  UTHR_CALL3(_fuse_put_uthr, FusePutCtx,
             .fbctx = backend_ctx,
             .relative_uri = relative_uri,
             .put_ctx = put_ctx);
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  WebdavBackendAsyncFuse *fbctx;
  const char *relative_uri;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
  char *file_path;
  WebdavTouchDoneEvent ev;
} FuseTouchCtx;

UTHR_DEFINE(_fuse_touch_uthr) {
  UTHR_HEADER(FuseTouchCtx, ctx);

  ctx->file_path = path_from_uri(ctx->fbctx, ctx->relative_uri);
  if (!ctx->file_path) {
    ctx->ev.error = WEBDAV_ERROR_NO_MEM;;
    goto done;
  }

  /* first try to create the file normally, if it already exists nbd */
  UTHR_SUBCALL(ctx,
               async_fuse_fs_mknod(ctx->fbctx->fuse_fs,
                                   ctx->file_path, S_IFREG | 0666, 0,
                                   _fuse_touch_uthr, ctx),
               ASYNC_FUSE_FS_MKNOD_DONE_EVENT,
               FuseFsOpDoneEvent, mknod_done_ev);
  if (mknod_done_ev->ret < 0 &&
      -mknod_done_ev->ret != EEXIST) {
    log_info("Error doing mknode \"%s\" (%s)",
             ctx->file_path, strerror(-mknod_done_ev->ret));
    ctx->ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  ctx->ev = (WebdavTouchDoneEvent) {
    .error = WEBDAV_ERROR_NONE,
    .resource_existed = mknod_done_ev->ret,
  };

 done:
  free(ctx->file_path);

  UTHR_RETURN(ctx,
              ctx->cb(WEBDAV_TOUCH_DONE_EVENT, &ctx->ev, ctx->cb_ud));

  UTHR_FOOTER();
}

void
webdav_backend_async_fuse_touch(webdav_backend_async_fuse_t backend_ctx,
                                const char *relative_uri,
                                event_handler_t cb, void *cb_ud) {
  UTHR_CALL4(_fuse_touch_uthr, FuseTouchCtx,
             .fbctx = backend_ctx,
             .relative_uri = relative_uri,
             .cb = cb,
             .cb_ud = cb_ud);
}

webdav_backend_async_fuse_t
webdav_backend_async_fuse_new(async_fuse_fs_t fs) {
  WebdavBackendAsyncFuse *ret = malloc(sizeof(*ret));
  if (!ret) {
    return NULL;
  }

  *ret = (WebdavBackendAsyncFuse) {
    .fuse_fs = fs,
  };

  return ret;
}

bool
webdav_backend_async_fuse_destroy(webdav_backend_async_fuse_t backend) {
  free(backend);
  return true;
}
