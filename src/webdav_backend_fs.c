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

#include <stdlib.h>
#include <string.h>

#include "iface_util.h"
#include "fs.h"
#include "uthread.h"
#include "util.h"
#include "util_fs.h"
#include "webdav_server.h"

#include "webdav_backend_fs.h"

enum {
  //  TRANSFER_BUF_SIZE=4096,
  TRANSFER_BUF_SIZE=16 * 4096,
};

typedef struct _webdav_backend_fs {
  fs_handle_t fs;
  char *base_path;
  size_t base_path_len;
} WebdavBackendFs;

static char *
path_from_uri(WebdavBackendFs *pbctx, const char *real_uri) {
  char *toret = NULL;

  assert(str_startswith(real_uri, "/"));

  toret = davfuse_util_strdup(pbctx->base_path);
  if (!toret) goto err;

  if (str_equals(real_uri, "/")) return toret;

  const char *start_of_dirname = real_uri;
  while (*start_of_dirname) {
    start_of_dirname += 1;

    const char *next = strchr(start_of_dirname, '/');
    if (!next) next = start_of_dirname + strlen(start_of_dirname);

    char *path_comp = malloc(next - start_of_dirname + 1);
    if (!path_comp) goto err;

    memcpy(path_comp, start_of_dirname, next - start_of_dirname);
    path_comp[next - start_of_dirname] = '\0';

    char *newtoret = util_fs_path_join(pbctx->fs, toret, path_comp);
    free(path_comp);

    if (!newtoret) goto err;
    free(toret);
    toret = newtoret;

    start_of_dirname = next;
  }

  if (false) {
  err:
    free(toret);
    toret = NULL;
  }

  return toret;
}

webdav_backend_fs_t
webdav_backend_fs_new(fs_handle_t fs, const char *root) {
  char *base_path = NULL;

  if (!fs_path_is_valid(fs, root)) {
    log_info("Bad input path: %s", root);
    return NULL;
  }

  WebdavBackendFs *backend = malloc(sizeof(*backend));
  if (!backend) {
    return NULL;
  }

  base_path = davfuse_util_strdup(root);
  if (!base_path) {
    goto error;
  }

  *backend = (WebdavBackendFs) {
    .fs = fs,
    .base_path = base_path,
    .base_path_len = strlen(base_path),
  };

  return backend;

 error:
  free(base_path);
  free(backend);
  return NULL;
}


typedef struct {
  UTHR_CTX_BASE;
  /* args */
  WebdavBackendFs *pbctx;
  const char *relative_uri;
  webdav_get_request_ctx_t get_ctx;
  /* ctx */
  char *file_path;
  char buf[TRANSFER_BUF_SIZE];
  fs_file_handle_t fd;
  fs_off_t offset;
  size_t amt_read;
} WebdavBackendFsGetCtx;

static
UTHR_DEFINE(_webdav_backend_fs_get_uthr) {
  webdav_error_t error;

  UTHR_HEADER(WebdavBackendFsGetCtx, ctx);

  ctx->fd = (fs_file_handle_t) 0;

  ctx->file_path = path_from_uri(ctx->pbctx, ctx->relative_uri);
  if (!ctx->file_path) {
    error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  const bool create_file = false;
  const fs_error_t ret_open = fs_open(ctx->pbctx->fs, ctx->file_path,
                                      create_file, &ctx->fd, NULL);
  if (ret_open) {
    if (ret_open == FS_ERROR_IS_DIR) {
      /* TODO: maybe generate directory listing */
      error = WEBDAV_ERROR_IS_COL;
    }
    else {
      error = ret_open == FS_ERROR_DOES_NOT_EXIST
        ? WEBDAV_ERROR_DOES_NOT_EXIST
        : WEBDAV_ERROR_GENERAL;
    }
    goto done;
  }

  /* need to initialize `is_directory` & `size` to avoid spurious
     -Wmaybe-uninitialized warnings from GCC */
  FsAttrs attrs = {
    .size = 0,
    .is_directory = false,
  };
  const fs_error_t ret_fgetattr = fs_fgetattr(ctx->pbctx->fs, ctx->fd, &attrs);
  if (ret_fgetattr) {
    error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  /* this should never happen */
  ASSERT_TRUE(!attrs.is_directory);

  /* write out the size hint */
  /* TODO: remove this, the file might end up
     being larger or smaller than this */
  UTHR_YIELD(ctx,
             webdav_get_request_size_hint(ctx->get_ctx, attrs.size,
                                          _webdav_backend_fs_get_uthr, ctx));
  UTHR_RECEIVE_EVENT(WEBDAV_GET_REQUEST_SIZE_HINT_DONE_EVENT,
                     WebdavGetRequestSizeHintDoneEvent, size_hint_ev);
  if (size_hint_ev->error) {
    error = size_hint_ev->error;
    goto done;
  }

  ctx->offset = 0;
  while (true) {
    const fs_error_t read_ret = fs_read(ctx->pbctx->fs, ctx->fd,
                                        ctx->buf, sizeof(ctx->buf), ctx->offset,
                                        &ctx->amt_read);
    if (read_ret) {
      log_error("Error while reading from %s at offset %d: %s",
                ctx->file_path, (int) ctx->offset,
                util_fs_strerror(read_ret));
      error = WEBDAV_ERROR_GENERAL;
      goto done;
    }

    if (!ctx->amt_read) {
      /* EOF */
      break;
    }

    UTHR_YIELD(ctx,
               webdav_get_request_write(ctx->get_ctx, ctx->buf, ctx->amt_read,
                                        _webdav_backend_fs_get_uthr, ctx));
    UTHR_RECEIVE_EVENT(WEBDAV_GET_REQUEST_WRITE_DONE_EVENT,
                       WebdavGetRequestWriteDoneEvent, write_done_ev);
    if (write_done_ev->error) {
      error = write_done_ev->error;
      goto done;
    }

    ctx->offset += ctx->amt_read;
  }

  error = WEBDAV_ERROR_NONE;

 done:
  if (ctx->fd) {
    const fs_error_t ret_close = fs_close(ctx->pbctx->fs, ctx->fd);
    ASSERT_TRUE(!ret_close);
  }

  free(ctx->file_path);

  UTHR_RETURN(ctx,
              webdav_get_request_end(ctx->get_ctx, error));

  UTHR_FOOTER();
}

void
webdav_backend_fs_get(WebdavBackendFs *backend_handle, const char *relative_uri,
                      webdav_get_request_ctx_t get_ctx) {
  UTHR_CALL3(_webdav_backend_fs_get_uthr, WebdavBackendFsGetCtx,
             .pbctx = backend_handle,
             .relative_uri = relative_uri,
             .get_ctx = get_ctx);
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  WebdavBackendFs *pbctx;
  const char *relative_uri;
  webdav_put_request_ctx_t put_ctx;
  /* ctx */
  fs_file_handle_t fd;
  char *file_path;
  bool resource_existed;
  size_t total_amount_transferred;
  char buf[TRANSFER_BUF_SIZE];
} WebdavBackendFsPutCtx;

static
UTHR_DEFINE(_webdav_backend_fs_put_uthr) {
  UTHR_HEADER(WebdavBackendFsPutCtx, ctx);

  webdav_error_t error;

  ctx->fd = (fs_file_handle_t) 0;

  ctx->file_path = path_from_uri(ctx->pbctx, ctx->relative_uri);
  if (!ctx->file_path) {
    error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  bool created;
  bool create = true;
  const fs_error_t ret_open =
    fs_open(ctx->pbctx->fs, ctx->file_path,
            create, &ctx->fd, &created);
  if (ret_open) {
    log_info("Error opening \"%s\": %s", ctx->file_path,
             util_fs_strerror(ret_open));
    switch (ret_open) {
    case FS_ERROR_DOES_NOT_EXIST: error = WEBDAV_ERROR_DOES_NOT_EXIST; break;
    case FS_ERROR_NOT_DIR: error = WEBDAV_ERROR_NOT_COLLECTION; break;
    case FS_ERROR_IS_DIR: error = WEBDAV_ERROR_IS_COL; break;
    default: error = WEBDAV_ERROR_GENERAL; break;
    }
    goto done;
  }

  ctx->resource_existed = !created;

  const fs_error_t ret_truncate =
    fs_ftruncate(ctx->pbctx->fs, ctx->fd, 0);
  if (ret_truncate) {
    log_info("Error truncated \"%s\": %s", ctx->file_path,
             util_fs_strerror(ret_truncate));
    error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  ctx->total_amount_transferred = 0;
  while (true) {
    UTHR_YIELD(ctx,
               webdav_put_request_read(ctx->put_ctx,
                                       ctx->buf, sizeof(ctx->buf),
                                       _webdav_backend_fs_put_uthr, ctx));
    UTHR_RECEIVE_EVENT(WEBDAV_PUT_REQUEST_READ_DONE_EVENT,
                       WebdavPutRequestReadDoneEvent,
                       read_done_ev);
    if (read_done_ev->error) {
      log_info("Error while reading data for %s: %d",
               ctx->relative_uri, read_done_ev->error);
      error = read_done_ev->error;
      goto done;
    }

    /* EOF */
    if (!read_done_ev->nbyte) {
      break;
    }

    const size_t amount_read = read_done_ev->nbyte;
    size_t amount_written = 0;
    while (amount_written < amount_read) {
      /* need to initialize `new_amount_written` to avoid
         spurious -Wmaybe-uninitialized warnings from GCC */
      size_t new_amount_written = 0;
      const fs_error_t ret_write = fs_write(ctx->pbctx->fs, ctx->fd,
                                            ctx->buf + amount_written,
                                            amount_read - amount_written,
                                            amount_written + ctx->total_amount_transferred,
                                            &new_amount_written);
      if (ret_write) {
        log_error("Couldn't write to resource \"%s\" (fd: %p)",
                  ctx->relative_uri, (void *) ctx->fd);
        error = WEBDAV_ERROR_GENERAL;
        goto done;
      }

      assert(new_amount_written);
      amount_written += new_amount_written;
    }

    assert(amount_written == amount_read);
    ctx->total_amount_transferred += amount_written;
  }

  log_info("Resource \"%s\" created with %lu bytes",
           ctx->relative_uri,
           (unsigned long) ctx->total_amount_transferred);
  error = WEBDAV_ERROR_NONE;

 done:
  free(ctx->file_path);

  if (ctx->fd) {
    const fs_error_t ret_close = fs_close(ctx->pbctx->fs, ctx->fd);
    ASSERT_TRUE(!ret_close);
  }

  UTHR_RETURN(ctx,
              webdav_put_request_end(ctx->put_ctx, error, ctx->resource_existed));

  UTHR_FOOTER();
}

void
webdav_backend_fs_put(WebdavBackendFs *backend_handle, const char *relative_uri,
                      webdav_put_request_ctx_t put_ctx) {
  UTHR_CALL3(_webdav_backend_fs_put_uthr, WebdavBackendFsPutCtx,
             .pbctx = backend_handle,
             .relative_uri = relative_uri,
             .put_ctx = put_ctx);
}

void
webdav_backend_fs_mkcol(webdav_backend_fs_t backend_handle, const char *relative_uri,
                        event_handler_t cb, void *ud) {
  WebdavMkcolDoneEvent ev;
  WebdavBackendFs *const pbctx = backend_handle;

  char *const file_path = path_from_uri(pbctx, relative_uri);
  if (!file_path) {
    ev.error = WEBDAV_ERROR_NO_MEM;
    goto done;
  }

  const fs_error_t ret_mkdir = fs_mkdir(pbctx->fs, file_path);
  if (ret_mkdir) {
    if (ret_mkdir == FS_ERROR_DOES_NOT_EXIST) {
      ev.error = WEBDAV_ERROR_DOES_NOT_EXIST;
    }
    else if (ret_mkdir == FS_ERROR_NO_SPACE) {
      ev.error = WEBDAV_ERROR_NO_SPACE;
    }
    else if (ret_mkdir == FS_ERROR_NOT_DIR) {
      ev.error = WEBDAV_ERROR_NOT_COLLECTION;
    }
    else if (ret_mkdir == FS_ERROR_PERM) {
      ev.error = WEBDAV_ERROR_PERM;
    }
    else if (ret_mkdir == FS_ERROR_EXISTS) {
      ev.error = WEBDAV_ERROR_EXISTS;
    }
    else {
      ev.error = WEBDAV_ERROR_GENERAL;
    }
  }
  else {
    ev.error = WEBDAV_ERROR_NONE;
  }

 done:
  free(file_path);
  return cb(WEBDAV_MKCOL_DONE_EVENT, &ev, ud);
}

static webdav_propfind_entry_t
create_propfind_entry_from_stat(const char *relative_uri, FsAttrs *attrs) {
  return webdav_new_propfind_entry(relative_uri,
                                   (attrs->modified_time == FS_INVALID_TIME
                                    ? INVALID_WEBDAV_RESOURCE_TIME
                                    : attrs->modified_time),
                                   (attrs->created_time == FS_INVALID_TIME
                                    ? INVALID_WEBDAV_RESOURCE_TIME
                                    : attrs->created_time),
                                   attrs->is_directory,
                                   (attrs->is_directory
                                    ? INVALID_WEBDAV_RESOURCE_SIZE
                                    : ((webdav_resource_size_t) attrs->size)));
}

void
webdav_backend_fs_propfind(WebdavBackendFs *pbctx,
                           const char *relative_uri, webdav_depth_t depth,
                           webdav_propfind_req_type_t propfind_req_type,
                           event_handler_t cb, void *cb_ud) {
  WebdavPropfindDoneEvent ev = {
    .entries = LINKED_LIST_INITIALIZER,
    .error = 0,
  };
  fs_directory_handle_t dirp = (fs_directory_handle_t) 0;
  bool is_dir = false;
  char *file_path = NULL;
  char *entry_name = NULL;
  char *new_uri = NULL;
  char *child_path = NULL;

  /* TODO: support this,
     TODO: instead of 500, return this:
     "403 Forbidden - A server may reject PROPFIND requests on collections
     with depth header of "Infinity", in which case it should use this error
     with the precondition code 'propfind-finite-depth' inside the error body."
  */
  if (depth == DEPTH_INF) {
    log_info("We don't support infinity propfind requests");
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  /* TODO: support this */
  if (propfind_req_type != WEBDAV_PROPFIND_PROP &&
      propfind_req_type != WEBDAV_PROPFIND_ALLPROP) {
    log_info("We don't support 'propname' requests");
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  file_path = path_from_uri(pbctx, relative_uri);
  if (!file_path) {
    log_info("Couldn't make file path from \"%s\'", file_path);
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  /* NB: the consistency between this and the file that we open is
     not guaranteed */
  FsAttrs attrs;
  const fs_error_t ret_getattr = fs_getattr(pbctx->fs, file_path, &attrs);
  if (ret_getattr) {
    log_info("Couldn't getattr(\"%s\"): %s",
             file_path, util_fs_strerror(ret_getattr));
    ev.error = ret_getattr == FS_ERROR_DOES_NOT_EXIST
      ? WEBDAV_ERROR_DOES_NOT_EXIST
      : WEBDAV_ERROR_GENERAL;
    goto done;
  }

  is_dir = attrs.is_directory;

  if (depth == DEPTH_1 && is_dir) {
    /* open the resource */
    fs_error_t ret_open = fs_opendir(pbctx->fs, file_path, &dirp);
    if (ret_open) {
      log_info("Couldn't opendir(\"%s\"): %s",
               file_path, util_fs_strerror(ret_open));
      ev.error = ret_open == FS_ERROR_DOES_NOT_EXIST
        ? WEBDAV_ERROR_DOES_NOT_EXIST
        : WEBDAV_ERROR_GENERAL;
      goto done;
    }

    while (true) {
      bool attrs_is_filled;
      FsAttrs dirent_attrs;
      free(entry_name);
      entry_name = NULL;
      const fs_error_t ret_readdir =
        fs_readdir(pbctx->fs, dirp,
                   &entry_name, &attrs_is_filled, &dirent_attrs);
      if (ret_readdir) {
        log_info("Couldn't readdir \"%s\": %s",
                 file_path, util_fs_strerror(ret_readdir));
        ev.error = WEBDAV_ERROR_GENERAL;
        goto done;
      }

      if (!entry_name) {
        /* EOF */
        break;
      }

      /* must stat the file */
      if (!attrs_is_filled) {
        /* NB: slight race condition here,
           file that we did readdir() on may not be
           the one we're statting here */
        free(child_path);
        child_path =
          util_fs_path_join(pbctx->fs, file_path, entry_name);
        if (!child_path) {
          log_info("Couldn't path join \"%s\" and \"%s\"",
                   file_path, entry_name);
          ev.error = WEBDAV_ERROR_GENERAL;
          goto done;
        }

        const fs_error_t ret_fgetattr =
          fs_getattr(pbctx->fs, child_path, &dirent_attrs);
        if (ret_fgetattr) {
          log_info("Couldn't fgetattr(\"%s\"): %s",
                   child_path, util_fs_strerror(ret_fgetattr));
          ev.error = WEBDAV_ERROR_GENERAL;
          goto done;
        }
      }

      const size_t name_len = strlen(entry_name);
      ASSERT_TRUE(name_len);

      new_uri = str_equals(relative_uri, "/")
        ? super_strcat("/", entry_name, NULL)
        : super_strcat(relative_uri, "/", entry_name, NULL);
      ASSERT_NOT_NULL(new_uri);

      const webdav_propfind_entry_t pfe =
        create_propfind_entry_from_stat(new_uri, &dirent_attrs);
      ASSERT_TRUE(pfe);

      ev.entries = linked_list_prepend(ev.entries, pfe);

    }
  }

  /* add the root directory last, so it is first */
  /* XXX: this actually matters for win32 clients...
     put this logic in webdav_server.c since it's protocol level
     *or* we can make this part of the server<->backend interface
   */
  webdav_propfind_entry_t pfe =
    create_propfind_entry_from_stat(relative_uri, &attrs);
  ASSERT_NOT_NULL(pfe);
  ev.entries = linked_list_prepend(ev.entries, pfe);

  ev.error = WEBDAV_ERROR_NONE;

 done:
  if (ev.error) {
    linked_list_free(ev.entries,
                     (linked_list_elt_handler_t) webdav_destroy_propfind_entry);
  }

  if (dirp) {
    fs_error_t ret_close = fs_closedir(pbctx->fs, dirp);
    ASSERT_TRUE(!ret_close);
  }

  free(file_path);
  free(new_uri);
  free(child_path);
  free(entry_name);

  return cb(WEBDAV_PROPFIND_DONE_EVENT, &ev, cb_ud);
}

void
webdav_backend_fs_touch(WebdavBackendFs *pbctx,
                        const char *relative_uri,
                        event_handler_t cb, void *ud) {
  WebdavTouchDoneEvent ev;

  char *file_path = path_from_uri(pbctx, relative_uri);
  if (!file_path) {
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  bool created;
  fs_error_t ret_touch = util_fs_touch(pbctx->fs, file_path, &created);
  if (ret_touch) {
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  ev = (WebdavTouchDoneEvent) {
    .error = WEBDAV_ERROR_NONE,
    .resource_existed = !created,
  };

 done:
  free(file_path);

  return cb(WEBDAV_TOUCH_DONE_EVENT, &ev, ud);
}

void
webdav_backend_fs_delete(WebdavBackendFs *pbctx,
                         const char *relative_uri,
                         event_handler_t cb, void *ud) {
  WebdavDeleteDoneEvent ev;
  char *file_path = path_from_uri(pbctx, relative_uri);
  if (!file_path) {
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  bool exists;
  fs_error_t ret_exists = util_fs_file_exists(pbctx->fs, file_path, &exists);
  if (ret_exists) {
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }
  else if (!exists) {
    ev.error = WEBDAV_ERROR_DOES_NOT_EXIST;
    goto done;
  }

  linked_list_t failed_to_delete = util_fs_rmtree(pbctx->fs, file_path);

  ev = (WebdavDeleteDoneEvent) {
    .error = WEBDAV_ERROR_NONE,
    .failed_to_delete = failed_to_delete,
  };

 done:
  free(file_path);

  return cb(WEBDAV_DELETE_DONE_EVENT, &ev, ud);
}

void
_webdav_backend_fs_copy_move(WebdavBackendFs *pbctx,
                             bool is_move,
                             const char *src_relative_uri, const char *dst_relative_uri,
                             bool overwrite, webdav_depth_t depth,
                             event_handler_t cb, void *ud) {
  assert(depth == DEPTH_INF ||
	 (depth == DEPTH_0 && !is_move));

  webdav_error_t err;
  bool dst_existed;

  char *const file_path = path_from_uri(pbctx, src_relative_uri);
  char *const destination_path = path_from_uri(pbctx, dst_relative_uri);

  char *const destination_path_dirname =
    util_fs_path_dirname(pbctx->fs, destination_path);
  if (!destination_path_dirname) {
    log_info("Error while getting the dirname of: %s",
             destination_path);
    err =  WEBDAV_ERROR_GENERAL;
    goto done;
  }

  bool destination_directory_exists;
  const fs_error_t ret_exists =
    util_fs_file_exists(pbctx->fs, destination_path_dirname,
                        &destination_directory_exists);
  if (ret_exists) {
    log_info("Error while checking if \"%s\" existed", destination_path_dirname);
    err = WEBDAV_ERROR_GENERAL;
    goto done;
  }
  else if (!destination_directory_exists) {
    log_debug("Destination directory \"%s\" does not exist!",
              destination_path_dirname);
    err = WEBDAV_ERROR_DESTINATION_DOES_NOT_EXIST;
    goto done;
  }

  bool src_exists;
  const fs_error_t ret_exists_2 =
    util_fs_file_exists(pbctx->fs, file_path, &src_exists);
  if (ret_exists_2) {
    log_info("Error while checking if \"%s\" existed", file_path);
    err = WEBDAV_ERROR_GENERAL;
    goto done;
  }
  else if (!src_exists) {
    err = WEBDAV_ERROR_DOES_NOT_EXIST;
    goto done;
  }

  const int ret_exists_3 = util_fs_file_exists(pbctx->fs, destination_path,
                                               &dst_existed);
  if (ret_exists_3) {
    log_info("Error while checking if \"%s\" existed",
             destination_path);
    err = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  /* if this is a move and an overwrite, first attempt native fs method
     NB: This is not an optimization, we need this for correctness when
     the user is changing the case of a file on a case-insensitive FS
     (otherwise we'll delete the source inadvertently while trying to
     delete whatever is at the destination)
     */
  if (is_move && overwrite) {
    fs_error_t ret_rename = fs_rename(pbctx->fs, file_path, destination_path);
    if (ret_rename) {
      log_info("Error while calling eagerly calling rename(\"%s\", \"%s\")",
               file_path, destination_path);
    }
    else {
      err = WEBDAV_ERROR_NONE;
      goto done;
    }
  }

  /* kill directory if we're overwriting it */
  if (dst_existed) {
    if (!overwrite) {
      err = WEBDAV_ERROR_DESTINATION_EXISTS;
      goto done;
    }

    linked_list_t failed_to_remove = util_fs_rmtree(pbctx->fs, destination_path);
    linked_list_free(failed_to_remove, free);
  }

  bool copy_failed = true;
  if (is_move) {
    /* first try moving */
    fs_error_t ret_rename = fs_rename(pbctx->fs, file_path, destination_path);
    if (ret_rename && ret_rename != FS_ERROR_CROSS_DEVICE) {
      log_info("Error while calling rename(\"%s\", \"%s\")",
	       file_path, destination_path);
      err = WEBDAV_ERROR_GENERAL;
      goto done;
    }
    copy_failed = ret_rename;
  }

  if (copy_failed) {
    if (depth == DEPTH_0) {
      bool is_dir;
      const fs_error_t ret_isdir =
        util_fs_file_is_dir(pbctx->fs, file_path, &is_dir);
      if (ret_isdir) {
        log_info("Error while determining if %s was a dir", file_path);
        err = WEBDAV_ERROR_GENERAL;
        goto done;
      }

      if (is_dir) {
	const fs_error_t ret_mkdir =
          fs_mkdir(pbctx->fs, destination_path);
	if (ret_mkdir) {
	  log_info("Failure to mkdir(\"%s\")",
		   destination_path);
	  err = WEBDAV_ERROR_GENERAL;
	  goto done;
	}
      }
      else {
	const fs_error_t ret_copyfile =
          util_fs_copyfile(pbctx->fs,
                           file_path, destination_path);
	if (ret_copyfile) {
	  log_info("Failure to copyfile(\"%s\", \"%s\")",
                   file_path, destination_path);
	  err = WEBDAV_ERROR_GENERAL;
	  goto done;
	}
      }

      copy_failed = false;
    }
    else {
      const linked_list_t failed_to_copy =
	util_fs_copytree(pbctx->fs, file_path, destination_path, is_move);
      copy_failed = failed_to_copy;
      linked_list_free(failed_to_copy, free);
    }
  }

  err = copy_failed
    ? WEBDAV_ERROR_GENERAL
    : WEBDAV_ERROR_NONE;

 done:
  free(file_path);
  free(destination_path);
  free(destination_path_dirname);

  bool initted_dst_existed = err ? false : dst_existed;
  if (is_move) {
    WebdavMoveDoneEvent move_done_ev = {
      .error = err,
      /* TODO: implement */
      .failed_to_move = LINKED_LIST_INITIALIZER,
      .dst_existed = initted_dst_existed,
    };
    return cb(WEBDAV_MOVE_DONE_EVENT, &move_done_ev, ud);
  }
  else {
    WebdavCopyDoneEvent copy_done_ev = {
      .error = err,
      /* TODO: implement */
      .failed_to_copy = LINKED_LIST_INITIALIZER,
      .dst_existed = initted_dst_existed,
    };
    return cb(WEBDAV_COPY_DONE_EVENT, &copy_done_ev, ud);
  }
}

void
webdav_backend_fs_copy(WebdavBackendFs *backend_handle,
                       const char *src_relative_uri, const char *dst_relative_uri,
                       bool overwrite, webdav_depth_t depth,
                       event_handler_t cb, void *ud) {
  bool is_move = false;
  return _webdav_backend_fs_copy_move(backend_handle, is_move,
                                      src_relative_uri, dst_relative_uri,
                                      overwrite, depth,
                                      cb, ud);
}

void
webdav_backend_fs_move(WebdavBackendFs *backend_handle,
                       const char *src_relative_uri, const char *dst_relative_uri,
                       bool overwrite,
                       event_handler_t cb, void *ud) {
  bool is_move = true;
  return _webdav_backend_fs_copy_move(backend_handle, is_move,
                                      src_relative_uri, dst_relative_uri,
                                      overwrite, DEPTH_INF,
                                      cb, ud);
}

void
webdav_backend_fs_destroy(webdav_backend_fs_t backend) {
  free(backend->base_path);
  free(backend);
}
