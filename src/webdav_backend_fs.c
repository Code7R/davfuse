#define _ISOC99_SOURCE

#include <stdlib.h>
#include <string.h>

#include "fs.h"
#include "uthread.h"
#include "util.h"
#include "util_fs.h"

#include "webdav_server.h"
#include "webdav_backend_fs.h"

enum {
  TRANSFER_BUF_SIZE = 4096,
};

typedef struct _webdav_backend_fs {
  fs_t fs;
  char *base_path;
  size_t base_path_len;
} WebdavBackendFs;

static char *
path_from_uri(WebdavBackendFs *pbctx, const char *real_uri) {
  size_t uri_len = strlen(real_uri);
  if (str_equals(real_uri, "/")) {
    uri_len = 0;
  }
  /* return relative path (no leading slash), but also
     don't include trailing slash, since posix treats that like "/." */
  else if (real_uri[uri_len - 1] == '/') {
    uri_len -= 1;
  }

  char *toret = malloc(pbctx->base_path_len + uri_len + 1);
  if (!toret) {
    return NULL;
  }
  memcpy(toret, pbctx->base_path, pbctx->base_path_len);
  memcpy(toret + pbctx->base_path_len, real_uri, uri_len);
  toret[pbctx->base_path_len + uri_len] = '\0';

  return toret;
}

webdav_backend_fs_t
webdav_backend_fs_new(fs_t fs, const char *root) {
  char *base_path = NULL;
  WebdavBackendFs *backend = malloc(sizeof(*backend));
  if (!backend) {
    return NULL;
  }

  base_path = strdup_x(root);
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
} PosixGetCtx;

static
UTHR_DEFINE(_webdav_backend_fs_get_uthr) {
  webdav_error_t error;

  UTHR_HEADER(PosixGetCtx, ctx);

  ctx->fd = -1;

  ctx->file_path = path_from_uri(ctx->pbctx, ctx->relative_uri);
  if (!ctx->file_path) {
    error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  const fs_error_t ret_open = fs_open(ctx->pbctx->fs, ctx->file_path, false,
                                      &ctx->fd, NULL);
  if (ret_open) {
    error = ret_open == FS_ERROR_DOES_NOT_EXIST
      ? WEBDAV_ERROR_DOES_NOT_EXIST
      : WEBDAV_ERROR_GENERAL;
    goto done;
  }

  FsAttrs attrs;
  const fs_error_t fstat_ret = fs_fgetattr(ctx->pbctx->fs, ctx->fd, &attrs);
  if (fstat_ret) {
    error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  /* check if this is a directory */
  if (attrs.is_directory) {
    error = WEBDAV_ERROR_IS_COL;
    goto done;
  }

  /* write out the size hint */
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
      error = WEBDAV_ERROR_GENERAL;
      goto done;
    }

    if (!ctx->amt_read) {
      /* EOF */
      break;
    }

    UTHR_YIELD(ctx,
               webdav_get_request_write(ctx->get_ctx, ctx->buf, read_ret,
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
  UTHR_CALL3(_webdav_backend_fs_get_uthr, PosixGetCtx,
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
} PosixPutCtx;

static
UTHR_DEFINE(_webdav_backend_fs_put_uthr) {
  UTHR_HEADER(PosixPutCtx, ctx);

  webdav_error_t error;

  ctx->fd = (fs_file_handle_t) 0;

  ctx->file_path = path_from_uri(ctx->pbctx, ctx->relative_uri);
  if (!ctx->file_path) {
    error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  bool created;
  const fs_error_t ret_open =
    fs_open(ctx->pbctx->fs, ctx->file_path, true, &ctx->fd, &created);
  if (ret_open) {
    log_info("Error opening \"%s\"", ctx->file_path);
    switch (ret_open) {
    case FS_ERROR_DOES_NOT_EXIST: error = WEBDAV_ERROR_DOES_NOT_EXIST; break;
    case FS_ERROR_NOT_DIR: error = WEBDAV_ERROR_NOT_COLLECTION; break;
    case FS_ERROR_IS_DIR: error = WEBDAV_ERROR_IS_COL; break;
    default: error = WEBDAV_ERROR_GENERAL; break;
    }
    goto done;
  }

  ctx->resource_existed = !created;

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
      size_t new_amount_written;
      const fs_error_t ret_write = fs_write(ctx->pbctx->fs, ctx->fd,
                                            ctx->buf + amount_written,
                                            amount_read - amount_written,
                                            amount_written + ctx->total_amount_transferred,
                                            &new_amount_written);
      if (ret_write) {
        log_error("Couldn't write to resource \"%s\" (fd: %p)",
                  ctx->relative_uri, ctx->fd);
        error = WEBDAV_ERROR_GENERAL;
        goto done;
      }

      amount_written += new_amount_written;
    }

    assert(amount_written == amount_read);
    ctx->total_amount_transferred += amount_written;
  }

  log_info("Resource \"%s\" created with %zu bytes",
           ctx->relative_uri, ctx->total_amount_transferred);
  error = WEBDAV_ERROR_NONE;

 done:
  free(ctx->file_path);

  if (ctx->fd >= 0) {
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
  UTHR_CALL3(_webdav_backend_fs_put_uthr, PosixPutCtx,
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
                                   attrs->modified_time,
                                   /* mod_dav from apache also uses mtime as creation time */
                                   attrs->modified_time,
                                   attrs->is_directory,
                                   attrs->size);
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
  union {
    fs_directory_handle_t dirp;
    fs_file_handle_t fd;
  } handle;
  bool is_dir = false;
  bool valid_handle = false;
  char *file_path = NULL;

  /* TODO: support this */
  if (depth == DEPTH_INF) {
    log_info("We don't support infinity propfind requests");
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  /* TODO: support this */
  if (propfind_req_type != WEBDAV_PROPFIND_PROP) {
    log_info("We only support 'prop' requests");
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  file_path = path_from_uri(pbctx, relative_uri);
  if (!file_path) {
    log_info("Couldn't make file path from \"%s\'", file_path);
    ev.error = true;
    goto done;
  }

  /* open the resource */
  FsAttrs attrs;
  fs_error_t open_error = 0;
  while (!valid_handle && !open_error) {
    open_error = fs_opendir(pbctx->fs, file_path, &handle.dirp);
    if (open_error == ENOTDIR) {
      open_error = fs_open(pbctx->fs, file_path, false, &handle.fd, NULL);
      if (!open_error) {
        /* check if this is a directory, if so try again... */
        const fs_error_t ret_getattr = fs_fgetattr(pbctx->fs, handle.fd, &attrs);
        if (ret_getattr || attrs.is_directory) {
          /* it's a directory! try again */
          const fs_error_t ret_close = fs_close(pbctx->fs, handle.fd);
          ASSERT_TRUE(!ret_close);
        }
        else {
          valid_handle = true;
        }
      }
    }
    else if (handle.dirp) {
      is_dir = true;
      valid_handle = true;
    }
  }

  if (open_error) {
    assert(!valid_handle);
    ev.error = open_error == FS_ERROR_DOES_NOT_EXIST
      ? WEBDAV_ERROR_DOES_NOT_EXIST
      : WEBDAV_ERROR_GENERAL;
    goto done;
  }

  if (is_dir) {
    /* TODO: it would be nice to get modified time too */
    attrs = (FsAttrs) {
      .is_directory = true,
    };
  }

  webdav_propfind_entry_t pfe = create_propfind_entry_from_stat(relative_uri, &attrs);
  ASSERT_NOT_NULL(pfe);
  ev.entries = linked_list_prepend(ev.entries, pfe);

  assert(attrs.is_directory == is_dir);

  if (depth == DEPTH_1 && is_dir) {
    size_t relative_uri_len = strlen(relative_uri);
    while (true) {
      char *name;
      bool attrs_is_filled;
      FsAttrs dirent_attrs;
      const fs_error_t ret_readdir =
        fs_readdir(pbctx->fs, handle.dirp,
                   &name, &attrs_is_filled, &dirent_attrs);
      if (ret_readdir) {
        ev.error = WEBDAV_ERROR_GENERAL;
        goto done;
      }

      if (!name) {
        /* EOF */
        break;
      }

      /* must stat the file */
      if (!attrs_is_filled) {
        /* TODO: implement */
        abort();
      }

      size_t name_len = strlen(name);
      assert(name_len);

      char *new_uri;
      if (str_equals(relative_uri, "/")) {
        new_uri = malloc_or_abort(1 + name_len + 1);
        new_uri[0] = '/';
        memcpy(&new_uri[1], name, name_len);
        new_uri[name_len + 1] = '\0';
      }
      else {
        /* NB: intentionally don't use `asprintf()` */
        new_uri = malloc_or_abort(relative_uri_len + 1 + name_len + 1);
        memcpy(new_uri, relative_uri, relative_uri_len);
        new_uri[relative_uri_len] = '/';
        memcpy(new_uri + relative_uri_len + 1, name, name_len);
        new_uri[relative_uri_len + 1 + name_len] = '\0';
      }

      webdav_propfind_entry_t pfe = create_propfind_entry_from_stat(new_uri, &dirent_attrs);
      ASSERT_TRUE(pfe);
      ev.entries = linked_list_prepend(ev.entries, pfe);

      free(name);
    }
  }

  ev.error = WEBDAV_ERROR_NONE;

 done:
  if (ev.error) {
    linked_list_free(ev.entries,
                     (linked_list_elt_handler_t) webdav_destroy_propfind_entry);
  }

  if (valid_handle) {
    fs_error_t ret_close;
    if (is_dir) {
      ret_close = fs_closedir(pbctx->fs, handle.dirp);
    }
    else {
      ret_close = fs_close(pbctx->fs, handle.fd);
    }
    ASSERT_TRUE(!ret_close);
  }

  free(file_path);

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

  char *const file_path = path_from_uri(pbctx, src_relative_uri);
  char *const destination_path = path_from_uri(pbctx, dst_relative_uri);

  char *const destination_path_dirname = fs_dirname(pbctx->fs, destination_path);
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

  bool dst_existed;
  const int ret_exists_3 = util_fs_file_exists(pbctx->fs, destination_path,
                                               &dst_existed);
  if (ret_exists_3) {
    log_info("Error while checking if \"%s\" existed",
             destination_path);
    err = WEBDAV_ERROR_GENERAL;
    goto done;
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
      fs_error_t ret_isdir = util_fs_file_is_dir(pbctx->fs, file_path, &is_dir);
      if (ret_isdir) {
        log_info("Error while determining if %s was a dir", file_path);
        err = WEBDAV_ERROR_GENERAL;
        goto done;
      }

      if (is_dir) {
	fs_error_t ret_mkdir = fs_mkdir(pbctx->fs, destination_path);
	if (ret_mkdir) {
	  log_info("Failure to mkdir(\"%s\")",
		   destination_path);
	  err = WEBDAV_ERROR_GENERAL;
	  goto done;
	}
      }
      else {
	fs_error_t ret_copyfile =
          util_fs_copyfile(pbctx->fs,
                           file_path, destination_path);
	if (ret_copyfile) {
	  log_info("Failure to copyfile(\"%s\", \"%s\")", file_path);
	  err = WEBDAV_ERROR_GENERAL;
	  goto done;
	}
      }

      copy_failed = false;
    }
    else {
      linked_list_t failed_to_copy =
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

  if (is_move) {
    WebdavMoveDoneEvent move_done_ev = {
      .error = err,
      /* TODO: implement */
      .failed_to_move = LINKED_LIST_INITIALIZER,
      .dst_existed = dst_existed,
    };
    return cb(WEBDAV_MOVE_DONE_EVENT, &move_done_ev, ud);
  }
  else {
    WebdavCopyDoneEvent copy_done_ev = {
      .error = err,
      /* TODO: implement */
      .failed_to_copy = LINKED_LIST_INITIALIZER,
      .dst_existed = dst_existed,
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
  UNUSED(backend);
  abort();
}
