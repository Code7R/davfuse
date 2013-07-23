/*
  A webdav server interface into a posix file system
 */
/*
  TODO:
  * Make more async, (use worker threads)
  */
#define _ISOC99_SOURCE
#define _BSD_SOURCE

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <unistd.h>

#include <assert.h>
#include <errno.h>
#include <signal.h>

#include "c_util.h"
#include "file_utils.h"
#include "fstatat.h"
#include "fdevent.h"
#include "fd_utils.h"
#include "logging.h"
#include "webdav_server.h"
#include "uthread.h"
#include "util.h"

enum {
  TRANSFER_BUF_SIZE = 4096,
};

typedef struct {
  char *base_path;
  size_t base_path_len;
} PosixBackendCtx;

static void *
malloc_or_abort(size_t n) {
  int saved_errno = errno;
  void *ret = malloc(n);
  ASSERT_NOT_NULL(ret);
  errno = saved_errno;
  return ret;
}

static char *
path_from_uri(PosixBackendCtx *pbctx, const char *real_uri) {
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

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  PosixBackendCtx *pbctx;
  const char *relative_uri;
  webdav_get_request_ctx_t get_ctx;
  /* ctx */
  char *file_path;
  char buf[TRANSFER_BUF_SIZE];
  int fd;
} PosixGetCtx;

static
UTHR_DEFINE(_posix_get_uthr) {
  webdav_error_t error;

  UTHR_HEADER(PosixGetCtx, ctx);

  ctx->fd = -1;

  ctx->file_path = path_from_uri(ctx->pbctx, ctx->relative_uri);
  if (!ctx->file_path) {
    error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  ctx->fd = open(ctx->file_path, O_RDONLY);
  if (ctx->fd < 0) {
    error = errno == ENOENT
      ? WEBDAV_ERROR_DOES_NOT_EXIST
      : WEBDAV_ERROR_GENERAL;
    goto done;
  }

  struct stat st;
  const int fstat_ret = fstat(ctx->fd, &st);
  if (fstat_ret < 0) {
    error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  /* check if this is a directory */
  if (S_ISDIR(st.st_mode)) {
    error = WEBDAV_ERROR_IS_COL;
    goto done;
  }

  /* write out the size hint */
  UTHR_YIELD(ctx,
             webdav_get_request_size_hint(ctx->get_ctx, st.st_size,
                                          _posix_get_uthr, ctx));
  UTHR_RECEIVE_EVENT(WEBDAV_GET_REQUEST_SIZE_HINT_DONE_EVENT,
                     WebdavGetRequestSizeHintDoneEvent, size_hint_ev);
  if (size_hint_ev->error) {
    error = size_hint_ev->error;
    goto done;
  }

  while (true) {
    const ssize_t read_ret = read(ctx->fd, ctx->buf, sizeof(ctx->buf));
    if (read_ret < 0) {
      error = WEBDAV_ERROR_GENERAL;
      goto done;
    }

    if (!read_ret) {
      /* EOF */
      break;
    }

    UTHR_YIELD(ctx,
               webdav_get_request_write(ctx->get_ctx, ctx->buf, read_ret,
                                        _posix_get_uthr, ctx));
    UTHR_RECEIVE_EVENT(WEBDAV_GET_REQUEST_WRITE_DONE_EVENT,
                       WebdavGetRequestWriteDoneEvent, write_done_ev);
    if (write_done_ev->error) {
      error = write_done_ev->error;
      goto done;
    }
  }

  error = WEBDAV_ERROR_NONE;

 done:
  if (ctx->fd >= 0) {
    close(ctx->fd);
  }

  free(ctx->file_path);

  UTHR_RETURN(ctx,
              webdav_get_request_end(ctx->get_ctx, error));

  UTHR_FOOTER();
}

static void
posix_get(void *backend_handle, const char *relative_uri,
          webdav_get_request_ctx_t get_ctx) {
  UTHR_CALL3(_posix_get_uthr, PosixGetCtx,
             .pbctx = (PosixBackendCtx *) backend_handle,
             .relative_uri = relative_uri,
             .get_ctx = get_ctx);
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  PosixBackendCtx *pbctx;
  const char *relative_uri;
  webdav_put_request_ctx_t put_ctx;
  /* ctx */
  int fd;
  char *file_path;
  bool resource_existed;
  size_t total_amount_transferred;
  char buf[TRANSFER_BUF_SIZE];
} PosixPutCtx;

static
UTHR_DEFINE(_posix_put_uthr) {
  UTHR_HEADER(PosixPutCtx, ctx);

  webdav_error_t error;

  ctx->fd = -1;

  ctx->file_path = path_from_uri(ctx->pbctx, ctx->relative_uri);
  if (!ctx->file_path) {
    error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  bool created;
  const bool success_open_create =
    open_or_create(ctx->file_path, O_WRONLY, 0666, &ctx->fd, &created);

  if (!success_open_create) {
    log_info("Error opening \"%s\" (%s)",
             ctx->file_path, strerror(errno));
    switch (errno) {
    case ENOENT: error = WEBDAV_ERROR_DOES_NOT_EXIST; break;
    case ENOTDIR: error = WEBDAV_ERROR_NOT_COLLECTION; break;
    case EISDIR: error = WEBDAV_ERROR_IS_COL; break;
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
                                       _posix_put_uthr, ctx));
    UTHR_RECEIVE_EVENT(WEBDAV_PUT_REQUEST_READ_DONE_EVENT,
                       WebdavPutRequestReadDoneEvent,
                       read_done_ev);

    /* EOF */
    if (!read_done_ev->nbyte) {
      break;
    }

    const size_t amount_read = read_done_ev->nbyte;
    size_t amount_written = 0;
    while (amount_written < amount_read) {
      int write_ret = write(ctx->fd, ctx->buf + amount_written, amount_read - amount_written);
      if (write_ret < 0) {
        log_error("Couldn't write to resource \"%s\" (fd: %d)",
                  ctx->relative_uri, ctx->fd);
        error = WEBDAV_ERROR_GENERAL;
        goto done;
      }

      amount_written += write_ret;
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
    close_or_abort(ctx->fd);
  }

  UTHR_RETURN(ctx,
              webdav_put_request_end(ctx->put_ctx, error, ctx->resource_existed));

  UTHR_FOOTER();
}

static void
posix_put(void *backend_handle, const char *relative_uri,
          webdav_put_request_ctx_t put_ctx) {
  UTHR_CALL3(_posix_put_uthr, PosixPutCtx,
             .pbctx = (PosixBackendCtx *) backend_handle,
             .relative_uri = relative_uri,
             .put_ctx = put_ctx);

}


static void
posix_mkcol(void *backend_handle, const char *relative_uri,
	    event_handler_t cb, void *ud) {
  WebdavMkcolDoneEvent ev;
  PosixBackendCtx *pbctx = backend_handle;

  char *file_path = path_from_uri(pbctx, relative_uri);
  if (!file_path) {
    ev.error = WEBDAV_ERROR_NO_MEM;
    goto done;
  }

  int ret = mkdir(file_path, 0777);
  if (ret) {
    if (errno == ENOENT) {
      ev.error = WEBDAV_ERROR_DOES_NOT_EXIST;
    }
    else if (errno == ENOSPC ||
             errno == EDQUOT) {
      ev.error = WEBDAV_ERROR_NO_SPACE;
    }
    else if (errno == ENOTDIR) {
      ev.error = WEBDAV_ERROR_NOT_COLLECTION;
    }
    else if (errno == EACCES) {
      ev.error = WEBDAV_ERROR_PERM;
    }
    else if (errno == EEXIST) {
      ev.error = WEBDAV_ERROR_EXISTS;
      /*
      struct stat st;
      ret = stat(file_path, &st);
      if (ret < 0) {
	ev.error = WEBDAV_ERROR_GENERAL;
      }
      else if (S_ISDIR(st.st_mode)) {
	ev.error = WEBDAV_ERROR_EXISTS;
      }
      else {
	ev.error = WEBDAV_ERROR_NOT_COLLECTION;
      }
      */
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
create_propfind_entry_from_stat(const char *relative_uri, struct stat *st) {
  return webdav_new_propfind_entry(relative_uri,
                                   st->st_mtime,
                                   /* mod_dav from apache also uses mtime as creation time */
                                   st->st_mtime,
                                   S_ISDIR(st->st_mode),
                                   st->st_size);
}

static void
posix_propfind(void *backend_handle,
               const char *relative_uri, webdav_depth_t depth,
               webdav_propfind_req_type_t propfind_req_type,
               event_handler_t cb, void *cb_ud) {
  WebdavPropfindDoneEvent ev = {
    .entries = LINKED_LIST_INITIALIZER,
    .error = 0,
  };
  union {
    DIR *dirp;
    int fd;
  } handle;
  bool is_dir = false;
  bool valid_handle = false;
  PosixBackendCtx *pbctx = (PosixBackendCtx *) backend_handle;
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
  errno = 0;
  while (!valid_handle && !errno) {
    handle.dirp = opendir(file_path);
    if (!handle.dirp && errno == ENOTDIR) {
      errno = 0;
      handle.fd = open(file_path, O_RDONLY);

      if (handle.fd >= 0) {
        /* check if this is a directory, if so try again... */
        struct stat st;
        int fstat_ret = fstat(handle.fd, &st);
        if (fstat_ret < 0 ||
            S_ISDIR(st.st_mode)) {
          /* it's a directory! try again */
          close_or_abort(handle.fd);
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

  if (errno) {
    assert(!valid_handle);
    ev.error = errno == ENOENT
      ? WEBDAV_ERROR_DOES_NOT_EXIST
      : WEBDAV_ERROR_GENERAL;
    goto done;
  }

  /* first get info for root element */
  int fd_for_stat = is_dir ? dirfd(handle.dirp) : handle.fd;
  if (fd_for_stat < 0) {
    /* dirfd() failed for some reason, we can't deal with this */
    abort();
  }

  struct stat st;
  int fstat_ret = fstat(fd_for_stat, &st);
  if (fstat_ret < 0) {
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  webdav_propfind_entry_t pfe = create_propfind_entry_from_stat(relative_uri, &st);
  ASSERT_NOT_NULL(pfe);
  ev.entries = linked_list_prepend(ev.entries, pfe);

  assert(S_ISDIR(st.st_mode) == is_dir);

  if (depth == DEPTH_1 && S_ISDIR(st.st_mode)) {
    size_t relative_uri_len = strlen(relative_uri);
    while (true) {
      int orig_errno = errno;
      struct dirent *dirent = readdir(handle.dirp);
      if (!dirent && orig_errno != errno) {
        ev.error = WEBDAV_ERROR_GENERAL;
        goto done;
      }

      if (!dirent) {
        /* EOF */
        break;
      }

      if (str_equals(dirent->d_name, ".") ||
          str_equals(dirent->d_name, "..")) {
        /* ignore these entries */
        continue;
      }

      /* must stat the file */
      struct stat entry_st;
      int fstatatx_ret = fstatat_x(fd_for_stat, dirent->d_name, &entry_st, 0);
      if (fstatatx_ret < 0) {
        ev.error = WEBDAV_ERROR_GENERAL;
        goto done;
      }

      size_t name_len = strlen(dirent->d_name);
      assert(name_len);

      char *new_uri;
      if (str_equals(relative_uri, "/")) {
        new_uri = malloc_or_abort(1 + name_len + 1);
        new_uri[0] = '/';
        memcpy(&new_uri[1], dirent->d_name, name_len);
        new_uri[name_len + 1] = '\0';
      }
      else {
        /* NB: intentionally don't use `asprintf()` */
        new_uri = malloc_or_abort(relative_uri_len + 1 + name_len + 1);
        memcpy(new_uri, relative_uri, relative_uri_len);
        new_uri[relative_uri_len] = '/';
        memcpy(new_uri + relative_uri_len + 1, dirent->d_name, name_len);
        new_uri[relative_uri_len + 1 + name_len] = '\0';
      }

      webdav_propfind_entry_t pfe = create_propfind_entry_from_stat(new_uri, &entry_st);
      ASSERT_TRUE(pfe);
      ev.entries = linked_list_prepend(ev.entries, pfe);
    }
  }

  ev.error = WEBDAV_ERROR_NONE;

 done:
  if (ev.error) {
    linked_list_free(ev.entries,
                     (linked_list_elt_handler_t) webdav_destroy_propfind_entry);
  }

  if (valid_handle) {
    if (is_dir) {
      closedir_or_abort(handle.dirp);
    }
    else {
      close_or_abort(handle.fd);
    }
  }

  free(file_path);

  return cb(WEBDAV_PROPFIND_DONE_EVENT, &ev, cb_ud);
}

static void
posix_touch(void *backend_handle,
            const char *relative_uri,
            event_handler_t cb, void *ud) {
  WebdavTouchDoneEvent ev;
  PosixBackendCtx *pbctx = backend_handle;

  char *file_path = path_from_uri(pbctx, relative_uri);
  if (!file_path) {
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  int ret_touch = touch(file_path);
  if (ret_touch < 0) {
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  ev = (WebdavTouchDoneEvent) {
    .error = WEBDAV_ERROR_NONE,
    .resource_existed = !ret_touch,
  };

 done:
  free(file_path);

  return cb(WEBDAV_TOUCH_DONE_EVENT, &ev, ud);
}

static void
posix_delete(void *backend_handle,
	     const char *relative_uri,
	     event_handler_t cb, void *ud) {
  WebdavDeleteDoneEvent ev;
  PosixBackendCtx *pbctx = backend_handle;
  char *file_path = path_from_uri(pbctx, relative_uri);
  if (!file_path) {
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  int ret_exists = file_exists(file_path);
  if (ret_exists < 0) {
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }
  else if (!ret_exists) {
    ev.error = WEBDAV_ERROR_DOES_NOT_EXIST;
    goto done;
  }

  linked_list_t failed_to_delete = rmtree(file_path);

  ev = (WebdavDeleteDoneEvent) {
    .error = WEBDAV_ERROR_NONE,
    .failed_to_delete = failed_to_delete,
  };

 done:
  free(file_path);

  return cb(WEBDAV_DELETE_DONE_EVENT, &ev, ud);
}

static void
_posix_copy_move(void *backend_handle,
		 bool is_move,
		 const char *src_relative_uri, const char *dst_relative_uri,
		 bool overwrite, webdav_depth_t depth,
		 event_handler_t cb, void *ud) {
  assert(depth == DEPTH_INF ||
	 (depth == DEPTH_0 && !is_move));

  PosixBackendCtx *pbctx = backend_handle;
  webdav_error_t err;

  char *file_path = path_from_uri(pbctx, src_relative_uri);
  char *destination_path = path_from_uri(pbctx, dst_relative_uri);

  char *destination_path_copy = strdup(destination_path);
  char *destination_path_dirname = dirname(destination_path_copy);
  bool destination_directory_exists = file_exists(destination_path_dirname);
  if (!destination_directory_exists) {
    err = WEBDAV_ERROR_DESTINATION_DOES_NOT_EXIST;
    goto done;
  }

  struct stat src_st;
  int src_ret = stat(file_path, &src_st);
  if (src_ret < 0) {
    if (errno != ENOENT) {
      log_info("Error while calling stat(\"%s\"): %s",
	       destination_path,
	       strerror(errno));
    }
    err = errno == ENOENT
      ? WEBDAV_ERROR_DOES_NOT_EXIST
      : WEBDAV_ERROR_GENERAL;
    goto done;
  }

  struct stat dst_st;
  int dst_ret = stat(destination_path, &dst_st);
  if (dst_ret && errno != ENOENT) {
    log_info("Error while calling stat(\"%s\"): %s",
	     destination_path,
	     strerror(errno));
    err = WEBDAV_ERROR_GENERAL;
    goto done;
  }
  bool dst_existed = !dst_ret;

  /* kill directory if we're overwriting it */
  if (dst_existed) {
    if (!overwrite) {
      err = WEBDAV_ERROR_DESTINATION_EXISTS;
      goto done;
    }

    linked_list_t failed_to_remove = rmtree(destination_path);
    linked_list_free(failed_to_remove, free);
  }

  bool copy_failed = true;
  if (is_move) {
    /* first try moving */
    int ret = rename(file_path, destination_path);
    if (ret < 0 && errno != EXDEV) {
      log_info("Error while calling rename(\"%s\", \"%s\"): %s",
	       file_path, destination_path,
	       strerror(errno));
      err = WEBDAV_ERROR_GENERAL;
      goto done;
    }
    copy_failed = ret < 0;
  }

  if (copy_failed) {
    if (depth == DEPTH_0) {
      if (file_is_dir(file_path) > 0) {
	int ret = mkdir(destination_path, 0777);
	if (ret < 0) {
	  log_info("Failure to mkdir(\"%s\"): %s",
		   destination_path, strerror(errno));
	  err = WEBDAV_ERROR_GENERAL;
	  goto done;
	}
      }
      else {
	bool ret = copyfile(file_path, destination_path);
	if (!ret) {
	  log_info("Failure to copyfile(\"%s\", \"%s\")",
		   file_path, destination_path);
	  err = WEBDAV_ERROR_GENERAL;
	  goto done;
	}
      }

      copy_failed = false;
    }
    else {
      linked_list_t failed_to_copy =
	copytree(file_path, destination_path, is_move);
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
  free(destination_path_copy);

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

static void
posix_copy(void *backend_handle,
	   const char *src_relative_uri, const char *dst_relative_uri,
	   bool overwrite, webdav_depth_t depth,
	   event_handler_t cb, void *ud) {
  bool is_move = false;
  return _posix_copy_move(backend_handle, is_move,
			  src_relative_uri, dst_relative_uri,
			  overwrite, depth,
			  cb, ud);
}

static void
posix_move(void *backend_handle,
	   const char *src_relative_uri, const char *dst_relative_uri,
	   bool overwrite,
	   event_handler_t cb, void *ud) {
  bool is_move = true;
  return _posix_copy_move(backend_handle, is_move,
			  src_relative_uri, dst_relative_uri,
			  overwrite, DEPTH_INF,
			  cb, ud);
}

static WebdavBackendOperations
posix_backend_operations = {
  .copy = posix_copy,
  .delete = posix_delete,
  .get = posix_get,
  .propfind = posix_propfind,
  .put = posix_put,
  .mkcol = posix_mkcol,
  .move = posix_move,
  .touch = posix_touch,
};

int
main(int argc, char *argv[]) {
  port_t port;

  /* TODO: make configurable */
  log_level_t log_level = LOG_DEBUG;

  init_logging(stdout, log_level);
  log_info("Logging initted.");

  /* ignore SIGPIPE */
  signal(SIGPIPE, SIG_IGN);

  if (argc > 1) {
    long to_port = strtol(argv[1], NULL, 10);
    if ((to_port == 0 && errno) ||
	to_port < 0 ||
	to_port > MAX_PORT) {
      log_critical("Bad port: %s", argv[1]);
      return -1;
    }
    port = (port_t) to_port;
  }
  else {
    port = 8080;
  }

  char *public_prefix;
  if (argc > 2) {
    public_prefix = argv[2];
  }
  else {
    public_prefix = "http://localhost:8080/";
  }

  char *base_path;
  if (argc > 3) {
    base_path = strdup(argv[3]);
  }
  else {
    base_path = getcwd(NULL, 0);
  }
  ASSERT_NOT_NULL(base_path);

  /* create server socket */
  int server_fd = create_ipv4_bound_socket(port);
  assert(server_fd >= 0);

  /* create event loop */
  FDEventLoop loop;
  bool ret = fdevent_init(&loop);
  ASSERT_TRUE(ret);

  /* start webdav server */
  PosixBackendCtx pbctx = {
    .base_path = base_path,
    .base_path_len = strlen(base_path),
  };

  webdav_backend_t fs = webdav_backend_new(&posix_backend_operations,
                                           sizeof(posix_backend_operations),
                                           &pbctx);
  webdav_server_t ws = webdav_server_start(&loop, server_fd, public_prefix, fs);

  ASSERT_TRUE(ws);

  log_info("Starting main loop");
  fdevent_main_loop(&loop);

  log_info("Server stopped");

  webdav_backend_destroy(fs);

  free(base_path);

  return 0;
}
