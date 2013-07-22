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

typedef struct {
  char *base_path;
  size_t base_path_len;
} PosixBackendCtx;

static void
fill_file_info(WebdavFileInfo *fi, struct stat *st) {
  *fi = (WebdavFileInfo) {
    .modified_time = (webdav_file_time_t) st->st_mtime,
    /* TODO: this should be configurable but for now we just
       set getlastmodified and creationdate to the same date
       because that's what apache mod_dav does */
    .creation_time = (webdav_file_time_t) st->st_ctime,
    .is_collection = S_ISDIR(st->st_mode),
    .length = (size_t) st->st_size,
  };
}

static char *
path_from_uri(PosixBackendCtx *pbctx, const char *real_uri) {
  UNUSED(fill_file_info);

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
  char buf[4096];
  int fd;
} PosixGetCtx;

static
UTHR_DEFINE(_posix_get_uthr) {
  webdav_error_t error;

  UTHR_HEADER(PosixGetCtx, ctx);

  ctx->fd = -1;

  ctx->file_path = path_from_uri(ctx->pbctx, ctx->relative_uri);
  if (!ctx->file_path) {
    error = WEBDAV_ERROR_NO_MEM;
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
  int fstat_ret = fstat(ctx->fd, &st);
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
    ssize_t read_ret = read(ctx->fd, ctx->buf, sizeof(ctx->buf));
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
  UTHR_CALL6(_posix_get_uthr, PosixGetCtx,
             .pbctx = (PosixBackendCtx *) backend_handle,
             .relative_uri = relative_uri,
             .get_ctx = get_ctx);
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

static void
posix_delete(void *backend_handle,
	     const char *relative_uri,
	     event_handler_t cb, void *ud) {
  PosixBackendCtx *pbctx = backend_handle;
  char *file_path = path_from_uri(pbctx, relative_uri);

  /* TODO: yield after every delete */
  linked_list_t failed_to_delete = rmtree(file_path);
  free(file_path);

  WebdavDeleteDoneEvent ev = {
    .error = WEBDAV_ERROR_NONE,
    .failed_to_delete = failed_to_delete,
  };
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
    };
    return cb(WEBDAV_MOVE_DONE_EVENT, &move_done_ev, ud);
  }
  else {
    WebdavCopyDoneEvent copy_done_ev = {
      .error = err,
      /* TODO: implement */
      .failed_to_copy = LINKED_LIST_INITIALIZER,
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
  .get = posix_get,
  .mkcol = posix_mkcol,
  .delete = posix_delete,
  .copy = posix_copy,
  .move = posix_move,
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
  assert(ret);

  /* start webdav server */
  PosixBackendCtx pbctx = {
    .base_path = base_path,
    .base_path_len = strlen(base_path),
  };

  webdav_backend_t fs = webdav_backend_new(&posix_backend_operations,
                                           sizeof(posix_backend_operations),
                                           &pbctx);
  webdav_server_t ws = webdav_server_start(&loop, server_fd, public_prefix, fs);

  assert(ws);

  log_info("Starting main loop");
  fdevent_main_loop(&loop);

  log_info("Server stopped");

  webdav_backend_destroy(fs);

  free(base_path);

  return 0;
}
