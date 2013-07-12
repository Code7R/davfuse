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
#include "util.h"

typedef struct {
  char *base_path;
  size_t base_path_len;
} PosixFsCtx;

static bool
is_fd_handle(void *h) {
  return ((intptr_t) h) & 1;
}

static int
file_handle_to_fd(void *fh) {
  assert(is_fd_handle(fh));
  return (int) (((intptr_t) fh) >> 1);
}

static void *
fd_to_file_handle(int fd) {
  return (void *)((((intptr_t) fd) << 1) | 0x1);
}

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
path_from_uri(PosixFsCtx *pwds, const char *real_uri) {
  size_t uri_len = strlen(real_uri);
  if (str_equals(real_uri, "/")) {
    uri_len = 0;
  }
  /* return relative path (no leading slash), but also
     don't include trailing slash, since posix treats that like "/." */
  else if (real_uri[uri_len - 1] == '/') {
    uri_len -= 1;
  }

  char *toret = malloc(pwds->base_path_len + uri_len + 1);
  if (!toret) {
    return NULL;
  }
  memcpy(toret, pwds->base_path, pwds->base_path_len);
  memcpy(toret + pwds->base_path_len, real_uri, uri_len);
  toret[pwds->base_path_len + uri_len] = '\0';

  return toret;
}

static void
posix_open(void *fs_handle, const char *relative_uri, bool create,
	   event_handler_t cb, void *ud) {
  PosixFsCtx *pwds = fs_handle;
  WebdavOpenDoneEvent ev;

  char *file_path = path_from_uri(pwds, relative_uri);
  if (!file_path) {
    ev.error = WEBDAV_ERROR_NO_MEM;
    goto done;
  }

  /* TODO: perhaps use O_NONBLOCK
     (if that even works for files these days) */
  void *file_handle = NULL;

  while (!file_handle) {
    int fd = open(file_path, O_RDWR | (create ? O_CREAT : 0) /* | O_CLOEXEC */, 0666);
    if (fd >= 0) {
      file_handle = fd_to_file_handle(fd);
    }

    if (!file_handle && errno == EISDIR) {
      file_handle = opendir(file_path);
      assert(!is_fd_handle(file_handle));
    }

    if (!file_handle) {
      if (errno == ENOENT && create) {
	/* we tried opening the directory, but it disappeared,
	   WEBDAV_ERROR_DOES_NOT_EXIST is not a valid response
	   when create is true */
	continue;
      }

      log_info("Couldn't open resource (%s): %s",
	       file_path, strerror(errno));
      ev.error = errno == ENOENT
	? WEBDAV_ERROR_DOES_NOT_EXIST
	: WEBDAV_ERROR_GENERAL;
      goto done;
    }
  }

  ev = (WebdavOpenDoneEvent) {
    .error = WEBDAV_ERROR_NONE,
    .file_handle = file_handle,
  };

 done:
  free(file_path);

  return cb(WEBDAV_OPEN_DONE_EVENT, &ev, ud);
}

static void
posix_fstat(void *fs_handle,
	    void *file_handle,
	    event_handler_t cb, void *ud) {
  UNUSED(fs_handle);

  WebdavFstatDoneEvent ev;
  int fd;
  if (is_fd_handle(file_handle)) {
    fd = file_handle_to_fd(file_handle);
  }
  else {
    fd = dirfd(file_handle);
  }

  struct stat st;
  int statret = fstat(fd, &st);
  if (statret) {
    log_info("Couldn't fstat fd (%d): %s",
	     fd, strerror(errno));
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  ev.error = WEBDAV_ERROR_NONE;
  fill_file_info(&ev.file_info, &st);

 done:
  return cb(WEBDAV_FSTAT_DONE_EVENT, &ev, ud);
}

static void
posix_read(void *fs_handle,
	   void *file_handle,
	   void *buf, size_t nbyte,
	   event_handler_t cb, void *ud) {
  UNUSED(fs_handle);
  WebdavReadDoneEvent ev;

  if (!is_fd_handle(file_handle)) {
    ev.error = WEBDAV_ERROR_IS_COL;
    goto done;
  }

  int fd = file_handle_to_fd(file_handle);

  int ret = read(fd, buf, nbyte);
  if (ret < 0) {
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  ev = (WebdavReadDoneEvent) {
    .error = WEBDAV_ERROR_NONE,
    .nbyte = ret,
  };

 done:
  return cb(WEBDAV_READ_DONE_EVENT, &ev, ud);
}

static void
posix_write(void *fs_handle,
	    void *file_handle,
	    const void *buf, size_t nbyte,
	    event_handler_t cb, void *ud) {
  UNUSED(fs_handle);

  WebdavWriteDoneEvent ev;

  if (!is_fd_handle(file_handle)) {
    ev.error = WEBDAV_ERROR_IS_COL;
    goto done;
  }

  int fd = file_handle_to_fd(file_handle);

  int ret = write(fd, buf, nbyte);
  if (ret < 0) {
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  ev = (WebdavWriteDoneEvent) {
    .error = WEBDAV_ERROR_NONE,
    .nbyte = ret,
  };

 done:
  return cb(WEBDAV_WRITE_DONE_EVENT, &ev, ud);
}

static void
posix_readcol(void *fs_handle,
	      void *col_handle,
	      WebdavCollectionEntry *ce, size_t nentries,
	      event_handler_t cb, void *ud) {
  UNUSED(fs_handle);

  WebdavReadcolDoneEvent ev;
  if (is_fd_handle(col_handle)) {
    ev.error = WEBDAV_ERROR_NOT_COLLECTION;
    goto done;
  }

  DIR *dirp = col_handle;

  struct dirent entry, *result;
  size_t i;
  for (i = 0; i < nentries; ++i) {
    int ret = readdir_r(dirp, &entry, &result);
    if (ret) {
      ev.error = WEBDAV_ERROR_GENERAL;
      goto done;
    }

    if (!result) {
      break;
    }

    /* TODO: handle this error more gracefully */
    if (strlen(result->d_name) > sizeof(ce->name) - 1) {
      ev.error = WEBDAV_ERROR_GENERAL;
      goto done;
    }

    strcpy(ce[i].name, result->d_name);

    struct stat st;
    int fstatat_ret = fstatat(dirfd(dirp), result->d_name, &st, 0);
    if (fstatat_ret) {
      ev.error = WEBDAV_ERROR_GENERAL;
      goto done;
    }

    fill_file_info(&ce[i].file_info, &st);
  }

  ev = (WebdavReadcolDoneEvent) {
    .error = WEBDAV_ERROR_NONE,
    .nread = i,
  };

 done:
  return cb(WEBDAV_READCOL_DONE_EVENT, &ev, ud);
}

static void
posix_close(void *fs_handle,
	    void *file_handle,
	    event_handler_t cb, void *ud) {
  UNUSED(fs_handle);

  int ret;
  if (is_fd_handle(file_handle)) {
    int fd = file_handle_to_fd(file_handle);
    ret = close(fd);
  }
  else {
    ret = closedir(file_handle);
  }

  WebdavFstatDoneEvent ev = {
    .error = ret ? WEBDAV_ERROR_GENERAL : WEBDAV_ERROR_NONE,
  };

  return cb(WEBDAV_CLOSE_DONE_EVENT, &ev, ud);
}

static void
posix_mkcol(void *fs_handle, const char *relative_uri,
	    event_handler_t cb, void *ud) {
  WebdavMkcolDoneEvent ev;
  PosixFsCtx *pwds = fs_handle;

  char *file_path = path_from_uri(pwds, relative_uri);
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
posix_delete(void *fs_handle,
	     const char *relative_uri,
	     event_handler_t cb, void *ud) {
  PosixFsCtx *fs_ctx = fs_handle;
  char *file_path = path_from_uri(fs_ctx, relative_uri);

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
_posix_copy_move(void *fs_handle,
		 bool is_move,
		 const char *src_relative_uri, const char *dst_relative_uri,
		 bool overwrite, webdav_depth_t depth,
		 event_handler_t cb, void *ud) {
  assert(depth == DEPTH_INF ||
	 (depth == DEPTH_0 && !is_move));

  PosixFsCtx *fs_ctx = fs_handle;
  webdav_error_t err;

  char *file_path = path_from_uri(fs_ctx, src_relative_uri);
  char *destination_path = path_from_uri(fs_ctx, dst_relative_uri);

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
posix_copy(void *fs_handle,
	   const char *src_relative_uri, const char *dst_relative_uri,
	   bool overwrite, webdav_depth_t depth,
	   event_handler_t cb, void *ud) {
  bool is_move = false;
  return _posix_copy_move(fs_handle, is_move,
			  src_relative_uri, dst_relative_uri,
			  overwrite, depth,
			  cb, ud);
}

static void
posix_move(void *fs_handle,
	   const char *src_relative_uri, const char *dst_relative_uri,
	   bool overwrite,
	   event_handler_t cb, void *ud) {
  bool is_move = true;
  return _posix_copy_move(fs_handle, is_move,
			  src_relative_uri, dst_relative_uri,
			  overwrite, DEPTH_INF,
			  cb, ud);
}

static WebdavOperations
posix_operations = {
  .open = posix_open,
  .fstat = posix_fstat,
  .read = posix_read,
  .write = posix_write,
  .readcol = posix_readcol,
  .close = posix_close,
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
  PosixFsCtx pwds = {
    .base_path = base_path,
    .base_path_len = strlen(base_path),
  };

  webdav_fs_t fs = webdav_fs_new(&posix_operations, sizeof(posix_operations), &pwds);
  webdav_server_t ws = webdav_server_start(&loop, server_fd, public_prefix, fs);

  assert(ws);

  log_info("Starting main loop");
  fdevent_main_loop(&loop);

  return 0;
}
