#define _ISOC99_SOURCE
#define _BSD_SOURCE

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <assert.h>
#include <errno.h>

#include "c_util.h"
#include "fstatat.h"
#include "fdevent.h"
#include "fd_utils.h"
#include "logging.h"
#include "webdav_server.h"
#include "util.h"

typedef struct {
  char *base_path;
  size_t base_path_len;
} PosixWebdavServer;

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
path_from_uri(PosixWebdavServer *pwds, const char *real_uri) {
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
  PosixWebdavServer *pwds = fs_handle;
  WebdavOpenDoneEvent ev;

  char *file_path = path_from_uri(pwds, relative_uri);
  if (!file_path) {
    ev.error = WEBDAV_ERROR_NO_MEM;
    goto done;
  }

  /* TODO: perhaps use O_NONBLOCK
     (if that even works for files these days) */
  int fd = open(file_path, O_RDWR | (create ? O_CREAT : 0) | O_CLOEXEC, 0666);
  if (!fd) {
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  ev = (WebdavOpenDoneEvent) {
    .error = WEBDAV_ERROR_NONE,
    .file_handle = (void *) fd,
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
  int fd = (int) file_handle;

  struct stat st;
  int statret = fstat(fd, &st);
  if (statret) {
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
  int fd = (int) file_handle;

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
posix_close(void *fs_handle,
	    void *file_handle,
	    event_handler_t cb, void *ud) {
  UNUSED(fs_handle);

  int fd = (int) file_handle;
  int ret = close(fd);

  WebdavFstatDoneEvent ev = {
    .error = ret ? WEBDAV_ERROR_GENERAL : WEBDAV_ERROR_NONE,
  };

  return cb(WEBDAV_CLOSE_DONE_EVENT, &ev, ud);
}

static void
posix_mkcol(void *fs_handle, const char *relative_uri,
	    event_handler_t cb, void *ud) {
  WebdavMkcolDoneEvent ev;
  PosixWebdavServer *pwds = fs_handle;

  char *file_path = path_from_uri(pwds, relative_uri);
  if (!file_path) {
    ev.error = WEBDAV_ERROR_NO_MEM;
    goto done;
  }

  int ret = mkdir(file_path, 0777);
  if (ret) {
    /* TODO: return more specific error if server requires */
    ev.error = WEBDAV_ERROR_GENERAL;
    /*
    if (errno == ENOENT) {
      status_code = HTTP_STATUS_CODE_CONFLICT;
    }
    else if (errno == ENOSPC ||
             errno == EDQUOT) {
      status_code = HTTP_STATUS_CODE_INSUFFICIENT_STORAGE;
    }
    else if (errno == ENOTDIR) {
      status_code = HTTP_STATUS_CODE_FORBIDDEN;
    }
    else if (errno == EACCES) {
      status_code = HTTP_STATUS_CODE_METHOD_NOT_ALLOWED;
    }
    else if (errno == EEXIST) {
      struct stat st;
      ret = stat(file_path, &st);
      if (ret < 0) {
        status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
      }
      else if (S_ISDIR(st.st_mode)) {
        status_code = HTTP_STATUS_CODE_METHOD_NOT_ALLOWED;
      }
      else {
        status_code = HTTP_STATUS_CODE_FORBIDDEN;
      }
    }
    else {
      status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    }
  }
*/
    goto done;
  }

  ev.error = WEBDAV_ERROR_NONE;

 done:
  free(file_path);
  return cb(WEBDAV_MKCOL_DONE_EVENT, &ev, ud);
}

static void
posix_opencol(void *fs_handle, const char *relative_uri,
	      event_handler_t cb, void *ud) {
  WebdavOpencolDoneEvent ev;

  char *file_path = path_from_uri(fs_handle, relative_uri);
  if (!file_path) {
    ev.error = WEBDAV_ERROR_NO_MEM;
    goto done;
  }

  DIR *dirp = opendir(file_path);
  if (!dirp) {
    /* TODO: return more specific error if server requires */
    ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  ev = (WebdavOpencolDoneEvent) {
    .error = WEBDAV_ERROR_NONE,
    .col_handle = dirp,
  };

 done:
  free(file_path);
  return cb(WEBDAV_OPENCOL_DONE_EVENT, &ev, ud);
}

static void
posix_readcol(void *fs_handle,
	      void *col_handle,
	      WebdavCollectionEntry *ce, size_t nentries,
	      event_handler_t cb, void *ud) {
  UNUSED(fs_handle);

  WebdavReadcolDoneEvent ev;
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
posix_closecol(void *fs_handle,
	       void *col_handle,
	       event_handler_t cb, void *ud) {
  UNUSED(fs_handle);

  DIR *dirp = col_handle;
  int ret = closedir(dirp);

  WebdavReadcolDoneEvent ev = {
    .error = ret ? WEBDAV_ERROR_GENERAL : WEBDAV_ERROR_NONE,
  };

  return cb(WEBDAV_CLOSECOL_DONE_EVENT, &ev, ud);
}

static WebdavOperations
posix_webdav_operations = {
  .open = posix_open,
  .fstat = posix_fstat,
  .read = posix_read,
  .close = posix_close,
  .mkcol = posix_mkcol,
  .opencol = posix_opencol,
  .readcol = posix_readcol,
  .closecol = posix_closecol,
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

  /* create server socket */
  int server_fd = create_ipv4_bound_socket(port);
  assert(server_fd >= 0);

  /* create event loop */
  FDEventLoop loop;
  bool ret = fdevent_init(&loop);
  assert(ret);

  /* start webdav server */
  char *base_path = getcwd(NULL, 0);
  ASSERT_NOT_NULL(base_path);
  PosixWebdavServer pwds = {
    .base_path = base_path,
    .base_path_len = strlen(base_path),
  };

  webdav_fs_t fs = webdav_fs_new(&posix_webdav_operations, sizeof(posix_webdav_operations),
				 &pwds);
  webdav_server_t ws = webdav_server_start(&loop, server_fd, fs);

  assert(ws);

  log_info("Starting main loop");
  fdevent_main_loop(&loop);

  return 0;
}
