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
/* for dirfd/pread/pwrite */
#define _POSIX_C_SOURCE 200809L

#include "fs_posix.h"

#include "fd_utils.h"
#include "fs_helpers.h"
#include "fstatat.h"
#include "util.h"

#include <assert.h>
#include <limits.h>
#include <errno.h>

#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>

typedef enum {
  _FS_POSIX_SINGLETON=1,
} posix_singleton_t;

#define POSIX_SINGLETON_MAX INT_MAX
#define POSIX_SINGLETON_MIN INT_MIN

STATIC_ASSERT(sizeof(int) <= sizeof(fs_posix_file_handle_t),
              "fs_posix_file_handle_t is not large enough to hold an int");

STATIC_ASSERT(sizeof(_FS_POSIX_SINGLETON) <= sizeof(fs_posix_handle_t),
              "fs_posix_handle_t is not large enough to hold the singletone");

static fs_posix_handle_t
singleton_to_handle(posix_singleton_t single) {
  return (fs_posix_handle_t) (uintptr_t) single;
}

static posix_singleton_t
handle_to_singleton(fs_posix_handle_t single) {
  intptr_t a = (intptr_t) single;
  if (a < POSIX_SINGLETON_MIN) abort();
  if (a > POSIX_SINGLETON_MAX) abort();
  return (posix_singleton_t) a;
}

static void
ASSERT_VALID_FS(fs_posix_handle_t fs) {
  UNUSED(handle_to_singleton(fs));
  assert(handle_to_singleton(fs) == _FS_POSIX_SINGLETON);
}

static fs_posix_file_handle_t
fd_to_file_handle(int fd) {
  /* an invalid file handle has the value 0
     to shift valid file handles up by 1 */
  if (fd >= 0) {
    fd += 1;
  }
  else {
    fd = 0;
  }
  return (fs_posix_file_handle_t) (uintptr_t) fd;
}

static int
file_handle_to_fd(fs_posix_file_handle_t handle) {
  if (!handle) {
    return -1;
  }
  else {
    return ((uintptr_t) handle) - 1;
  }
}

static fs_posix_directory_handle_t
dirp_to_directory_handle(DIR *dirp) {
  return (fs_posix_directory_handle_t) dirp;
}

static DIR *
directory_handle_to_dirp(fs_posix_directory_handle_t handle) {
  return (DIR *) handle;
}

static fs_error_t
errno_to_fs_error(void) {
  switch (errno) {
  case 0:
    abort();
  case ENOTDIR:
    return FS_ERROR_NOT_DIR;
  case EISDIR:
    return FS_ERROR_IS_DIR;
  case ENOENT:
    return FS_ERROR_DOES_NOT_EXIST;
  case ENOSPC: case EDQUOT:
    return FS_ERROR_NO_SPACE;
  case EACCES: case EPERM:
    return FS_ERROR_PERM;
  case EEXIST:
    return FS_ERROR_EXISTS;
  case EXDEV:
    return FS_ERROR_CROSS_DEVICE;
  default:
    return FS_ERROR_IO;
  }
}

static void
fill_attrs(FsAttrs *attrs, struct stat *st) {
  *attrs = (FsAttrs) {
    .modified_time = st->st_mtime,
    /* special case this on systems that support this */
    .created_time = FS_INVALID_TIME,
    .is_directory = S_ISDIR(st->st_mode),
    .size = st->st_size,
    .file_id = st->st_ino,
    .volume_id = st->st_dev,
  };
}

fs_posix_handle_t
fs_posix_default_new(void) {
  /* don't need context */
  return singleton_to_handle(_FS_POSIX_SINGLETON);
}

static bool
open_or_create(const char *file_path, int flags, mode_t mode,
               int *fd, bool *created) {
  assert(!(flags & O_CREAT));
  assert(!(flags & O_EXCL));

  do {
    errno = 0;
    *fd = open(file_path, flags);
    if (*fd < 0 && errno == ENOENT) {
      errno = 0;
      *fd = open(file_path, flags | O_CREAT | O_EXCL, mode);

      if (*fd < 0 && errno == EEXIST) {
        errno = 0;
        continue;
      }

      if (*fd >= 0) {
        assert(!errno);
        if (created) {
          *created = true;
        }
      }
    }
    else if (*fd >= 0) {
      assert(!errno);
      if (created) {
        *created = false;
      }
    }
  }
  while (*fd < 0 && !errno);

  return !errno;
}

fs_error_t
fs_posix_open(fs_posix_handle_t fs,
              const char *path, bool create,
              OUT_VAR fs_posix_file_handle_t *handle,
              OUT_VAR bool *created) {
  ASSERT_VALID_FS(fs);

  fs_error_t toret;
  int fd = -1;

  if (create) {
    const bool success_open =
      open_or_create(path, O_RDWR, 0666, &fd, created);
    if (!success_open) {
      goto posix_error;
    }
  }
  else {
    fd = open(path, O_RDWR);
    if (fd < 0) {
      goto posix_error;
    }
  }

  if (false) {
  posix_error:
    toret = errno_to_fs_error();
    if (fd >= 0) {
      close_or_abort(fd);
    }
  }
  else {
    *handle = fd_to_file_handle(fd);
    toret = FS_ERROR_SUCCESS;
  }

  return toret;
}

fs_error_t
fs_posix_fgetattr(fs_posix_handle_t fs, fs_posix_file_handle_t file_handle,
                  OUT_VAR FsAttrs *attrs) {
  ASSERT_VALID_FS(fs);
  int fd = file_handle_to_fd(file_handle);
  struct stat st;
  int ret_fstat = fstat(fd, &st);
  if (ret_fstat < 0) {
    return errno_to_fs_error();
  }

  fill_attrs(attrs, &st);

  return FS_ERROR_SUCCESS;
}

fs_error_t
fs_posix_ftruncate(fs_posix_handle_t fs, fs_posix_file_handle_t file_handle,
                   fs_off_t offset) {
  ASSERT_VALID_FS(fs);
  int fd = file_handle_to_fd(file_handle);
  int ret_ftruncate = ftruncate(fd, offset);
  if (ret_ftruncate < 0) {
    return errno_to_fs_error();
  }

  return FS_ERROR_SUCCESS;
}

fs_error_t
fs_posix_read(fs_posix_handle_t fs, fs_posix_file_handle_t file_handle,
              OUT_VAR char *buf, size_t size, fs_off_t off,
              OUT_VAR size_t *amt_read) {
  ASSERT_VALID_FS(fs);
  int fd = file_handle_to_fd(file_handle);
  ssize_t ret_pread = pread(fd, buf, size, off);
  if (ret_pread < 0) {
    return errno_to_fs_error();
  }

  *amt_read = ret_pread;

  return FS_ERROR_SUCCESS;
}

fs_error_t
fs_posix_write(fs_posix_handle_t fs, fs_posix_file_handle_t file_handle,
               const char *buf, size_t size, fs_off_t offset,
               OUT_VAR size_t *amt_written) {
  ASSERT_VALID_FS(fs);
  int fd = file_handle_to_fd(file_handle);
  ssize_t ret_pwrite = pwrite(fd, buf, size, offset);
  if (ret_pwrite < 0) {
    return errno_to_fs_error();
  }

  *amt_written = ret_pwrite;

  return FS_ERROR_SUCCESS;
}

fs_error_t
fs_posix_close(fs_posix_handle_t fs, fs_posix_file_handle_t file_handle) {
  ASSERT_VALID_FS(fs);
  int fd = file_handle_to_fd(file_handle);
  int ret_close = close(fd);
  if (ret_close < 0) {
    return errno_to_fs_error();
  }

  return FS_ERROR_SUCCESS;
}

fs_error_t
fs_posix_opendir(fs_posix_handle_t fs, const char *path,
                 OUT_VAR fs_posix_directory_handle_t *dir_handle) {
  ASSERT_VALID_FS(fs);
  *dir_handle = dirp_to_directory_handle(opendir(path));
  if (!*dir_handle) {
    return errno_to_fs_error();
  }

  return FS_ERROR_SUCCESS;
}

fs_error_t
fs_posix_readdir(fs_posix_handle_t fs, fs_posix_directory_handle_t dir_handle,
                 /* name is required and malloc'd by the implementation,
                    the user must free the returned pointer
                 */
                 OUT_VAR char **name,
                 /* attrs is optionally filled by the implementation */
                 OUT_VAR bool *attrs_is_filled,
                 OUT_VAR FsAttrs *attrs) {
  UNUSED(attrs);
  ASSERT_VALID_FS(fs);

  DIR *const dirp = directory_handle_to_dirp(dir_handle);

  while (true) {
    errno = 0;
    struct dirent *const ent = readdir(dirp);
    if (!ent && errno) {
      return errno_to_fs_error();
    }

    if (!ent) {
      *name = NULL;
      break;
    }

    /* since we're possibly using -fcatch-undefined-behavior
       we have to do this cast, otherwise we'll get misaligned pointer errors
       (some systems return a `struct dirent *` that's not aligned to a byte
       boundary implied by the header definition of `struct dirent`:
       http://clang-developers.42468.n3.nabble.com/fcatch-undefined-behavior-false-positive-with-readdir-td4026941.html */
    /* `d_name` is an array embedded in `struct dirent` */
    /* char *const ent_name = ent->d_name; */
    char *const ent_name = (char *) ent + offsetof(struct dirent, d_name);

    if (str_equals(ent_name, ".") ||
        str_equals(ent_name, "..")) {
      continue;
    }

    *name = davfuse_util_strdup(ent_name);
    if (attrs_is_filled) {
      *attrs_is_filled = false;
    }

    const int dir_fd = dirfd(dirp);
    if (dir_fd >= 0) {
      struct stat entry_st;
      const int fstatatx_ret = fstatat_x(dir_fd, ent_name, &entry_st, 0);
      if (!fstatatx_ret) {
        if (attrs_is_filled) {
          *attrs_is_filled = true;
        }
        if (attrs) {
          fill_attrs(attrs, &entry_st);
        }
      }
      else {
        log_warning("fstatat_x failed: %s", strerror(errno));
      }
    }
    else {
      log_warning("Couldn't get the fd of the directory pointer: %s",
                  strerror(errno));
    }

    break;
  }

  return FS_ERROR_SUCCESS;
}

fs_error_t
fs_posix_closedir(fs_posix_handle_t fs, fs_posix_directory_handle_t dir_handle) {
  ASSERT_VALID_FS(fs);

  DIR *const dirp = directory_handle_to_dirp(dir_handle);

  int ret_closedir = closedir(dirp);
  if (ret_closedir < 0) {
    return errno_to_fs_error();
  }

  return FS_ERROR_SUCCESS;
}

/* can remove either a file or a directory,
   removing a directory should fail if it's not empty
*/
fs_error_t
fs_posix_remove(fs_posix_handle_t fs, const char *path) {
  ASSERT_VALID_FS(fs);
  int ret = unlink(path);
  if (ret < 0 &&
      (errno == EPERM ||
       /* posix says to return EPERM when unlink() is called on a directory
          linux returns EISDIR */
       errno == EISDIR)) {
    int saved_errno = errno;
    int rmdir_ret = rmdir(path);
    if (!rmdir_ret) {
      ret = 0;
    }
    else {
      errno = saved_errno;
    }
  }

  if (ret < 0) {
    return errno_to_fs_error();
  }

  return FS_ERROR_SUCCESS;
}

fs_error_t
fs_posix_mkdir(fs_posix_handle_t fs, const char *path) {
  ASSERT_VALID_FS(fs);
  int ret_mkdir = mkdir(path, 0777);
  if (ret_mkdir < 0) {
    return errno_to_fs_error();
  }

  return FS_ERROR_SUCCESS;
}

fs_error_t
fs_posix_getattr(fs_posix_handle_t fs, const char *path,
                 OUT_VAR FsAttrs *attrs) {
  ASSERT_VALID_FS(fs);
  struct stat st;
  int ret_stat = stat(path, &st);
  if (ret_stat < 0) {
    return errno_to_fs_error();
  }

  fill_attrs(attrs, &st);

  return FS_ERROR_SUCCESS;
}

fs_error_t
fs_posix_rename(fs_posix_handle_t fs,
                const char *src, const char *dst) {
  ASSERT_VALID_FS(fs);
  int ret_rename = rename(src, dst);
  if (ret_rename < 0) {
    return errno_to_fs_error();
  }

  return FS_ERROR_SUCCESS;
}

fs_error_t
fs_posix_set_times(fs_posix_handle_t fs,
                   const char *path,
                   fs_time_t atime,
                   fs_time_t mtime) {
  ASSERT_VALID_FS(fs);

  struct timeval now;
  struct timeval new_times[2];

  if (atime == FS_INVALID_TIME ||
      mtime == FS_INVALID_TIME) {
    const int res_gettimeofday = gettimeofday(&now, NULL);
    if (res_gettimeofday < 0) return errno_to_fs_error();
  }

  new_times[0] = atime == FS_INVALID_TIME
    ? now
    : (struct timeval) {atime, 0};

  new_times[1] = mtime == FS_INVALID_TIME
    ? now
    : (struct timeval) {mtime, 0};

  const int res_utimes = utimes(path, new_times);
  if (res_utimes < 0) return errno_to_fs_error();

  return FS_ERROR_SUCCESS;
}

bool
fs_posix_destroy(fs_posix_handle_t fs) {
  ASSERT_VALID_FS(fs);
  return true;
}

bool
fs_posix_path_is_root(fs_posix_handle_t fs, const char *path) {
  ASSERT_VALID_FS(fs);
  assert(fs_posix_path_is_valid(fs, path));
  return str_equals(path, "/");
}

bool
fs_posix_path_is_valid(fs_posix_handle_t fs,
                       const char *path) {
  ASSERT_VALID_FS(fs);
  return (str_startswith(path, "/") &&
          (str_equals(path, "/") || !str_endswith(path, "/")));
}

char *
fs_posix_path_dirname(fs_posix_handle_t fs, const char *path) {
  ASSERT_VALID_FS(fs);
  assert(fs_posix_path_is_valid(fs, path));

  if (fs_posix_path_is_root(fs, path)) {
    return davfuse_util_strdup(path);
  }

  const char *end_of_path = strrchr(path, '/');
  if (end_of_path == path) {
    return davfuse_util_strdup("/");
  }

  return strndup_x(path, end_of_path - path);
}

char *
fs_posix_path_basename(fs_posix_handle_t fs, const char *path) {
  ASSERT_VALID_FS(fs);
  assert(fs_posix_path_is_valid(fs, path));

  if (fs_posix_path_is_root(fs, path)) {
    return davfuse_util_strdup(path);
  }

  return fs_helpers_basename("/", path);
}

static bool
fs_posix_path_component_is_valid(fs_posix_handle_t fs,
                                 const char *component) {
  ASSERT_VALID_FS(fs);
  return !strchr(component, '/');
}

char *
fs_posix_path_join(fs_posix_handle_t fs,
                   const char *dirname, const char *basename) {
  ASSERT_VALID_FS(fs);
  assert(fs_posix_path_is_valid(fs, dirname));
  if (!fs_posix_path_component_is_valid(fs, basename)) {
    return NULL;
  }
  return fs_helpers_join("/", dirname, basename);
}
