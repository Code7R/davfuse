#define _ISOC99_SOURCE
/* for dirfd/pread/pwrite */
#define _POSIX_C_SOURCE 200809L

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>

#include <assert.h>
#include <errno.h>

#include "fd_utils.h"
#include "fs_posix_fstatat.h"
#include "util.h"

#include "fs_posix.h"

enum {
  _FS_POSIX_SINGLETON=1,
};

static void
ASSERT_VALID_FS(fs_posix_t fs) {
  UNUSED(fs);
  assert(fs == _FS_POSIX_SINGLETON);
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
  return fd;
}

static int
file_handle_to_fd(fs_posix_file_handle_t handle) {
  assert(handle >= 0);
  if (!handle) {
    return -1;
  }
  else {
    return handle - 1;
  }
}

static fs_posix_error_t
errno_to_fs_error(void) {
  switch (errno) {
  case 0:
    abort();
  case ENOTDIR:
    return FS_POSIX_ERROR_NOT_DIR;
  case EISDIR:
    return FS_POSIX_ERROR_IS_DIR;
  case ENOENT:
    return FS_POSIX_ERROR_DOES_NOT_EXIST;
  case ENOSPC: case EDQUOT:
    return FS_POSIX_ERROR_NO_SPACE;
  case EACCES: case EPERM:
    return FS_POSIX_ERROR_PERM;
  case EEXIST:
    return FS_POSIX_ERROR_EXISTS;
  case EXDEV:
    return FS_POSIX_ERROR_CROSS_DEVICE;
  default:
    return FS_POSIX_ERROR_IO;
  }
}

static void
fill_attrs(FsPosixAttrs *attrs, struct stat *st) {
  *attrs = (FsPosixAttrs) {
    .modified_time = st->st_mtime,
    /* special case this on systems that support this */
    .created_time = FS_POSIX_INVALID_TIME,
    .is_directory = S_ISDIR(st->st_mode),
    .size = st->st_size,
  };
}

fs_posix_t
fs_posix_default_new(void) {
  /* don't need context */
  return _FS_POSIX_SINGLETON;
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

fs_posix_error_t
fs_posix_open(fs_posix_t fs,
              const char *path, bool create,
              OUT_VAR fs_posix_file_handle_t *handle,
              OUT_VAR bool *created) {
  ASSERT_VALID_FS(fs);

  fs_posix_error_t toret;
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
    toret = FS_POSIX_ERROR_SUCCESS;
  }

  return toret;
}

fs_posix_error_t
fs_posix_fgetattr(fs_posix_t fs, fs_posix_file_handle_t file_handle,
                  OUT_VAR FsPosixAttrs *attrs) {
  ASSERT_VALID_FS(fs);
  int fd = file_handle_to_fd(file_handle);
  struct stat st;
  int ret_fstat = fstat(fd, &st);
  if (ret_fstat < 0) {
    return errno_to_fs_error();
  }

  fill_attrs(attrs, &st);

  return FS_POSIX_ERROR_SUCCESS;
}

fs_posix_error_t
fs_posix_ftruncate(fs_posix_t fs, fs_posix_file_handle_t file_handle,
                   fs_posix_off_t offset) {
  ASSERT_VALID_FS(fs);
  int fd = file_handle_to_fd(file_handle);
  int ret_ftruncate = ftruncate(fd, offset);
  if (ret_ftruncate < 0) {
    return errno_to_fs_error();
  }

  return FS_POSIX_ERROR_SUCCESS;
}

fs_posix_error_t
fs_posix_read(fs_posix_t fs, fs_posix_file_handle_t file_handle,
              OUT_VAR char *buf, size_t size, fs_posix_off_t off,
              OUT_VAR size_t *amt_read) {
  ASSERT_VALID_FS(fs);
  int fd = file_handle_to_fd(file_handle);
  ssize_t ret_pread = pread(fd, buf, size, off);
  if (ret_pread < 0) {
    return errno_to_fs_error();
  }

  *amt_read = ret_pread;

  return FS_POSIX_ERROR_SUCCESS;
}

fs_posix_error_t
fs_posix_write(fs_posix_t fs, fs_posix_file_handle_t file_handle,
               const char *buf, size_t size, fs_posix_off_t offset,
               OUT_VAR size_t *amt_written) {
  ASSERT_VALID_FS(fs);
  int fd = file_handle_to_fd(file_handle);
  ssize_t ret_pwrite = pwrite(fd, buf, size, offset);
  if (ret_pwrite < 0) {
    return errno_to_fs_error();
  }

  *amt_written = ret_pwrite;

  return FS_POSIX_ERROR_SUCCESS;
}

fs_posix_error_t
fs_posix_close(fs_posix_t fs, fs_posix_file_handle_t file_handle) {
  ASSERT_VALID_FS(fs);
  int fd = file_handle_to_fd(file_handle);
  int ret_close = close(fd);
  if (ret_close < 0) {
    return errno_to_fs_error();
  }

  return FS_POSIX_ERROR_SUCCESS;
}

fs_posix_error_t
fs_posix_opendir(fs_posix_t fs, const char *path,
                 OUT_VAR fs_posix_directory_handle_t *dir_handle) {
  ASSERT_VALID_FS(fs);
  *dir_handle = opendir(path);
  if (!*dir_handle) {
    return errno_to_fs_error();
  }

  return FS_POSIX_ERROR_SUCCESS;
}

fs_posix_error_t
fs_posix_readdir(fs_posix_t fs, fs_posix_directory_handle_t dir_handle,
                 /* name is required and malloc'd by the implementation,
                    the user must free the returned pointer
                 */
                 OUT_VAR char **name,
                 /* attrs is optionally filled by the implementation */
                 OUT_VAR bool *attrs_is_filled,
                 OUT_VAR FsPosixAttrs *attrs) {
  UNUSED(attrs);
  ASSERT_VALID_FS(fs);

  while (true) {
    errno = 0;
    struct dirent *const ent = readdir(dir_handle);
    if (!ent && errno) {
      return errno_to_fs_error();
    }

    if (!ent) {
      *name = NULL;
      break;
    }

    char *const ent_name = ent->d_name;

    if (str_equals(ent_name, ".") ||
        str_equals(ent_name, "..")) {
      continue;
    }

    *name = strdup_x(ent_name);
    if (attrs_is_filled) {
      *attrs_is_filled = false;
    }

    const int dir_fd = dirfd(dir_handle);
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
    }
    else {
      log_warning("Couldn't get the fd of the directory pointer: %s",
                  strerror(errno));
    }

    break;
  }

  return FS_POSIX_ERROR_SUCCESS;
}

fs_posix_error_t
fs_posix_closedir(fs_posix_t fs, fs_posix_directory_handle_t dir_handle) {
  ASSERT_VALID_FS(fs);
  int ret_closedir = closedir(dir_handle);
  if (ret_closedir < 0) {
    return errno_to_fs_error();
  }

  return FS_POSIX_ERROR_SUCCESS;
}

/* can remove either a file or a directory,
   removing a directory should fail if it's not empty
*/
fs_posix_error_t
fs_posix_remove(fs_posix_t fs, const char *path) {
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

  return FS_POSIX_ERROR_SUCCESS;
}

fs_posix_error_t
fs_posix_mkdir(fs_posix_t fs, const char *path) {
  ASSERT_VALID_FS(fs);
  int ret_mkdir = mkdir(path, 0777);
  if (ret_mkdir < 0) {
    return errno_to_fs_error();
  }

  return FS_POSIX_ERROR_SUCCESS;
}

fs_posix_error_t
fs_posix_getattr(fs_posix_t fs, const char *path,
                 OUT_VAR FsPosixAttrs *attrs) {
  ASSERT_VALID_FS(fs);
  struct stat st;
  int ret_stat = stat(path, &st);
  if (ret_stat < 0) {
    return errno_to_fs_error();
  }

  fill_attrs(attrs, &st);

  return FS_POSIX_ERROR_SUCCESS;
}

fs_posix_error_t
fs_posix_rename(fs_posix_t fs,
                const char *src, const char *dst) {
  ASSERT_VALID_FS(fs);
  int ret_rename = rename(src, dst);
  if (ret_rename < 0) {
    return errno_to_fs_error();
  }

  return FS_POSIX_ERROR_SUCCESS;
}

bool
fs_posix_destroy(fs_posix_t fs) {
  ASSERT_VALID_FS(fs);
  return true;
}

bool
fs_posix_path_is_root(fs_posix_t fs, const char *a) {
  ASSERT_VALID_FS(fs);

  return str_equals(a, "/");
}

bool
fs_posix_path_equals(fs_posix_t fs, const char *a, const char *b) {
  ASSERT_VALID_FS(fs);

  return str_equals(a, b);
}

bool
fs_posix_path_is_parent(fs_posix_t fs,
                        const char *potential_parent,
                        const char *potential_child) {
  ASSERT_VALID_FS(fs);

  if (!str_startswith(potential_child, potential_parent)) {
    return false;
  }

  size_t potential_parent_len = strlen(potential_parent);
  return potential_child[potential_parent_len] == '/';
}

const char *
fs_posix_path_sep(fs_posix_t fs) {
  ASSERT_VALID_FS(fs);

  return "/";
}
