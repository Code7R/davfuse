#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <unistd.h>

#include <assert.h>
#include <errno.h>

#include "fs_posix.h"
#include "util.h"

enum {
  _FS_POSIX_SINGLETON=1,
};

static void
ASSERT_VALID_FS(fs_posix_t fs) {
  UNUSED(fs);
  assert(fs == _FS_POSIX_SINGLETON);
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
    .created_time = st->st_mtime,
    .is_directory = S_ISDIR(st->st_mode),
    .size = st->st_size,
  };
}

fs_posix_t
fs_posix_blank_new(void) {
  /* don't need context */
  return _FS_POSIX_SINGLETON;
}

static bool
open_or_create(const char *file_path, int flags, mode_t mode,
               int *fd, bool *created) {
  assert(!(flags & O_CREAT));
  assert(!(flags & O_EXCL));

  errno = 0;
  do {
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
  bool success_open;
  if (create) {
    success_open = open_or_create(path, O_RDWR, 0666, handle, created);
  }
  else {
    *handle = open(path, O_RDWR);
    success_open = *handle >= 0;
  }

  if (!success_open) {
    return errno_to_fs_error();
  }

  return FS_POSIX_ERROR_SUCCESS;
}

fs_posix_error_t
fs_posix_fgetattr(fs_posix_t fs, fs_posix_file_handle_t file_handle,
                  OUT_VAR FsPosixAttrs *attrs) {
  ASSERT_VALID_FS(fs);
  struct stat st;
  int ret_fstat = fstat(file_handle, &st);
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
  int ret_ftruncate = ftruncate(file_handle, offset);
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
  ssize_t ret_pread = pread(file_handle, buf, size, off);
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
  ssize_t ret_pwrite = pwrite(file_handle, buf, size, offset);
  if (ret_pwrite < 0) {
    return errno_to_fs_error();
  }

  *amt_written = ret_pwrite;

  return FS_POSIX_ERROR_SUCCESS;
}

fs_posix_error_t
fs_posix_close(fs_posix_t fs, fs_posix_file_handle_t handle) {
  ASSERT_VALID_FS(fs);
  int ret_close = close(handle);
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
  errno = 0;
  struct dirent *ent = readdir(dir_handle);
  if (!ent && errno) {
    return errno_to_fs_error();
  }

  /* TODO: deal with this
      if (str_equals(dirent->d_name, ".") ||
          str_equals(dirent->d_name, "..")) {
        continue;
      }

      int fstatatx_ret = fstatat_x(fd_for_stat, dirent->d_name, &entry_st, 0);
      if (fstatatx_ret < 0) {
        ev.error = WEBDAV_ERROR_GENERAL;
        goto done;
      }


  */

  if (!ent) {
    *name = NULL;
  }
  else {
    *name = strdup_x(ent->d_name);
    *attrs_is_filled = false;
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
  int ret_mkdir = mkdir(path, 0666);
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

char *
fs_posix_dirname(fs_posix_t fs,
                 const char *path) {
  UNUSED(fs);
  UNUSED(path);
  abort();
  return NULL;
}
