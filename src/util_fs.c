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

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "dfs.h"
#include "logging.h"
#include "util.h"
#include "fs.h"

#include "util_fs.h"

const char *
util_fs_strerror(fs_error_t error) {
#define M(v, msg) case v: return msg
  switch (error) {
    M(FS_ERROR_NOT_DIR, "Not a directory");
    M(FS_ERROR_IS_DIR, "Is a directory");
    M(FS_ERROR_DOES_NOT_EXIST, "Does not exist");
    M(FS_ERROR_NO_SPACE, "No space left");
    M(FS_ERROR_PERM, "Permission denied");
    M(FS_ERROR_EXISTS, "File exists");
    M(FS_ERROR_CROSS_DEVICE, "Different devices");
    M(FS_ERROR_IO, "IO Error");
    M(FS_ERROR_SUCCESS, "Success");
    M(FS_ERROR_ACCESS, "Access Denied");
    M(FS_ERROR_INVALID_ARG, "Invalid Argument");
    M(FS_ERROR_NO_MEM, "No memory");
  default:
    return "Unknown error";
  }
#undef M
}

void
util_fs_closedir_or_abort(fs_handle_t fs, fs_directory_handle_t dir) {
  const fs_error_t close_ret = fs_closedir(fs, dir);
  ASSERT_TRUE(!close_ret);
}

void
util_fs_close_or_abort(fs_handle_t fs, fs_file_handle_t f) {
  const fs_error_t close_ret = fs_close(fs, f);
  ASSERT_TRUE(!close_ret);
}

fs_error_t
util_fs_file_exists(fs_handle_t fs, const char *file_path, bool *exists) {
  FsAttrs attrs;
  const fs_error_t ret = fs_getattr(fs, file_path, &attrs);
  if (ret) {
    if (ret == FS_ERROR_DOES_NOT_EXIST) {
      *exists = false;
      return FS_ERROR_SUCCESS;
    }
    else {
      return ret;
    }
  }
  else {
    *exists = true;
    return FS_ERROR_SUCCESS;
  }
}

fs_error_t
util_fs_file_is_dir(fs_handle_t fs, const char *file_path, bool *is_dir) {
  /* need to initialize `is_directory` to avoid spurious
     -Wmaybe-uninitialized warnings from GCC */
  FsAttrs attrs = {.is_directory = false};
  const fs_error_t ret = fs_getattr(fs, file_path, &attrs);
  if (ret) {
    if (ret == ENOENT) {
      *is_dir = false;
      return FS_ERROR_SUCCESS;
    }
    else {
      return ret;
    }
  }
  else {
    *is_dir = attrs.is_directory;
    return FS_ERROR_SUCCESS;
  }
}

fs_error_t
util_fs_touch(fs_handle_t fs, const char *file_path, bool *created) {
  bool create = true;
  fs_file_handle_t h;
  const fs_error_t ret_open = fs_open(fs, file_path, create, &h, created);
  if (!ret_open) {
    util_fs_close_or_abort(fs, h);
    return FS_ERROR_SUCCESS;
  }
  else if (ret_open == FS_ERROR_IS_DIR) {
    return FS_ERROR_SUCCESS;
  }

  log_debug("Error while opening \"%s\" for touch: %s",
            file_path, util_fs_strerror(ret_open));

  return ret_open;
}

static linked_list_t
_rm_tree_expand(void *ud, void *node, linked_list_t ll) {
  const fs_handle_t fs = (fs_handle_t) ud;
  char *const path = (char *) node;

  fs_directory_handle_t dir_handle;
  const fs_error_t ret_opendir = fs_opendir(fs, path, &dir_handle);
  if (ret_opendir) {
    if (ret_opendir != FS_ERROR_NOT_DIR) {
      log_warning("Couldn't opendir %s: %s", path,
                  util_fs_strerror(ret_opendir));
    }
    return ll;
  }

  while (true) {
    char *name;
    const fs_error_t ret_readdir = fs_readdir(fs, dir_handle, &name, NULL, NULL);
    if (ret_readdir) {
      log_warning("Error while doing readdir: %d", ret_readdir);
      break;
    }

    if (!name) {
      break;
    }

    char *new_child = util_fs_path_join(fs, path, name);
    log_debug("Join %s and %s to get %s", path, name, new_child);
    if (!new_child) {
      log_warning("Error while creating child path: %s %s",
                  path, name);
      break;
    }

    ll = linked_list_prepend(ll, new_child);

    free(name);
  }

  util_fs_closedir_or_abort(fs, dir_handle);

  return ll;
}

linked_list_t
util_fs_rmtree(fs_handle_t fs, const char *fpath_) {
  linked_list_t failed_to_delete = LINKED_LIST_INITIALIZER;

  char *fpath = davfuse_util_strdup(fpath_);
  if (!fpath) {
    abort();
  }

  bool is_postorder = true;
  depth_first_t dfs = dfs_create((void *) fpath, is_postorder,
                                 _rm_tree_expand,
                                 dfs_ignore_user_data_free,
                                 (void *) fs);
  char *path;

  while ((path = dfs_next(dfs))) {
    log_debug("Deleting %s", path);
    const fs_error_t ret_remove = fs_remove(fs, path);
    if (ret_remove) {
      /* failed to delete, just move on */
      log_debug("Failed to delete %s: %s",
                path, util_fs_strerror(ret_remove));
      failed_to_delete = linked_list_prepend(failed_to_delete, path);
      path = NULL;
    }

    free(path);
  }

  dfs_destroy(dfs);

  return failed_to_delete;
}

fs_error_t
util_fs_copyfile(fs_handle_t fs,
                 const char *from_path,
                 const char *to_path) {
  enum {
    BUF_SIZE=2 << 5,
  };
  fs_file_handle_t src_handle = (fs_file_handle_t) 0;
  fs_file_handle_t dst_handle = (fs_file_handle_t) 0;
  fs_error_t toret;

  const bool create = false;
  const fs_error_t ret_open =
    fs_open(fs, from_path, create, &src_handle, NULL);
  if (ret_open) {
    toret = ret_open;
    goto done;
  }

  const bool create2 = true;
  const fs_error_t ret_open_2 =
    fs_open(fs, to_path, create2, &dst_handle, NULL);
  if (ret_open_2) {
    toret = ret_open;
    goto done;
  }

  fs_off_t offset = 0;
  while (true) {
    char buffer[BUF_SIZE];
    /* need to initialize `amt` to avoid spurious
       -Wmaybe-uninitialized warnings from GCC */
    size_t amt = 0;
    const fs_error_t ret_read =
      fs_read(fs, src_handle, buffer, sizeof(buffer), offset, &amt);
    if (ret_read) {
      toret = ret_open;
      goto done;
    }

    /* EOF */
    if (!amt) {
      break;
    }

    size_t written = 0;
    while (written < amt) {
      /* need to initialize `just_wrote` to avoid spurious
         -Wmaybe-uninitialized warnings from GCC */
      size_t just_wrote = 0;
      const fs_error_t ret_write =
        fs_write(fs, dst_handle,
                 buffer + written, amt - written,
                 offset + written, &just_wrote);
      if (ret_write) {
        toret = ret_open;
        goto done;
      }
      written += just_wrote;
    }

    offset += written;
  }

  toret = FS_ERROR_SUCCESS;

 done:
  if (src_handle) {
    util_fs_close_or_abort(fs, src_handle);
  }

  if (dst_handle) {
    util_fs_close_or_abort(fs, dst_handle);
  }

  return toret;
}

static char *
reparent_path(fs_handle_t fs,
              const char *from_path, const char *to_path,
              const char *to_transform) {
  char *p = NULL;
  char *new_path = NULL;
  linked_list_t ll = (linked_list_t) 0;

  if (str_equals(from_path, to_transform)) {
    return davfuse_util_strdup(to_path);
  }

  assert(str_startswith(to_transform, from_path) /* &&
         to_transform[strlen(from_path)] == fs_path_sep(fs) */);

  p = davfuse_util_strdup(to_transform);
  while (!str_equals(from_path, p)) {
    char *basename = fs_path_basename(fs, p);
    if (!basename) goto err;
    ll = linked_list_prepend(ll, basename);

    char *temp_p = fs_path_dirname(fs, p);
    if (!temp_p) goto err;
    free(p);
    p = temp_p;
  }

  new_path = davfuse_util_strdup(to_path);
  LINKED_LIST_FOR(char, comp, ll) {
    char *new_new_path = util_fs_path_join(fs, new_path, comp);
    if (!new_new_path) goto err;
    free(new_path);
    new_path = new_new_path;
  }

  if (false) {
  err:
    free(new_path);
    new_path = NULL;
  }

  free(p);
  linked_list_free(ll, free);

  return new_path;
}

linked_list_t
util_fs_copytree(fs_handle_t fs,
                 const char *from_path,
                 const char *to_path,
                 bool delete_original) {
  char *fpath = davfuse_util_strdup(from_path);
  if (!fpath) {
    abort();
  }

  linked_list_t failed_to_copy = LINKED_LIST_INITIALIZER;
  depth_first_t dfs = dfs_create((void *) fpath, false,
                                 _rm_tree_expand,
                                 dfs_ignore_user_data_free,
                                 (void *) fs);
  char *path;

  while ((path = dfs_next(dfs))) {
    char *dest_path = NULL;
    bool is_dir;
    const fs_error_t ret_is_dir = util_fs_file_is_dir(fs, path, &is_dir);
    if (ret_is_dir) {
      if (ret_is_dir != FS_ERROR_DOES_NOT_EXIST) {
        failed_to_copy = linked_list_prepend(failed_to_copy, path);
        path = NULL;
      }
      goto done;
    }

    dest_path = reparent_path(fs, from_path, to_path, path);
    log_debug("Copying %s to %s", path, dest_path);

    bool copy_success;
    if (is_dir) {
      const fs_error_t ret_mkdir = fs_mkdir(fs, dest_path);
      if (ret_mkdir) {
        log_info("Error calling fs_mkdir(\"%s\"): %s",
                 dest_path, util_fs_strerror(ret_mkdir));
      }
      copy_success = !ret_mkdir;
    }
    else {
      const fs_error_t ret_copyfile =
        util_fs_copyfile(fs, path, dest_path);
      if (ret_copyfile) {
        log_info("Error calling util_fs_copyfile(\"%s\", \"%s\"): %s",
                 path, dest_path, util_fs_strerror(ret_copyfile));
      }

      copy_success = !ret_copyfile;
      if (copy_success && delete_original) {
        /* eagerly delete this entry */
        const fs_error_t ret_remove = fs_remove(fs, path);
        if (ret_remove && ret_remove != FS_ERROR_DOES_NOT_EXIST) {
          log_warning("Failed to delete %s after copying: %s",
                      path, dest_path);
        }
      }
    }

    if (!copy_success) {
      failed_to_copy = linked_list_prepend(failed_to_copy, path);
      path = NULL;
    }

  done:
    free(dest_path);
    free(path);
  }

  dfs_destroy(dfs);

  if (delete_original) {
    /* delete all entries left over, but only if they exist */
    dfs = dfs_create((void *) fpath, true,
                     _rm_tree_expand, dfs_ignore_user_data_free,
                     (void *) fs);
    while ((path = dfs_next(dfs))) {
      char *dest_path = reparent_path(fs, from_path, to_path, path);
      bool path_is_dir, dest_path_is_dir;
      const fs_error_t is_dir_ret_1 = util_fs_file_is_dir(fs, path, &path_is_dir);
      const fs_error_t is_dir_ret_2 = util_fs_file_is_dir(fs, path, &dest_path_is_dir);
      ASSERT_TRUE(!is_dir_ret_1 && !is_dir_ret_2);
      if (path_is_dir && dest_path_is_dir) {
        /* move was successful, delete parent */
        const fs_error_t ret_rmdir = fs_remove(fs, path);
        if (ret_rmdir && ret_rmdir != FS_ERROR_DOES_NOT_EXIST) {
          log_warning("Failing to delete %s after copying (%d)",
                      path, ret_rmdir);
        }
      }
      free(dest_path);
      free(path);
    }
    dfs_destroy(dfs);
  }

  return failed_to_copy;
}

char *
util_fs_path_dirname(fs_handle_t fs, const char *path) {
  return fs_path_dirname(fs, path);
}

char *
util_fs_path_basename(fs_handle_t fs, const char *path) {
  return fs_path_basename(fs, path);
}

char *
util_fs_path_join(fs_handle_t fs, const char *path, const char *name) {
  return fs_path_join(fs, path, name);
}

