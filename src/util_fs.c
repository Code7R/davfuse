#define _ISOC99_SOURCE
#define _BSD_SOURCE

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "dfs.h"
#include "logging.h"
#include "util.h"

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
  default:
    return "Unknown error";
  }
#undef M
}

void
util_fs_closedir_or_abort(fs_t fs, fs_directory_handle_t dir) {
  const fs_error_t close_ret = fs_closedir(fs, dir);
  ASSERT_TRUE(!close_ret);
}

void
util_fs_close_or_abort(fs_t fs, fs_file_handle_t f) {
  const fs_error_t close_ret = fs_close(fs, f);
  ASSERT_TRUE(!close_ret);
}

fs_error_t
util_fs_file_exists(fs_t fs, const char *file_path, bool *exists) {
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
util_fs_file_is_dir(fs_t fs, const char *file_path, bool *is_dir) {
  FsAttrs attrs;
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
util_fs_touch(fs_t fs, const char *file_path, bool *created) {
  bool create = true;
  fs_file_handle_t h;
  const fs_error_t  ret_open = fs_open(fs, file_path, create,
                                           &h, created);
  if (!ret_open) {
    util_fs_close_or_abort(fs, h);
    return FS_ERROR_SUCCESS;
  }


  log_debug("Error while opening \"%s\" for touch", file_path);

  return ret_open;
}

static linked_list_t
_rm_tree_expand(void *ud, void *node, linked_list_t ll) {
  const fs_t fs = (fs_t) ud;
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

  size_t len_of_dirname = strlen(path);
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

    size_t len_of_basename = strlen(name);
    char *new_child = malloc_or_abort(len_of_dirname + 1 + len_of_basename + 1);

    memcpy(new_child, path, len_of_dirname);
    new_child[len_of_dirname] = '/';
    memcpy(new_child + len_of_dirname + 1, name, len_of_basename);
    new_child[len_of_dirname + 1 + len_of_basename] = '\0';

    ll = linked_list_prepend(ll, new_child);

    free(name);
  }

  util_fs_closedir_or_abort(fs, dir_handle);

  return ll;
}

linked_list_t
util_fs_rmtree(fs_t fs, const char *fpath_) {
  linked_list_t failed_to_delete = LINKED_LIST_INITIALIZER;

  char *fpath = strdup(fpath_);
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
util_fs_copyfile(fs_t fs,
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
    size_t amt;
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
      size_t just_wrote;
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
reparent_path(const char *from_path, const char *to_path,
              const char *to_transform) {
  /* we only accept absolute paths */
  assert(str_startswith(from_path, "/"));
  assert(str_startswith(to_path, "/"));
  assert(str_startswith(to_transform, "/"));

  if (str_equals(from_path, to_transform)) {
    return strdup(to_path);
  }

  assert(str_startswith(to_transform, from_path));
  size_t from_path_len = strlen(from_path);
  assert(to_transform[from_path_len] == '/');

  size_t to_path_len = strlen(to_path);
  size_t appendage_len = strlen(to_transform + from_path_len);
  char *new_str = malloc(to_path_len + appendage_len + 1);
  memcpy(new_str, to_path, to_path_len);
  memcpy(new_str + to_path_len, to_transform + from_path_len, appendage_len);
  new_str[to_path_len + appendage_len] = '\0';

  return new_str;
}

linked_list_t
util_fs_copytree(fs_t fs,
                 const char *from_path,
                 const char *to_path,
                 bool delete_original) {
  char *fpath = strdup(from_path);
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

    dest_path = reparent_path(from_path, to_path, path);
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
                      path);
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
      char *dest_path = reparent_path(from_path, to_path, path);
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
