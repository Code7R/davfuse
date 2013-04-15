#define _ISOC99_SOURCE
#define _BSD_SOURCE

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "dfs.h"
#include "logging.h"
#include "util.h"

int
file_exists(const char *file_path) {
  struct stat st;
  int ret = stat(file_path, &st);
  if (ret < 0) {
    if (errno == ENOENT ||
        errno == ENOTDIR) {
      return 0;
    }
    else {
      return ret;
    }
  }
  else {
    return 1;
  }
}

int
file_is_dir(const char *file_path) {
  struct stat st;
  int ret = stat(file_path, &st);
  if (ret < 0) {
    return ret;
  }

  return S_ISDIR(st.st_mode);
}

static linked_list_t
_rm_tree_expand(void *node, linked_list_t ll) {
  char *path = (char *) node;

  DIR *dir = opendir(path);
  if (dir) {
    struct dirent *d;
    size_t len_of_dirname = strlen(path);
    while ((d = readdir(dir)) != NULL) {
      if (str_equals(d->d_name, "..") ||
          str_equals(d->d_name, ".")) {
        continue;
      }

      size_t len_of_basename = strlen(d->d_name);
      char *new_child = malloc(len_of_dirname + 1 + len_of_basename + 1);
      if (!new_child) {
        /* TODO: our malloc error interface kind of sucks */
        abort();
      }

      memcpy(new_child, path, len_of_dirname);
      new_child[len_of_dirname] = '/';
      memcpy(new_child + len_of_dirname + 1, d->d_name, len_of_basename);
      new_child[len_of_dirname + 1 + len_of_basename] = '\0';

      ll = linked_list_prepend(ll, new_child);
    }

    closedir(dir);
  }
  else if (errno != ENOTDIR) {
    log_warning("Couldn't opendir %s: %s", path, strerror(errno));
  }

  return ll;
}

linked_list_t
rmtree(const char *fpath_) {
  linked_list_t failed_to_delete = LINKED_LIST_INITIALIZER;

  /* TODO: yield after every delete */

  char *fpath = strdup(fpath_);
  if (!fpath) {
    abort();
  }

  depth_first_t dfs = dfs_create((void *) fpath, true,
                                 _rm_tree_expand, free);
  char *path;

  while ((path = dfs_next(dfs))) {
    log_debug("Deleting %s", path);
    int ret = remove(path);
    if (ret < 0) {
      /* failed to delete, just move on */
      log_debug("Failed to delete %s: %s", path, strerror(errno));
      failed_to_delete = linked_list_prepend(failed_to_delete, path);
      path = NULL;
    }

    free(path);
  }

  dfs_destroy(dfs);

  return failed_to_delete;
}

bool
copyfile(const char *from_path, const char *to_path) {
  enum {
    BUF_SIZE=2 << 5,
  };
  int dst_fd = -1;
  int src_fd = -1;
  bool success = false;

  src_fd = open(from_path, O_RDONLY/* | O_NONBLOCK*/);
  if (src_fd < 0) {
    goto done;
  }

  dst_fd = open(to_path,
                O_WRONLY | /*O_NONBLOCK | */O_CREAT | O_TRUNC | O_EXCL,
                0666);
  if (dst_fd < 0) {
    goto done;
  }

  while (true) {
    char buffer[BUF_SIZE];
    ssize_t amt = read(src_fd, buffer, sizeof(buffer));
    if (amt < 0) {
      goto done;
    }
    /* EOF */
    if (!amt) {
      break;
    }

    ssize_t written = 0;
    while (written < amt) {
      ssize_t just_wrote = write(dst_fd, buffer + written, amt - written);
      if (just_wrote < 0) {
        goto done;
      }
      written += just_wrote;
    }
  }

  success = true;

 done:
  if (src_fd >= 0) {
    close(src_fd);
  }

  if (dst_fd >= 0) {
    close(dst_fd);
  }

  return success;
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
copytree(const char *from_path, const char *to_path, bool delete_original) {
  char *fpath = strdup(from_path);
  if (!fpath) {
    abort();
  }

  linked_list_t failed_to_copy = LINKED_LIST_INITIALIZER;
  depth_first_t dfs = dfs_create((void *) fpath, false,
                                 _rm_tree_expand, free);
  char *path;

  while ((path = dfs_next(dfs))) {
    char *dest_path = NULL;
    int is_dir = file_is_dir(path);
    if (is_dir < 0) {
      if (errno != ENOENT) {
        failed_to_copy = linked_list_prepend(failed_to_copy, path);
        path = NULL;
      }
      goto done;
    }

    dest_path = reparent_path(from_path, to_path, path);
    log_debug("Copying %s to %s", path, dest_path);

    bool copy_success;
    if (is_dir) {
      int ret = mkdir(dest_path, 0777);
      copy_success = ret >= 0;
    }
    else {
      copy_success = copyfile(path, dest_path);
      if (copy_success && delete_original) {
        /* eagerly delete this entry */
        int ret = unlink(path);
        if (ret < 0 && errno != ENOENT) {
          log_warning("Failed to delete %s after copying: %s",
                      path, strerror(errno));
        }
      }
    }

    if (!copy_success) {
      log_info("Error copying %s to %s: %s",
                path, dest_path, strerror(errno));
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
                     _rm_tree_expand, free);
    while ((path = dfs_next(dfs))) {
      char *dest_path = reparent_path(from_path, to_path, path);
      if (file_is_dir(path) &&
          file_is_dir(dest_path)) {
        /* move was successful, delete parent */
        int ret = rmdir(path);
        if (ret < 0 && errno != ENOENT) {
          log_warning("Failing to delete %s after copying: %s",
                      path, strerror(errno));
        }
      }
      free(dest_path);
      free(path);
    }
    dfs_destroy(dfs);
  }

  return failed_to_copy;
}
