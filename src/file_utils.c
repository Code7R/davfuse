#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include <assert.h>
#include <dirent.h>
#include <stdbool.h>
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

  depth_first_t dfs = dfs_create((void *) fpath, _rm_tree_expand, free);
  char *path;
  bool pre_order;

  while ((dfs_next(dfs, &pre_order, (void **) &path), path)) {
    /* pre order means we will visit this entry again, delete after */
    if (pre_order) {
      continue;
    }

    struct stat st;
    int ret = stat(path, &st);
    if (ret < 0) {
      if (errno != ENOENT) {
        failed_to_delete = linked_list_prepend(failed_to_delete, path);
        path = NULL;
        log_debug("Error while stat(\"%s\"): %s", path, strerror(errno));
      }

      goto done;
    }

    log_debug("Deleting %s", path);
    if (S_ISDIR(st.st_mode)) {
      /* if we're a directory, attempt to delete first */
      ret = rmdir(path);
    }
    else {
      ret = unlink(path);
    }

    if (ret < 0) {
      /* failed to delete, just move on */
      log_debug("Failed to delete %s: %s", path, strerror(errno));
      failed_to_delete = linked_list_prepend(failed_to_delete, path);
      path = NULL;
    }

  done:
    free(path);
  }

  dfs_destroy(dfs);

  return failed_to_delete;
}
