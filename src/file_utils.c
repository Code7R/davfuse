#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include <assert.h>
#include <dirent.h>
#include <stdbool.h>
#include <string.h>

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

linked_list_t
rmtree(const char *fpath_) {
  linked_list_t failed_to_delete = LINKED_LIST_INITIALIZER;
  linked_list_t delete_queue = LINKED_LIST_INITIALIZER;

  /* TODO: yield after every delete */
  char *fpath = strdup(fpath_);
  if (!fpath) {
    /* TODO: our malloc error interface kind of sucks */
    abort();
  }

  delete_queue = linked_list_prepend(delete_queue, fpath);
  while (delete_queue) {
    DIR *dir = NULL;
    char *path;
    delete_queue = linked_list_popleft(delete_queue, (void **) &path);

    struct stat st;
    int ret = stat(path, &st);
    if (ret < 0) {
      if (errno != ENOENT) {
        failed_to_delete = linked_list_prepend(failed_to_delete, path);
        path = NULL;
        log_debug("Error while stat(\"%s\"): %s", path, strerror(errno));
      }

      goto okay_done;
    }

    log_debug("Deleting %s", path);
    if (S_ISDIR(st.st_mode)) {
      /* if we're a directory, attempt to delete first */
      ret = rmdir(path);
      if (ret < 0) {
        if (errno == ENOTEMPTY) {
          /* not empty... if the top of the failed_to_delete stack is an descendant of ours,
             then add ourselves to it, otherwise, add ourselves back to the queue an all of
             our children */
          char *top_child = linked_list_peekleft(failed_to_delete);

          log_debug("TOP CHILD: %s", top_child);
          log_debug("path: %s", path);
          if (top_child && str_startswith(top_child, path)) {
            failed_to_delete = linked_list_prepend(failed_to_delete, path);
            path = NULL;
          }
          else {
            char *path_alias = path;
            /* keep the dir around, try to delete later */
            delete_queue = linked_list_prepend(delete_queue, path);
            /* don't free path, now that it's back on the top of the delete queue */
            path = NULL;

            struct dirent *d;
            dir = opendir(path_alias);
            if (!dir) {
              log_debug("Error while opendir(%s): %s", path_alias, strerror(errno));
              goto okay_done;
            }

            size_t len_of_dirname = strlen(path_alias);
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

              memcpy(new_child, path_alias, len_of_dirname);
              new_child[len_of_dirname] = '/';
              memcpy(new_child + len_of_dirname + 1, d->d_name, len_of_basename);
              new_child[len_of_dirname + 1 + len_of_basename] = '\0';

              delete_queue = linked_list_prepend(delete_queue, new_child);
            }
          }
        }
        else {
          /* failed to delete, just move on */
          log_debug("Failed to delete %s: %s", path, strerror(errno));
          failed_to_delete = linked_list_prepend(failed_to_delete, path);
          path = NULL;
        }
      }
    }
    else {
      ret = unlink(path);
      if (ret < 0) {
        /* failed to delete, just move on */
        log_debug("Failed to delete %s: %s", path, strerror(errno));
        failed_to_delete = linked_list_prepend(failed_to_delete, path);
        path = NULL;
      }
    }

  okay_done:
    free(path);
    if (dir) {
      closedir(dir);
    }
  }

  /* we should have drained all of the delete queue */
  assert(!delete_queue);

  return failed_to_delete;
}
