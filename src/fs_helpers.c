#include "fs_helpers.h"

#include "util.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

char *
fs_helpers_join(const char *path_sep, const char *path, const char *name) {
  assert(path_sep);
  assert(path);
  assert(name);

  size_t len_of_basename = strlen(name);

  bool add_sep = !str_endswith(path, path_sep);

  char *new_child;
  size_t len_of_sep = strlen(path_sep);
  size_t len_of_dirname = strlen(path);
  new_child = malloc(len_of_dirname +
                     (add_sep ? len_of_sep : 0) +
                     len_of_basename + 1);
  if (!new_child) {
    return NULL;
  }

  size_t add = 0;
  memcpy(new_child + add, path, len_of_dirname);
  add += len_of_dirname;

  if (add_sep) {
    memcpy(new_child + add, path_sep, len_of_sep);
    add += len_of_sep;
  }

  memcpy(new_child + add, name, len_of_basename);
  add += len_of_basename;

  new_child[add] = '\0';

  return new_child;
}

char *
fs_helpers_basename(const char *path_sep, const char *path) {
  /* TODO: support this */
  if (strlen(path_sep) != 1) {
    return NULL;
  }

  const char *end_of_path = strrchr(path, path_sep[0]);
  return davfuse_util_strdup(end_of_path + 1);
}
