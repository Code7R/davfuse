/*
  davfuse: FUSE file systems as WebDAV servers
  Copyright (C) 2013 Rian Hunter <rian@alum.mit.edu>

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

#include "fs_dynamic.h"

#include "c_util.h"

#include <stdlib.h>

typedef struct _dynamic_handle {
  void *fs;
  const FsOperations *ops;
  bool destroy;
} FsDynamic;

static FsDynamic *
fs_handle_to_pointer(fs_dynamic_handle_t h) {
  /* these should be type synonyms, so no cast is necessary */
  return h;
}

static fs_dynamic_handle_t
pointer_to_fs_handle(FsDynamic *h) {
  /* these should be type synonyms, so no cast is necessary */
  return h;
}

fs_dynamic_handle_t
fs_dynamic_default_new(void) {
  return 0;
}

fs_dynamic_handle_t
fs_dynamic_new(void *fs, const FsOperations *ops, bool destroy) {
  FsDynamic *toret = malloc(sizeof(*toret));
  if (!toret) return 0;
  toret->fs = fs;
  toret->ops = ops;
  toret->destroy = destroy;
  return pointer_to_fs_handle(toret);
}

fs_error_t
fs_dynamic_open(fs_dynamic_handle_t fs,
                const char *path, bool create,
                OUT_VAR fs_dynamic_file_handle_t *handle,
                OUT_VAR bool *created) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->open(fs_dyn->fs,
                           path, create, (void **) handle, created);
}

fs_error_t
fs_dynamic_fgetattr(fs_dynamic_handle_t fs, fs_dynamic_file_handle_t file_handle,
                    OUT_VAR FsAttrs *attrs) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->fgetattr(fs_dyn->fs,
                               file_handle, attrs);
}

fs_error_t
fs_dynamic_ftruncate(fs_dynamic_handle_t fs, fs_dynamic_file_handle_t file_handle,
                     fs_off_t offset) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->ftruncate(fs_dyn->fs, file_handle, offset);
}

fs_error_t
fs_dynamic_read(fs_dynamic_handle_t fs, fs_dynamic_file_handle_t file_handle,
                OUT_VAR char *buf, size_t size, fs_off_t off,
                OUT_VAR size_t *amt_read) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->read(fs_dyn->fs, file_handle, buf, size, off, amt_read);
}

fs_error_t
fs_dynamic_write(fs_dynamic_handle_t fs, fs_dynamic_file_handle_t file_handle,
                 const char *buf, size_t size, fs_off_t offset,
                 OUT_VAR size_t *amt_written) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->write(fs_dyn->fs, file_handle, buf, size, offset, amt_written);
}

fs_error_t
fs_dynamic_opendir(fs_dynamic_handle_t fs, const char *path,
                   OUT_VAR fs_dynamic_directory_handle_t *dir_handle) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->opendir(fs_dyn->fs, path, (void **) dir_handle);
}

fs_error_t
fs_dynamic_readdir(fs_dynamic_handle_t fs, fs_dynamic_directory_handle_t dir_handle,
                   /* name is required and malloc'd by the implementation,
                      the user must free the returned pointer
                   */
                   OUT_VAR char **name,
                   /* attrs is optionally filled by the implementation */
                   OUT_VAR bool *attrs_is_filled,
                   OUT_VAR FsAttrs *attrs) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->readdir(fs_dyn->fs, dir_handle, name, attrs_is_filled, attrs);
}

fs_error_t
fs_dynamic_closedir(fs_dynamic_handle_t fs, fs_dynamic_directory_handle_t dir_handle) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->closedir(fs_dyn->fs, dir_handle);
}

/* can remove either a file or a directory,
   removing a directory should fail if it's not empty
*/
fs_error_t
fs_dynamic_remove(fs_dynamic_handle_t fs, const char *path) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->remove(fs_dyn->fs, path);
}

fs_error_t
fs_dynamic_mkdir(fs_dynamic_handle_t fs, const char *path) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->mkdir(fs_dyn->fs, path);
}

fs_error_t
fs_dynamic_getattr(fs_dynamic_handle_t fs, const char *path,
                   OUT_VAR FsAttrs *attrs) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->getattr(fs_dyn->fs, path, attrs);
}

fs_error_t
fs_dynamic_rename(fs_dynamic_handle_t fs,
                  const char *src, const char *dst) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->rename(fs_dyn->fs, src, dst);
}

fs_error_t
fs_dynamic_close(fs_dynamic_handle_t fs, fs_dynamic_file_handle_t handle) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->close(fs_dyn->fs, handle);
}

fs_error_t
fs_dynamic_set_times(fs_dynamic_handle_t fs,
                     const char *path,
                     fs_time_t atime,
                     fs_time_t mtime) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->set_times(fs_dyn->fs, path, atime, mtime);
}

bool
fs_dynamic_destroy(fs_dynamic_handle_t fs) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);

  if (fs_dyn->destroy) {
    bool success = fs_dyn->ops->destroy(fs_dyn->fs);
    if (!success) return false;
  }

  free(fs_dyn);
  return true;
}

bool
fs_dynamic_path_is_root(fs_dynamic_handle_t fs, const char *a) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->path_is_root(fs_dyn->fs, a);
}

bool
fs_dynamic_path_is_valid(fs_dynamic_handle_t fs,
                         const char *path) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->path_is_valid(fs_dyn->fs, path);
}

char *
fs_dynamic_path_dirname(fs_dynamic_handle_t fs, const char *path) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->path_dirname(fs_dyn->fs, path);
}

char *
fs_dynamic_path_basename(fs_dynamic_handle_t fs, const char *path) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->path_basename(fs_dyn->fs, path);
}

char *
fs_dynamic_path_join(fs_dynamic_handle_t fs,
                     const char *dirname, const char *basename) {
  FsDynamic *fs_dyn = fs_handle_to_pointer(fs);
  return fs_dyn->ops->path_join(fs_dyn->fs, dirname, basename);
}
