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

#ifndef _FS_DYNAMIC_H
#define _FS_DYNAMIC_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "c_util.h"
#include "iface_util.h"
#include "shared_types_fs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  fs_error_t (*open)(fs_handle_t, const char *, bool,
                     OUT_VAR fs_file_handle_t *, OUT_VAR bool *);
  fs_error_t (*fgetattr)(fs_handle_t, fs_file_handle_t,
                         OUT_VAR FsAttrs *);
  fs_error_t (*ftruncate)(fs_handle_t, fs_file_handle_t,
                          fs_off_t);
  fs_error_t (*read)(fs_handle_t, fs_file_handle_t,
                     OUT_VAR char *, size_t, fs_off_t,
                     OUT_VAR size_t *);
  fs_error_t (*write)(fs_handle_t, fs_file_handle_t,
                      const char *, size_t, fs_off_t,
                      OUT_VAR size_t *);
  fs_error_t (*close)(fs_handle_t, fs_file_handle_t);
  fs_error_t (*opendir)(fs_handle_t, const char *,
                        OUT_VAR fs_directory_handle_t *);
  fs_error_t (*readdir)(fs_handle_t, fs_directory_handle_t,
                        OUT_VAR char **, OUT_VAR bool *, OUT_VAR FsAttrs *);
  fs_error_t (*closedir)(fs_handle_t, fs_directory_handle_t);
  fs_error_t (*remove)(fs_handle_t, const char *);
  fs_error_t (*mkdir)(fs_handle_t, const char *);
  fs_error_t (*getattr)(fs_handle_t, const char *,
                        OUT_VAR FsAttrs *);
  fs_error_t (*rename)(fs_handle_t, const char *, const char *);
  fs_error_t (*set_times)(fs_handle_t fs,
                          const char *path,
                          fs_time_t atime,
                          fs_time_t mtime);
  bool (*path_is_root)(fs_handle_t fs, const char *a);
  const char *(*path_sep)(fs_handle_t fs);
  bool (*path_equals)(fs_handle_t fs, const char *a, const char *b);
  bool (*path_is_parent)(fs_handle_t fs,
                         const char *potential_parent,
                         const char *potential_child);
  bool (*destroy)(fs_handle_t fs);
} FsOperations;

fs_handle_t
fs_dynamic_default_new(void);

fs_handle_t
fs_dynamic_new(fs_handle_t fs, const FsOperations *ops, bool destroy);

fs_error_t
fs_dynamic_open(fs_handle_t fs,
                const char *path, bool create,
                OUT_VAR fs_file_handle_t *handle,
                OUT_VAR bool *created);

fs_error_t
fs_dynamic_fgetattr(fs_handle_t fs, fs_file_handle_t file_handle,
                    OUT_VAR FsAttrs *attrs);

fs_error_t
fs_dynamic_ftruncate(fs_handle_t fs, fs_file_handle_t file_handle,
                     fs_off_t offset);

fs_error_t
fs_dynamic_read(fs_handle_t fs, fs_file_handle_t file_handle,
                OUT_VAR char *buf, size_t size, fs_off_t off,
                OUT_VAR size_t *amt_read);

fs_error_t
fs_dynamic_write(fs_handle_t fs, fs_file_handle_t file_handle,
                 const char *buf, size_t size, fs_off_t offset,
                 OUT_VAR size_t *amt_written);

fs_error_t
fs_dynamic_opendir(fs_handle_t fs, const char *path,
                   OUT_VAR fs_directory_handle_t *dir_handle);

fs_error_t
fs_dynamic_readdir(fs_handle_t fs, fs_directory_handle_t dir_handle,
                   /* name is required and malloc'd by the implementation,
                      the user must free the returned pointer
                   */
                   OUT_VAR char **name,
                   /* attrs is optionally filled by the implementation */
                   OUT_VAR bool *attrs_is_filled,
                   OUT_VAR FsAttrs *attrs);

fs_error_t
fs_dynamic_closedir(fs_handle_t fs, fs_directory_handle_t dir_handle);

/* can remove either a file or a directory,
   removing a directory should fail if it's not empty
*/
fs_error_t
fs_dynamic_remove(fs_handle_t fs, const char *path);

fs_error_t
fs_dynamic_mkdir(fs_handle_t fs, const char *path);

fs_error_t
fs_dynamic_getattr(fs_handle_t fs, const char *path,
                   OUT_VAR FsAttrs *attrs);

fs_error_t
fs_dynamic_rename(fs_handle_t fs,
                  const char *src, const char *dst);

fs_error_t
fs_dynamic_close(fs_handle_t fs, fs_file_handle_t handle);

fs_error_t
fs_dynamic_set_times(fs_handle_t fs,
                     const char *path,
                     fs_time_t atime,
                     fs_time_t mtime);

bool
fs_dynamic_destroy(fs_handle_t fs);

bool
fs_dynamic_path_is_root(fs_handle_t fs, const char *a);

const char *
fs_dynamic_path_sep(fs_handle_t fs);

bool
fs_dynamic_path_equals(fs_handle_t fs, const char *a, const char *b);

bool
fs_dynamic_path_is_parent(fs_handle_t fs,
                          const char *potential_parent,
                          const char *potential_child);

CREATE_IMPL_TAG(FS_DYNAMIC_IMPL);

#ifdef __cplusplus
}
#endif

#endif
