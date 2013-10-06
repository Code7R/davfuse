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

#ifndef _FS_POSIX_H
#define _FS_POSIX_H

#include <dirent.h>

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "c_util.h"
#include "iface_util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef intptr_t fs_posix_t;
typedef intptr_t fs_posix_file_handle_t;
typedef DIR *fs_posix_directory_handle_t;

/* non-opaque structures */
typedef enum {
  FS_POSIX_ERROR_SUCCESS,
  FS_POSIX_ERROR_DOES_NOT_EXIST,
  FS_POSIX_ERROR_NOT_DIR,
  FS_POSIX_ERROR_IS_DIR,
  FS_POSIX_ERROR_IO,
  FS_POSIX_ERROR_NO_SPACE,
  FS_POSIX_ERROR_PERM,
  FS_POSIX_ERROR_EXISTS,
  FS_POSIX_ERROR_CROSS_DEVICE,
} fs_posix_error_t;

typedef long long fs_posix_time_t;
typedef long long fs_posix_off_t;

/* NB: not totally sure about defining constants like this,
   a #define might be better */
HEADER_CONST const fs_posix_time_t FS_POSIX_INVALID_TIME = LLONG_MAX;
HEADER_CONST const fs_posix_off_t FS_POSIX_INVALID_OFF = LLONG_MAX;

typedef struct {
  fs_posix_time_t modified_time;
  fs_posix_time_t created_time;
  bool is_directory;
  fs_posix_off_t size;
} FsPosixAttrs;

fs_posix_t
fs_posix_default_new(void);

fs_posix_error_t
fs_posix_open(fs_posix_t fs,
              const char *path, bool create,
              OUT_VAR fs_posix_file_handle_t *handle,
              OUT_VAR bool *created);

fs_posix_error_t
fs_posix_fgetattr(fs_posix_t fs, fs_posix_file_handle_t file_handle,
                  OUT_VAR FsPosixAttrs *attrs);

fs_posix_error_t
fs_posix_ftruncate(fs_posix_t fs, fs_posix_file_handle_t file_handle,
                   fs_posix_off_t offset);

fs_posix_error_t
fs_posix_read(fs_posix_t fs, fs_posix_file_handle_t file_handle,
              OUT_VAR char *buf, size_t size, fs_posix_off_t off,
              OUT_VAR size_t *amt_read);

fs_posix_error_t
fs_posix_write(fs_posix_t fs, fs_posix_file_handle_t file_handle,
               const char *buf, size_t size, fs_posix_off_t offset,
               OUT_VAR size_t *amt_written);

fs_posix_error_t
fs_posix_opendir(fs_posix_t fs, const char *path,
                 OUT_VAR fs_posix_directory_handle_t *dir_handle);

fs_posix_error_t
fs_posix_readdir(fs_posix_t fs, fs_posix_directory_handle_t dir_handle,
                 /* name is required and malloc'd by the implementation,
                    the user must free the returned pointer
                 */
                 OUT_VAR char **name,
                 /* attrs is optionally filled by the implementation */
                 OUT_VAR bool *attrs_is_filled,
                 OUT_VAR FsPosixAttrs *attrs);

fs_posix_error_t
fs_posix_closedir(fs_posix_t fs, fs_posix_directory_handle_t dir_handle);

/* can remove either a file or a directory,
   removing a directory should fail if it's not empty
*/
fs_posix_error_t
fs_posix_remove(fs_posix_t fs, const char *path);

fs_posix_error_t
fs_posix_mkdir(fs_posix_t fs, const char *path);

fs_posix_error_t
fs_posix_getattr(fs_posix_t fs, const char *path,
                 OUT_VAR FsPosixAttrs *attrs);

fs_posix_error_t
fs_posix_rename(fs_posix_t fs,
                const char *src, const char *dst);

fs_posix_error_t
fs_posix_close(fs_posix_t fs, fs_posix_file_handle_t handle);

bool
fs_posix_destroy(fs_posix_t fs);

bool
fs_posix_path_is_root(fs_posix_t fs, const char *a);

const char *
fs_posix_path_sep(fs_posix_t fs);

bool
fs_posix_path_equals(fs_posix_t fs, const char *a, const char *b);

bool
fs_posix_path_is_parent(fs_posix_t fs,
                        const char *potential_parent,
                        const char *potential_child);

CREATE_IMPL_TAG(FS_POSIX_IMPL);

#ifdef __cplusplus
}
#endif

#endif
