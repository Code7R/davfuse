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

#ifndef _FS_WIN32_H
#define _FS_WIN32_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

#include "c_util.h"
#include "iface_util.h"
#include "shared_types_fs.h"

#ifdef __cplusplus
extern "C" {
#endif

struct _win32_fs_handle;
struct _win32_directory_handle;
struct _win32_file_handle;

typedef struct _win32_fs_handle *fs_win32_handle_t;
typedef struct _win32_directory_handle *fs_win32_directory_handle_t;
typedef struct _win32_file_handle *fs_win32_file_handle_t;

fs_win32_handle_t
fs_win32_default_new(void);

fs_error_t
fs_win32_open(fs_win32_handle_t fs,
              const char *path, bool create,
              OUT_VAR fs_win32_file_handle_t *handle,
              OUT_VAR bool *created);

fs_error_t
fs_win32_fgetattr(fs_win32_handle_t fs, fs_win32_file_handle_t file_handle,
                  OUT_VAR FsAttrs *attrs);

fs_error_t
fs_win32_ftruncate(fs_win32_handle_t fs, fs_win32_file_handle_t file_handle,
                   fs_off_t offset);

fs_error_t
fs_win32_read(fs_win32_handle_t fs, fs_win32_file_handle_t file_handle,
              OUT_VAR char *buf, size_t size, fs_off_t off,
              OUT_VAR size_t *amt_read);

fs_error_t
fs_win32_write(fs_win32_handle_t fs, fs_win32_file_handle_t file_handle,
               const char *buf, size_t size, fs_off_t offset,
               OUT_VAR size_t *amt_written);

fs_error_t
fs_win32_opendir(fs_win32_handle_t fs, const char *path,
                 OUT_VAR fs_win32_directory_handle_t *dir_handle);

fs_error_t
fs_win32_readdir(fs_win32_handle_t fs, fs_win32_directory_handle_t dir_handle,
                 /* name is required and malloc'd by the implementation,
                    the user must free the returned pointer
                 */
                 OUT_VAR char **name,
                 /* attrs is optionally filled by the implementation */
                 OUT_VAR bool *attrs_is_filled,
                 OUT_VAR FsAttrs *attrs);

fs_error_t
fs_win32_closedir(fs_win32_handle_t fs, fs_win32_directory_handle_t dir_handle);

/* can remove either a file or a directory,
   removing a directory should fail if it's not empty
*/
fs_error_t
fs_win32_remove(fs_win32_handle_t fs, const char *path);

fs_error_t
fs_win32_mkdir(fs_win32_handle_t fs, const char *path);

fs_error_t
fs_win32_getattr(fs_win32_handle_t fs, const char *path,
                 OUT_VAR FsAttrs *attrs);

fs_error_t
fs_win32_rename(fs_win32_handle_t fs,
                const char *src, const char *dst);

fs_error_t
fs_win32_set_times(fs_win32_handle_t fs,
                   const char *path,
                   fs_time_t atime,
                   fs_time_t mtime);

fs_error_t
fs_win32_close(fs_win32_handle_t fs, fs_win32_file_handle_t handle);

bool
fs_win32_destroy(fs_win32_handle_t fs);

bool
fs_win32_path_is_root(fs_win32_handle_t fs, const char *path);

bool
fs_win32_path_is_valid(fs_win32_handle_t fs,
                       const char *path);

char *
fs_win32_path_dirname(fs_win32_handle_t fs, const char *path);

char *
fs_win32_path_basename(fs_win32_handle_t fs, const char *path);

char *
fs_win32_path_join(fs_win32_handle_t fs,
                   const char *dirname, const char *basename);

CREATE_IMPL_TAG(FS_WIN32_IMPL);

#ifdef __cplusplus
}
#endif

#endif
