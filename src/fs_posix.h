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

#include <sys/types.h>
#include <dirent.h>

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

struct _posix_fs_handle;
struct _posix_file_handle;

typedef struct _posix_fs_handle *fs_posix_handle_t;
typedef DIR *fs_posix_directory_handle_t;
typedef struct _posix_file_handle *fs_posix_file_handle_t;

fs_posix_handle_t
fs_posix_default_new(void);

fs_error_t
fs_posix_open(fs_posix_handle_t fs,
              const char *path, bool create,
              OUT_VAR fs_posix_file_handle_t *handle,
              OUT_VAR bool *created);

fs_error_t
fs_posix_fgetattr(fs_posix_handle_t fs, fs_posix_file_handle_t file_handle,
                  OUT_VAR FsAttrs *attrs);

fs_error_t
fs_posix_ftruncate(fs_posix_handle_t fs, fs_posix_file_handle_t file_handle,
                   fs_off_t offset);

fs_error_t
fs_posix_read(fs_posix_handle_t fs, fs_posix_file_handle_t file_handle,
              OUT_VAR char *buf, size_t size, fs_off_t off,
              OUT_VAR size_t *amt_read);

fs_error_t
fs_posix_write(fs_posix_handle_t fs, fs_posix_file_handle_t file_handle,
               const char *buf, size_t size, fs_off_t offset,
               OUT_VAR size_t *amt_written);

fs_error_t
fs_posix_opendir(fs_posix_handle_t fs, const char *path,
                 OUT_VAR fs_posix_directory_handle_t *dir_handle);

fs_error_t
fs_posix_readdir(fs_posix_handle_t fs, fs_posix_directory_handle_t dir_handle,
                 /* name is required and malloc'd by the implementation,
                    the user must free the returned pointer
                 */
                 OUT_VAR char **name,
                 /* attrs is optionally filled by the implementation */
                 OUT_VAR bool *attrs_is_filled,
                 OUT_VAR FsAttrs *attrs);

fs_error_t
fs_posix_closedir(fs_posix_handle_t fs, fs_posix_directory_handle_t dir_handle);

/* can remove either a file or a directory,
   removing a directory should fail if it's not empty
*/
fs_error_t
fs_posix_remove(fs_posix_handle_t fs, const char *path);

fs_error_t
fs_posix_mkdir(fs_posix_handle_t fs, const char *path);

fs_error_t
fs_posix_getattr(fs_posix_handle_t fs, const char *path,
                 OUT_VAR FsAttrs *attrs);

fs_error_t
fs_posix_rename(fs_posix_handle_t fs,
                const char *src, const char *dst);

fs_error_t
fs_posix_close(fs_posix_handle_t fs, fs_posix_file_handle_t handle);

fs_error_t
fs_posix_set_times(fs_posix_handle_t fs,
                   const char *path,
                   fs_time_t atime,
                   fs_time_t mtime);

bool
fs_posix_destroy(fs_posix_handle_t fs);

bool
fs_posix_path_is_root(fs_posix_handle_t fs, const char *a);

bool
fs_posix_path_is_valid(fs_posix_handle_t fs, const char *path);

char *
fs_posix_path_dirname(fs_posix_handle_t fs, const char *path);

char *
fs_posix_path_basename(fs_posix_handle_t fs, const char *path);

char *
fs_posix_path_join(fs_posix_handle_t fs,
                   const char *dirname, const char *basename);

CREATE_IMPL_TAG(FS_POSIX_IMPL);

#ifdef __cplusplus
}
#endif

#endif
