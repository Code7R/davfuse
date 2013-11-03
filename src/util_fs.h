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

#ifndef _UTIL_FS_H
#define _UTIL_FS_H

#include <stdbool.h>

#include "util.h"
#include "fs.h"

#ifdef __cplusplus
extern "C" {
#endif

const char *
util_fs_strerror(fs_error_t error);

void
util_fs_closedir_or_abort(fs_handle_t fs, fs_directory_handle_t dir);

void
util_fs_close_or_abort(fs_handle_t fs, fs_file_handle_t f);

fs_error_t
util_fs_file_exists(fs_handle_t fs, const char *path, bool *exists);

fs_error_t
util_fs_file_is_dir(fs_handle_t fs, const char *path, bool *is_dir);

fs_error_t
util_fs_touch(fs_handle_t fs, const char *path, bool *created);

linked_list_t
util_fs_rmtree(fs_handle_t fs, const char *path);

fs_error_t
util_fs_copyfile(fs_handle_t fs,
                 const char *file_path,
                 const char *destination_path);

linked_list_t
util_fs_copytree(fs_handle_t fs,
                 const char *file_path,
                 const char *destination_path,
                 bool is_move);

char *
util_fs_path_dirname(fs_handle_t fs, const char *path);

char *
util_fs_path_basename(fs_handle_t fs, const char *path);

bool
util_fs_path_equals(fs_handle_t fs,
                    const char *a, const char *b);

bool
util_fs_path_is_parent(fs_handle_t fs,
                       const char *a, const char *b);

char *
util_fs_path_join(fs_handle_t fs, const char *path, const char *name);

#ifdef __cplusplus
}
#endif

#endif
