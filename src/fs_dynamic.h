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

/* create new types for the dynamic handle */
struct _dynamic_handle;
struct _dynamic_directory_handle;
struct _dynamic_file_handle;

typedef struct _dynamic_handle *fs_dynamic_handle_t;
typedef struct _dynamic_directory_handle *fs_dynamic_directory_handle_t;
typedef struct _dynamic_file_handle *fs_dynamic_file_handle_t;

typedef fs_error_t (*fs_dynamic_open_fn)(void *, const char *, bool, OUT_VAR void **, OUT_VAR bool *);
typedef fs_error_t (*fs_dynamic_fgetattr_fn)(void *, void *, OUT_VAR FsAttrs *);
typedef fs_error_t (*fs_dynamic_ftruncate_fn)(void *, void *, fs_off_t);
typedef fs_error_t (*fs_dynamic_read_fn)(void *, void *, OUT_VAR char *, size_t, fs_off_t, OUT_VAR size_t *);
typedef fs_error_t (*fs_dynamic_write_fn)(void *, void *, const char *, size_t, fs_off_t, OUT_VAR size_t *);
typedef fs_error_t (*fs_dynamic_close_fn)(void *, void *);
typedef fs_error_t (*fs_dynamic_opendir_fn)(void *, const char *, OUT_VAR void **);
typedef fs_error_t (*fs_dynamic_readdir_fn)(void *, void *, OUT_VAR char **, OUT_VAR bool *, OUT_VAR FsAttrs *);
typedef fs_error_t (*fs_dynamic_closedir_fn)(void *, void *);
typedef fs_error_t (*fs_dynamic_remove_fn)(void *, const char *);
typedef fs_error_t (*fs_dynamic_mkdir_fn)(void *, const char *);
typedef fs_error_t (*fs_dynamic_getattr_fn)(void *, const char *, OUT_VAR FsAttrs *);
typedef fs_error_t (*fs_dynamic_rename_fn)(void *, const char *, const char *);
typedef fs_error_t (*fs_dynamic_set_times_fn)(void *fs, const char *path, fs_time_t atime, fs_time_t mtime);
typedef bool (*fs_dynamic_path_is_root_fn)(void *fs, const char *a);
typedef bool (*fs_dynamic_path_is_valid_fn)(void *fs, const char *path);
typedef char *(*fs_dynamic_path_dirname_fn)(void *fs, const char *path);
typedef char *(*fs_dynamic_path_basename_fn)(void *fs, const char *path);
typedef char *(*fs_dynamic_path_join_fn)(void *fs, const char *path, const char *name);
typedef bool (*fs_dynamic_destroy_fn)(void *fs);

typedef struct {
  fs_dynamic_open_fn open;
  fs_dynamic_fgetattr_fn fgetattr;
  fs_dynamic_ftruncate_fn ftruncate;
  fs_dynamic_read_fn read;
  fs_dynamic_write_fn write;
  fs_dynamic_close_fn close;
  fs_dynamic_opendir_fn opendir;
  fs_dynamic_readdir_fn readdir;
  fs_dynamic_closedir_fn closedir;
  fs_dynamic_remove_fn remove;
  fs_dynamic_mkdir_fn mkdir;
  fs_dynamic_getattr_fn getattr;
  fs_dynamic_rename_fn rename;
  fs_dynamic_set_times_fn set_times;
  fs_dynamic_path_is_root_fn path_is_root;
  fs_dynamic_path_is_valid_fn path_is_valid;
  fs_dynamic_path_dirname_fn path_dirname;
  fs_dynamic_path_basename_fn path_basename;
  fs_dynamic_path_join_fn path_join;
  fs_dynamic_destroy_fn destroy;
} FsOperations;

fs_dynamic_handle_t
fs_dynamic_default_new(void);

fs_dynamic_handle_t
fs_dynamic_new(void *fs, const FsOperations *ops, bool destroy);

fs_error_t
fs_dynamic_open(fs_dynamic_handle_t fs,
                const char *path, bool create,
                OUT_VAR fs_dynamic_file_handle_t *handle,
                OUT_VAR bool *created);

fs_error_t
fs_dynamic_fgetattr(fs_dynamic_handle_t fs, fs_dynamic_file_handle_t file_handle,
                    OUT_VAR FsAttrs *attrs);

fs_error_t
fs_dynamic_ftruncate(fs_dynamic_handle_t fs, fs_dynamic_file_handle_t file_handle,
                     fs_off_t offset);

fs_error_t
fs_dynamic_read(fs_dynamic_handle_t fs, fs_dynamic_file_handle_t file_handle,
                OUT_VAR char *buf, size_t size, fs_off_t off,
                OUT_VAR size_t *amt_read);

fs_error_t
fs_dynamic_write(fs_dynamic_handle_t fs, fs_dynamic_file_handle_t file_handle,
                 const char *buf, size_t size, fs_off_t offset,
                 OUT_VAR size_t *amt_written);

fs_error_t
fs_dynamic_opendir(fs_dynamic_handle_t fs, const char *path,
                   OUT_VAR fs_dynamic_directory_handle_t *dir_handle);

fs_error_t
fs_dynamic_readdir(fs_dynamic_handle_t fs, fs_dynamic_directory_handle_t dir_handle,
                   /* name is required and malloc'd by the implementation,
                      the user must free the returned pointer
                   */
                   OUT_VAR char **name,
                   /* attrs is optionally filled by the implementation */
                   OUT_VAR bool *attrs_is_filled,
                   OUT_VAR FsAttrs *attrs);

fs_error_t
fs_dynamic_closedir(fs_dynamic_handle_t fs, fs_dynamic_directory_handle_t dir_handle);

/* can remove either a file or a directory,
   removing a directory should fail if it's not empty
*/
fs_error_t
fs_dynamic_remove(fs_dynamic_handle_t fs, const char *path);

fs_error_t
fs_dynamic_mkdir(fs_dynamic_handle_t fs, const char *path);

fs_error_t
fs_dynamic_getattr(fs_dynamic_handle_t fs, const char *path,
                   OUT_VAR FsAttrs *attrs);

fs_error_t
fs_dynamic_rename(fs_dynamic_handle_t fs,
                  const char *src, const char *dst);

fs_error_t
fs_dynamic_close(fs_dynamic_handle_t fs, fs_dynamic_file_handle_t handle);

fs_error_t
fs_dynamic_set_times(fs_dynamic_handle_t fs,
                     const char *path,
                     fs_time_t atime,
                     fs_time_t mtime);

bool
fs_dynamic_destroy(fs_dynamic_handle_t fs);

bool
fs_dynamic_path_is_root(fs_dynamic_handle_t fs, const char *a);

bool
fs_dynamic_path_is_valid(fs_dynamic_handle_t fs,
                         const char *path);

char *
fs_dynamic_path_dirname(fs_dynamic_handle_t fs, const char *path);

char *
fs_dynamic_path_basename(fs_dynamic_handle_t fs, const char *path);

char *
fs_dynamic_path_join(fs_dynamic_handle_t fs,
                     const char *dirname, const char *basename);

CREATE_IMPL_TAG(FS_DYNAMIC_IMPL);

#ifdef __cplusplus
}
#endif

#endif
