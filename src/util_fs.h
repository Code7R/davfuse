#ifndef _UTIL_FS_H
#define _UTIL_FS_H

#include <stdbool.h>

#include "util.h"
#include "util_fs_fs.h"

#ifdef __cplusplus
extern "C" {
#endif

const char *
util_fs_strerror(fs_error_t error);

void
util_fs_closedir_or_abort(fs_t fs, fs_directory_handle_t dir);

void
util_fs_close_or_abort(fs_t fs, fs_file_handle_t f);

fs_error_t
util_fs_file_exists(fs_t fs, const char *path, bool *exists);

fs_error_t
util_fs_file_is_dir(fs_t fs, const char *path, bool *is_dir);

fs_error_t
util_fs_touch(fs_t fs, const char *path, bool *created);

linked_list_t
util_fs_rmtree(fs_t fs, const char *path);

fs_error_t
util_fs_copyfile(fs_t fs,
                 const char *file_path,
                 const char *destination_path);

linked_list_t
util_fs_copytree(fs_t fs,
                 const char *file_path,
                 const char *destination_path,
                 bool is_move);

char *
util_fs_path_dirname(fs_t fs, const char *path);

char *
util_fs_path_join(fs_t fs, const char *path, const char *name);

#ifdef __cplusplus
}
#endif

#endif
