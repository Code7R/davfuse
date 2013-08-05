#ifndef _UTIL_FS_H
#define _UTIL_FS_H

#include <stdbool.h>

#include "fs.h"
#include "util.h"

fs_error_t
util_fs_touch(fs_t fs, const char *path, bool *created);

fs_error_t
util_fs_file_exists(fs_t fs, const char *path, bool *exists);

linked_list_t
util_fs_rmtree(fs_t fs, const char *path);

fs_error_t
util_fs_file_is_dir(fs_t fs, const char *path, bool *is_dir);

fs_error_t
util_fs_copyfile(fs_t fs,
                 const char *file_path,
                 const char *destination_path);

linked_list_t
util_fs_copytree(fs_t fs,
                 const char *file_path,
                 const char *destination_path,
                 bool is_move);
#endif
