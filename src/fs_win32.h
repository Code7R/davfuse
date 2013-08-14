#ifndef _FS_WIN32_H
#define _FS_WIN32_H

#include <windows.h>

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

#include "c_util.h"

#ifdef __cplusplus
extern "C" {
#endif

struct _fs_win32_directory_handle;

typedef int fs_win32_t;
typedef HANDLE fs_win32_file_handle_t;
typedef struct _fs_win32_directory_handle *fs_win32_directory_handle_t;

/* non-opaque structures */
typedef enum {
  FS_WIN32_ERROR_SUCCESS,
  FS_WIN32_ERROR_DOES_NOT_EXIST,
  FS_WIN32_ERROR_NOT_DIR,
  FS_WIN32_ERROR_IS_DIR,
  FS_WIN32_ERROR_IO,
  FS_WIN32_ERROR_NO_SPACE,
  FS_WIN32_ERROR_PERM,
  FS_WIN32_ERROR_EXISTS,
  FS_WIN32_ERROR_CROSS_DEVICE,
  FS_WIN32_ERROR_NO_MEM,
  FS_WIN32_ERROR_INVALID_ARG,
} fs_win32_error_t;

typedef long long fs_win32_time_t;
typedef unsigned long long fs_win32_off_t;

/* NB: not totally sure about defining constants like this,
   a #define might be better */
HEADER_CONST const fs_win32_time_t FS_WIN32_INVALID_TIME = LLONG_MAX;
HEADER_CONST const fs_win32_off_t FS_WIN32_INVALID_OFF = ULLONG_MAX;

typedef struct {
  fs_win32_time_t modified_time;
  fs_win32_time_t created_time;
  bool is_directory;
  fs_win32_off_t size;
} FsWin32Attrs;

fs_win32_t
fs_win32_blank_new(void);

fs_win32_error_t
fs_win32_open(fs_win32_t fs,
              const char *path, bool create,
              OUT_VAR fs_win32_file_handle_t *handle,
              OUT_VAR bool *created);

fs_win32_error_t
fs_win32_fgetattr(fs_win32_t fs, fs_win32_file_handle_t file_handle,
                  OUT_VAR FsWin32Attrs *attrs);

fs_win32_error_t
fs_win32_ftruncate(fs_win32_t fs, fs_win32_file_handle_t file_handle,
                   fs_win32_off_t offset);

fs_win32_error_t
fs_win32_read(fs_win32_t fs, fs_win32_file_handle_t file_handle,
              OUT_VAR char *buf, size_t size, fs_win32_off_t off,
              OUT_VAR size_t *amt_read);

fs_win32_error_t
fs_win32_write(fs_win32_t fs, fs_win32_file_handle_t file_handle,
               const char *buf, size_t size, fs_win32_off_t offset,
               OUT_VAR size_t *amt_written);

fs_win32_error_t
fs_win32_opendir(fs_win32_t fs, const char *path,
                 OUT_VAR fs_win32_directory_handle_t *dir_handle);

fs_win32_error_t
fs_win32_readdir(fs_win32_t fs, fs_win32_directory_handle_t dir_handle,
                 /* name is required and malloc'd by the implementation,
                    the user must free the returned pointer
                 */
                 OUT_VAR char **name,
                 /* attrs is optionally filled by the implementation */
                 OUT_VAR bool *attrs_is_filled,
                 OUT_VAR FsWin32Attrs *attrs);

fs_win32_error_t
fs_win32_closedir(fs_win32_t fs, fs_win32_directory_handle_t dir_handle);

/* can remove either a file or a directory,
   removing a directory should fail if it's not empty
*/
fs_win32_error_t
fs_win32_remove(fs_win32_t fs, const char *path);

fs_win32_error_t
fs_win32_mkdir(fs_win32_t fs, const char *path);

fs_win32_error_t
fs_win32_getattr(fs_win32_t fs, const char *path,
                 OUT_VAR FsWin32Attrs *attrs);

fs_win32_error_t
fs_win32_rename(fs_win32_t fs,
                const char *src, const char *dst);

fs_win32_error_t
fs_win32_close(fs_win32_t fs, fs_win32_file_handle_t handle);

bool
fs_win32_destroy(fs_win32_t fs);

bool
fs_win32_path_is_root(fs_win32_t fs, const char *path);

bool
fs_win32_path_equals(fs_win32_t fs, const char *a, const char *b);

bool
fs_win32_path_is_parent(fs_win32_t fs,
                        const char *potential_parent,
                        const char *potential_child);

const char *
fs_win32_path_sep(fs_win32_t fs);

#ifdef __cplusplus
}
#endif

#endif
