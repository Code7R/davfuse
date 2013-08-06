#ifndef _FS_POSIX_H
#define _FS_POSIX_H

#include <dirent.h>

#include <stdbool.h>
#include <stddef.h>

#include "c_util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int fs_posix_t;
typedef int fs_posix_file_handle_t;
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

typedef struct {
  fs_posix_time_t modified_time;
  fs_posix_time_t created_time;
  bool is_directory;
  fs_posix_off_t size;
} FsPosixAttrs;

fs_posix_t
fs_posix_blank_new(void);

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

char *
fs_posix_dirname(fs_posix_t fs, const char *path);

#ifdef __cplusplus
}
#endif

#endif
