/*
  davfuse: FUSE file systems as WebDAV servers
  Copyright (C) 2012, 2013 Rian Hunter <rian@alum.mit.edu>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lessage General Public License as published by
  the Free Software Foundation, either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#include <windows.h>

#include <assert.h>
#include <stdint.h>

#include "fs_win32.h"
#include "util.h"

enum {
  _FS_WIN32_SINGLETON=1,
};

typedef struct _fs_win32_directory_handle {
  HANDLE find_handle;
  WIN32_FIND_DATA last_find_data;
} FsWin32DirectoryHandle;

/* we follow this:
   http://utf8everywhere.org/#how */

static void
ASSERT_VALID_FS(fs_win32_t fs) {
  UNUSED(fs);
  assert(fs == _FS_WIN32_SINGLETON);
}

static fs_win32_error_t
convert_error(DWORD winerror) {
  switch (winerror) {
  case 0:
    abort();
  case ERROR_DIRECTORY:
    return FS_WIN32_ERROR_NOT_DIR;
  case ERROR_FILE_NOT_FOUND: case ERROR_PATH_NOT_FOUND:
    return FS_WIN32_ERROR_DOES_NOT_EXIST;
  case ERROR_ACCESS_DENIED:
    return FS_WIN32_ERROR_PERM;
  case ERROR_FILE_EXISTS: case ERROR_ALREADY_EXISTS:
    return FS_WIN32_ERROR_EXISTS;
  default:
    return FS_WIN32_ERROR_IO;
  }
}

static fs_win32_error_t
windows_error_to_fs_error() {
  return convert_error(GetLastError());
}

static bool
windows_is_dir(DWORD attrs) {
  return attrs & FILE_ATTRIBUTE_DIRECTORY;
}

static fs_win32_time_t
windows_time_to_fs_time(FILETIME *a) {
  ULARGE_INTEGER uli;
  assert(sizeof(a->dwLowDateTime) + sizeof(a->dwHighDateTime) <=
         sizeof(fs_win32_time_t));
  assert(sizeof(uli.QuadPart) <= sizeof(fs_win32_time_t));
  uli.LowPart  = a->dwLowDateTime;
  uli.HighPart = a->dwHighDateTime;
  return ((fs_win32_time_t) (uli.QuadPart / 10000000)) - 11644473600;
}

static fs_win32_off_t
windows_size_to_fs_size(DWORD low, DWORD high) {
  return ((((fs_win32_off_t) high) << (sizeof(low) * 8)) | low);
}

#define FILL_ATTRS(file_info)                                           \
  (FsWin32Attrs) {                                                      \
    .modified_time = windows_time_to_fs_time(&(file_info).ftLastWriteTime), \
      .created_time = windows_time_to_fs_time(&(file_info).ftCreationTime), \
      .is_directory = windows_is_dir((file_info).dwFileAttributes),     \
      .size = windows_size_to_fs_size((file_info).nFileSizeLow,         \
                                      (file_info).nFileSizeHigh),       \
      }

static LPWSTR
utf8_to_mb(const char *s) {
  /* TODO: are these flags good? */
  DWORD flags = /*MB_COMPOSITE | */MB_ERR_INVALID_CHARS;

  int len = strlen(s) + 1;

  int required_characters_size =
    MultiByteToWideChar(CP_UTF8, flags,
                        s, len, NULL, 0);
  if (!required_characters_size) {
    log_info("MultiByteToWideChar failed: %d",
             GetLastError());
    return NULL;
  }

  LPWSTR out = malloc(sizeof(*out) * required_characters_size);
  if (!out) {
    return NULL;
  }

  int new_return =
    MultiByteToWideChar(CP_UTF8, flags,
                        s, len, out, required_characters_size);
  if (!new_return) {
    free(out);
    return NULL;
  }

  return out;
}

static char *
mb_to_utf8(LPWSTR s) {
  /* WC_ERR_INVALID_CHARS is only on windows vista and later */
  DWORD flags = 0 /*| WC_ERR_INVALID_CHARS*/;
  int required_buffer_size =
    WideCharToMultiByte(CP_UTF8, flags,
                        s, -1,
                        NULL, 0,
                        NULL, NULL);
  if (!required_buffer_size) {
    return NULL;
  }

  char *out = malloc(required_buffer_size);
  if (!s) {
    return NULL;
  }

  int new_return =
    WideCharToMultiByte(CP_UTF8, flags,
                        s, -1,
                        out, required_buffer_size,
                        NULL, NULL);
  if (!new_return) {
    return NULL;
  }

  return out;
}

fs_win32_t
fs_win32_default_new(void) {
  return _FS_WIN32_SINGLETON;
}

fs_win32_error_t
fs_win32_open(fs_win32_t fs,
              const char *path, bool create,
              OUT_VAR fs_win32_file_handle_t *handle,
              OUT_VAR bool *created) {
  ASSERT_VALID_FS(fs);
  const LPWSTR wpath = utf8_to_mb(path);
  if (!wpath) {
    return FS_WIN32_ERROR_NO_MEM;
  }

  const DWORD access = GENERIC_READ | GENERIC_WRITE;
  const DWORD share_mode = (FILE_SHARE_DELETE |
                            FILE_SHARE_WRITE |
                            FILE_SHARE_READ);
  const DWORD flags = 0;

  HANDLE h;
  if (create) {
    h = CreateFileW(wpath, access, share_mode,
                    NULL, OPEN_ALWAYS, flags, NULL);
    if (h != INVALID_HANDLE_VALUE) {
      if (created) {
        /* NB: with OPEN_ALWAYS, GetLastError() will return
           ERROR_ALREADY_EXISTS if the file was already there */
        *created = !GetLastError();
      }
    }
  }
  else {
    h = CreateFileW(wpath, access, share_mode,
                    NULL, OPEN_EXISTING, flags, NULL);
  }

  fs_win32_error_t toret;

  if (h == INVALID_HANDLE_VALUE) {
    toret = windows_error_to_fs_error();

    if (GetLastError() == ERROR_ACCESS_DENIED) {
      /* this can happen if the file is a directory, so just check that */
      DWORD ret_get_attrs = GetFileAttributesW(wpath);
      if (ret_get_attrs != INVALID_FILE_ATTRIBUTES &&
          windows_is_dir(ret_get_attrs)) {
        toret = FS_WIN32_ERROR_IS_DIR;
      }
    }
  }
  else {
    toret = FS_WIN32_ERROR_SUCCESS;
    *handle = h;
  }

  free(wpath);

  return toret;
}

fs_win32_error_t
fs_win32_fgetattr(fs_win32_t fs, fs_win32_file_handle_t file_handle,
                  OUT_VAR FsWin32Attrs *attrs) {
  ASSERT_VALID_FS(fs);
  BY_HANDLE_FILE_INFORMATION file_info;
  const BOOL ret = GetFileInformationByHandle(file_handle, &file_info);
  if (!ret) {
    return windows_error_to_fs_error();
  }

  *attrs = FILL_ATTRS(file_info);

  return FS_WIN32_ERROR_SUCCESS;
}

static fs_win32_error_t
_set_file_pointer(fs_win32_file_handle_t file_handle,
                  fs_win32_off_t offset) {
  if (offset >> (sizeof(LONG) * 2 * 8 - 1)) {
    /* if the highest byte (and higher) of the second long is set
       then the input is too large and cannot be represented in
       two longs */
    return FS_WIN32_ERROR_INVALID_ARG;
  }

  const LONG low_offset = offset;
  LONG high_offset = offset >> (sizeof(low_offset) * 8);

  const DWORD ret_set_pointer =
    SetFilePointer(file_handle, low_offset, &high_offset, FILE_BEGIN);
  if (ret_set_pointer == INVALID_SET_FILE_POINTER) {
    return windows_error_to_fs_error();
  }

  return FS_WIN32_ERROR_SUCCESS;
}

fs_win32_error_t
fs_win32_ftruncate(fs_win32_t fs, fs_win32_file_handle_t file_handle,
                   fs_win32_off_t offset) {
  ASSERT_VALID_FS(fs);

  const fs_win32_error_t ret_set_pointer =
    _set_file_pointer(file_handle, offset);
  if (ret_set_pointer) {
    return ret_set_pointer;
  }

  const BOOL success_set_end = SetEndOfFile(file_handle);
  if (!success_set_end) {
    return windows_error_to_fs_error();
  }

  return FS_WIN32_ERROR_SUCCESS;
}

fs_win32_error_t
fs_win32_read(fs_win32_t fs, fs_win32_file_handle_t file_handle,
              OUT_VAR char *buf, size_t size, fs_win32_off_t offset,
              OUT_VAR size_t *amt_read) {
  ASSERT_VALID_FS(fs);

  const fs_win32_error_t ret_set_pointer =
    _set_file_pointer(file_handle, offset);
  if (ret_set_pointer) {
    return ret_set_pointer;
  }

  if (size > MAXDWORD) {
    return FS_WIN32_ERROR_INVALID_ARG;
  }

  DWORD bytes_read;
  if (sizeof(bytes_read) > sizeof(*amt_read)) {
    return FS_WIN32_ERROR_INVALID_ARG;
  }

  const BOOL success_read = ReadFile(file_handle, buf, size,
                                     &bytes_read, NULL);
  if (!success_read) {
    return windows_error_to_fs_error();
  }

  assert(bytes_read <= SIZE_MAX);
  *amt_read = bytes_read;

  return FS_WIN32_ERROR_SUCCESS;
}

fs_win32_error_t
fs_win32_write(fs_win32_t fs, fs_win32_file_handle_t file_handle,
               const char *buf, size_t size, fs_win32_off_t offset,
               OUT_VAR size_t *amt_written) {
  ASSERT_VALID_FS(fs);

  const fs_win32_error_t ret_set_pointer =
    _set_file_pointer(file_handle, offset);
  if (ret_set_pointer) {
    return ret_set_pointer;
  }

  if (size > MAXDWORD) {
    return FS_WIN32_ERROR_INVALID_ARG;
  }

  DWORD bytes_written;
  if (sizeof(bytes_written) > sizeof(*amt_written)) {
    return FS_WIN32_ERROR_INVALID_ARG;
  }

  const BOOL success_write = WriteFile(file_handle, buf, size,
                                       &bytes_written, NULL);
  if (!success_write) {
    return windows_error_to_fs_error();
  }

  *amt_written = bytes_written;

  return FS_WIN32_ERROR_SUCCESS;
}

fs_win32_error_t
fs_win32_close(fs_win32_t fs, fs_win32_file_handle_t file_handle) {
  ASSERT_VALID_FS(fs);

  const BOOL success_close = CloseHandle(file_handle);
  if (!success_close) {
    return windows_error_to_fs_error();
  }

  return FS_WIN32_ERROR_SUCCESS;
}

fs_win32_error_t
fs_win32_opendir(fs_win32_t fs, const char *path_,
                 OUT_VAR fs_win32_directory_handle_t *dir_handle) {
  ASSERT_VALID_FS(fs);

  fs_win32_error_t toret;
  LPWSTR wpath = NULL;
  char *path = NULL;

  *dir_handle = NULL;

  size_t path_len = strlen(path_);
  path = malloc(path_len + sizeof("\\*.*"));
  if (!path) {
    toret = FS_WIN32_ERROR_NO_MEM;
    goto error;
  }

  memcpy(path, path_, path_len);
  memcpy(path + path_len, "\\*.*", sizeof("\\*.*"));

  wpath = utf8_to_mb(path);
  if (!wpath) {
    toret = FS_WIN32_ERROR_NO_MEM;
    goto error;
  }

  *dir_handle = malloc(sizeof(**dir_handle));
  if (!*dir_handle) {
    toret = FS_WIN32_ERROR_NO_MEM;
    goto error;
  }

  (*dir_handle)->find_handle =
    FindFirstFileExW(wpath, FindExInfoStandard, &(*dir_handle)->last_find_data,
                     FindExSearchNameMatch, NULL, 0);
  if ((*dir_handle)->find_handle == INVALID_HANDLE_VALUE) {
    DWORD err = GetLastError();
    if (err == ERROR_NO_MORE_FILES) {
      memcpy((*dir_handle)->last_find_data.cAlternateFileName,
             &err, sizeof(err));
      toret = FS_WIN32_ERROR_SUCCESS;
    }
    else {
      goto win32_error;
    }
  }
  else {
    memset((*dir_handle)->last_find_data.cAlternateFileName, 0,
           sizeof((*dir_handle)->last_find_data.cAlternateFileName));
    toret = FS_WIN32_ERROR_SUCCESS;
  }

  if (false) {
  win32_error:
    toret = windows_error_to_fs_error();
  error:
    free(*dir_handle);
  }

  free(path);
  free(wpath);

  return toret;
}

fs_win32_error_t
fs_win32_readdir(fs_win32_t fs, fs_win32_directory_handle_t dir_handle,
                 /* name is required and malloc'd by the implementation,
                    the user must free the returned pointer
                 */
                 OUT_VAR char **name,
                 /* attrs is optionally filled by the implementation */
                 OUT_VAR bool *attrs_is_filled,
                 OUT_VAR FsWin32Attrs *attrs) {
  ASSERT_VALID_FS(fs);

  while (true) {
    DWORD last_err;
    memcpy(&last_err, dir_handle->last_find_data.cAlternateFileName,
           sizeof(last_err));
    if (last_err) {
      if (last_err == ERROR_NO_MORE_FILES) {
        *name = NULL;
        return FS_WIN32_ERROR_SUCCESS;
      }
      else {
        return convert_error(last_err);
      }
    }

    *name = mb_to_utf8(dir_handle->last_find_data.cFileName);
    if (!*name) {
      return FS_WIN32_ERROR_NO_MEM;
    }

    if (!str_equals(*name, "..") &&
        !str_equals(*name, ".")) {
      if (attrs_is_filled) {
        *attrs_is_filled = true;
      }
      if (attrs) {

        *attrs = FILL_ATTRS(dir_handle->last_find_data);
      }
    }
    else {
      free(*name);
      *name = NULL;
    }

    /* now pull the next info */
    const BOOL success_find_next =
      FindNextFileW(dir_handle->find_handle,
                    &dir_handle->last_find_data);
    if (!success_find_next) {
      DWORD err = GetLastError();
      memcpy(dir_handle->last_find_data.cAlternateFileName, &err, sizeof(err));
    }
    else {
      memset(dir_handle->last_find_data.cAlternateFileName, 0,
             sizeof(dir_handle->last_find_data.cAlternateFileName));
    }

    if (*name) {
      return FS_WIN32_ERROR_SUCCESS;
    }
  }
}

fs_win32_error_t
fs_win32_closedir(fs_win32_t fs, fs_win32_directory_handle_t dir_handle) {
  ASSERT_VALID_FS(fs);

  if (dir_handle->find_handle == INVALID_HANDLE_VALUE) {
    /* this should only happen if there were no files
       in the first call to FindFirstFileExW() */
    DWORD last_err;
    memcpy(&last_err, dir_handle->last_find_data.cAlternateFileName,
           sizeof(last_err));
    assert(last_err == ERROR_NO_MORE_FILES);
  }
  else {
    const BOOL success_close = FindClose(dir_handle->find_handle);
    if (!success_close) {
      return windows_error_to_fs_error();
    }
  }

  free(dir_handle);

  return FS_WIN32_ERROR_SUCCESS;
}

/* can remove either a file or a directory,
   removing a directory should fail if it's not empty
*/
fs_win32_error_t
fs_win32_remove(fs_win32_t fs, const char *path) {
  ASSERT_VALID_FS(fs);

  LPWSTR wpath = utf8_to_mb(path);
  if (!wpath) {
    return FS_WIN32_ERROR_NO_MEM;
  }

  const BOOL success_remove_directory =
    RemoveDirectoryW(wpath);
  if (!success_remove_directory) {
    if (GetLastError() == ERROR_DIRECTORY) {
      const BOOL sucess_remove_file =
        DeleteFileW(wpath);
      if (!sucess_remove_file) {
        goto error;
      }
    }
    else {
      goto error;
    }
  }

  fs_win32_error_t toret;
  if (true) {
    toret = FS_WIN32_ERROR_SUCCESS;
  }
  else {
  error:
    toret = windows_error_to_fs_error();
  }

  free(wpath);

  return toret;
}

fs_win32_error_t
fs_win32_mkdir(fs_win32_t fs, const char *path) {
  ASSERT_VALID_FS(fs);

  LPWSTR wpath = utf8_to_mb(path);
  if (!wpath) {
    return FS_WIN32_ERROR_NO_MEM;
  }

  const BOOL success_create_directory =
    CreateDirectoryW(wpath, NULL);

  fs_win32_error_t toret = success_create_directory
    ? FS_WIN32_ERROR_SUCCESS
    : windows_error_to_fs_error();

  free(wpath);

  return toret;
}

fs_win32_error_t
fs_win32_getattr(fs_win32_t fs, const char *path,
                 OUT_VAR FsWin32Attrs *attrs) {
  ASSERT_VALID_FS(fs);

  LPWSTR wpath = utf8_to_mb(path);
  if (!wpath) {
    return FS_WIN32_ERROR_NO_MEM;
  }

  WIN32_FILE_ATTRIBUTE_DATA file_info;
  const BOOL ret =
    GetFileAttributesEx(wpath, GetFileExInfoStandard, &file_info);
  if (!ret) {
    goto error;
  }

  *attrs = FILL_ATTRS(file_info);

  fs_win32_error_t toret;
  if (true) {
    toret = FS_WIN32_ERROR_SUCCESS;
  }
  else {
  error:
    toret = windows_error_to_fs_error();
  }

  free(wpath);

  return toret;
}

fs_win32_error_t
fs_win32_rename(fs_win32_t fs,
                const char *src, const char *dst) {
  ASSERT_VALID_FS(fs);

  LPWSTR wsrc = NULL;
  LPWSTR wdst = NULL;

  wsrc = utf8_to_mb(src);
  if (!wsrc) {
    goto error;
  }

  wdst = utf8_to_mb(dst);
  if (!wdst) {
    goto error;
  }

  const BOOL success_move =
    MoveFileEx(wsrc, wdst, MOVEFILE_REPLACE_EXISTING);
  if (!success_move) {
    goto error;
  }

  fs_win32_error_t toret;
  if (false) {
  error:
    toret = windows_error_to_fs_error();
  }
  else {
    toret = FS_WIN32_ERROR_SUCCESS;
  }

  free(wsrc);
  free(wdst);

  return toret;
}

bool
fs_win32_destroy(fs_win32_t fs) {
  UNUSED(fs);
  return false;
}

bool
fs_win32_path_is_root(fs_win32_t fs, const char *path) {
  ASSERT_VALID_FS(fs);
  UNUSED(path);
  return false;
}

bool
fs_win32_path_equals(fs_win32_t fs, const char *a, const char *b) {
  ASSERT_VALID_FS(fs);
  return str_case_equals(a, b);
}

bool
fs_win32_path_is_parent(fs_win32_t fs,
                        const char *potential_parent,
                        const char *potential_child) {
  ASSERT_VALID_FS(fs);

  if (!str_case_startswith(potential_child, potential_parent)) {
    return false;
  }

  size_t potential_parent_len = strlen(potential_parent);
  return !strncmp(&potential_child[potential_parent_len],
                  fs_win32_path_sep(fs),
                  strlen(fs_win32_path_sep(fs)));
}

const char *
fs_win32_path_sep(fs_win32_t fs) {
  ASSERT_VALID_FS(fs);
  return "\\";
}
