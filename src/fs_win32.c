#include <windows.h>

#include <assert.h>
#include <stdint.h>

#include "fs_win32.h"

enum {
  _FS_WIN32_SINGLETON=1,
};

/* we follow this:
   http://utf8everywhere.org/#how */

static void
ASSERT_VALID_FS(fs_win32_t fs) {
  UNUSED(fs);
  assert(fs == _FS_WIN32_SINGLETON);
}

static fs_win32_error_t
windows_error_to_fs_error() {
  abort();
  return FS_WIN32_ERROR_NO_MEM;
}

static LPWSTR
utf8_to_mb(const char *s) {
  /* TODO: are these flags good? */
  DWORD flags = MB_COMPOSITE | MB_ERR_INVALID_CHARS;

  int len = strlen(s) + 1;

  int required_characters_size =
    MultiByteToWideChar(CP_UTF8, flags,
                        s, len, NULL, 0);
  if (!required_characters_size) {
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
fs_win32_blank_new(void) {
  return _FS_WIN32_SINGLETON;
}

fs_win32_error_t
fs_win32_open(fs_win32_t fs,
              const char *path, bool create,
              OUT_VAR fs_win32_file_handle_t *handle,
              OUT_VAR bool *created) {
  ASSERT_VALID_FS(fs);
  const LPWSTR wpath = utf8_to_mb(path);
  if (!path) {
    return FS_WIN32_ERROR_NO_MEM;
  }

  const DWORD access = GENERIC_READ | GENERIC_WRITE;
  const DWORD share_mode = (FILE_SHARE_DELETE |
                            FILE_SHARE_WRITE |
                            FILE_SHARE_READ);
  HANDLE h;
  while (true) {
    h = CreateFileW(wpath, access, share_mode,
                    NULL, OPEN_EXISTING, 0, NULL);
    if (create &&
        h == INVALID_HANDLE_VALUE &&
        GetLastError() == ERROR_FILE_NOT_FOUND) {
      h = CreateFileW(wpath, access, share_mode,
                      NULL, CREATE_NEW, 0, NULL);
      if (h == INVALID_HANDLE_VALUE &&
          GetLastError() == ERROR_FILE_EXISTS) {
        continue;
      }

      if (h != INVALID_HANDLE_VALUE) {
        if (created) {
          *created = true;
        }
      }
    }
    else if (h != INVALID_HANDLE_VALUE) {
      if (created) {
        *created = false;
      }
    }

    break;
  }

  free(wpath);

  if (h == INVALID_HANDLE_VALUE) {
    return windows_error_to_fs_error();
  }

  *handle = h;

  return FS_WIN32_ERROR_SUCCESS;
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

fs_win32_error_t
fs_win32_fgetattr(fs_win32_t fs, fs_win32_file_handle_t file_handle,
                  OUT_VAR FsWin32Attrs *attrs) {
  ASSERT_VALID_FS(fs);
  BY_HANDLE_FILE_INFORMATION file_info;
  const BOOL ret = GetFileInformationByHandle(file_handle, &file_info);
  if (!ret) {
    return windows_error_to_fs_error();
  }

  *attrs = (FsWin32Attrs) {
    .modified_time = windows_time_to_fs_time(&file_info.ftLastWriteTime),
    .created_time = windows_time_to_fs_time(&file_info.ftCreationTime),
    .is_directory = file_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY,
    .size = ((((fs_win32_off_t) file_info.nFileSizeHigh) <<
              (sizeof(file_info.nFileSizeLow) * 8)) |
             file_info.nFileSizeLow),
  };

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
fs_win32_opendir(fs_win32_t fs, const char *path,
                 OUT_VAR fs_win32_directory_handle_t *dir_handle) {
  UNUSED(fs);
  UNUSED(path);
  UNUSED(dir_handle);
  return FS_WIN32_ERROR_NO_MEM;
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
  UNUSED(fs);
  UNUSED(dir_handle);
  UNUSED(name);
  UNUSED(attrs_is_filled);
  UNUSED(attrs);
  return FS_WIN32_ERROR_NO_MEM;
}

fs_win32_error_t
fs_win32_closedir(fs_win32_t fs, fs_win32_directory_handle_t dir_handle) {
  UNUSED(fs);
  UNUSED(dir_handle);
  return FS_WIN32_ERROR_NO_MEM;
}

/* can remove either a file or a directory,
   removing a directory should fail if it's not empty
*/
fs_win32_error_t
fs_win32_remove(fs_win32_t fs, const char *path) {
  UNUSED(fs);
  UNUSED(path);
  return FS_WIN32_ERROR_NO_MEM;
}

fs_win32_error_t
fs_win32_mkdir(fs_win32_t fs, const char *path) {
  UNUSED(fs);
  UNUSED(path);
  return FS_WIN32_ERROR_NO_MEM;
}

fs_win32_error_t
fs_win32_getattr(fs_win32_t fs, const char *path,
                 OUT_VAR FsWin32Attrs *attrs) {
  UNUSED(fs);
  UNUSED(path);
  UNUSED(attrs);
  return FS_WIN32_ERROR_NO_MEM;
}

fs_win32_error_t
fs_win32_rename(fs_win32_t fs,
                const char *src, const char *dst) {
  UNUSED(fs);
  UNUSED(src);
  UNUSED(dst);
  return FS_WIN32_ERROR_NO_MEM;
}

bool
fs_win32_destroy(fs_win32_t fs) {
  UNUSED(fs);
  return false;
}

char *
fs_win32_dirname(fs_win32_t fs, const char *path) {
  UNUSED(mb_to_utf8);
  UNUSED(fs);
  UNUSED(path);
  return NULL;
}
