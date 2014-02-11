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

#include "fs_win32.h"

#include "fs_helpers.h"
#include "util.h"

#include <assert.h>
#include <stdint.h>

#include <windows.h>

enum {
  _FS_SINGLETON=1,
};


STATIC_ASSERT(sizeof(HANDLE) <= sizeof(fs_win32_file_handle_t),
              "fs_win32_file_handle_t is not large enough to hold a HANDLE");

STATIC_ASSERT(sizeof(_FS_SINGLETON) <= sizeof(fs_win32_handle_t),
              "fs_file_handle_t is not large enough to hold a _FS_SINGLETON");

/* we follow this:
   http://utf8everywhere.org/#how */

typedef struct _win32_directory_handle {
  HANDLE find_handle;
  WIN32_FIND_DATA last_find_data;
} FsWin32DirectoryHandle;

static fs_win32_file_handle_t
win32_handle_to_file_handle(HANDLE h) {
  /* either INVALID_HANDLE_VALUE is defined to be 0
     or h is never 0 */
  ASSERT_TRUE(!INVALID_HANDLE_VALUE || h);
  return (h == INVALID_HANDLE_VALUE) ? 0 : ((fs_win32_file_handle_t) (uintptr_t) h);
}

static HANDLE
file_handle_to_win32_handle(fs_win32_file_handle_t handle) {
  return handle ? ((HANDLE) (uintptr_t) handle) : INVALID_HANDLE_VALUE;
}

static fs_win32_directory_handle_t
pointer_to_directory_handle(FsWin32DirectoryHandle *h) {
  /* these are type synonyms so no cast should be necessary */
  return h;
}

static FsWin32DirectoryHandle *
directory_handle_to_pointer(fs_win32_directory_handle_t handle) {
  /* these are type synonyms so no cast should be necessary */
  return handle;
}

static void
ASSERT_VALID_FS(fs_win32_handle_t fs) {
  UNUSED(fs);
  assert(fs == (fs_win32_handle_t) _FS_SINGLETON);
}

static fs_error_t
convert_error(DWORD winerror) {
  switch (winerror) {
  case 0:
    abort();
  case ERROR_DIRECTORY:
    return FS_ERROR_NOT_DIR;
  case ERROR_FILE_NOT_FOUND: case ERROR_PATH_NOT_FOUND:
    return FS_ERROR_DOES_NOT_EXIST;
  case ERROR_ACCESS_DENIED:
    return FS_ERROR_PERM;
  case ERROR_FILE_EXISTS: case ERROR_ALREADY_EXISTS:
    return FS_ERROR_EXISTS;
  default:
    return FS_ERROR_IO;
  }
}

static fs_error_t
windows_error_to_fs_error() {
  return convert_error(GetLastError());
}

static bool
windows_is_dir(DWORD attrs) {
  return attrs & FILE_ATTRIBUTE_DIRECTORY;
}

static const fs_time_t WINDOWS_UNIX_TIME_OFFSET = 11644473600;
static const DWORDLONG WINDOWS_UNIX_TIME_MULTIPLIER = 10000000;

static fs_time_t
windows_time_to_fs_time(const FILETIME *a) {
  ULARGE_INTEGER uli;
  STATIC_ASSERT(sizeof(a->dwLowDateTime) + sizeof(a->dwHighDateTime) <=
                sizeof(fs_time_t), "fs_time_t is too small!");
  STATIC_ASSERT(sizeof(uli.QuadPart) <= sizeof(fs_time_t),
                "fs_time_t is too small!");
  uli.LowPart  = a->dwLowDateTime;
  uli.HighPart = a->dwHighDateTime;
  return (((fs_time_t) (uli.QuadPart / WINDOWS_UNIX_TIME_MULTIPLIER)) -
          WINDOWS_UNIX_TIME_OFFSET);
}

static void
fs_time_to_windows_time(FILETIME *a, fs_time_t new_time) {
  const fs_time_t offsetted = new_time + WINDOWS_UNIX_TIME_OFFSET;
  assert(offsetted >= 0);
  DWORDLONG mult = ((DWORDLONG) offsetted * WINDOWS_UNIX_TIME_MULTIPLIER);
  static const DWORD MAX_DWORD = 0xffffffff;
  a->dwLowDateTime = mult & MAX_DWORD;
  a->dwHighDateTime = (mult >> (sizeof(a->dwLowDateTime) * 8)) & MAX_DWORD;
  STATIC_ASSERT(sizeof(a->dwLowDateTime) + sizeof(a->dwHighDateTime) ==
                sizeof(mult), "dwords aren't 4 bytes long");
}

static fs_off_t
windows_size_to_fs_size(DWORD low, DWORD high) {
  return ((((fs_off_t) high) << (sizeof(low) * 8)) | low);
}

#define FILL_ATTRS(file_info)                                           \
  ((FsAttrs) {                                                     \
    .modified_time = windows_time_to_fs_time(&(file_info).ftLastWriteTime), \
      .created_time = windows_time_to_fs_time(&(file_info).ftCreationTime), \
      .is_directory = windows_is_dir((file_info).dwFileAttributes),     \
      .size = windows_size_to_fs_size((file_info).nFileSizeLow,         \
                                      (file_info).nFileSizeHigh),       \
      })

static LPWSTR
utf8_to_mb(const char *s) {
  /* TODO: are these flags good? */
  DWORD flags = /*MB_COMPOSITE | */MB_ERR_INVALID_CHARS;

  int len = strlen(s) + 1;

  int required_characters_size =
    MultiByteToWideChar(CP_UTF8, flags,
                        s, len, NULL, 0);
  if (!required_characters_size) {
    log_info("MultiByteToWideChar failed: %u",
             (unsigned) GetLastError());
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

fs_win32_handle_t
fs_win32_default_new(void) {
  return (fs_win32_handle_t) _FS_SINGLETON;
}

fs_error_t
fs_win32_open(fs_win32_handle_t fs,
              const char *path, bool create,
              OUT_VAR fs_win32_file_handle_t *handle,
              OUT_VAR bool *created) {
  ASSERT_VALID_FS(fs);
  const LPWSTR wpath = utf8_to_mb(path);
  if (!wpath) {
    return FS_ERROR_NO_MEM;
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
        assert(!GetLastError() ||
               GetLastError() == ERROR_ALREADY_EXISTS);
        *created = !GetLastError();
      }
    }
  }
  else {
    h = CreateFileW(wpath, access, share_mode,
                    NULL, OPEN_EXISTING, flags, NULL);
  }

  fs_error_t toret;

  if (h == INVALID_HANDLE_VALUE) {
    toret = windows_error_to_fs_error();

    if (GetLastError() == ERROR_ACCESS_DENIED) {
      /* this can happen if the file is a directory, so just check that */
      DWORD ret_get_attrs = GetFileAttributesW(wpath);
      if (ret_get_attrs != INVALID_FILE_ATTRIBUTES &&
          windows_is_dir(ret_get_attrs)) {
        toret = FS_ERROR_IS_DIR;
      }
    }
  }
  else {
    toret = FS_ERROR_SUCCESS;
    *handle = win32_handle_to_file_handle(h);
  }

  free(wpath);

  return toret;
}

fs_error_t
fs_win32_fgetattr(fs_win32_handle_t fs, fs_win32_file_handle_t file_handle,
                  OUT_VAR FsAttrs *attrs) {
  ASSERT_VALID_FS(fs);
  HANDLE handle = file_handle_to_win32_handle(file_handle);
  BY_HANDLE_FILE_INFORMATION file_info;
  const BOOL ret = GetFileInformationByHandle(handle, &file_info);
  if (!ret) {
    return windows_error_to_fs_error();
  }

  *attrs = FILL_ATTRS(file_info);

  return FS_ERROR_SUCCESS;
}

static fs_error_t
_set_file_pointer(fs_win32_file_handle_t file_handle,
                  fs_off_t offset) {
  if (offset >> (sizeof(LONG) * 2 * 8 - 1)) {
    /* if the highest byte (and higher) of the second long is set
       then the input is too large and cannot be represented in
       two longs */
    return FS_ERROR_INVALID_ARG;
  }

  const LONG low_offset = offset;
  LONG high_offset = offset >> (sizeof(low_offset) * 8);

  HANDLE handle = file_handle_to_win32_handle(file_handle);
  const DWORD ret_set_pointer =
    SetFilePointer(handle, low_offset, &high_offset, FILE_BEGIN);
  if (ret_set_pointer == INVALID_SET_FILE_POINTER) {
    return windows_error_to_fs_error();
  }

  return FS_ERROR_SUCCESS;
}

fs_error_t
fs_win32_ftruncate(fs_win32_handle_t fs, fs_win32_file_handle_t file_handle,
                   fs_off_t offset) {
  ASSERT_VALID_FS(fs);

  const fs_error_t ret_set_pointer =
    _set_file_pointer(file_handle, offset);
  if (ret_set_pointer) {
    return ret_set_pointer;
  }

  HANDLE handle = file_handle_to_win32_handle(file_handle);
  const BOOL success_set_end = SetEndOfFile(handle);
  if (!success_set_end) {
    return windows_error_to_fs_error();
  }

  return FS_ERROR_SUCCESS;
}

fs_error_t
fs_win32_read(fs_win32_handle_t fs, fs_win32_file_handle_t file_handle,
              OUT_VAR char *buf, size_t size, fs_off_t offset,
              OUT_VAR size_t *amt_read) {
  ASSERT_VALID_FS(fs);

  const fs_error_t ret_set_pointer =
    _set_file_pointer(file_handle, offset);
  if (ret_set_pointer) {
    return ret_set_pointer;
  }

  if (size > MAXDWORD) {
    return FS_ERROR_INVALID_ARG;
  }

  DWORD bytes_read;
  if (sizeof(bytes_read) > sizeof(*amt_read)) {
    return FS_ERROR_INVALID_ARG;
  }

  HANDLE handle = file_handle_to_win32_handle(file_handle);
  const BOOL success_read = ReadFile(handle, buf, size,
                                     &bytes_read, NULL);
  if (!success_read) {
    return windows_error_to_fs_error();
  }

  STATIC_ASSERT(sizeof(bytes_read) <= sizeof(*amt_read),
		"sizeof(bytes_read) > sizeof(*amt_read)");
  *amt_read = bytes_read;

  return FS_ERROR_SUCCESS;
}

fs_error_t
fs_win32_write(fs_win32_handle_t fs, fs_win32_file_handle_t file_handle,
               const char *buf, size_t size, fs_off_t offset,
               OUT_VAR size_t *amt_written) {
  ASSERT_VALID_FS(fs);

  const fs_error_t ret_set_pointer =
    _set_file_pointer(file_handle, offset);
  if (ret_set_pointer) {
    return ret_set_pointer;
  }

  if (size > MAXDWORD) {
    return FS_ERROR_INVALID_ARG;
  }

  DWORD bytes_written;
  if (sizeof(bytes_written) > sizeof(*amt_written)) {
    return FS_ERROR_INVALID_ARG;
  }

  HANDLE handle = file_handle_to_win32_handle(file_handle);
  const BOOL success_write = WriteFile(handle, buf, size,
                                       &bytes_written, NULL);
  if (!success_write) {
    return windows_error_to_fs_error();
  }

  *amt_written = bytes_written;

  return FS_ERROR_SUCCESS;
}

fs_error_t
fs_win32_close(fs_win32_handle_t fs, fs_win32_file_handle_t file_handle) {
  ASSERT_VALID_FS(fs);

  HANDLE handle = file_handle_to_win32_handle(file_handle);
  const BOOL success_close = CloseHandle(handle);
  if (!success_close) {
    return windows_error_to_fs_error();
  }

  return FS_ERROR_SUCCESS;
}

fs_error_t
fs_win32_opendir(fs_win32_handle_t fs, const char *path_,
                 OUT_VAR fs_win32_directory_handle_t *dir_handle) {
  ASSERT_VALID_FS(fs);

  fs_error_t toret;
  LPWSTR wpath = NULL;
  char *path = NULL;
  FsWin32DirectoryHandle *h = NULL;

  *dir_handle = 0;

  size_t path_len = strlen(path_);
  path = malloc(path_len + sizeof("\\*.*"));
  if (!path) {
    toret = FS_ERROR_NO_MEM;
    goto error;
  }

  memcpy(path, path_, path_len);
  memcpy(path + path_len, "\\*.*", sizeof("\\*.*"));

  wpath = utf8_to_mb(path);
  if (!wpath) {
    toret = FS_ERROR_NO_MEM;
    goto error;
  }

  h = malloc(sizeof(*h));
  if (!h) {
    toret = FS_ERROR_NO_MEM;
    goto error;
  }

  h->find_handle =
    FindFirstFileExW(wpath, FindExInfoStandard, &h->last_find_data,
                     FindExSearchNameMatch, NULL, 0);
  if (h->find_handle == INVALID_HANDLE_VALUE) {
    DWORD err = GetLastError();
    if (err == ERROR_NO_MORE_FILES) {
      memcpy(h->last_find_data.cAlternateFileName,
             &err, sizeof(err));
      toret = FS_ERROR_SUCCESS;
    }
    else {
      goto win32_error;
    }
  }
  else {
    memset(h->last_find_data.cAlternateFileName, 0,
           sizeof(h->last_find_data.cAlternateFileName));
    toret = FS_ERROR_SUCCESS;
  }

  if (false) {
  win32_error:
    toret = windows_error_to_fs_error();
  error:
    free(h);
  }
  else {
    *dir_handle = pointer_to_directory_handle(h);
  }

  free(path);
  free(wpath);

  return toret;
}

fs_error_t
fs_win32_readdir(fs_win32_handle_t fs, fs_win32_directory_handle_t dir_handle,
                 /* name is required and malloc'd by the implementation,
                    the user must free the returned pointer
                 */
                 OUT_VAR char **name,
                 /* attrs is optionally filled by the implementation */
                 OUT_VAR bool *attrs_is_filled,
                 OUT_VAR FsAttrs *attrs) {
  ASSERT_VALID_FS(fs);

  FsWin32DirectoryHandle *const h = directory_handle_to_pointer(dir_handle);

  while (true) {
    DWORD last_err;
    memcpy(&last_err, h->last_find_data.cAlternateFileName,
           sizeof(last_err));
    if (last_err) {
      if (last_err == ERROR_NO_MORE_FILES) {
        *name = NULL;
        return FS_ERROR_SUCCESS;
      }
      else {
        return convert_error(last_err);
      }
    }

    *name = mb_to_utf8(h->last_find_data.cFileName);
    if (!*name) {
      return FS_ERROR_NO_MEM;
    }

    if (!str_equals(*name, "..") &&
        !str_equals(*name, ".")) {
      if (attrs_is_filled) {
        *attrs_is_filled = true;
      }
      if (attrs) {
        /* TODO: we can't get file_id info from this structure
           we have use to GetFileInformationByHandle */
        *attrs = FILL_ATTRS(h->last_find_data);
      }
    }
    else {
      free(*name);
      *name = NULL;
    }

    /* now pull the next info */
    const BOOL success_find_next =
      FindNextFileW(h->find_handle,
                    &h->last_find_data);
    if (!success_find_next) {
      DWORD err = GetLastError();
      memcpy(h->last_find_data.cAlternateFileName, &err, sizeof(err));
    }
    else {
      memset(h->last_find_data.cAlternateFileName, 0,
             sizeof(h->last_find_data.cAlternateFileName));
    }

    if (*name) {
      return FS_ERROR_SUCCESS;
    }
  }
}

fs_error_t
fs_win32_closedir(fs_win32_handle_t fs, fs_win32_directory_handle_t dir_handle) {
  ASSERT_VALID_FS(fs);

  FsWin32DirectoryHandle *const h = directory_handle_to_pointer(dir_handle);

  if (h->find_handle == INVALID_HANDLE_VALUE) {
    /* this should only happen if there were no files
       in the first call to FindFirstFileExW() */
    DWORD last_err;
    memcpy(&last_err, h->last_find_data.cAlternateFileName,
           sizeof(last_err));
    assert(last_err == ERROR_NO_MORE_FILES);
  }
  else {
    const BOOL success_close = FindClose(h->find_handle);
    if (!success_close) {
      return windows_error_to_fs_error();
    }
  }

  free(h);

  return FS_ERROR_SUCCESS;
}

/* can remove either a file or a directory,
   removing a directory should fail if it's not empty
*/
fs_error_t
fs_win32_remove(fs_win32_handle_t fs, const char *path) {
  ASSERT_VALID_FS(fs);

  LPWSTR wpath = utf8_to_mb(path);
  if (!wpath) {
    return FS_ERROR_NO_MEM;
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

  fs_error_t toret;
  if (true) {
    toret = FS_ERROR_SUCCESS;
  }
  else {
  error:
    toret = windows_error_to_fs_error();
  }

  free(wpath);

  return toret;
}

fs_error_t
fs_win32_mkdir(fs_win32_handle_t fs, const char *path) {
  ASSERT_VALID_FS(fs);

  LPWSTR wpath = utf8_to_mb(path);
  if (!wpath) {
    return FS_ERROR_NO_MEM;
  }

  const BOOL success_create_directory =
    CreateDirectoryW(wpath, NULL);

  fs_error_t toret = success_create_directory
    ? FS_ERROR_SUCCESS
    : windows_error_to_fs_error();

  free(wpath);

  return toret;
}

fs_error_t
fs_win32_getattr(fs_win32_handle_t fs, const char *path,
                 OUT_VAR FsAttrs *attrs) {
  ASSERT_VALID_FS(fs);

  LPWSTR wpath = utf8_to_mb(path);
  if (!wpath) {
    return FS_ERROR_NO_MEM;
  }

  WIN32_FILE_ATTRIBUTE_DATA file_info;
  const BOOL ret =
    GetFileAttributesEx(wpath, GetFileExInfoStandard, &file_info);
  if (!ret) {
    goto error;
  }

  *attrs = FILL_ATTRS(file_info);

  fs_error_t toret;
  if (true) {
    toret = FS_ERROR_SUCCESS;
  }
  else {
  error:
    toret = windows_error_to_fs_error();
  }

  free(wpath);

  return toret;
}

fs_error_t
fs_win32_rename(fs_win32_handle_t fs,
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

  fs_error_t toret;
  if (false) {
  error:
    toret = windows_error_to_fs_error();
  }
  else {
    toret = FS_ERROR_SUCCESS;
  }

  free(wsrc);
  free(wdst);

  return toret;
}

fs_error_t
fs_win32_set_times(fs_win32_handle_t fs,
                   const char *path,
                   fs_time_t atime,
                   fs_time_t mtime) {
  ASSERT_VALID_FS(fs);

  FILETIME atime_to_set;
  if (atime != FS_INVALID_TIME) {
    fs_time_to_windows_time(&atime_to_set, atime);
  }

  FILETIME mtime_to_set;
  if (mtime != FS_INVALID_TIME) {
    fs_time_to_windows_time(&mtime_to_set, mtime);
  }

  const LPWSTR wpath = utf8_to_mb(path);
  if (!wpath) return FS_ERROR_NO_MEM;

  const DWORD access = GENERIC_WRITE;
  const DWORD share_mode = (FILE_SHARE_WRITE |
                            FILE_SHARE_READ |
                            FILE_SHARE_DELETE);
  const DWORD flags = FILE_FLAG_BACKUP_SEMANTICS;
  HANDLE file_handle =
    CreateFileW(wpath, access, share_mode, NULL,
                OPEN_EXISTING, flags, NULL);
  if (file_handle == INVALID_HANDLE_VALUE) goto err;

  const BOOL res =
    SetFileTime(file_handle, NULL,
                atime == FS_INVALID_TIME ? NULL : &atime_to_set,
                mtime == FS_INVALID_TIME ? NULL : &mtime_to_set);
  if (!res) goto err;

  fs_error_t toret;
  if (false) {
  err:
    toret = windows_error_to_fs_error();
  }
  else toret = FS_ERROR_SUCCESS;

  const BOOL success_close = CloseHandle(file_handle);
  if (!success_close) {
    log_error("Error while closing %s during set_times",
              path);
  }

  free(wpath);

  return toret;
}

bool
fs_win32_destroy(fs_win32_handle_t fs) {
  ASSERT_VALID_FS(fs);
  return true;
}

bool
fs_win32_path_is_root(fs_win32_handle_t fs, const char *path) {
  ASSERT_VALID_FS(fs);
  assert(fs_win32_path_is_valid(fs, path));

  /* TODO: add support for UNC paths */
  return (strlen(path) == 3 &&
          (('a' <= path[0] && path[0] <= 'z') ||
           ('A' <= path[0] && path[0] <= 'Z')) &&
          path[1] == ':' && path[2] == '\\');
}

bool
fs_win32_path_is_valid(fs_win32_handle_t fs,
                       const char *path) {
  ASSERT_VALID_FS(fs);
  if (!path) return false;

  if (strlen(path) >= 3 &&
      (('a' <= path[0] && path[0] <= 'z') ||
       ('A' <= path[0] && path[0] <= 'Z')) &&
      path[1] == ':' && path[2] == '\\') {
    return true;
  }

  /* TODO: add support for UNC paths */

  return false;
}

static bool
fs_win32_path_component_is_valid(fs_win32_handle_t fs,
                                 const char *component) {
/* lots of restrictions here:
http://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
*/
  static const char BAD_WIN_CHARS[] =
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
    "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
    "<>:\"/\\|?*";

  ASSERT_VALID_FS(fs);
  char *first_bad = strpbrk(component, BAD_WIN_CHARS);

  if (first_bad) return false;

  static const char *BAD_WIN_NAMES[] = {
    ".", "..", "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4",
    "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4",
    "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
  };
  for (unsigned i = 0; i < NELEMS(BAD_WIN_NAMES); ++i) {
    if (str_equals(component, BAD_WIN_NAMES[i])) {
      return false;
    }
  }

  size_t num_component_chars = strlen(component);
  if (component[num_component_chars - 1] == '.' ||
      component[num_component_chars - 1] == ' ') return false;

  return true;
}

char *
fs_win32_path_dirname(fs_win32_handle_t fs, const char *path) {
  ASSERT_VALID_FS(fs);
  assert(fs_win32_path_is_valid(fs, path));

  if (fs_win32_path_is_root(fs, path)) {
    return davfuse_util_strdup(path);
  }

  const char *end_of_path = strrchr(path, '\\');
  /* a valid path would have a \ character in it */
  assert(end_of_path);

  /* if this last \ character, then that means the dirname
     is a root, so we want to keep the \ character */
  if (end_of_path[-1] == ':' &&
      (('a' <= end_of_path[-2] && end_of_path[-2] <= 'z') ||
       ('A' <= end_of_path[-2] && end_of_path[-2] <= 'Z'))) {
    end_of_path += 1;
  }

  return strndup_x(path, end_of_path - path);
}

char *
fs_win32_path_basename(fs_win32_handle_t fs, const char *path) {
  ASSERT_VALID_FS(fs);
  assert(fs_win32_path_is_valid(fs, path));

  if (fs_win32_path_is_root(fs, path)) {
    return davfuse_util_strdup(path);
  }

  return fs_helpers_basename("\\", path);
}

char *
fs_win32_path_join(fs_win32_handle_t fs,
                   const char *dirname, const char *basename) {
  ASSERT_VALID_FS(fs);
  assert(fs_win32_path_is_valid(fs, dirname));
  if (!fs_win32_path_component_is_valid(fs, basename)) {
    return NULL;
  }
  return fs_helpers_join("\\", dirname, basename);
}
