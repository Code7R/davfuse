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

#ifndef __SHARED_TYPES_FS_H
#define __SHARED_TYPES_FS_H

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "c_util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* non-opaque structures */
typedef enum {
  FS_ERROR_SUCCESS,
  FS_ERROR_DOES_NOT_EXIST,
  FS_ERROR_NOT_DIR,
  FS_ERROR_IS_DIR,
  FS_ERROR_IO,
  FS_ERROR_NO_SPACE,
  FS_ERROR_PERM,
  FS_ERROR_EXISTS,
  FS_ERROR_ACCESS,
  FS_ERROR_CROSS_DEVICE,
  FS_ERROR_INVALID_ARG,
  FS_ERROR_NO_MEM,
} fs_error_t;

typedef intmax_t fs_time_t;
typedef intmax_t fs_off_t;
typedef uintmax_t fs_file_id_t;
typedef uintmax_t fs_volume_id_t;

enum {
  FS_INVALID_TIME = INTMAX_MAX,
  FS_INVALID_OFF = INTMAX_MAX,
};

typedef struct {
  fs_time_t modified_time;
  fs_time_t created_time;
  bool is_directory;
  fs_off_t size;
  fs_file_id_t file_id;
  fs_volume_id_t volume_id;
} FsAttrs;

#ifdef __cplusplus
}
#endif

#endif
