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

#ifndef LOGGING_H
#define LOGGING_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "c_util.h"
#include "logging_types.h"
#include "log_printer.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef STATIC_LOGGING_LEVEL
enum {
  _logging_cur_level=STATIC_LOGGING_LEVEL,
};
#else
#ifndef _IS_LOGGING_C
extern log_level_t _logging_cur_level;
#endif

void
logging_set_global_level(log_level_t new_level);
#endif

#define logging_should_print(level) ((level) <= _logging_cur_level)

/* NB: perhaps this should just be a header function */
#define logging_log(level, ...)				 \
  do {						 \
    const log_level_t level_ = level;                                   \
    if (logging_should_print(level_)) {                                 \
      log_printer_print(__FILE__, __LINE__, level_, __VA_ARGS__);       \
    }						 \
  }						 \
  while (false)

#define log_debug(...) logging_log(LOG_DEBUG, __VA_ARGS__)
#define log_info(...) logging_log(LOG_INFO, __VA_ARGS__)
#define log_warning(...) logging_log(LOG_WARNING, __VA_ARGS__)
#define log_error(...) logging_log(LOG_ERROR, __VA_ARGS__)
#define log_critical(...) logging_log(LOG_CRITICAL, __VA_ARGS__)

#define log_critical_errno(str) \
  log_critical(str ": %s", strerror(errno))
#define log_error_errno(str) \
  log_error(str ": %s", strerror(errno))

#ifdef __cplusplus
}
#endif

#endif
