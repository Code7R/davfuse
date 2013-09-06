#ifndef LOGGING_H
#define LOGGING_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "c_util.h"
#include "logging_types.h"
#include "logging_log_printer.h"

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
#define log(level, ...)				 \
  do {						 \
    const log_level_t level_ = level;                                   \
    if (logging_should_print(level_)) {                                 \
      log_printer_print(__FILE__, __LINE__, level_, __VA_ARGS__);       \
    }						 \
  }						 \
  while (false)

#define log_debug(...) log(LOG_DEBUG, __VA_ARGS__)
#define log_info(...) log(LOG_INFO, __VA_ARGS__)
#define log_warning(...) log(LOG_WARNING, __VA_ARGS__)
#define log_error(...) log(LOG_ERROR, __VA_ARGS__)
#define log_critical(...) log(LOG_CRITICAL, __VA_ARGS__)

#define log_critical_errno(str) \
  log_critical(str ": %s", strerror(errno))
#define log_error_errno(str) \
  log_error(str ": %s", strerror(errno))

#ifdef __cplusplus
}
#endif

#endif
