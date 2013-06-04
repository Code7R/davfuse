#ifndef LOGGING_H
#define LOGGING_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
  LOG_NOTHING,
  LOG_CRITICAL,
  LOG_ERROR,
  LOG_WARNING,
  LOG_INFO,
  LOG_DEBUG,
} log_level_t;

/* initializes to zero so logging must be explicitly enabled */
#ifndef _IS_LOGGING_C
extern log_level_t _logging_cur_level;
#endif

/* NB: perhaps this should just be a header function */
#define log(level, ...)				 \
  do {						 \
    if ((level) <= _logging_cur_level) {	 \
      _log(__FILE__, level, __VA_ARGS__);	 \
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

bool
init_logging(FILE *log_destination, log_level_t level);

void
_log(const char *filename, log_level_t level, const char *format, ...);

#endif
