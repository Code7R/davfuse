#define _ISOC99_SOURCE
#define _POSIX_C_SOURCE 200112L

#include <unistd.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "c_util.h"
#include "util.h"

#define _IS_LOGGING_C
#include "logging.h"

/* NB: non-static because it's accessed by the header function */
log_level_t _logging_cur_level;

static FILE *_logging_dest;
static bool _show_colors;

bool
init_logging(FILE *log_destination, log_level_t level) {
  _logging_dest = log_destination;
  _logging_cur_level = level;

  /* this code makes this module become POSIX */
  char *term_env = getenv("TERM");
  _show_colors = (isatty(fileno(_logging_dest)) &&
                  term_env && !str_equals(term_env, "dumb"));

  return true;
}

static const char *
color_for_filename(const char *filename) {
  /* do a basic hash */
  unsigned x = 1000001;
  for (size_t i = 0; filename[i]; ++i) {
    x = (x * 7) ^ ((unsigned) filename[i]);
  }

  static const char *const color_table[] = {
    "31",
    "32",
    "33",
    "34",
    "35",
    "36",
    "1;31",
    "1;32",
    "1;33",
    "1;34",
    "1;35",
    "1;36",
  };

  return color_table[x % NELEMS(color_table)];
}

void
_log(const char *filename, log_level_t level, const char *format, ...) {
  UNUSED(level);

  if (!_logging_dest) {
    fprintf(stderr, "Must set _logging_dest before logging!");
    abort();
  }

  const char *basename_ = strrchr(filename, '/');
  if (!basename_) {
    basename_ = filename;
  }
  else {
    basename_ += 1;
  }

  /* TODO: only do this on VT100 compatible terminals */
  if (_show_colors) {
    const char *color_code = color_for_filename(basename_);

    fprintf(_logging_dest, "\x1b[%sm%s\x1b[0m: ", color_code, basename_);

    if (level == LOG_DEBUG) {
      /* display text as gray if it's debug */
      fprintf(_logging_dest, "\x1b[1;30m");
    }
    else if (level <= LOG_WARNING) {
      fprintf(_logging_dest, "\x1b[31m");
    }
  }
  else {
    fprintf(_logging_dest, "%s: ", basename_);
  }

  va_list ap;
  va_start(ap, format);
  vfprintf(_logging_dest, format, ap);
  va_end(ap);

  if (_show_colors &&
      (level == LOG_DEBUG ||
       level <= LOG_WARNING)) {
    fprintf(_logging_dest, "\x1b[0m");
  }

  fprintf(_logging_dest, "\n");
}
