#include <stdbool.h>
#include <stdio.h>

#define _IS_LOGGING_C
#include "logging.h"

FILE *_logging_dest;
log_level_t _logging_cur_level;

bool
init_logging(FILE *log_destination, log_level_t level) {
  _logging_dest = log_destination;
  _logging_cur_level = level;
  return true;
}
