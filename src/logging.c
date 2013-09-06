#define _IS_LOGGING_C
#include "logging.h"

/* NB: non-static because it's accessed by the header function */
/* initializes to zero so logging must be explicitly enabled */
log_level_t _logging_cur_level;

void
logging_set_global_level(log_level_t level) {
  _logging_cur_level = level;
}
