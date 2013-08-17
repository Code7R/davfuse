#ifndef _LOGGING_TYPES_H
#define _LOGGING_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  LOG_NOTHING,
  LOG_CRITICAL,
  LOG_ERROR,
  LOG_WARNING,
  LOG_INFO,
  LOG_DEBUG,
} log_level_t;

#ifdef __cplusplus
}
#endif

#endif
