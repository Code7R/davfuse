#ifndef _INCLUDE_HTTP_BACKEND_COMMON_H
#error "DON'T INCLUDE THIS UNLESS YOU KNOW WHAT YOU ARE DOING"
#endif

#ifndef __HTTP_BACKEND_COMMON_H
#define __HTTP_BACKEND_COMMON_H

#include "coroutine_io.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef io_error_t http_backend_error_t;

enum {
  HTTP_BACKEND_ERROR_NONE=IO_ERROR_NONE,
  HTTP_BACKEND_ERROR_UNKNOWN=IO_ERROR_GENERAL,
};

typedef struct {
  http_backend_error_t error;
  http_backend_handle_t handle;
} HTTPBackendAcceptDoneEvent;

typedef ReadFnDoneEvent HTTPBackendReadDoneEvent;
typedef WriteFnDoneEvent HTTPBackendWriteDoneEvent;

void
http_backend_accept(http_backend_t backend,
                    event_handler_t cb,
                    void *ud);

void
http_backend_stop_accept(http_backend_t backend);

void
http_backend_read(http_backend_t backend,
                  http_backend_handle_t handle,
                  void *buf, size_t nbyte,
                  event_handler_t cb,
                  void *ud);

void
http_backend_write(http_backend_t backend,
                   http_backend_handle_t handle,
                   const void *buf, size_t nbyte,
                   event_handler_t cb,
                   void *ud);

bool
http_backend_close(http_backend_t backend,
                   http_backend_handle_t handle);

#ifdef __cplusplus
}
#endif

#endif
