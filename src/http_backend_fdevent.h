#ifndef _HTTP_BACKEND_FDEVENT_H
#define _HTTP_BACKEND_FDEVENT_H

/* this is for backend common */
#include "fdevent.h"
#include "socket.h"

#ifdef __cplusplus
extern "C" {
#endif

struct _http_backend;

typedef struct _http_backend *http_backend_t;
typedef fd_t http_backend_handle_t;

http_backend_t
http_backend_fdevent_new(fdevent_loop_t loop,
                         const struct sockaddr *addr, socklen_t addr_len);

void
http_backend_fdevent_destroy(http_backend_t backend);

#ifdef __cplusplus
}
#endif

#define _INCLUDE_HTTP_BACKEND_COMMON_H
#include "_http_backend_common.h"
#undef _INCLUDE_HTTP_BACKEND_COMMON_H

#endif
