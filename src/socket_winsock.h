#ifndef _SOCKET_WINSOCK_H
#define _SOCKET_WINSOCK_H

#include <stdbool.h>

#include <winsock2.h>
#include <Ws2tcpip.h>

#include "c_util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int socklen_t;
typedef SOCKET fd_t;
typedef int socket_ssize_t;

typedef enum {
  SOCKET_EWOULDBLOCK=WSAEWOULDBLOCK,
  SOCKET_EAGAIN=WSAEWOULDBLOCK,
  SOCKET_EINTR=WSAEINTR,
} socket_error_t;

HEADER_FUNCTION socket_error_t
last_socket_error(void) {
  return WSAGetLastError();
}

#define _INCLUDE_SOCKET_COMMON_H
#include "_socket_common.h"
#undef _INCLUDE_SOCKET_COMMON_H

#ifdef __cplusplus
}
#endif

#endif
