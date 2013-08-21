#ifndef _SOCKETS_POSIX_H
#define _SOCKETS_POSIX_H

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <netinet/in.h>

#include <unistd.h>

#include <errno.h>
#include <string.h>

#include "c_util.h"
#include "iface_util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int fd_t;
typedef ssize_t socket_ssize_t;

enum {
  INVALID_SOCKET=-1,
  SOCKET_ERROR=-1,
};

typedef enum {
  SOCKET_EWOULDBLOCK=EWOULDBLOCK,
  SOCKET_EAGAIN=EAGAIN,
  SOCKET_EINTR=EINTR,
  SOCKET_ENOTCONN=ENOTCONN,
} socket_error_t;

enum {
  SD_BOTH=SHUT_RDWR,
};

HEADER_FUNCTION socket_error_t
last_socket_error(void) {
  return (socket_error_t) errno;
}

HEADER_FUNCTION const char *
socket_error_message(socket_error_t a) {
  return strerror(a);
}

HEADER_FUNCTION int
closesocket(fd_t sock) {
  return close(sock);
}

#ifdef __cplusplus
}
#endif

#define _INCLUDE_SOCKET_COMMON_H
#include "_socket_common.h"
#undef _INCLUDE_SOCKET_COMMON_H

CREATE_IMPL_TAG(SOCKETS_POSIX_IMPL);

#endif
