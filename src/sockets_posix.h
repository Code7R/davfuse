/*
  davfuse: FUSE file systems as WebDAV servers
  Copyright (C) 2012, 2013 Rian Hunter <rian@alum.mit.edu>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation, either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

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

typedef int socket_t;
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
  SOCKET_EADDRINUSE=EADDRINUSE,
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
closesocket(socket_t sock) {
  return close(sock);
}

HEADER_FUNCTION socket_t
socket_from_fd(int fd) {
  return fd;
}

HEADER_FUNCTION int
fd_from_socket(socket_t sock) {
  return sock;
}

#ifdef __cplusplus
}
#endif

#define _INCLUDE_SOCKET_COMMON_H
#include "_socket_common.h"
#undef _INCLUDE_SOCKET_COMMON_H

CREATE_IMPL_TAG(SOCKETS_POSIX_IMPL);

#endif
