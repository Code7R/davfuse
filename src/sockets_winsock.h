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
typedef SOCKET socket_t;
typedef int socket_ssize_t;

typedef enum {
  SOCKET_EWOULDBLOCK=WSAEWOULDBLOCK,
  SOCKET_EAGAIN=WSAEWOULDBLOCK,
  SOCKET_EINTR=WSAEINTR,
  SOCKET_ENOTCONN=WSAENOTCONN,
  SOCKET_EADDRINUSE=WSAEADDRINUSE,
} socket_error_t;

HEADER_FUNCTION socket_error_t
last_socket_error(void) {
  return (socket_error_t) WSAGetLastError();
}

HEADER_FUNCTION socket_t
socket_from_fd(int fd) {
  UNUSED(fd);
  return INVALID_SOCKET;
}

HEADER_FUNCTION int
fd_from_socket(socket_t sock) {
  UNUSED(sock);
  return -1;
}

const char *
socket_error_message(socket_error_t);

#ifdef __cplusplus
}
#endif

#define _INCLUDE_SOCKET_COMMON_H
#include "_socket_common.h"
#undef _INCLUDE_SOCKET_COMMON_H

#endif
