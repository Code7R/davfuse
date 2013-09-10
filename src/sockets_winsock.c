/*
  davfuse: FUSE file systems as WebDAV servers
  Copyright (C) 2012, 2013 Rian Hunter <rian@alum.mit.edu>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lessage General Public License as published by
  the Free Software Foundation, either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#define _ISOC99_SOURCE

#include <winsock2.h>
#include <Ws2tcpip.h>

#include <stdbool.h>

#include "logging.h"

#include "sockets_winsock.h"

bool
init_socket_subsystem(void) {
  WORD wVersionRequested = MAKEWORD(2, 2);
  WSADATA wsaData;

  int err = WSAStartup(wVersionRequested, &wsaData);
  if (err) {
    /* Tell the user that we could not find a usable */
    /* Winsock DLL.                                  */
    log_error("Couldn't initialize WSAStartup: %d", err);
    return false;
  }

  if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
    /* we didn't get the version we requested */
    WSACleanup();
    return false;
  }

  return true;
}

bool
shutdown_socket_subsystem(void) {
  int ret_wsacleanup = WSACleanup();
  return !ret_wsacleanup;
}

bool
set_socket_non_blocking(fd_t sock) {
  u_long argp = 1;
  int ret_ioctl = ioctlsocket(sock, FIONBIO, &argp);
  return !ret_ioctl;
}

bool ignore_sigpipe() {
  return true;
}
