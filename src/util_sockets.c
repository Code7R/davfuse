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

#include "util.h"
#include "sockets.h"

#include "util_sockets.h"

const char *
last_socket_error_message(void) {
  return socket_error_message(last_socket_error());
}

void
init_sockaddr_in(struct sockaddr_in *addr, ipv4_t ip, port_t port) {
  memset(addr, 0, sizeof(*addr));

  addr->sin_family = AF_INET;
  addr->sin_port = htons(port);
  addr->sin_addr.s_addr = htonl(ip);
}


fd_t
create_bound_socket(const struct sockaddr *addr, socklen_t addr_len) {
  int ret;
  fd_t socket_fd = INVALID_SOCKET;

  socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd == INVALID_SOCKET) {
    log_error("socket: %s", last_socket_error_message());
    goto error;
  }

  int reuse = 1;
  ret = setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR,
                   (void *) &reuse, sizeof(reuse));
  if (ret) {
    log_error("setsockopt: %s", last_socket_error_message());
    goto error;
  }

  ret = bind(socket_fd, addr, addr_len);
  if (ret) {
    log_error("bind: %s", last_socket_error_message());
    goto error;
  }

  ret = listen(socket_fd, 5);
  if (ret) {
    log_error("listen: %s", last_socket_error_message());
    goto error;
  }

  return socket_fd;

 error:
  if (socket_fd != INVALID_SOCKET) {
    int ret = closesocket(socket_fd);
    ASSERT_TRUE(!ret);
  }

  return -1;
}

fd_t
create_ipv4_bound_socket(ipv4_t ip, port_t port) {
  struct sockaddr_in listen_addr;

  init_sockaddr_in(&listen_addr, ip, port);

  return create_bound_socket((struct sockaddr *) &listen_addr,
			     sizeof(listen_addr));
}
