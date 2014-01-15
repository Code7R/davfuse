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

#include "util_sockets.h"

#include "sockets.h"
#include "util.h"

#include <stdlib.h>

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

socket_t
create_bound_socket(const struct sockaddr *addr, socklen_t addr_len) {
  int ret;
  socket_t socket_fd = INVALID_SOCKET;

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

  ret = listen(socket_fd, SOMAXCONN);
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

socket_t
create_ipv4_bound_socket(ipv4_t ip, port_t port) {
  struct sockaddr_in listen_addr;

  init_sockaddr_in(&listen_addr, ip, port);

  return create_bound_socket((struct sockaddr *) &listen_addr,
			     sizeof(listen_addr));
}

static
unsigned
gcd(unsigned a, unsigned b) {
  assert(a && b);
  while (b) {
    unsigned t = b;
    b = a % b;
    a = t;
  }
  return a;
}

static
bool
are_mutually_prime(unsigned a, unsigned b) {
  return gcd(a, b) == 1;
}


static
unsigned
find_random_smaller_mutually_prime(unsigned a) {
  assert(a);

  unsigned toret;
  do toret = rand() % (a - 1) + 1;
  while (are_mutually_prime(a, toret));

  return toret;
}

port_t
bind_random_free_listen_port(socket_t socket_fd, ipv4_t ip, port_t low, port_t high) {
  /* find a port in the range (inclusive) to bind to
     based on searching a random permutation of the numbers
     in the range */

  assert(low <= high);

  bool allocated_socket = false;
  if (socket_fd == INVALID_SOCKET) {
    allocated_socket = true;
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == INVALID_SOCKET) goto fail;
  }

  /* unsigned has to be bigger than port_t because otherwise the highest
     port minus the lowest port plus one would be an overflow */
  STATIC_ASSERT(sizeof(unsigned) > sizeof(port_t),
                "unsigned is too large or port_t is too small");
  unsigned range_size = (unsigned) high - (unsigned) low + 1;

  port_t cur_port = low + rand() % range_size;
  unsigned adder = high == low
    ? 0 /* we're just iterating once anyway */
    : find_random_smaller_mutually_prime(range_size);

  unsigned i;
  for (i = 0; i < range_size; ++i) {
    struct sockaddr_in listen_addr;
    init_sockaddr_in(&listen_addr, ip, cur_port);

    int ret_bind = bind(socket_fd,
                        (struct sockaddr *) &listen_addr,
                        sizeof(listen_addr));
    if (!ret_bind) break;
    if (last_socket_error() != SOCKET_EADDRINUSE) goto fail;

    cur_port += adder;

    /* deal with wraparound
       NB: this is unsigned overflow so it's not undefined */
    if (cur_port > high) cur_port = low + (cur_port - high - 1);
    else if (cur_port < low) cur_port += low;
  }

  if (i == range_size) {
  fail:
    cur_port = 0;
  }

  if (allocated_socket && socket_fd != INVALID_SOCKET) {
    /* log if close fails */
    closesocket(socket_fd);
  }

  return cur_port;
}

port_t
find_random_free_listen_port(ipv4_t ip, port_t low, port_t high) {
  return bind_random_free_listen_port(INVALID_SOCKET, ip, low, high);
}

int
localhost_socketpair(socket_t sv[2]) {
  socket_t socket_fd = INVALID_SOCKET;
  socket_t client_fd = INVALID_SOCKET;

  socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd == INVALID_SOCKET) goto fail;

  const port_t target_port = bind_random_free_listen_port(socket_fd,
                                                          LOCALHOST_IP,
                                                          PRIVATE_PORT_START,
                                                          PRIVATE_PORT_END);
  if (!target_port) goto fail;

  const int ret_listen = listen(socket_fd, 5);
  if (ret_listen) goto fail;

  client_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (client_fd == INVALID_SOCKET) goto fail;

  struct sockaddr_in connect_addr;
  init_sockaddr_in(&connect_addr, LOCALHOST_IP, target_port);

  const int ret_connect =
    connect(client_fd, (struct sockaddr *) &connect_addr,
            sizeof(connect_addr));
  if (ret_connect) goto fail;

  socklen_t filled = sizeof(connect_addr);
  const socket_t ret_accept =
    accept(socket_fd, (struct sockaddr *) &connect_addr, &filled);
  if (ret_accept == INVALID_SOCKET) goto fail;

  sv[0] = ret_accept;
  sv[1] = client_fd;

  closesocket(socket_fd);

  return 0;

 fail:
  // TODO: log if close() fails
  if (socket_fd != INVALID_SOCKET) closesocket(socket_fd);

  // TODO: log if close() fails
  if (client_fd != INVALID_SOCKET) closesocket(client_fd);

  return -1;
}
