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

#ifndef _SOCKET_UTILS_H
#define _SOCKET_UTILS_H

#include <stdint.h>

#include "sockets.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint16_t port_t;
typedef uint32_t ipv4_t;

enum {
  MAX_PORT=UINT16_MAX,
};

const char *
last_socket_error_message(void);

void
init_sockaddr_in(struct sockaddr_in *addr, ipv4_t ip, port_t port);

fd_t
create_bound_socket(const struct sockaddr *addr, socklen_t address_len);

fd_t
create_ipv4_bound_socket(ipv4_t ip, port_t port);

#ifdef __cplusplus
}
#endif

#endif
