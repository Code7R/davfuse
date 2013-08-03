#ifndef _SOCKET_UTILS_H
#define _SOCKET_UTILS_H

#include <stdint.h>
#include "socket.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint16_t port_t;

enum {
  MAX_PORT=UINT16_MAX,
};

void
init_sockaddr_in(struct sockaddr_in *addr, port_t port);

fd_t
create_bound_socket(const struct sockaddr *addr, socklen_t address_len);

fd_t
create_ipv4_bound_socket(port_t port);

#ifdef __cplusplus
}
#endif

#endif
