#ifndef FD_UTILS_H
#define FD_UTILS_H

#include <sys/socket.h>

#include <stdbool.h>
#include <stdint.h>

bool
set_non_blocking(int fd);

int
create_bound_socket(const struct sockaddr *addr, socklen_t address_len);

typedef uint16_t port_t;

enum {
  MAX_PORT=(1 << 16) - 1,
};

int
create_ipv4_bound_socket(port_t port);

#endif /* FD_UTILS_H */
