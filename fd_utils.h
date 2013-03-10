#ifndef FD_UTILS_H
#define FD_UTILS_H

#include <sys/socket.h>

#include <stdbool.h>

bool
set_non_blocking(int fd);

int
create_bound_socket(const struct sockaddr *addr, socklen_t address_len);

int
create_ipv4_bound_socket(short port);

#endif /* FD_UTILS_H */
