#ifndef FD_UTILS_H
#define FD_UTILS_H

#include <sys/socket.h>

#include <stdbool.h>
#include <stdint.h>

void
close_or_abort(int fd);

bool
set_non_blocking(int fd);

bool
set_blocking(int fd);

#endif /* FD_UTILS_H */
