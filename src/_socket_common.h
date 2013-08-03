#ifndef _INCLUDE_SOCKET_COMMON_H
#error "DON'T INCLUDE THIS UNLESS YOU KNOW WHAT YOU ARE DOING"
#endif

bool
init_socket_subsystem(void);

bool
set_socket_non_blocking(fd_t sock);

bool
ignore_sigpipe();
