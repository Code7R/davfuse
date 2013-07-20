#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>

#include "c_util.h"
#include "fd_utils.h"
#include "logging.h"

bool
set_non_blocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    log_warning("Couldn't read file flags: %s", strerror(errno));
    return false;
  }

  if (flags & O_NONBLOCK) {
    return true;
  }

  return fcntl(fd, F_SETFL, (long) flags | O_NONBLOCK) >= 0;
}

bool
set_blocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    log_warning("Couldn't read file flags: %s", strerror(errno));
    return false;
  }

  if (!(flags & O_NONBLOCK)) {
    return true;
  }

  return fcntl(fd, F_SETFL, (long) flags & ~O_NONBLOCK) >= 0;
}

int
create_bound_socket(const struct sockaddr *addr, socklen_t addr_len) {
  int ret;
  int socket_fd = -1;
  int reuse = 1;

  socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd < 0) {
    log_error_errno("socket");
    goto error;
  }

  ret = setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
  if (ret) {
    log_error_errno("setsockopt");
    goto error;
  }

  ret = bind(socket_fd, addr, addr_len);
  if (ret) {
    log_error_errno("bind");
    goto error;
  }

  return socket_fd;

 error:
  if (socket_fd >= 0) {
    close(socket_fd);
  }

  return -1;
}

int create_ipv4_bound_socket(port_t port) {
  struct sockaddr_in listen_addr;

  memset(&listen_addr, 0, sizeof(listen_addr));

  listen_addr.sin_family = AF_INET;
  listen_addr.sin_port = htons(port);
  listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  return create_bound_socket((struct sockaddr *) &listen_addr,
			     sizeof(listen_addr));
}

