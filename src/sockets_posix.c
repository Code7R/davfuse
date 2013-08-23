#define _ISOC99_SOURCE

#include <fcntl.h>

#include <signal.h>
#include <stdbool.h>

#include "logging.h"

#include "sockets_posix.h"

bool
init_socket_subsystem(void) {
  return true;
}

bool
shutdown_socket_subsystem(void) {
  return true;
}

bool
set_socket_non_blocking(fd_t fd) {
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

bool ignore_sigpipe() {
  /* reset errno */
  errno = 0;
  void (*ret_signal)(int) = signal(SIGPIPE, SIG_IGN);
  bool success = ret_signal != SIG_ERR && !errno;
  if (!success) {
    log_error("Error ignoring SIGPIPE: %p %s", ret_signal, strerror(errno));
  }
  return success;
}
