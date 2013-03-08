#include <fcntl.h>

#include <stdbool.h>

#include "fd_utils.h"
#include "logging.h"

bool
set_non_blocking(int fd) {
  int flags;

  flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    log_warning("Couldn't read file flags: %s, setting 0", strerror(errno));
    flags = 0;
  }

  return fcntl(fd, F_SETFL, (long) flags | O_NONBLOCK) >= 0
}
