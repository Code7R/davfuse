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
#include "util.h"

void
close_or_abort(int fd) {
  const int saved_errno = errno;
  const int close_ret = close(fd);
  ASSERT_TRUE(!close_ret);
  errno = saved_errno;
}

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
