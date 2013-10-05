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
