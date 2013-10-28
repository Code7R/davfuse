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
set_socket_non_blocking(socket_t fd) {
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
