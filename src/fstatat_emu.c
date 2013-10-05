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
#define _BSD_SOURCE

#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <unistd.h>

#include <errno.h>
#include <stdlib.h>

int fstatat_x(int dirfd, const char *pathname, struct stat *buf,
              int flags) {
  if (flags) {
    errno = EINVAL;
    return -1;
  }

  /* save the current working directory */
  int cwd_fd = open(".", O_RDONLY);
  if (cwd_fd < 0) {
    return -1;
  }

  int toret;

  /* okay now switch to dirfd */
  int fchdir_ret = fchdir(dirfd);
  if (fchdir_ret < 0) {
    toret = -1;
    goto done;
  }

  int stat_ret = stat(pathname, buf);
  if (stat_ret < 0) {
    toret = -1;
    goto done;
  }

  toret = 0;

  int fchdir_ret_2;
 done:
  fchdir_ret_2 = fchdir(cwd_fd);
  if (fchdir_ret_2) {
    /* if we couldn't preserve the cwd, let's just die */
    abort();
  }

  int close_ret = close(cwd_fd);
  if (close_ret) {
    /* failing on close is a leak */
    abort();
  }

  return toret;
}
