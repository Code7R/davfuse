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

#include <dlfcn.h>
#include <pthread.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#include "logging.h"

/* NB: for this fstatat_x emulation to work,
   we need to make sure the current directory is only changed
   while holding a lock, so we redefine chdir, fchdir since they
   aren't thread-safe
   NB: if you don't like this, then don't use this emulation
       but you have to fix code that relies on the functionality of fstatat_x()
*/

int
chdir(const char *path) {
  (void) path;
  assert(false);
  errno = ENOSYS;
  return -1;
}

int
fchdir(int fildes) {
  (void) fildes;
  assert(false);
  errno = ENOSYS;
  return -1;
}

typedef int (*fchdir_t)(int);
static fchdir_t _old_fchdir;
static pthread_mutex_t _fchdir_mutex = PTHREAD_MUTEX_INITIALIZER;

int
fchdir_acquire(int fildes) {
  /* save the current working directory */
  int cwd_fd = -1;
  int ret_pthread = -1;

  cwd_fd = open(".", O_RDONLY);
  if (cwd_fd < 0) goto fail;

  ret_pthread = pthread_mutex_lock(&_fchdir_mutex);
  if (ret_pthread) goto fail;

  if (!_old_fchdir) {
    _old_fchdir = (fchdir_t) dlsym(RTLD_NEXT, "fchdir");
    if (!_old_fchdir) goto fail;
  }

  int ret_fchdir = _old_fchdir(fildes);
  if (ret_fchdir) goto fail;

  return cwd_fd;

  int _pre_errno;
 fail:
  _pre_errno = errno;

  if (!ret_pthread) {
    int ret2 = pthread_mutex_unlock(&_fchdir_mutex);
    if (ret2) abort();
  }

  if (cwd_fd >= 0) {
    int ret2 = close(cwd_fd);
    if (ret2) log_error("failed to close: %d, leaking...", cwd_fd);
  }

  errno = _pre_errno;

  return -1;
}

int
fchdir_release(int cwd_fd) {
  if (!_old_fchdir) {
    _old_fchdir = (fchdir_t) dlsym(RTLD_NEXT, "fchdir");
    if (!_old_fchdir) return -1;
  }

  int ret_fchdir = _old_fchdir(cwd_fd);
  if (ret_fchdir) return -1;

  int ret_unlock = pthread_mutex_unlock(&_fchdir_mutex);
  if (ret_unlock) abort();

  int ret_close = close(cwd_fd);
  if (ret_close) {
    log_error("failed to close: %d, leaking...", cwd_fd);
  }

  return 0;
}

int fstatat_x(int dirfd, const char *pathname, struct stat *buf,
              int flags) {
  if (flags) {
    errno = EINVAL;
    return -1;
  }

  int toret;

  /* okay now switch to dirfd */
  int fchdir_ret = fchdir_acquire(dirfd);
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

 done:
  if (fchdir_ret >= 0) {
    int ret = fchdir_release(fchdir_ret);
    if (ret) abort();
  }

  return toret;
}
