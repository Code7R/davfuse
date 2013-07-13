#define _ISOC99_SOURCE

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
