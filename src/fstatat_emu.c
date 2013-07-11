#define _ISOC99_SOURCE
#define _POSIX_SOURCE

#include <sys/stat.h>
#include <errno.h>

#include "c_util.h"

int fstatat(int dirfd, const char *pathname, struct stat *buf,
	    int flags) {
  UNUSED(dirfd);
  UNUSED(pathname);
  UNUSED(buf);
  UNUSED(flags);
  errno = ENOSYS;
  return -1;
}
