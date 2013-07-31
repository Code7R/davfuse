#define _ATFILE_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <sys/stat.h>

int fstatat_x(int dirfd, const char *pathname, struct stat *buf,
              int flags) {
  return fstatat(dirfd, pathname, buf, flags);
}
