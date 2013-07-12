#ifndef FSTATAT_NATIVE_H
#define FSTATAT_NATIVE_H

#include <fcntl.h>
#include <sys/stat.h>

int fstatat_x(int dirfd, const char *pathname, struct stat *buf,
              int flags);

#endif
