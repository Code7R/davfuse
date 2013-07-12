#ifndef FSTATAT_EMU_H
#define FSTATAT_EMU_H

#include <sys/stat.h>

int fstatat_x(int dirfd, const char *pathname, struct stat *buf,
              int flags);

#endif
