#ifndef FSTATAT_EMU_H
#define FSTATAT_EMU_H

int fstatat(int dirfd, const char *pathname, struct stat *buf,
	    int flags);

#endif
