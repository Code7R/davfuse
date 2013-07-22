#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <libgen.h>

#include <stdbool.h>

#include "util.h"

void
close_or_abort(int fd);

void
closedir_or_abort(DIR *dirp);

int
file_exists(const char *file_path);

int
file_is_dir(const char *file_path);

int
touch(const char *file_path);

bool
open_or_create(const char *file_path, int flags, mode_t mode,
               int *fd, bool *created);

linked_list_t
rmtree(const char *file_path);

bool
copyfile(const char *from_path, const char *to_path);

linked_list_t
copytree(const char *from_path, const char *to_path, bool delete_original);

#endif
