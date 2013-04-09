#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <stdbool.h>

#include "util.h"

int
file_exists(const char *file_path);

linked_list_t
rmtree(const char *file_path);

#endif
