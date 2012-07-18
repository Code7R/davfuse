#include <stddef.h>

#include "davfuse.h"

/*int fuse_main_real(int argc, char *argv[], const struct fuse_operations *op,
  size_t op_size, void *user_data) {*/
int fuse_main_real(int argc, char *argv[], const void *op,
                   size_t op_size, void *user_data) {
  return 0;
}
