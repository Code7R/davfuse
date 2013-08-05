
#include "fs.h"
#include "util_fs.h"

fs_error_t
util_fs_touch(fs_t fs, const char *path, bool *created) {
  UNUSED(fs);
  UNUSED(path);
  UNUSED(created);
  abort();
  return 0;
}

fs_error_t
util_fs_file_exists(fs_t fs, const char *path, bool *exists) {
  UNUSED(fs);
  UNUSED(path);
  UNUSED(exists);
  abort();
  return 0;
}


linked_list_t
util_fs_rmtree(fs_t fs, const char *path) {
  UNUSED(fs);
  UNUSED(path);
  abort();
  return LINKED_LIST_INITIALIZER;
}

fs_error_t
util_fs_file_is_dir(fs_t fs, const char *path, bool *is_dir) {
  UNUSED(fs);
  UNUSED(path);
  UNUSED(is_dir);
  abort();
  return 0;
}

fs_error_t
util_fs_copyfile(fs_t fs,
                 const char *file_path,
                 const char *destination_path) {
  UNUSED(fs);
  UNUSED(file_path);
  UNUSED(destination_path);
  abort();
  return 0;
}

linked_list_t
util_fs_copytree(fs_t fs,
                 const char *file_path,
                 const char *destination_path,
                 bool is_move) {
  UNUSED(fs);
  UNUSED(file_path);
  UNUSED(destination_path);
  UNUSED(is_move);
  abort();
  return LINKED_LIST_INITIALIZER;
}
