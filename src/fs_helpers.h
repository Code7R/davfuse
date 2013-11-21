#ifndef _fs_helpers_h
#define _fs_helpers_h

#ifdef __cplusplus
extern "C" {
#endif

char *
fs_helpers_join(const char *path_sep, const char *path, const char *name);

char *
fs_helpers_basename(const char *path_sep, const char *path);

#ifdef __cplusplus
}
#endif

#endif

