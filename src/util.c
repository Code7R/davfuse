#include <stddef.h>

#include "util.h"

size_t
strnlen(const char *s, size_t maxlen) {
  size_t the_size;
  for (the_size = 0; the_size < maxlen && s[the_size] != '\0'; ++the_size) {
  }
  return the_size;
}
