/*
  davfuse: FUSE file systems as WebDAV servers
  Copyright (C) 2012, 2013 Rian Hunter <rian@alum.mit.edu>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation, either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#ifndef UTIL_H
#define UTIL_H

#include <errno.h>

#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "c_util.h"
#include "events.h"
#include "logging.h"

#ifdef __cplusplus
#ifndef SIZE_MAX
#define SIZE_MAX ((size_t) -1)
#define __DEFINED_SIZE_MAX
#endif

extern "C" {
#endif

struct _ll {
  void *elt;
  struct _ll *next;
};

typedef struct _ll *linked_list_t;
typedef void (*linked_list_elt_handler_t)(void *);
typedef void (*linked_list_elt_handler_ud_t)(void *, void *);
#define __APP(x, y) x ## y
#define _APP(x, y) __APP(x, y)
#define LINKED_LIST_FOR(type, elt_, ll) \
  linked_list_t _APP(__ll2,__LINE__) = (ll);\
  for (type *elt_ = (type *) (_APP(__ll2,__LINE__) ? _APP(__ll2,__LINE__)->elt : NULL);\
       elt_;\
       _APP(__ll2,__LINE__) = _APP(__ll2,__LINE__)->next,\
         elt_ = (type *) (_APP(__ll2,__LINE__) ? _APP(__ll2,__LINE__)->elt : NULL))
#define LINKED_LIST_INITIALIZER NULL

linked_list_t
linked_list_prepend(linked_list_t, void *elt);

void
linked_list_free(linked_list_t, linked_list_elt_handler_t);

void
linked_list_free_ud(linked_list_t, linked_list_elt_handler_ud_t, void *);

linked_list_t
linked_list_popleft(linked_list_t, void **elt);

void *
linked_list_peekleft(linked_list_t);

void *
linked_list_pop_link(linked_list_t *llp);

PURE_FUNCTION size_t
strnlen(const char *s, size_t maxlen);

const char *
skip_ws(const char *str);

PURE_FUNCTION bool
str_startswith(const char *a, const char *b);

PURE_FUNCTION bool
str_case_startswith(const char *a, const char *b);

PURE_FUNCTION bool
str_endswith(const char *a, const char *b);

PURE_FUNCTION char *
davfuse_util_strdup(const char *s);

PURE_FUNCTION char *
strndup_x(const char *s, size_t n);

HEADER_FUNCTION CONST_FUNCTION char
ascii_to_lower(char a) {
  enum {
    ASCII_UPPER_CASE_LOWER_BOUND=65,
    ASCII_UPPER_CASE_UPPER_BOUND=90,
    ASCII_UPPER_CASE_LOWER_OFFSET=32,
  };
  return a + ((ASCII_UPPER_CASE_LOWER_BOUND <= a &&
               a <= ASCII_UPPER_CASE_UPPER_BOUND) ?
              ASCII_UPPER_CASE_LOWER_OFFSET :
              0);
}

PURE_FUNCTION int
ascii_strncasecmp(const char *a, const char *b, size_t n);

HEADER_FUNCTION PURE_FUNCTION int
ascii_strcasecmp(const char *a, const char *b) {
  return ascii_strncasecmp(a, b, SIZE_MAX);
}

HEADER_FUNCTION PURE_FUNCTION bool
ascii_strcaseequal(const char *a, const char *b) {
  return !ascii_strcasecmp(a, b);
}

HEADER_FUNCTION void
assert_ascii_locale(void) {
  enum {
    ASCII_SPACE=32,
    ASCII_0=48,
  };
  /* make sure the locale is ASCII */
  assert(isspace(ASCII_SPACE) && isdigit(ASCII_0));
}

HEADER_FUNCTION PURE_FUNCTION int
strcasecmp_x(const char *a, const char *b) {
  assert_ascii_locale();
  return ascii_strcasecmp(a, b);
}

HEADER_FUNCTION PURE_FUNCTION bool
str_equals(const char *a, const char *b) {
  return !strcmp(a, b);
}

HEADER_FUNCTION PURE_FUNCTION bool
str_case_equals(const char *a, const char *b) {
  return !strcasecmp_x(a, b);
}

#define DEFINE_MIN(type) \
  type CONST_FUNCTION min_##type(type a, type b) {      \
    return a < b ? a : b;                               \
  }

#define EASY_ALLOC(type, name) type *name = malloc(sizeof(*name)); do { if (!name) { abort();} } while (false)

HEADER_FUNCTION DEFINE_MIN(size_t);

HEADER_FUNCTION void
ASSERT_NOT_NULL(const void *foo) {
  if (!foo) {
    log_critical("Illegal null value");
    abort();
  }
}

HEADER_FUNCTION void
ASSERT_TRUE(bool foo) {
  if (!foo) {
    log_critical("Illegal false value");
    abort();
  }
}

/* TODO: make this varargs */
HEADER_FUNCTION void
ASSERT_TRUE_MSG(bool foo, const char *msg) {
  if (!foo) {
    log_critical("%s", msg);
    abort();
  }
}


HEADER_FUNCTION bool
all_null(const void *buf, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    if (((char *) buf)[i]) {
      return false;
    }
  }

  return true;
}

HEADER_FUNCTION void *
malloc_or_abort(size_t n) {
  int saved_errno = errno;
  void *ret = malloc(n);
  ASSERT_NOT_NULL(ret);
  errno = saved_errno;
  return ret;
}

typedef struct {
  event_handler_t cb;
  void *ud;
} Callback;

HEADER_FUNCTION Callback *
callback_construct(event_handler_t cb, void *ud) {
  Callback *cbud = (Callback *) malloc(sizeof(*cbud));
  if (!cbud) {
    return NULL;
  }

  *cbud = (Callback) {.cb = cb, .ud = ud};

  return cbud;
}

HEADER_FUNCTION void
callback_deconstruct(Callback *cbud,
                     event_handler_t *cb, void **ud) {
  *cb = cbud->cb;
  *ud = cbud->ud;
  free(cbud);
}

char *
super_strcat(const char *first, ...);

char *
davfuse_util_asprintf(const char *format, ...);

#ifdef __cplusplus
}

#ifdef __DEFINED_SIZE_MAX
#undef __DEFINED_SIZE_MAX
#undef SIZE_MAX
#endif

#endif

#endif /* UTIL_H */
