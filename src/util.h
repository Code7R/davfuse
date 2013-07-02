#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "c_util.h"

struct _ll {
  void *elt;
  struct _ll *next;
};

typedef struct _ll *linked_list_t;
typedef void (*linked_list_elt_handler_t)(void *);
typedef void (*linked_list_elt_handler_ud_t)(void *, void *);
#define __APP(x, y) x ## y
#define _APP(x, y) __APP(x, y)
#define LINKED_LIST_FOR(type, elt_, ll) linked_list_t _APP(__ll2,__LINE__) = (ll); for (type *elt_ = _APP(__ll2,__LINE__) ? _APP(__ll2,__LINE__)->elt : NULL; elt_; _APP(__ll2,__LINE__) = _APP(__ll2,__LINE__)->next, elt_ = _APP(__ll2,__LINE__) ? _APP(__ll2,__LINE__)->elt : NULL)
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

size_t
strnlen(const char *s, size_t maxlen);

const char *
skip_ws(const char *str);

PURE_FUNCTION bool
str_startswith(const char *a, const char *b);

HEADER_FUNCTION PURE_FUNCTION bool
str_equals(const char *a, const char *b) {
  return !strcmp(a, b);
}

HEADER_FUNCTION PURE_FUNCTION bool
str_case_equals(const char *a, const char *b) {
  return !strcasecmp(a, b);
}

#define DEFINE_MIN(type) \
  type min_##type(type a, type b) {		\
    return a < b ? a : b;			\
  }

#define EASY_ALLOC(type, name) type *name = malloc(sizeof(*name)); do { if (!name) { abort();} } while (false)

#endif /* UTIL_H */
