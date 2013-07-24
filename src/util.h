#ifndef UTIL_H
#define UTIL_H

#include <errno.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "c_util.h"
#include "events.h"
#include "logging.h"

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

PURE_FUNCTION bool
str_endswith(const char *a, const char *b);

PURE_FUNCTION char *
strdup_x(const char *s);

PURE_FUNCTION char *
strndup_x(const char *s, size_t n);

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

HEADER_FUNCTION DEFINE_MIN(size_t);

HEADER_FUNCTION void
ASSERT_NOT_NULL(void *foo) {
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
  Callback *cbud = malloc(sizeof(*cbud));
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

#endif /* UTIL_H */

