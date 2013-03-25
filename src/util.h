#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>
#include <stddef.h>

struct _ll {
  void *elt;
  void *next;
};

typedef struct _ll *linked_list_t;
typedef void (*linked_list_elt_handler_t)(void *);
#define LINKED_LIST_FOR(type, elt_, ll) for (type *elt_ = ll ? ll->elt : NULL; elt_; ll = ll->next, elt_ = ll ? ll->elt : NULL)
#define LINKED_LIST_INITIALIZER NULL

linked_list_t
linked_list_prepend(linked_list_t, void *elt);

linked_list_t
linked_list_next(linked_list_t);

void
linked_list_free(linked_list_t, linked_list_elt_handler_t);

size_t
strnlen(const char *s, size_t maxlen);
const char *
skip_ws(const char *str);

#define EASY_ALLOC(type, name) type *name = malloc(sizeof(*name)); do { if (!name) { abort();} } while (false)


#endif /* UTIL_H */
