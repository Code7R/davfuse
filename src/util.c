#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "c_util.h"
#include "util.h"

size_t
strnlen(const char *s, size_t maxlen) {
  size_t the_size;
  for (the_size = 0; the_size < maxlen && s[the_size] != '\0'; ++the_size) {
  }
  return the_size;
}

const char *
skip_ws(const char *str) {
  size_t i = 0;
  for (; str[i] == ' '; ++i);
  return &str[i];
}

linked_list_t
linked_list_prepend(linked_list_t ll, void *elt) {
  linked_list_t new = malloc(sizeof(*new));
  /* this is a very simple interface */
  if (!new) { abort(); };
  new->next = ll;
  new->elt = elt;
  return new;
}

void
linked_list_free(linked_list_t ll, linked_list_elt_handler_t handle) {
  while (ll) {
    if (handle) {
      handle(ll->elt);
    }

    linked_list_t old = ll;
    ll = old->next;

    free(old);
  }
}

void
linked_list_free_ud(linked_list_t ll, linked_list_elt_handler_ud_t handle, void *ud) {
  while (ll) {
    if (handle) {
      handle(ll->elt, ud);
    }

    linked_list_t old = ll;
    ll = old->next;

    free(old);
  }
}

linked_list_t
linked_list_popleft(linked_list_t ll, void **elt) {
  if (!ll) {
    if (elt) {
      *elt = NULL;
    }
    return NULL;
  }

  if (elt) {
    *elt = ll->elt;
  }
  linked_list_t next = ll->next;
  free(ll);

  return next;
}

void *
linked_list_peekleft(linked_list_t ll) {
  if (!ll) {
    return NULL;
  }
  return ll->elt;
}

bool PURE_FUNCTION
str_startswith(const char *a, const char *b) {
  size_t len_a = strlen(a);
  size_t len_b = strlen(b);
  if (len_a < len_b) {
    return false;
  }

  return !memcmp(a, b, len_b);
}
