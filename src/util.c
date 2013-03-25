#include <stddef.h>
#include <stdlib.h>

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
