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
  ASSERT_NOT_NULL(new);
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

void *
linked_list_pop_link(linked_list_t *llp) {
  linked_list_t cur_link = *llp;

  *llp = cur_link->next;

  void *elt = cur_link->elt;

  free(cur_link);

  return elt;
}

PURE_FUNCTION bool
str_startswith(const char *a, const char *b) {
  size_t len_a = strlen(a);
  size_t len_b = strlen(b);
  if (len_a < len_b) {
    return false;
  }

  return !memcmp(a, b, len_b);
}

PURE_FUNCTION bool
str_endswith(const char *a, const char *b) {
  size_t len_a = strlen(a);
  size_t len_b = strlen(b);
  if (len_a < len_b) {
    return false;
  }

  return !memcmp(a + len_a - len_b, b, len_b);
}

PURE_FUNCTION char *
strdup_x(const char *s) {
  size_t len = strlen(s);
  char *toret = malloc(len + 1);
  if (!toret) {
    return NULL;
  }
  return memcpy(toret, s, len + 1);
}

PURE_FUNCTION char *
strndup_x(const char *s, size_t n) {
  size_t len = min_size_t(strlen(s), n);
  char *toret = malloc(len + 1);
  if (!toret) {
    return NULL;
  }
  memcpy(toret, s, len);
  toret[len] = '\0';
  return toret;
}
