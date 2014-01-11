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

#include <stdarg.h>
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

PURE_FUNCTION int
ascii_strncasecmp(const char *a, const char *b, size_t n) {
  int ret;
  size_t i = 0;
  for (; (a[i] != '\0' || b[i] != '\0') && i < n; ++i) {
    ret = ascii_to_lower(a[i]) - ascii_to_lower(b[i]);
    if (ret) {
      return ret;
    }
  }

  if (i == n) {
    return 0;
  }

  return ascii_to_lower(a[i]) - ascii_to_lower(b[i]);
}

PURE_FUNCTION bool
str_case_startswith(const char *a, const char *b) {
  size_t len_a = strlen(a);
  size_t len_b = strlen(b);
  if (len_a < len_b) {
    return false;
  }

  assert_ascii_locale();

  return !ascii_strncasecmp(a, b, len_b);
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
davfuse_util_strdup(const char *s) {
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

char *
super_strcat(const char *first, ...) {
  va_list ap;

  /* first compute the necessary length */
  size_t required_size = 0;
  va_start(ap, first);
  const char *next = first;
  while (next) {
    required_size += strlen(next);
    next = va_arg(ap, const char *);
  }
  va_end(ap);

  char *toret = malloc(required_size + 1);
  if (!toret) {
    return NULL;
  }

  /* now copy the memory */
  size_t offset = 0;
  va_start(ap, first);
  const char *next_add = first;
  while (next_add) {
    size_t adding = strlen(next_add);
    memcpy(toret + offset, next_add, adding);
    offset += adding;
    next_add = va_arg(ap, const char *);
  }
  va_end(ap);

  toret[offset] = '\0';

  return toret;
}

char *
davfuse_util_asprintf(const char *format, ...) {
  va_list ap;

  va_start(ap, format);
#if defined(_MSC_VER) || defined(__MSVCRT_VERSION__)
  int len = _vscprintf(format, ap);
#else
  int len = vsnprintf(0, 0, format, ap);
#endif
  va_end( ap );

  char* p = malloc(len + 1);
  if (!p) return NULL;

  va_start(ap, format);
  int len2 = vsnprintf(p, len + 1, format, ap);
  va_end(ap);

  if (len2 < 0) {
    free(p);
    return NULL;
  }

  return p;
}
