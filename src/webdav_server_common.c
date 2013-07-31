#define _ISOC99_SOURCE

#include "http_helpers.h"
#include "util.h"
#include "_webdav_server_private_types.h"

#include "webdav_server_common.h"

WebdavProperty *
create_webdav_property(const char *element_name, const char *ns_href) {
  EASY_ALLOC(WebdavProperty, elt);

  elt->element_name = strdup_x(element_name);
  elt->ns_href = strdup_x(ns_href);

  return elt;
}

void
free_webdav_property(WebdavProperty *wp) {
  free(wp->element_name);
  free(wp->ns_href);
  free(wp);
}

WebdavProppatchDirective *
create_webdav_proppatch_directive(webdav_proppatch_directive_type_t type,
                                  const char *name,
                                  const char *ns_href,
                                  const char *value) {
  char *name_dup = NULL;
  char *ns_href_dup = NULL;
  char *value_dup = NULL;
  WebdavProppatchDirective *directive = NULL;

  /* assert valid values */
  assert(type == WEBDAV_PROPPATCH_DIRECTIVE_SET || !value);

  name_dup = strdup_x(name);
  if (!name_dup) {
    goto error;
  }

  ns_href_dup = strdup_x(ns_href);
  if (!ns_href_dup) {
    goto error;
  }

  if (value) {
    value_dup = strdup_x(value);
    if (!value_dup) {
      goto error;
    }
  }

  directive = malloc(sizeof(*directive));
  if (!directive) {
    goto error;
  }

  *directive = (WebdavProppatchDirective) {
    .type = type,
    .name = name_dup,
    .ns_href = ns_href_dup,
    .value = value_dup,
  };


  if (false) {
  error:
    free(name_dup);
    free(ns_href_dup);
    free(value_dup);
    free(directive);
  }

  return directive;
}

void
free_webdav_proppatch_directive(WebdavProppatchDirective *wp) {
  free(wp->name);
  free(wp->ns_href);
  free(wp->value);
  free(wp);
}

char *
uri_from_path(struct handler_context *hc, const char *path) {
  /* TODO: urlencode `path` */
  assert(str_startswith(path, "/"));
  assert(str_equals(path, "/") || !str_endswith(path, "/"));

  char *encoded_path = encode_urlpath(path, strlen(path));

  const char *request_uri = hc->rhs.uri;

  /* NB: we should always be generating urls for paths
     that are descendants of the request uri */

  char *prefix = hc->serv->public_prefix;
  char *real_uri;
  if (str_startswith(request_uri, "/")) {
    /* request uri was in relative format, generate a relative uri */
    char *slashslash = strstr(hc->serv->public_prefix, "//");
    prefix = strchr(slashslash + 2, '/');
  }

  size_t prefix_len = strlen(prefix);
  size_t path_len = strlen(encoded_path);

  /* make extra space for a trailing space */
  real_uri = malloc(prefix_len - 1 + path_len + 1 + 1);
  if (!real_uri) {
    goto done;
  }

  memcpy(real_uri, prefix, prefix_len - 1);
  memcpy(real_uri + prefix_len - 1, encoded_path, path_len);
  real_uri[prefix_len - 1 + path_len] = '/';
  real_uri[prefix_len - 1 + path_len + 1] = '\0';

  if (!str_equals(request_uri, real_uri)) {
    real_uri[prefix_len - 1 + path_len] = '\0';
  }

  if (false) {
    /* if (false) for now, copy/move might need to transform a path
       that's not a child of the request uri */
    /* 8.3 URL Handling, RFC 4918 */
    assert(str_startswith(real_uri, request_uri));
  }

 done:
  free(encoded_path);

  return real_uri;
}
