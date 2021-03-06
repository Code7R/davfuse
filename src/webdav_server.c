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

/*
  An async webdav server
*/
#define _ISOC99_SOURCE

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "events.h"
#include "event_loop.h"
#include "http_helpers.h"
#include "http_server.h"
#include "logging.h"
#include "sockets.h"
#include "uptime.h"
#include "uthread.h"
#include "util.h"
#include "webdav_backend.h"
#include "webdav_server_xml.h"
#include "_webdav_server_types.h"
#include "_webdav_server_private_types.h"

#define _IS_WEBDAV_SERVER_C
#include "webdav_server.h"
#undef _IS_WEBDAV_SERVER_C

static const char *const WEBDAV_SERVER_QUIT_URL = "/____quit_handler____";
static const char *const WEBDAV_SERVER_DISCONNECT_URL = "/____disconnect_handler____";

static const char *const WEBDAV_HEADER_DEPTH = "Depth";
static const char *const WEBDAV_HEADER_DESTINATION = "Destination";
static const char *const WEBDAV_HEADER_IF = "If";
static const char *const WEBDAV_HEADER_LOCK_TOKEN = "Lock-Token";
static const char *const WEBDAV_HEADER_OVERWRITE = "Overwrite";
static const char *const WEBDAV_HEADER_TIMEOUT = "Timeout";

static EVENT_HANDLER_DECLARE(handle_request);
static EVENT_HANDLER_DECLARE(handle_copy_request);
static EVENT_HANDLER_DECLARE(handle_delete_request);
static EVENT_HANDLER_DECLARE(handle_get_request);
static EVENT_HANDLER_DECLARE(handle_lock_request);
static EVENT_HANDLER_DECLARE(handle_mkcol_request);
static EVENT_HANDLER_DECLARE(handle_options_request);
static EVENT_HANDLER_DECLARE(handle_post_request);
static EVENT_HANDLER_DECLARE(handle_propfind_request);
static EVENT_HANDLER_DECLARE(handle_proppatch_request);
static EVENT_HANDLER_DECLARE(handle_put_request);
static EVENT_HANDLER_DECLARE(handle_unlock_request);

static char *
path_from_request_uri(struct handler_context *hc, const char *uri) {
  const char *abs_path_start;

  if (!str_startswith(uri, "/")) {
    /* we don't handle non-relative URIs */
    http_request_log_info(hc->rh,
                          "Invalid request path (\"%s\")! "
                          "we currently only support relative paths",
                          uri);
    return NULL;
  }

  size_t internal_root_len = strlen(hc->serv->internal_root);

  abs_path_start = uri;

  if (!str_equals(hc->serv->internal_root, "/")) {
    if (str_equals(abs_path_start, hc->serv->internal_root)) {
      return davfuse_util_strdup("/");
    }

    /* now `abs_path_start` must start with the internal root,
       otherwise this isn't a mapped resource */
    if (!str_startswith(abs_path_start, hc->serv->internal_root) ||
        abs_path_start[internal_root_len] != '/') {
      http_request_log_info(hc->rh,
                            "Invalid request path (\"%s\")! "
                            "doesn't start with internal root: (\"%s\")",
                            abs_path_start, hc->serv->internal_root);
      return NULL;
    }
    abs_path_start += internal_root_len;
  }

  /* okay now `abs_path_start` should point to a URI without the
     scheme/authority, now strip out the query part */

  const char *abs_path_end = strchr(abs_path_start, '?');
  if (!abs_path_end) {
    abs_path_end = abs_path_start + strlen(abs_path_start);
  }

  /* if uri ends with '/' shave it off */
  if (abs_path_end[-1] == '/' && abs_path_end - abs_path_start != 1) {
    abs_path_end -= 1;
  }

  /* path could be something like /hai%20;there/sup, this fixes that */
  return decode_urlpath(abs_path_start, abs_path_end - abs_path_start);
}

static char *
path_from_public_uri(struct handler_context *hc, const char *uri) {
  if (!str_startswith(uri, hc->serv->public_uri_root)) {
    return NULL;
  }

  const char *const relative_uri =
    uri + (strlen(hc->serv->public_uri_root) - 1);
  return path_from_request_uri(hc, relative_uri);
}


static char *
public_uri_from_path(struct handler_context *hc, const char *path, bool is_collection) {
  UNUSED(is_collection);
  assert(str_startswith(path, "/"));
  assert(str_equals(path, "/") || !str_endswith(path, "/"));

  char *const encoded_path = encode_urlpath(path, strlen(path));

  const bool internal_root_is_root = str_equals(hc->serv->internal_root, "/");
  const bool path_is_root = str_equals(path, "/");

  char *const real_uri = super_strcat(hc->serv->public_uri_root,
                                      hc->serv->internal_root + 1,
                                      internal_root_is_root
                                      ? ""
                                      : (path_is_root
                                         ? ""
                                         : "/"),
                                      encoded_path + 1,
                                      (!internal_root_is_root || !path_is_root) && is_collection
                                      ? "/"
                                      : "",
                                      NULL);
  if (!real_uri) {
    goto done;
  }

 done:
  free(encoded_path);

  return real_uri;
}

static bool
is_relative_uri_parent(const char *potential_parent_uri,
                       const char *potential_child_uri) {
  /* we don't support this yet */
  ASSERT_TRUE(!strchr(potential_parent_uri, '?'));
  ASSERT_TRUE(!strchr(potential_child_uri, '?'));
  size_t parent_len = strlen(potential_parent_uri);
  return (!str_equals(potential_parent_uri, potential_child_uri) &&
          str_startswith(potential_child_uri, potential_parent_uri) &&
          (potential_parent_uri[parent_len - 1] == '/' ||
           potential_child_uri[parent_len] == '/'));
}

#define UTIL_WEBDAV_BACKEND_SINGLE_PROPFIND_DONE_EVENT GENERIC_EVENT

typedef struct {
  webdav_error_t error;
  struct webdav_propfind_entry entry;
} UtilWebdavBackendSinglePropfindDoneEvent;

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  webdav_backend_t backend;
  const char *relative_uri;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
  UtilWebdavBackendSinglePropfindDoneEvent ev;
} UtilWebdavBackendSinglePropfindCtx;

static
UTHR_DEFINE(_util_webdav_backend_single_propfind_uthr) {
  UTHR_HEADER(UtilWebdavBackendSinglePropfindCtx, ctx);

  UTHR_YIELD(ctx,
             webdav_backend_propfind(ctx->backend,
                                     ctx->relative_uri,
                                     DEPTH_0, WEBDAV_PROPFIND_ALLPROP,
                                     _util_webdav_backend_single_propfind_uthr,
                                     ctx));
  UTHR_RECEIVE_EVENT(WEBDAV_PROPFIND_DONE_EVENT,
                     WebdavPropfindDoneEvent, propfind_done_ev);
  if (propfind_done_ev->error) {
    ctx->ev.error = propfind_done_ev->error;
    goto done;
  }

  struct webdav_propfind_entry *const ent = linked_list_peekleft(propfind_done_ev->entries);
  ctx->ev.error = WEBDAV_ERROR_NONE;
  ctx->ev.entry = *ent;

  linked_list_free(propfind_done_ev->entries,
                   (linked_list_elt_handler_t) webdav_destroy_propfind_entry);

 done:
  UTHR_RETURN(ctx,
              ctx->cb(UTIL_WEBDAV_BACKEND_SINGLE_PROPFIND_DONE_EVENT,
                      &ctx->ev, ctx->cb_ud));

  UTHR_FOOTER();
}

static void
util_webdav_backend_single_propfind(webdav_backend_t backend,
                                    const char *relative_uri,
                                    event_handler_t cb, void *cb_ud) {
  UTHR_CALL4(_util_webdav_backend_single_propfind_uthr,
             UtilWebdavBackendSinglePropfindCtx,
             .backend = backend,
             .relative_uri = relative_uri,
             .cb = cb,
             .cb_ud = cb_ud);
}

#define REQUEST_URI_IS_COLLECTION_DONE_EVENT GENERIC_EVENT

typedef struct {
  webdav_error_t error;
  bool is_collection;
} RequestUriIsCollectionDoneEvent;

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  struct handler_context *hc;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
  char *path;
  RequestUriIsCollectionDoneEvent ev;
} RequestUriIsCollectionCtx;

static
UTHR_DEFINE(_request_uri_is_collection_uthr) {
  UTHR_HEADER(RequestUriIsCollectionCtx, ctx);

  ctx->path = path_from_request_uri(ctx->hc, ctx->hc->rhs.uri);
  if (!ctx->path) {
    http_request_log_info(ctx->hc->rh, "Couldn't make file path from \"%s\"", ctx->hc->rhs.uri);
    goto done;
  }

  UTHR_YIELD(ctx,
             util_webdav_backend_single_propfind(ctx->hc->serv->fs, ctx->path,
                                                 _request_uri_is_collection_uthr, ctx));
  UTHR_RECEIVE_EVENT(UTIL_WEBDAV_BACKEND_SINGLE_PROPFIND_DONE_EVENT,
                     UtilWebdavBackendSinglePropfindDoneEvent,
                     propfind_done_ev);
  if (propfind_done_ev->error) {
    ctx->ev.error = propfind_done_ev->error;
    goto done;
  }

  ctx->ev.error = WEBDAV_ERROR_NONE;
  ctx->ev.is_collection = propfind_done_ev->entry.is_collection;

 done:
  free(ctx->path);
  UTHR_RETURN(ctx,
              ctx->cb(REQUEST_URI_IS_COLLECTION_DONE_EVENT,
                      &ctx->ev, ctx->cb_ud));

  UTHR_FOOTER();
}


static void
request_uri_is_collection(struct handler_context *hc,
                          event_handler_t cb, void *cb_ud) {
  UTHR_CALL3(_request_uri_is_collection_uthr, RequestUriIsCollectionCtx,
             .hc = hc,
             .cb = cb,
             .cb_ud = cb_ud);
}

static webdav_depth_t
webdav_get_depth(const HTTPRequestHeaders *rhs) {
  webdav_depth_t depth;

  const char *depth_str = http_get_header_value(rhs, WEBDAV_HEADER_DEPTH);
  if (!depth_str || str_case_equals(depth_str, "infinity")) {
    depth = DEPTH_INF;
  }
  else {
    long ret = strtol(depth_str, NULL, 10);
    if ((ret == 0 && errno == EINVAL) ||
        (ret != 0 && ret != 1)) {
      depth = DEPTH_INVALID;
      log_info("Client sent up bad depth header: %s", depth_str);
    }
    else {
      depth = ret ? DEPTH_1 : DEPTH_0;
    }
  }

  return depth;
}

static webdav_timeout_t
webdav_get_timeout(const HTTPRequestHeaders *rhs) {
  UNUSED(rhs);
  UNUSED(WEBDAV_HEADER_TIMEOUT);
  /* just lock for 60 seconds for now,
     we don't have to honor timeout headers */
  /* TODO: fix this */
  return 60;
}

enum {
  ASCII_SPACE = 32,
  ASCII_HT = 9,
  ASCII_LEFT_PAREN = 40,
  ASCII_RIGHT_PAREN = 41,
  ASCII_SLASH = 47,
  ASCII_LEFT_BRACKET = 60,
  ASCII_RIGHT_BRACKET = 62,
};

static bool
is_bnf_lws(int c) {
  return (c == ASCII_SPACE || c == ASCII_HT);
}

static int
skip_bnf_lws(const char *str, int i) {
  for (; is_bnf_lws(str[i]); ++i);
  return i;
}

typedef enum {
  IF_LOCK_TOKEN_ERR_SUCCESS,
  IF_LOCK_TOKEN_ERR_DOESNT_EXIST,
  IF_LOCK_TOKEN_ERR_BAD_PARSE,
  IF_LOCK_TOKEN_ERR_INTERNAL,
} if_lock_token_err_t;

static if_lock_token_err_t
webdav_get_if_lock_token(struct handler_context *hc, char **resource_tag, char **lock_token) {
  if_lock_token_err_t toret;
  *resource_tag = NULL;
  *lock_token = NULL;

  const HTTPRequestHeaders *const rhs = &hc->rhs;

  const char *if_header = http_get_header_value(rhs, WEBDAV_HEADER_IF);
  if (!if_header) {
    toret = IF_LOCK_TOKEN_ERR_DOESNT_EXIST;
    goto error;
  }

  /* we do the simplest if header parsing right now,
     if it doesn't conform, then 500 */
  int i = 0;

  i = skip_bnf_lws(if_header, i);

  /* attempt to parse out resource tag */
  if (if_header[i] == ASCII_LEFT_BRACKET) {
    i++;
    const char *end_of_uri = strchr(if_header + i, ASCII_RIGHT_BRACKET);
    if (!end_of_uri) {
      toret = IF_LOCK_TOKEN_ERR_BAD_PARSE;
      goto error;
    }

    size_t len_of_uri = end_of_uri - (if_header + i);
    *resource_tag =
      strndup_x(if_header + i, len_of_uri);

    if (!*resource_tag) {
      toret = IF_LOCK_TOKEN_ERR_INTERNAL;
      goto error;
    }

    /* skip resource tag */
    i += len_of_uri + 1;
    i = skip_bnf_lws(if_header, i);
  }
  else {
    /* no resource tag passed in, this lock token is related to the method uri */
    if (str_startswith(rhs->uri, "/")) {
      /* if this was relative uri, make sure to make it into a public uri */
      *resource_tag = super_strcat(hc->serv->public_uri_root,
                                   &rhs->uri[1], NULL);
    }
    else {
      *resource_tag = davfuse_util_strdup(rhs->uri);
    }
  }

  /* get left paren */
  if (if_header[i++] != ASCII_LEFT_PAREN) {
    toret = IF_LOCK_TOKEN_ERR_BAD_PARSE;
    goto error;
  }

  i = skip_bnf_lws(if_header, i);

  /* get left bracket */
  if (if_header[i++] != ASCII_LEFT_BRACKET) {
    toret = IF_LOCK_TOKEN_ERR_BAD_PARSE;
    goto error;
  }

  /* read uri */
  const char *end_of_uri = strchr(if_header + i, ASCII_RIGHT_BRACKET);
  if (!end_of_uri) {
    toret = IF_LOCK_TOKEN_ERR_BAD_PARSE;
    goto error;
  }

  *lock_token =
    strndup_x(if_header + i, end_of_uri - (if_header + i));
  if (!*lock_token) {
    toret = IF_LOCK_TOKEN_ERR_INTERNAL;
    goto error;
  }

  if (false) {
  error:
    free(*resource_tag);
    *resource_tag = NULL;
    free(*lock_token);
    *lock_token = NULL;
  }
  else {
    toret = IF_LOCK_TOKEN_ERR_SUCCESS;
  }

  return toret;
}

static PURE_FUNCTION bool
is_parent_path(const char *potential_parent, const char *potential_child) {
  assert(potential_parent[strlen(potential_parent) - 1] != '/');
  assert(potential_child[strlen(potential_child) - 1] != '/');
  return (str_startswith(potential_child, potential_parent) &&
          potential_child[strlen(potential_parent)] == '/');
}

static void
free_webdav_lock_descriptor(void *ld) {
  WebdavLockDescriptor *wdld = ld;
  free(wdld->path);
  owner_xml_free(wdld->owner_xml);
  free(wdld->lock_token);
  free(ld);
}

static bool
perform_write_lock(struct webdav_server *ws,
                   const char *file_path,
                   bool is_collection,
                   webdav_timeout_t timeout_in_seconds,
                   webdav_depth_t depth,
                   bool is_exclusive,
                   owner_xml_t owner_xml,
                   bool *is_locked,
                   const char **lock_token,
                   const char **status_path,
                   bool *status_path_is_collection) {
  /* go through lock list and see if this path (or any descendants if depth != 0)
     have an incompatible lock
     if so then set that path as the status_path and return *is_locked = true
  */
  LINKED_LIST_FOR (WebdavLockDescriptor, elt, ws->locks) {
    bool parent_locks_us = false;
    if ((str_equals(elt->path, file_path) ||
         (depth == DEPTH_INF && is_parent_path(file_path, elt->path)) ||
         (parent_locks_us = (elt->depth == DEPTH_INF && is_parent_path(elt->path, file_path)))) &&
        (is_exclusive || elt->is_exclusive)) {
      *is_locked = true;
      *status_path = parent_locks_us ? file_path : elt->path;
      *status_path_is_collection = parent_locks_us ? is_collection : elt->is_collection;
      /* if the davfuse_util_strdup failed then we return false */
      return *status_path;
    }
  }

  /* generate a lock token */
  UptimeTimespec uptime;
  bool success_uptime = uptime_time(&uptime);
  if (!success_uptime) return false;

  char s_lock_token[256];
  int len = snprintf(s_lock_token, sizeof(s_lock_token), "x-this-lock-token:///%lu.%lu",
                     (long unsigned) uptime.seconds, (long unsigned) uptime.nanoseconds);
  if (len < 0 || (size_t) len >= sizeof(s_lock_token)) {
    /* lock token string was too long */
    return false;
  }

  /* okay we can lock this path, just add it to the lock list */
  EASY_ALLOC(WebdavLockDescriptor, new_lock);

  *new_lock = (WebdavLockDescriptor) {
    .path = davfuse_util_strdup(file_path),
    .depth = depth,
    .is_exclusive = is_exclusive,
    .owner_xml = owner_xml_copy(owner_xml),
    .lock_token = davfuse_util_strdup(s_lock_token),
    .timeout_in_seconds = timeout_in_seconds,
    .is_collection = is_collection,
  };

  if (!new_lock->path ||
      !new_lock->owner_xml ||
      !new_lock->lock_token) {
    /* just die on ENOMEM */
    abort();
  }

  *lock_token = new_lock->lock_token;

  ws->locks = linked_list_prepend(ws->locks, new_lock);
  if (!ws->locks) {
    abort();
  }

  *is_locked = false;

  return true;
}

static bool
unlock_resource(struct webdav_server *ws,
                const char *file_path,
                const char *lock_token,
                bool *unlocked) {
  *unlocked = false;

  for (linked_list_t *llp = &ws->locks; *llp; llp = *llp ? &(*llp)->next : llp) {
    WebdavLockDescriptor *elt = (*llp)->elt;
    if (str_equals(elt->path, file_path) &&
        str_equals(elt->lock_token, lock_token)) {
      WebdavLockDescriptor *popped_elt = linked_list_pop_link(llp);
      free_webdav_lock_descriptor(popped_elt);
      *unlocked = true;
      break;
    }
  }

  return true;
}

static bool
unconditionally_unlock_resource_and_descendants(struct webdav_server *ws,
                                                const char *file_path) {
  for (linked_list_t *llp = &ws->locks; *llp; llp = *llp ? &(*llp)->next : llp) {
    WebdavLockDescriptor *elt = (*llp)->elt;
    if (str_equals(file_path, elt->path) ||
        is_parent_path(file_path, elt->path)) {
      WebdavLockDescriptor *popped_elt = linked_list_pop_link(llp);
      free_webdav_lock_descriptor(popped_elt);
    }
  }

  return true;
}

static bool
refresh_lock(struct webdav_server *ws,
             const char *file_path, const char *lock_token,
             webdav_timeout_t new_timeout,
             bool *refreshed,
             owner_xml_t *owner_xml, bool *is_exclusive,
             webdav_depth_t *depth) {
  *refreshed = false;

  LINKED_LIST_FOR (WebdavLockDescriptor, elt, ws->locks) {
    if (str_equals(elt->lock_token, lock_token) &&
        (str_equals(elt->path, file_path) ||
         is_parent_path(elt->path, file_path))) {
      /* we don't necessarily have to do this, but just do it for now */
      elt->timeout_in_seconds = new_timeout;
      *refreshed = true;
      *owner_xml = elt->owner_xml;
      *is_exclusive = elt->is_exclusive;
      *depth = elt->depth;
      break;
    }
  }

  return true;
}

static bool
is_resource_locked(struct webdav_server *ws,
                   const char *file_path,
                   bool *is_locked,
                   const char **locked_path,
                   const char **locked_lock_token,
                   bool *is_locked_path_collection) {
  *is_locked = false;

  LINKED_LIST_FOR (WebdavLockDescriptor, elt, ws->locks) {
    if (str_equals(elt->path, file_path) ||
        (elt->depth == DEPTH_INF &&
         is_parent_path(elt->path, file_path))) {
      *is_locked = true;
      if (locked_path) {
        *locked_path = elt->path;
      }
      if (locked_lock_token) {
        *locked_lock_token = elt->lock_token;
      }
      if (is_locked_path_collection) {
        *is_locked_path_collection = elt->is_collection;
      }
      break;
    }
  }

  return true;
}

static bool
are_any_descendants_locked(struct webdav_server *ws,
                           const char *file_path,
                           bool *is_descendant_locked,
                           const char **locked_descendant,
                           bool *locked_descendant_is_collection) {
  *is_descendant_locked = false;

  LINKED_LIST_FOR (WebdavLockDescriptor, elt, ws->locks) {
    if (is_parent_path(file_path, elt->path)) {
      *is_descendant_locked = true;
      *locked_descendant = elt->path;
      *locked_descendant_is_collection = elt->is_collection;
      break;
    }
  }

  return true;
}

static void
_can_modify_path(struct handler_context *hc,
                 if_lock_token_err_t if_lock_token_err,
                 const char *lock_resource_tag,
                 const char *lock_token,
                 const char *fpath,
                 http_status_code_t *status_code,
                 char **response_body,
                 size_t *response_body_len) {
  *status_code = HTTP_STATUS_CODE___INVALID;

  /* TODO: this logic is kind of weird,
     we should check if we were passed if tokens first
     i.e:
     WHEN NOT IF HEADER: check if path is locked
     WHEN IF HEADER: check if all tokens exist and are locked and path names match
  */

  /* check if the path is locked or is a descendant of a locked path
     (directly or indirectly locked) */
  const char *locked_path = NULL;
  const char *locked_lock_token = NULL;
  bool is_locked;
  /* NB: normally wouldn't have to set this but there
     is a bug in the GCC optimizer that doesn't realize that:
     is_locked => defined(path_is_collection)
  */
  bool path_is_collection = false;
  bool success_locked =
    is_resource_locked(hc->serv, fpath, &is_locked, &locked_path, &locked_lock_token, &path_is_collection);
  if (!success_locked) {
    *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    return;
  }

  assert(!is_locked || locked_path);
  assert(!is_locked || locked_lock_token);

  char *lock_token_fpath = NULL;
  if (if_lock_token_err == IF_LOCK_TOKEN_ERR_SUCCESS) {
    lock_token_fpath = path_from_public_uri(hc, lock_resource_tag);
  }

  if (is_locked &&
      (if_lock_token_err != IF_LOCK_TOKEN_ERR_SUCCESS ||
       !str_equals(lock_token_fpath, locked_path) ||
       !str_equals(locked_lock_token, lock_token))) {
    /* this is locked, fail */
    char *const public_uri = public_uri_from_path(hc, locked_path, path_is_collection);
    bool success_generate =
      generate_locked_response(public_uri,
                               status_code,
                               response_body,
                               response_body_len);
    free(public_uri);
    if (!success_generate) {
      *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    }
  }
  /* if the file wasn't locked but we were given a lock token */
  else if (!is_locked &&
           if_lock_token_err == IF_LOCK_TOKEN_ERR_SUCCESS) {
    *response_body = NULL;
    *response_body_len = 0;
    *status_code = HTTP_STATUS_CODE_PRECONDITION_FAILED;
  }

  free(lock_token_fpath);
}

static void
can_modify_path(struct handler_context *hc,
                const char *fpath,
                http_status_code_t *status_code,
                char **response_body,
                size_t *response_body_len) {
  char *lock_resource = NULL;
  char *lock_token = NULL;

  *status_code = HTTP_STATUS_CODE___INVALID;

  /* parse if header */
  /* TODO: associate each lock token with a resource URL */
  if_lock_token_err_t if_lock_token_err =
    webdav_get_if_lock_token(hc, &lock_resource, &lock_token);

  if (if_lock_token_err == IF_LOCK_TOKEN_ERR_INTERNAL) {
    *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  if (if_lock_token_err == IF_LOCK_TOKEN_ERR_BAD_PARSE) {
    *status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }

  _can_modify_path(hc, if_lock_token_err,
                   lock_resource,
                   lock_token,
                   fpath,
                   status_code,
                   response_body, response_body_len);

 done:
  free(lock_resource);
  free(lock_token);
}

static void
can_unlink_path(struct handler_context *hc,
                const char *fpath,
                http_status_code_t *status_code,
                char **response_body,
                size_t *response_body_len) {
  char *lock_resource = NULL;
  char *lock_token = NULL;

  *status_code = HTTP_STATUS_CODE___INVALID;

  /* parse if header */
  /* TODO: associate each lock token with a resource URL */
  if_lock_token_err_t if_lock_token_err =
    webdav_get_if_lock_token(hc, &lock_resource, &lock_token);

  if (if_lock_token_err == IF_LOCK_TOKEN_ERR_INTERNAL) {
    *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  if (if_lock_token_err == IF_LOCK_TOKEN_ERR_BAD_PARSE) {
    *status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }

  _can_modify_path(hc, if_lock_token_err,
                   lock_resource,
                   lock_token,
                   fpath,
                   status_code,
                   response_body, response_body_len);

  if (!*status_code) {
    /* if we haven't gotten a status code yet,
       then check if any descendant is locked */
    bool is_descendant_locked;
    const char *locked_descendant;
    bool locked_descendant_is_collection;
    bool success_child_locked =
      are_any_descendants_locked(hc->serv, fpath,
                                 &is_descendant_locked, &locked_descendant, &locked_descendant_is_collection);
    if (!success_child_locked) {
      *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
      goto done;
    }

    if (is_descendant_locked) {
      char *const public_uri = public_uri_from_path(hc, locked_descendant, locked_descendant_is_collection);
      ASSERT_NOT_NULL(public_uri);

      bool success_generate =
        generate_locked_descendant_response(locked_descendant,
                                            status_code,
                                            response_body,
                                            response_body_len);
      free(public_uri);

      if (!success_generate) {
        *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
      }
    }
  }

 done:
  free(lock_resource);
  free(lock_token);
}


static
UTHR_DEFINE(request_proc) {
  struct header_context *ctx = &((struct handler_context *) UTHR_USER_DATA())->header;

  UTHR_HEADER(struct handler_context, hc);

  const http_error_code_t err = http_request_force_connection_close(hc->rh);
  (void) err;
  assert(err == HTTP_SUCCESS);

  http_request_log_info(hc->rh, "New request!");

  /* read out headers */
  UTHR_YIELD(hc,
             http_request_read_headers(hc->rh,
                                       &hc->rhs,
                                       request_proc, hc));
  assert(UTHR_EVENT_TYPE() == HTTP_REQUEST_READ_HEADERS_DONE_EVENT);
  HTTPRequestReadHeadersDoneEvent *read_headers_ev = UTHR_EVENT();
  UNUSED(read_headers_ev);
  assert(read_headers_ev->request_handle == hc->rh);
  if (read_headers_ev->err != HTTP_SUCCESS) {
    http_request_log_info(hc->rh, "Reading headers failed: %s",
                          http_error_to_string(read_headers_ev->err));
    goto done;
  }

  /* potentially redirect based on directory */
  if (!str_endswith(hc->rhs.uri, "/")) {
    UTHR_YIELD(hc,
               request_uri_is_collection(hc, request_proc, hc));
    UTHR_RECEIVE_EVENT(REQUEST_URI_IS_COLLECTION_DONE_EVENT, RequestUriIsCollectionDoneEvent, is_collection_done_ev);

    if (!is_collection_done_ev->error &&
        is_collection_done_ev->is_collection) {
      /* it's a collection and it doesn't end in a slash,
         => redirect */
      bool success_init = http_response_init(&hc->resp);
      ASSERT_TRUE(success_init);

      bool success_set_moved_code =
        http_response_set_code(&hc->resp, HTTP_STATUS_CODE_MOVED_PERMANENTLY);
      ASSERT_TRUE(success_set_moved_code);

      bool success_set_location_header =
        http_response_add_header(&hc->resp, "Location", "%s/", hc->rhs.uri);
      ASSERT_TRUE(success_set_location_header);

      bool success_set_content_length_header =
        http_response_add_header(&hc->resp, HTTP_HEADER_CONTENT_LENGTH, "0");
      ASSERT_TRUE(success_set_content_length_header);

      UTHR_YIELD(hc,
                 http_request_write_headers(hc->rh, &hc->resp,
                                            request_proc, hc));
      goto done;
    }
  }

#ifndef NDEBUG
  /* handle quit message */
  if (str_equals(hc->rhs.uri, WEBDAV_SERVER_QUIT_URL)) {
    webdav_server_stop(hc->serv);
  }
  else if (str_equals(hc->rhs.uri, WEBDAV_SERVER_DISCONNECT_URL)) {
    webdav_server_disconnect_existing_clients(hc->serv);
  }
#endif

  /* check if path isn't in our namespace so we can return 404 */
  if (!is_relative_uri_parent(hc->rhs.uri, hc->serv->internal_root) &&
      !is_relative_uri_parent(hc->serv->internal_root, hc->rhs.uri) &&
      !str_equals(hc->serv->internal_root, hc->rhs.uri)) {
    UTHR_YIELD(hc,
               http_request_string_response(hc->rh,
                                            HTTP_STATUS_CODE_NOT_FOUND,
                                            "",
                                            request_proc, hc));
    goto done;
  }

  /* TODO: move to hash-based dispatch where each method
     maps to a different bucket
  */
  if (str_case_equals(hc->rhs.method, "COPY")) {
    ctx->handler = handle_copy_request;
    hc->sub.copy.is_move = false;
  }
  else if (str_case_equals(hc->rhs.method, "DELETE")) {
    ctx->handler = handle_delete_request;
  }
  else if (str_case_equals(hc->rhs.method, "GET")) {
    ctx->handler = handle_get_request;
  }
  else if (str_case_equals(hc->rhs.method, "LOCK")) {
    ctx->handler = handle_lock_request;
  }
  else if (str_case_equals(hc->rhs.method, "MKCOL")) {
    ctx->handler = handle_mkcol_request;
  }
  else if (str_case_equals(hc->rhs.method, "MOVE")) {
    /* move is essentially copy, then delete source */
    /* allows for servers to optimize as well */
    ctx->handler = handle_copy_request;
    hc->sub.copy.is_move = true;
  }
  else if (str_case_equals(hc->rhs.method, "OPTIONS")) {
    ctx->handler = handle_options_request;
  }
  else if (str_case_equals(hc->rhs.method, "POST")) {
    ctx->handler = handle_post_request;
  }
  else if (str_case_equals(hc->rhs.method, "PROPFIND")) {
    ctx->handler = handle_propfind_request;
  }
  else if (str_case_equals(hc->rhs.method, "PROPPATCH")) {
    ctx->handler = handle_proppatch_request;
  }
  else if (str_case_equals(hc->rhs.method, "PUT")) {
    ctx->handler = handle_put_request;
  }
  else if (str_case_equals(hc->rhs.method, "UNLOCK")) {
    ctx->handler = handle_unlock_request;
  }
  else {
    ctx->handler = NULL;
  }

  bool ret = http_response_init(&hc->resp);
  ASSERT_TRUE(ret);

  if (ctx->handler) {
    UTHR_YIELD(hc, ctx->handler(GENERIC_EVENT, NULL, hc));
  }
  else {
    UTHR_YIELD(hc,
               http_request_string_response(hc->rh,
                                            HTTP_STATUS_CODE_NOT_IMPLEMENTED, "Not Implemented",
                                            request_proc, hc));
  }

 done:
  http_request_log_info(hc->rh, "Request done!");

  http_request_end(hc->rh);

  UTHR_RETURN(hc, 0);

  UTHR_FOOTER();
}

static
EVENT_HANDLER_DEFINE(handle_copy_request, ev_type, ev, ud) {
  UNUSED(ev_type);
  UNUSED(ev);

  struct handler_context *hc = ud;
  struct copy_context *ctx = &hc->sub.copy;
  http_status_code_t status_code;

  CRBEGIN(ctx->pos);

#define HANDLE_ERROR(if_err, status_code_, ...) \
  do {                                          \
    if (if_err) {                               \
      http_request_log_debug(hc->rh, "copy failed: " __VA_ARGS__);       \
      status_code = status_code_;               \
      goto done;                                \
    }                                           \
  }                                             \
  while (false)

  ctx->response_body = NULL;
  ctx->response_body_len = 0;
  ctx->dst_relative_uri = NULL;

  ctx->src_relative_uri = path_from_request_uri(hc, hc->rhs.uri);
  HANDLE_ERROR(!ctx->src_relative_uri,
               HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR,
               "couldn't get source path");

  if (ctx->is_move) {
    /* check if the path we're moving is locked */
    can_unlink_path(hc, ctx->src_relative_uri,
                    &status_code,
                    &ctx->response_body,
                    &ctx->response_body_len);
    if (status_code) {
      goto done;
    }
  }

  /* destination */
  const char *destination_url = http_get_header_value(&hc->rhs, WEBDAV_HEADER_DESTINATION);
  HANDLE_ERROR(!destination_url, HTTP_STATUS_CODE_BAD_REQUEST,
               "request didn't have destination");

  /* destination file path */
  ctx->dst_relative_uri = path_from_public_uri(hc, destination_url);
  HANDLE_ERROR(!ctx->dst_relative_uri, HTTP_STATUS_CODE_BAD_REQUEST,
               "couldn't get path from destination URI");

  /* check if we can copy/move to the destination due to a lock */
  can_unlink_path(hc, ctx->dst_relative_uri,
                  &status_code,
                  &ctx->response_body,
                  &ctx->response_body_len);
  if (status_code) {
    goto done;
  }

  /* depth */
  ctx->depth = webdav_get_depth(&hc->rhs);
  HANDLE_ERROR(!(ctx->depth == DEPTH_INF ||
                 (ctx->depth == DEPTH_0 && !ctx->is_move)),
               HTTP_STATUS_CODE_BAD_REQUEST,
               "bad depth header");

  /* overwrite */
  const char *overwrite_str = http_get_header_value(&hc->rhs, WEBDAV_HEADER_OVERWRITE);
  bool overwrite = !(overwrite_str && str_case_equals(overwrite_str, "f"));

  webdav_error_t err;
  bool dst_existed;
  if (ctx->is_move) {
    /* TODO: XXX: destroy all locks held for the source resource,
       for now just assert there is are no source locks
    */
    bool is_src_locked;
    bool success_is_locked =
      is_resource_locked(hc->serv, ctx->src_relative_uri,
                         &is_src_locked, NULL, NULL, NULL);
    if (!success_is_locked || is_src_locked) {
      abort();
    }

    CRYIELD(ctx->pos,
            webdav_backend_move(hc->serv->fs,
                                ctx->src_relative_uri, ctx->dst_relative_uri,
                                overwrite,
                                handle_copy_request, ud));
    assert(WEBDAV_MOVE_DONE_EVENT == ev_type);
    WebdavMoveDoneEvent *move_done_ev = ev;
    err = move_done_ev->error;
    dst_existed = move_done_ev->dst_existed;
    linked_list_free(move_done_ev->failed_to_move, free);
  }
  else {
    CRYIELD(ctx->pos,
            webdav_backend_copy(hc->serv->fs,
                                ctx->src_relative_uri, ctx->dst_relative_uri,
                                overwrite, ctx->depth,
                                handle_copy_request, ud));
    assert(WEBDAV_COPY_DONE_EVENT == ev_type);
    WebdavCopyDoneEvent *copy_done_ev = ev;
    err = copy_done_ev->error;
    dst_existed = copy_done_ev->dst_existed;
    linked_list_free(copy_done_ev->failed_to_copy, free);
  }

  switch (err) {
  case WEBDAV_ERROR_NONE:
    status_code = dst_existed
      ? HTTP_STATUS_CODE_NO_CONTENT
      : HTTP_STATUS_CODE_CREATED;
    break;
  case WEBDAV_ERROR_DOES_NOT_EXIST:
  case WEBDAV_ERROR_NOT_COLLECTION:
    status_code = HTTP_STATUS_CODE_NOT_FOUND;
    break;
  case WEBDAV_ERROR_DESTINATION_DOES_NOT_EXIST:
  case WEBDAV_ERROR_DESTINATION_NOT_COLLECTION:
    status_code = HTTP_STATUS_CODE_CONFLICT;
    break;
  case WEBDAV_ERROR_DESTINATION_EXISTS:
    status_code = HTTP_STATUS_CODE_PRECONDITION_FAILED;
    break;
  default:
    http_request_log_info(hc->rh,
                          "Error while %s \"%s\" to \"%s\": %s",
                          ctx->is_move ? "moving" : "copying",
                          ctx->src_relative_uri,
                          ctx->dst_relative_uri,
                          webdav_error_to_string(err));
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    break;
  }

 done:
  free(ctx->src_relative_uri);
  free(ctx->dst_relative_uri);

  CRYIELD(ctx->pos,
          http_request_simple_response(hc->rh,
                                       status_code,
                                       ctx->response_body,
                                       ctx->response_body_len,
                                       "application/xml; charset=\"utf-8\"",
                                       LINKED_LIST_INITIALIZER,
                                       handle_copy_request, hc));

  free(ctx->response_body);

  CRRETURN(ctx->pos,
           request_proc(GENERIC_EVENT, NULL, hc));

#undef HANDLE_ERROR

  CREND();
}

static
EVENT_HANDLER_DEFINE(handle_delete_request, ev_type, ev, ud) {
  UNUSED(ev_type);
  UNUSED(ev);

  struct handler_context *hc = ud;
  struct delete_context *ctx = &hc->sub.delete_x;
  http_status_code_t status_code = 0;

  CRBEGIN(ctx->pos);

  ctx->response_body = NULL;
  ctx->response_body_len = 0;

  webdav_depth_t depth = webdav_get_depth(&hc->rhs);
  if (depth != DEPTH_INF) {
    http_request_log_info(hc->rh, "Invalid ctx->depth sent %d", depth);
    status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }

  ctx->request_relative_uri = path_from_request_uri(hc, hc->rhs.uri);
  if (!ctx->request_relative_uri) {
    http_request_log_info(hc->rh, "Couldn't make file path from %s", hc->rhs.uri);
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* check that we can "unlink" this path */
  can_unlink_path(hc, ctx->request_relative_uri,
                  &status_code,
                  &ctx->response_body,
                  &ctx->response_body_len);
  if (status_code) {
    goto done;
  }

  /* at this point we know this path (and all descendants) can be unlinked
     now destroy our lock and all descendant locks */
  bool success_unlock =
    unconditionally_unlock_resource_and_descendants(hc->serv, ctx->request_relative_uri);
  if (!success_unlock) {
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  CRYIELD(ctx->pos,
          webdav_backend_delete(hc->serv->fs,
                                ctx->request_relative_uri,
                                handle_delete_request, ud));
  assert(WEBDAV_DELETE_DONE_EVENT == ev_type);
  WebdavDeleteDoneEvent *delete_done_ev = ev;

  if (delete_done_ev->error) {
    status_code = delete_done_ev->error == WEBDAV_ERROR_DOES_NOT_EXIST
      ? HTTP_STATUS_CODE_NOT_FOUND
      : HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* TODO: return multi-status */
  if (delete_done_ev->failed_to_delete) {
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
  }
  else {
    status_code = HTTP_STATUS_CODE_NO_CONTENT;
  }

  linked_list_free(delete_done_ev->failed_to_delete, free);

 done:
  assert(status_code);
  free(ctx->request_relative_uri);

  CRYIELD(ctx->pos,
          http_request_simple_response(hc->rh,
                                       status_code,
                                       ctx->response_body,
                                       ctx->response_body_len,
                                       "application/xml; charset=\"utf-8\"",
                                       LINKED_LIST_INITIALIZER,
                                       handle_delete_request, hc));

  free(ctx->response_body);

  CRRETURN(ctx->pos,
           request_proc(GENERIC_EVENT, NULL, hc));

  CREND();
}

void
webdav_get_request_size_hint(webdav_get_request_ctx_t hc,
                             size_t size,
                             event_handler_t cb, void *cb_ud) {
  struct get_context *ctx = &hc->sub.get;

  bool success_set_code = http_response_set_code(&hc->resp, HTTP_STATUS_CODE_OK);
  ASSERT_TRUE(success_set_code);

  assert(size <= ULONG_MAX);
  bool success_add_header =
    http_response_add_header(&hc->resp,
                             HTTP_HEADER_CONTENT_LENGTH, "%lu",
                             (unsigned long) size);
  ASSERT_TRUE(success_add_header);

  if (ctx->entry.modified_time != INVALID_WEBDAV_RESOURCE_TIME) {
    char time_buf[400];
    bool success_generate =
      generate_http_date(time_buf, sizeof(time_buf),
                         ctx->entry.modified_time);
    ASSERT_TRUE(success_generate);
    bool success_add_last_modified_header =
      http_response_add_header(&hc->resp,
                               HTTP_HEADER_LAST_MODIFIED,
                               "%s", time_buf);
    ASSERT_TRUE(success_add_last_modified_header);
  }

  ctx->set_size_hint = true;
  WebdavGetRequestSizeHintDoneEvent ev = {.error = WEBDAV_ERROR_NONE};
  return cb(WEBDAV_GET_REQUEST_SIZE_HINT_DONE_EVENT, &ev, cb_ud);
}

void
webdav_get_request_write(webdav_get_request_ctx_t get_ctx,
                         const void *buf, size_t nbyte,
                         event_handler_t cb, void *cb_ud) {
  WebdavGetRequestWriteEvent ev = {
    .buf = buf,
    .nbyte = nbyte,
    .cb = cb,
    .cb_ud = cb_ud,
  };

  return handle_get_request(WEBDAV_GET_REQUEST_WRITE_EVENT, &ev, get_ctx);
}

void
webdav_get_request_end(webdav_get_request_ctx_t get_ctx, webdav_error_t error) {
  WebdavGetRequestEndEvent ev = {
    .error = error,
  };
  return handle_get_request(WEBDAV_GET_REQUEST_END_EVENT, &ev, get_ctx);
}

static
EVENT_HANDLER_DEFINE(handle_get_request, ev_type, ev, ud) {
  UNUSED(ev_type);

  struct handler_context *hc = ud;
  struct get_context *ctx = &hc->sub.get;

  CRBEGIN(ctx->pos);

  http_status_code_t code;

  ctx->resource_uri = path_from_request_uri(hc, hc->rhs.uri);
  if (!ctx->resource_uri) {
    http_request_log_info(hc->rh,
                          "Error while getting resourece uri for request: \"%s\"",
                          hc->rhs.uri);
    code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* TODO: it might be better to put this logic in the backend */
  CRYIELD(ctx->pos,
          util_webdav_backend_single_propfind(hc->serv->fs,
                                              ctx->resource_uri,
                                              handle_get_request, ud));
  assert(ev_type == UTIL_WEBDAV_BACKEND_SINGLE_PROPFIND_DONE_EVENT);
  UtilWebdavBackendSinglePropfindDoneEvent *propfind_done_event = ev;
  if (propfind_done_event->error) {
    http_request_log_info(hc->rh,
                          "Error while getting properties for resource \"%s\"",
                          ctx->resource_uri);
    code = propfind_done_event->error == WEBDAV_ERROR_DOES_NOT_EXIST
      ? HTTP_STATUS_CODE_NOT_FOUND
      : HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  ctx->entry = propfind_done_event->entry;

  const char *if_modified_since_value =
    http_get_header_value(&hc->rhs, HTTP_HEADER_IF_MODIFIED_SINCE);
  if (ctx->entry.modified_time != INVALID_WEBDAV_RESOURCE_TIME &&
      if_modified_since_value) {
    time_t if_modified_since_time_value;
    bool success_parse =
      parse_http_date(if_modified_since_value,
                      &if_modified_since_time_value);
    if (!success_parse) {
      http_request_log_info(hc->rh,
                            "Bad if-modified-since header: \"%s\"",
                            if_modified_since_value);
      code = HTTP_STATUS_CODE_BAD_REQUEST;
      goto done;
    }

    http_request_log_debug(hc->rh,
                           "If modified since: %lu vs %lu",
                           (unsigned long) ctx->entry.modified_time,
                           (unsigned long) if_modified_since_time_value);

    if (ctx->entry.modified_time <= if_modified_since_time_value) {
      /* hasn't been modified recently, allow the request to skip */
      code = HTTP_STATUS_CODE_NOT_MODIFIED;
      goto done;
    }
  }

  CRYIELD(ctx->pos,
          webdav_backend_get(hc->serv->fs, ctx->resource_uri, hc));
  ctx->amt_sent = 0;
  while (ev_type != WEBDAV_GET_REQUEST_END_EVENT) {
    assert(ev_type == WEBDAV_GET_REQUEST_WRITE_EVENT);
    ctx->rwev = *((WebdavGetRequestWriteEvent *) ev);

    if (!ctx->set_size_hint) {
      /* this is an error */
      http_request_log_error(hc->rh, "Backend did not set size hint, failing write request");
      goto loop_error;
    }

    if (!ctx->sent_headers) {
      CRYIELD(ctx->pos,
              http_request_write_headers(hc->rh, &hc->resp,
                                         handle_get_request, hc));
      assert(ev_type == HTTP_REQUEST_WRITE_HEADERS_DONE_EVENT);
      HTTPRequestWriteHeadersDoneEvent *write_headers_ev = ev;
      assert(write_headers_ev->request_handle == hc->rh);
      if (write_headers_ev->err != HTTP_SUCCESS) {
        http_request_log_error(hc->rh,
                               "Error while writing headers, failing write request: %s",
                               http_error_to_string(write_headers_ev->err));
        goto loop_error;
      }
      ctx->sent_headers = true;
    }

    CRYIELD(ctx->pos,
            http_request_write(hc->rh, ctx->rwev.buf, ctx->rwev.nbyte,
                               handle_get_request, hc));
    assert(ev_type == HTTP_REQUEST_WRITE_DONE_EVENT);
    HTTPRequestWriteDoneEvent *write_ev = ev;
    assert(write_ev->request_handle == hc->rh);
    if (write_ev->err != HTTP_SUCCESS) {
        http_request_log_error(hc->rh,
                               "Error while writing data, failing write request: %s",
                               http_error_to_string(write_ev->err));
      goto loop_error;
    }

    ctx->amt_sent += ctx->rwev.nbyte;
    WebdavGetRequestWriteDoneEvent ev1 = {.error = WEBDAV_ERROR_NONE};
    if (false) {
    loop_error:
      ev1.error = WEBDAV_ERROR_GENERAL;
    }

    CRYIELD(ctx->pos,
            ctx->rwev.cb(WEBDAV_GET_REQUEST_WRITE_DONE_EVENT, &ev1, ctx->rwev.cb_ud));
  }
  WebdavGetRequestEndEvent *request_end_ev = ev;

  switch (request_end_ev->error){
  case WEBDAV_ERROR_NONE:
    assert(ctx->amt_sent <= ULONG_MAX);
    http_request_log_debug(hc->rh,
                           "Sent %lu bytes of \"%s\"",
                           (long unsigned) ctx->amt_sent, ctx->resource_uri);
    code = HTTP_STATUS_CODE_OK;
    break;
  case WEBDAV_ERROR_IS_COL:
    /* NB: if the backend returns this, then we return http method not allowed,
       but the backend is also free to define a get resource for a
       collection */
    code = HTTP_STATUS_CODE_METHOD_NOT_ALLOWED;
    break;
  case WEBDAV_ERROR_DOES_NOT_EXIST:
    code = HTTP_STATUS_CODE_NOT_FOUND;
    break;
  default:
    http_request_log_info(hc->rh,
                          "Error on completion backend's completion of \"%s\": %s",
                          ctx->resource_uri, webdav_error_to_string(request_end_ev->error));
    code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    break;
  }

 done:
  if (!ctx->sent_headers) {
    CRYIELD(ctx->pos,
            http_request_simple_response(hc->rh,
                                         code,
                                         "", 0,
                                         "text/plain",
                                         LINKED_LIST_INITIALIZER,
                                         handle_get_request, ud));
  }

  free(ctx->resource_uri);

  CRRETURN(ctx->pos,
           request_proc(GENERIC_EVENT, NULL, hc));

  CREND();
}

static
EVENT_HANDLER_DEFINE(handle_lock_request, ev_type, ev, ud) {
  UNUSED(ev_type);

  /* set this variable before coroutine restarts */
  struct handler_context *const hc = ud;
  struct lock_context *const ctx = &hc->sub.lock;
  http_status_code_t status_code = 0;

  CRBEGIN(ctx->pos);

  ctx->file_path = NULL;
  ctx->owner_xml = NULL;
  ctx->refresh_uri = NULL;
  ctx->resource_tag = NULL;
  ctx->resource_tag_path = NULL;
  ctx->response_body = NULL;
  ctx->response_body_len = 0;
  ctx->request_body = NULL;
  ctx->request_body_len = 0;

  /* read body first */
  CRYIELD(ctx->pos,
          http_request_read_body(hc->rh,
                                 handle_lock_request,
                                 ud));
  assert(ev_type == GENERIC_EVENT);

  HTTPRequestReadBodyDoneEvent *rbev = ev;
  if (rbev->error) {
    http_request_log_info(hc->rh, "Error while reading body of request");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  ctx->request_body = rbev->body;
  ctx->request_body_len = rbev->length;

  http_request_log_debug(hc->rh, "Incoming lock request XML");
  pretty_print_xml(ctx->request_body, ctx->request_body_len, LOG_DEBUG);

  /* get timeout */
  ctx->timeout_in_seconds = webdav_get_timeout(&hc->rhs);

  /* get if path is a collection */
  CRYIELD(ctx->pos,
          request_uri_is_collection(hc, handle_lock_request, ud));
  assert(ev_type == REQUEST_URI_IS_COLLECTION_DONE_EVENT);
  RequestUriIsCollectionDoneEvent *is_collection_done_ev = ev;
  if (is_collection_done_ev->error &&
      is_collection_done_ev->error != WEBDAV_ERROR_DOES_NOT_EXIST) {
    http_request_log_debug(hc->rh,
                           "Couldn't determine if uri was a collection \"%s\": %d",
                           hc->rhs.uri, is_collection_done_ev->error);
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  ctx->is_collection = is_collection_done_ev->error
    ? false
    : is_collection_done_ev->is_collection;

  /* get path */
  ctx->file_path = path_from_request_uri(hc, hc->rhs.uri);
  if (!ctx->file_path) {
    http_request_log_debug(hc->rh, "Invalid file path %s", hc->rhs.uri);
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* read "If" header */
  if_lock_token_err_t if_lock_token_err =
    webdav_get_if_lock_token(hc, &ctx->resource_tag, &ctx->refresh_uri);
  if (if_lock_token_err == IF_LOCK_TOKEN_ERR_BAD_PARSE) {
    http_request_log_debug(hc->rh, "Bad XML!");
    status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }

  if (if_lock_token_err == IF_LOCK_TOKEN_ERR_INTERNAL) {
    http_request_log_debug(hc->rh, "XML Parse failed...");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  if (if_lock_token_err == IF_LOCK_TOKEN_ERR_SUCCESS) {
    ctx->resource_tag_path = path_from_public_uri(hc, ctx->resource_tag);
    if (!ctx->resource_tag_path) {
      http_request_log_debug(hc->rh,
                             "Couldn't get normalized resource path from uri ...: %s",
                             ctx->resource_tag);
      status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
      goto done;
    }
  }

  if (!ctx->request_body &&
      if_lock_token_err == IF_LOCK_TOKEN_ERR_SUCCESS &&
      str_equals(ctx->resource_tag_path, ctx->file_path)) {
    owner_xml_t owner_xml_not_owned;
    bool is_exclusive;
    webdav_depth_t depth;
    bool refreshed;
    bool success_refresh = refresh_lock(hc->serv, ctx->file_path, ctx->refresh_uri,
                                        ctx->timeout_in_seconds,
                                        &refreshed,
                                        &owner_xml_not_owned,
                                        &is_exclusive,
                                        &depth);
    if (!success_refresh) {
      status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
      goto done;
    }

    if (!refreshed) {
      status_code = HTTP_STATUS_CODE_PRECONDITION_FAILED;
      goto done;
    }

    bool was_created = false;
    char *const public_uri = public_uri_from_path(hc, ctx->file_path, ctx->is_collection);
    ASSERT_NOT_NULL(public_uri);
    bool success_generate =
      generate_success_lock_response_body(public_uri, ctx->timeout_in_seconds,
                                          depth, is_exclusive, owner_xml_not_owned,
                                          ctx->refresh_uri, was_created,
                                          &status_code,
                                          &ctx->response_body,
                                          &ctx->response_body_len);
    free(public_uri);

    if (!success_generate) {
      status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    }

    goto done;
  }

  /* get webdav depth */
  ctx->depth = webdav_get_depth(&hc->rhs);
  if (ctx->depth != DEPTH_0 && ctx->depth != DEPTH_INF) {
    http_request_log_debug(hc->rh, "Invalid ctx->depth sent %d", ctx->depth);
    status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }

  /* parse request body */
  xml_parse_code_t error_parse = ctx->request_body
    ? parse_lock_request_body(ctx->request_body, ctx->request_body_len,
                              &ctx->is_exclusive, &ctx->owner_xml)
    : XML_PARSE_ERROR_NONE;
  if (error_parse == XML_PARSE_ERROR_STRUCTURE ||
      error_parse == XML_PARSE_ERROR_SYNTAX) {
    http_request_log_debug(hc->rh, "Bad request body");
    status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }
  else if (error_parse) {
    http_request_log_debug(hc->rh, "Internal error while parsing request");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* our XML library is having an error if owner_xml is NULL and it returns success */
  assert(ctx->owner_xml);

  /* actually attempt to lock the resource */
  ctx->lock_token = NULL;
  ctx->status_path = NULL;
  bool success_perform =
    perform_write_lock(hc->serv,
                       ctx->file_path, ctx->is_collection,
                       ctx->timeout_in_seconds, ctx->depth, ctx->is_exclusive, ctx->owner_xml,
                       &ctx->is_locked, &ctx->lock_token, &ctx->status_path, &ctx->status_path_is_collection);
  if (!success_perform) {
    http_request_log_debug(hc->rh, "Error while performing lock");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  ctx->created = false;
  if (!ctx->is_locked) {
    CRYIELD(ctx->pos,
            webdav_backend_touch(hc->serv->fs,
                                 ctx->file_path,
                                 handle_lock_request, ud));
    assert(WEBDAV_TOUCH_DONE_EVENT == ev_type);
    WebdavTouchDoneEvent *touch_done_ev = ev;
    if (touch_done_ev->error) {
      // failed to touch file
      // unlock and return
      bool performed_unlock = false;
      bool success_unlock =
        unlock_resource(hc->serv, ctx->file_path, ctx->lock_token, &performed_unlock);
      assert(!success_unlock || performed_unlock);
      ASSERT_TRUE(success_unlock);
      status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
      goto done;
    }

    if (!touch_done_ev->error &&
        !touch_done_ev->resource_existed) {
      ctx->created = true;
    }
  }

  ctx->headers = LINKED_LIST_INITIALIZER;

  /* generate lock attempt response */
  bool success_generate;
  if (ctx->is_locked) {
    http_request_log_debug(hc->rh, "Resource is already locked");
    if (str_equals(ctx->status_path, ctx->file_path)) {
      char *const public_uri = public_uri_from_path(hc, ctx->status_path, ctx->status_path_is_collection);
      ASSERT_NOT_NULL(public_uri);
      success_generate =
        generate_locked_response(public_uri,
                                 &status_code,
                                 &ctx->response_body,
                                 &ctx->response_body_len);
      free(public_uri);
    }
    else {
      char *const public_uri = public_uri_from_path(hc, ctx->file_path, ctx->is_collection);
      ASSERT_NOT_NULL(public_uri);

      char *const public_status_uri = public_uri_from_path(hc, ctx->status_path, ctx->status_path_is_collection);
      ASSERT_NOT_NULL(public_uri);

      success_generate =
        generate_failed_lock_response_body(public_uri, public_status_uri,
                                           &status_code,
                                           &ctx->response_body,
                                           &ctx->response_body_len);

      free(public_uri);
      free(public_status_uri);
    }
  }
  else {
    char *const public_uri = public_uri_from_path(hc, ctx->file_path, ctx->is_collection);
    ASSERT_NOT_NULL(public_uri);

    success_generate =
      generate_success_lock_response_body(public_uri, ctx->timeout_in_seconds,
                                          ctx->depth, ctx->is_exclusive, ctx->owner_xml,
                                          ctx->lock_token, ctx->created,
                                          &status_code,
                                          &ctx->response_body,
                                          &ctx->response_body_len);

    free(public_uri);

    if (success_generate) {
      /* add lock token header if we were locked */
      EASY_ALLOC(HeaderPair, hp);
      hp->name = "Lock-Token";
      char lock_token_header_value[256];
      int len_written = snprintf(lock_token_header_value, sizeof(lock_token_header_value),
                                 "<%s>", ctx->lock_token);
      /* TODO: Lazy */
      ASSERT_TRUE(!(len_written < 0 || (size_t) len_written >= sizeof(lock_token_header_value)));
      hp->value = davfuse_util_strdup(lock_token_header_value);
      ctx->headers = linked_list_prepend(ctx->headers, hp);
    }
  }

  if (!success_generate) {
    http_request_log_debug(hc->rh, "Error while sending back response");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
  }

 done:
  assert(status_code);
  http_request_log_debug(hc->rh, "Response with status code: %d", status_code);
  http_request_log_debug(hc->rh,
                         "Outgoing lock response XML (%lu bytes):",
                         (unsigned long) ctx->response_body_len);
  pretty_print_xml(ctx->response_body, ctx->response_body_len, LOG_DEBUG);

  free(ctx->request_body);
  free(ctx->file_path);
  owner_xml_free(ctx->owner_xml);
  free(ctx->resource_tag);
  free(ctx->resource_tag_path);
  free(ctx->refresh_uri);

  CRYIELD(ctx->pos,
          http_request_simple_response(hc->rh,
                                       status_code,
                                       ctx->response_body,
                                       ctx->response_body_len,
                                       "application/xml; charset=\"utf-8\"",
                                       ctx->headers,
                                       handle_lock_request, ud));
  assert(ev_type == GENERIC_EVENT);
  /* if there is an error sending, oh well, just let the request end */

  free(ctx->response_body);
  if (ctx->headers) {
    free(((HeaderPair *) ctx->headers->elt)->value);
    free(ctx->headers->elt);
    linked_list_free(ctx->headers, NULL);
  }

  CRRETURN(ctx->pos,
           request_proc(GENERIC_EVENT, NULL, hc));

  CREND();
}

static
EVENT_HANDLER_DEFINE(handle_mkcol_request, ev_type, ev, ud) {
  UNUSED(ev_type);

  /* these are run on every re-entry */
  struct handler_context *const hc = ud;
  struct mkcol_context *const ctx = &hc->sub.mkcol;
  http_status_code_t status_code = 0;

  CRBEGIN(ctx->pos);

  /* read body first */
  CRYIELD(ctx->pos,
          http_request_ignore_body(hc->rh,
                                   handle_mkcol_request, hc));
  HTTPRequestReadBodyDoneEvent *rbev = ev;
  if (rbev->error) {
    http_request_log_info(hc->rh, "Error while reading body of request");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  if (rbev->length) {
    http_request_log_info(hc->rh, "Request had a body!");
    status_code = HTTP_STATUS_CODE_UNSUPPORTED_MEDIA_TYPE;
    goto done;
  }

  ctx->request_relative_uri = path_from_request_uri(hc, hc->rhs.uri);
  if (!ctx->request_relative_uri) {
    http_request_log_info(hc->rh, "Couldn't make file path from %s", hc->rhs.uri);
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  CRYIELD(ctx->pos,
          webdav_backend_mkcol(hc->serv->fs,
                               ctx->request_relative_uri,
                               handle_mkcol_request, hc));
  assert(WEBDAV_MKCOL_DONE_EVENT == ev_type);
  WebdavMkcolDoneEvent *mkcol_done_ev = ev;
  switch (mkcol_done_ev->error) {
  case WEBDAV_ERROR_NONE:
    status_code = HTTP_STATUS_CODE_CREATED;
    break;
  case WEBDAV_ERROR_DOES_NOT_EXIST:
    status_code = HTTP_STATUS_CODE_CONFLICT;
    break;
  case WEBDAV_ERROR_NOT_COLLECTION:
    status_code = HTTP_STATUS_CODE_FORBIDDEN;
    break;
  case WEBDAV_ERROR_NO_SPACE:
    status_code = HTTP_STATUS_CODE_INSUFFICIENT_STORAGE;
    break;
  case WEBDAV_ERROR_PERM:
  case WEBDAV_ERROR_EXISTS:
    status_code = HTTP_STATUS_CODE_METHOD_NOT_ALLOWED;
    break;
  default:
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    break;
  }

 done:
  assert(status_code);

  free(ctx->request_relative_uri);

  CRYIELD(ctx->pos,
          http_request_string_response(hc->rh,
                                       status_code, "",
                                       handle_mkcol_request, hc));

  CRRETURN(ctx->pos,
           request_proc(GENERIC_EVENT, NULL, hc));

  CREND();
}

static
EVENT_HANDLER_DEFINE(handle_options_request, ev_type, ev, ud) {
  UNUSED(ev_type);
  UNUSED(ev);

  /* these are run on every re-entry */
  struct handler_context *const hc = ud;
  struct options_context *const ctx = &hc->sub.options;
  http_status_code_t status_code = 0;

  CRBEGIN(ctx->pos);

  /* read body first */
  CRYIELD(ctx->pos,
          http_request_ignore_body(hc->rh,
                                   handle_options_request, hc));
  HTTPRequestReadBodyDoneEvent *rbev = ev;
  if (rbev->error) {
    http_request_log_info(hc->rh, "Error while reading body of request");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto error;
  }

  webdav_error_t collection_error;
  /* Windows XP has a bug where it needs to read the root
     of the webdav resource its mounting, so we special case this */
  if (str_equals(hc->rhs.uri, "/") &&
      !str_equals(hc->serv->internal_root, "/")) {
    collection_error = WEBDAV_ERROR_DOES_NOT_EXIST;
  }
  else {
    CRYIELD(ctx->pos,
            request_uri_is_collection(hc, handle_options_request, hc));
    assert(ev_type == REQUEST_URI_IS_COLLECTION_DONE_EVENT);
    RequestUriIsCollectionDoneEvent *is_collection_done_ev = ev;
    if (is_collection_done_ev->error &&
        is_collection_done_ev->error != WEBDAV_ERROR_DOES_NOT_EXIST) {
      http_request_log_info(hc->rh,
                            "Error while checking if \"%s\" was a collection: %d",
                            hc->rhs.uri, is_collection_done_ev->error);
      status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
      goto error;
    }

    collection_error = is_collection_done_ev->error;
    ctx->uri_is_collection = is_collection_done_ev->is_collection;
  }

  const bool success_set_code =
    http_response_set_code(&hc->resp, HTTP_STATUS_CODE_OK);
  ASSERT_TRUE(success_set_code);

  const bool success_add_dav_header =
    http_response_add_header(&hc->resp, "DAV", "1,2");
  ASSERT_TRUE(success_add_dav_header);

  /* tell microsoft clients that we only support webdav and not frontpage extensions */
  const bool success_add_ms_header =
    http_response_add_header(&hc->resp, "MS-Author-Via", "DAV");
  ASSERT_TRUE(success_add_ms_header);

  const bool success_add_cl_header =
    http_response_add_header(&hc->resp, HTTP_HEADER_CONTENT_LENGTH, "0");
  ASSERT_TRUE(success_add_cl_header);

  if (collection_error == WEBDAV_ERROR_DOES_NOT_EXIST) {
    const bool success_add_allow_header =
      http_response_add_header(&hc->resp, "Allow",
                               "OPTIONS,MKCOL,PUT,LOCK");
    ASSERT_TRUE(success_add_allow_header);
  }
  else {
    size_t allow_header_off = 0;

#define ALLOW_METHOD(meth)                                              \
    do {                                                                \
      if (allow_header_off >= sizeof(ctx->allow_header)) {              \
        status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;           \
        goto error;                                                     \
      }                                                                 \
      memcpy(ctx->allow_header + allow_header_off, meth, sizeof(meth) - 1); \
      allow_header_off += sizeof(meth) - 1;                             \
    }                                                                   \
    while (0)

    ALLOW_METHOD("LOCK,UNLOCK,PROPFIND,DELETE,MOVE,COPY,OPTIONS,PROPPATCH");

    if (!ctx->uri_is_collection) {
      ALLOW_METHOD(",GET,PUT");
    }

    ALLOW_METHOD("\0");

#undef ALLOW_METHOD

    const bool success_add_allow_header =
      http_response_add_header(&hc->resp, "Allow", ctx->allow_header);
    if (!success_add_allow_header) {
      status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
      goto error;
    }
  }

  CRYIELD(ctx->pos,
          http_request_write_headers(hc->rh, &hc->resp,
                                     handle_options_request, ud));

  if (false) {
  error:
    assert(status_code);
    CRYIELD(ctx->pos,
            http_request_string_response(hc->rh,
                                         status_code,
                                         "",
                                         handle_options_request, ud));
  }

  CRRETURN(ctx->pos,
           request_proc(GENERIC_EVENT, NULL, hc));

  CREND();
}

static
EVENT_HANDLER_DEFINE(handle_post_request, ev_type, ev, ud) {
  UNUSED(ev_type);
  UNUSED(ev);

  struct handler_context *hc = ud;

  http_request_string_response(hc->rh,
                               HTTP_STATUS_CODE_NOT_IMPLEMENTED,
                               "",
                               request_proc, ud);
}

static
EVENT_HANDLER_DEFINE(handle_propfind_request, ev_type, ev, ud) {
  UNUSED(ev_type);
  UNUSED(ev);

  struct handler_context *const hc = ud;
  struct propfind_context *const ctx = &hc->sub.propfind;
  http_status_code_t status_code = 0;

  CRBEGIN(ctx->pos);

  ctx->request_relative_uri = NULL;
  ctx->buf = NULL;
  ctx->buf_used = 0;
  ctx->out_buf = NULL;
  ctx->out_buf_size = 0;

  if (is_relative_uri_parent(hc->rhs.uri, hc->serv->internal_root)) {
    http_request_log_debug(hc->rh, "URI is a parent of us and we don't allow PROPFIND");
    status_code = HTTP_STATUS_CODE_METHOD_NOT_ALLOWED;
    goto done;
  }

  ctx->request_relative_uri = path_from_request_uri(hc, hc->rhs.uri);
  if (!ctx->request_relative_uri) {
    http_request_log_info(hc->rh, "couldn't create request relative uri: %s",
                          hc->rhs.uri);
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* read all posted data */
  CRYIELD(ctx->pos,
          http_request_read_body(hc->rh, handle_propfind_request, hc));
  const HTTPRequestReadBodyDoneEvent *rbev = ev;
  if (rbev->error) {
    http_request_log_info(hc->rh, "propfind request had a body: %s",
                          ctx->request_relative_uri);
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }
  ctx->buf = rbev->body;
  ctx->buf_used = rbev->length;

  /* figure out depth */
  const webdav_depth_t depth = webdav_get_depth(&hc->rhs);
  if (depth == DEPTH_INVALID) {
    http_request_log_info(hc->rh, "bad depth header!");
    status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }

  assert(ctx->buf_used <= INT_MAX);
  http_request_log_debug(hc->rh,"XML request: Depth: %d", depth);
  pretty_print_xml(ctx->buf, ctx->buf_used, LOG_DEBUG);

  /* parse request */
  const xml_parse_code_t success_parse =
    parse_propfind_request(ctx->buf,
                           ctx->buf_used,
                           &ctx->propfind_req_type,
                           &ctx->props_to_get);
  if (success_parse == XML_PARSE_ERROR_SYNTAX ||
      success_parse == XML_PARSE_ERROR_STRUCTURE) {
    http_request_log_info(hc->rh, "bad syntax for propfind request!");
    status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }
  else if (success_parse == XML_PARSE_ERROR_INTERNAL) {
    http_request_log_info(hc->rh, "internal parser error!");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* run the request */
  CRYIELD(ctx->pos,
          webdav_backend_propfind(hc->serv->fs,
                                  ctx->request_relative_uri, depth,
                                  ctx->propfind_req_type,
                                  handle_propfind_request, hc));
  assert(ev_type == WEBDAV_PROPFIND_DONE_EVENT);
  const WebdavPropfindDoneEvent *run_propfind_ev = ev;
  if (run_propfind_ev->error) {
    http_request_log_info(hc->rh, "error while doing propfind: %d!", run_propfind_ev->error);
    status_code = run_propfind_ev->error == WEBDAV_ERROR_DOES_NOT_EXIST
      ? HTTP_STATUS_CODE_NOT_FOUND
      : HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  assert(run_propfind_ev->entries);

  LINKED_LIST_FOR (struct webdav_propfind_entry, propfind_entry,
                   run_propfind_ev->entries) {
    /* TODO: we don't support get on collections */
    if (propfind_entry->is_collection) {
      propfind_entry->modified_time = INVALID_WEBDAV_RESOURCE_TIME;
    }
    /* convert relative uri to public uris for generator */
    char *const relative_uri = propfind_entry->relative_uri;
    propfind_entry->relative_uri = public_uri_from_path(hc, relative_uri,
                                                        propfind_entry->is_collection);
    ASSERT_NOT_NULL(propfind_entry->relative_uri);
    free(relative_uri);
  }

  /* now generate response */
  const bool success_generate =
    generate_propfind_response(ctx->propfind_req_type,
                               ctx->props_to_get,
                               run_propfind_ev->entries,
                               &ctx->out_buf,
                               &ctx->out_buf_size,
                               &status_code);
  linked_list_free(run_propfind_ev->entries,
                   (linked_list_elt_handler_t) webdav_destroy_propfind_entry);

  if (!success_generate) {
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

 done:
  free(ctx->request_relative_uri);
  linked_list_free(ctx->props_to_get,
                   (linked_list_elt_handler_t) free_webdav_property);

  assert(status_code);
  http_request_log_debug(hc->rh, "Responding with status: %d", status_code);
  assert(ctx->out_buf_size <= ULONG_MAX);
  http_request_log_debug(hc->rh, "XML response will be: (%lu bytes)",
                         (unsigned long) ctx->out_buf_size);
  pretty_print_xml(ctx->out_buf, ctx->out_buf_size, LOG_DEBUG);

  if (status_code == HTTP_STATUS_CODE_METHOD_NOT_ALLOWED) {
    bool success_init = http_response_init(&hc->resp);
    ASSERT_TRUE(success_init);

    bool success_set_moved_code =
      http_response_set_code(&hc->resp, HTTP_STATUS_CODE_METHOD_NOT_ALLOWED);
    ASSERT_TRUE(success_set_moved_code);

    bool success_set_location_header =
      http_response_add_header(&hc->resp, "Allow", "GET,HEAD,POST,OPTIONS");
    ASSERT_TRUE(success_set_location_header);

    bool success_set_content_length_header =
      http_response_add_header(&hc->resp, HTTP_HEADER_CONTENT_LENGTH, "0");
    ASSERT_TRUE(success_set_content_length_header);

    CRYIELD(ctx->pos,
            http_request_write_headers(hc->rh, &hc->resp,
                                       handle_propfind_request, hc));
  }
  else {
    CRYIELD(ctx->pos,
            http_request_simple_response(hc->rh,
                                         status_code,
                                         ctx->out_buf,
                                         ctx->out_buf_size,
                                         "application/xml; charset=\"utf-8\"",
                                         LINKED_LIST_INITIALIZER,
                                         handle_propfind_request, hc));
  }

  if (ctx->out_buf) {
    free(ctx->out_buf);
  }
  free(ctx->buf);
  CRRETURN(ctx->pos, request_proc(GENERIC_EVENT, NULL, hc));

  CREND();
}

static void
run_proppatch(struct handler_context *hc, const char *uri,
              const char *input, size_t input_size,
              char **output, size_t *output_size,
              http_status_code_t *status_code);

static
EVENT_HANDLER_DEFINE(handle_proppatch_request, ev_type, ev, ud) {
  UNUSED(ev_type);
  UNUSED(ev);

  struct handler_context *hc = ud;
  http_status_code_t status_code = 0;

  CRBEGIN(hc->sub.proppatch.pos);

  hc->sub.proppatch.request_body = NULL;
  hc->sub.proppatch.request_body_size = 0;

  /* read all posted data */
  CRYIELD(hc->sub.proppatch.pos,
          http_request_read_body(hc->rh, handle_proppatch_request, hc));
  assert(ev);
  HTTPRequestReadBodyDoneEvent *rbev = ev;
  if (rbev->error) {
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }
  hc->sub.proppatch.request_body = rbev->body;
  hc->sub.proppatch.request_body_size = rbev->length;

  /* run the request */
  run_proppatch(hc, hc->rhs.uri,
                hc->sub.proppatch.request_body, hc->sub.proppatch.request_body_size,
                &hc->sub.proppatch.response_body, &hc->sub.proppatch.response_body_size,
                &status_code);

 done:
  assert(status_code);

  assert(hc->sub.proppatch.response_body_size <= INT_MAX);
  http_request_log_debug(hc->rh,
                         "XML response will be: (%d bytes)",
                         (int) hc->sub.proppatch.response_body_size);
  pretty_print_xml(hc->sub.proppatch.response_body,
                   hc->sub.proppatch.response_body_size,
                   LOG_DEBUG);

  CRYIELD(hc->sub.proppatch.pos,
          http_request_simple_response(hc->rh,
                                       status_code,
                                       hc->sub.proppatch.response_body,
                                       hc->sub.proppatch.response_body_size,
                                       "application/xml; charset=\"utf-8\"",
                                       LINKED_LIST_INITIALIZER,
                                       handle_proppatch_request, hc));

  free(hc->sub.proppatch.response_body);
  free(hc->sub.proppatch.request_body);

  CRRETURN(hc->sub.proppatch.pos, request_proc(GENERIC_EVENT, NULL, hc));

  CREND();
}

static void
run_proppatch(struct handler_context *hc, const char *uri,
              const char *input, size_t input_size,
              char **output, size_t *output_size,
              http_status_code_t *status_code) {
  UNUSED(hc);

  /* NB: litmus "lock" tests fail because we don't support
     setting arbitrary properties */
  char *file_path = path_from_request_uri(hc, uri);
  if (!file_path) {
    http_request_log_warning(hc->rh, "Couldn't make file path from %s", uri);
    *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* check if uri is locked */
  can_modify_path(hc, file_path,
                  status_code,
                  output, output_size);
  if (*status_code) {
    goto done;
  }

  /* now parse the xml */
  assert(input_size <= INT_MAX);
  http_request_log_debug(hc->rh, "XML request:");
  pretty_print_xml(input, input_size, LOG_DEBUG);

  linked_list_t props_to_patch;
  xml_parse_code_t error_parse =
    parse_proppatch_request(input, input_size,
                            &props_to_patch);
  if (error_parse == XML_PARSE_ERROR_STRUCTURE ||
      error_parse == XML_PARSE_ERROR_SYNTAX) {
    *status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }
  else if (error_parse == XML_PARSE_ERROR_INTERNAL) {
    *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* build response */
  bool success_generate =
    generate_proppatch_response(uri, props_to_patch,
                                output, output_size, status_code);
  if (!success_generate) {
    *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
  }

  linked_list_free(props_to_patch,
                   (linked_list_elt_handler_t) free_webdav_proppatch_directive);

 done:
  free(file_path);
}

void
webdav_put_request_read(webdav_put_request_ctx_t put_ctx,
                        void *buf, size_t nbyte,
                        event_handler_t cb, void *cb_ud) {
  WebdavPutRequestReadEvent ev = {
    .buf = buf,
    .nbyte = nbyte,
    .cb = cb,
    .cb_ud = cb_ud,
  };
  handle_put_request(WEBDAV_PUT_REQUEST_READ_EVENT, &ev, put_ctx);
}

void
webdav_put_request_end(webdav_get_request_ctx_t put_ctx,
                       webdav_error_t error,
                       bool resource_existed) {
  WebdavPutRequestEndEvent ev = {
    .error = error,
    .resource_existed = resource_existed,
  };

  handle_put_request(WEBDAV_PUT_REQUEST_END_EVENT, &ev, put_ctx);
}

static
EVENT_HANDLER_DEFINE(handle_put_request, ev_type, ev, ud) {
  UNUSED(ev_type);

  /* re-init these before restarting the coroutine */
  struct handler_context *const hc = ud;
  struct put_context *const ctx = &hc->sub.put;
  http_status_code_t status_code = 0;

  CRBEGIN(ctx->pos);

  ctx->response_body = NULL;
  ctx->response_body_len = 0;

  ctx->request_relative_uri = path_from_request_uri(hc, hc->rhs.uri);
  if (!ctx->request_relative_uri) {
    http_request_log_warning(hc->rh, "Couldn't make file path from %s", hc->rhs.uri);
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* check if path is locked */
  can_modify_path(hc, ctx->request_relative_uri,
                  &status_code,
                  &ctx->response_body,
                  &ctx->response_body_len);
  if (status_code) {
    goto done;
  }

  CRYIELD(ctx->pos,
          webdav_backend_put(hc->serv->fs,
                             ctx->request_relative_uri,
                             hc));
  while (ev_type != WEBDAV_PUT_REQUEST_END_EVENT) {
    assert(ev_type == WEBDAV_PUT_REQUEST_READ_EVENT);
    ctx->read_ev = *((WebdavPutRequestReadEvent *) ev);

    /* forward request to read to http server */
    CRYIELD(ctx->pos,
            http_request_read(hc->rh,
                              ctx->read_ev.buf, ctx->read_ev.nbyte,
                              handle_put_request, hc));
    assert(ev_type == HTTP_REQUEST_READ_DONE_EVENT);
    HTTPRequestReadDoneEvent *read_done_ev = ev;
    if (read_done_ev->err != HTTP_SUCCESS) {
      goto loop_error;
    }

    WebdavPutRequestReadDoneEvent out_ev = {
      .error = WEBDAV_ERROR_NONE,
      .nbyte = read_done_ev->nbyte,
    };

    if (false) {
    loop_error:
      out_ev.error = WEBDAV_ERROR_GENERAL;
    }

    CRYIELD(ctx->pos,
            ctx->read_ev.cb(WEBDAV_PUT_REQUEST_READ_DONE_EVENT,
                            &out_ev,
                            ctx->read_ev.cb_ud));
  }

  WebdavPutRequestEndEvent *end_ev = ev;
  if (end_ev->error) {
    if (end_ev->error == WEBDAV_ERROR_DOES_NOT_EXIST ||
        end_ev->error == WEBDAV_ERROR_NOT_COLLECTION) {
      status_code = HTTP_STATUS_CODE_CONFLICT;
    }
    else if (end_ev->error == WEBDAV_ERROR_IS_COL) {
      status_code = HTTP_STATUS_CODE_METHOD_NOT_ALLOWED;
    }
    else {
      status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    }
  }
  else {
    status_code = end_ev->resource_existed
      ? HTTP_STATUS_CODE_OK
      : HTTP_STATUS_CODE_CREATED;
  }

 done:
  assert(status_code);

  CRYIELD(ctx->pos,
          http_request_simple_response(hc->rh,
                                       status_code,
                                       ctx->response_body,
                                       ctx->response_body_len,
                                       "application/xml; charset=\"utf-8\"",
                                       LINKED_LIST_INITIALIZER,
                                       handle_put_request, ud));

  free(ctx->response_body);
  free(ctx->request_relative_uri);

  CRRETURN(ctx->pos,
           request_proc(GENERIC_EVENT, NULL, hc));

  CREND();
}

static if_lock_token_err_t
parse_lock_token_header(const char *lock_token_header,
                        char **lock_token) {
  int i = 0;

  i = skip_bnf_lws(lock_token_header, i);

  if (lock_token_header[i++] != ASCII_LEFT_BRACKET) {
    return IF_LOCK_TOKEN_ERR_BAD_PARSE;
  }

  char *right_bracket_location =
    strchr(lock_token_header + i, ASCII_RIGHT_BRACKET);

  *lock_token =
    strndup_x(lock_token_header + i,
              right_bracket_location - (lock_token_header + i));
  if (!*lock_token) {
    return IF_LOCK_TOKEN_ERR_INTERNAL;
  }

  return IF_LOCK_TOKEN_ERR_SUCCESS;
}

static
EVENT_HANDLER_DEFINE(handle_unlock_request, ev_type, ev, ud) {
  UNUSED(ev);
  UNUSED(ev_type);

  struct handler_context *hc = ud;
  http_status_code_t status_code = HTTP_STATUS_CODE___INVALID;
  char *lock_token = NULL;
  char *file_path = NULL;

  file_path = path_from_request_uri(hc, hc->rhs.uri);
  if (!file_path) {
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  const char *lock_token_header = http_get_header_value(&hc->rhs, WEBDAV_HEADER_LOCK_TOKEN);
  if (!lock_token_header) {
    status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }

  if_lock_token_err_t success_parse =
    parse_lock_token_header(lock_token_header, &lock_token);

  if (success_parse == IF_LOCK_TOKEN_ERR_BAD_PARSE) {
    status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }

  if (success_parse == IF_LOCK_TOKEN_ERR_INTERNAL) {
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* unlock based on token */
  bool unlocked;
  bool success_unlock =
    unlock_resource(hc->serv, file_path, lock_token, &unlocked);
  if (!success_unlock) {
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  if (unlocked) {
    status_code = HTTP_STATUS_CODE_NO_CONTENT;
  }
  else {
    /* unlocking could fail if the passed-in file path was wrong
       or the lock token simply wasn't locked */
    status_code = HTTP_STATUS_CODE_CONFLICT;
  }

 done:
  free(lock_token);
  free(file_path);
  assert(status_code != HTTP_STATUS_CODE___INVALID);

  http_request_string_response(hc->rh,
                               status_code, "",
                               request_proc, ud);
}

static
EVENT_HANDLER_DEFINE(handle_request, ev_type, ev, ud) {
  UNUSED(ev_type);
  assert(ev_type == HTTP_NEW_REQUEST_EVENT);
  HTTPNewRequestEvent *new_request_ev = ev;

  UTHR_CALL3(request_proc, struct handler_context,
             .rh = new_request_ev->request_handle,
             .serv = ud);
}

webdav_server_t
webdav_server_new(event_loop_handle_t loop,
                  socket_t sock,
                  const char *public_uri_root,
                  const char *internal_root,
                  webdav_backend_t fs) {
  char *public_uri_root_copy = NULL;
  char *internal_root_copy = NULL;
  http_server_t http = (http_server_t) 0;
  struct webdav_server *serv = NULL;

  if (!str_endswith(public_uri_root, "/")) {
    log_info("public_uri_root must end in '/': %s", public_uri_root);
    goto error;
  }

  public_uri_root_copy = davfuse_util_strdup(public_uri_root);
  if (!public_uri_root_copy) goto error;

  internal_root_copy = davfuse_util_strdup(internal_root);
  if (!internal_root_copy) goto error;

  serv = malloc(sizeof(*serv));
  if (!serv) goto error;

  http = http_server_new(loop, sock, handle_request, serv);
  if (!http) goto error;

  *serv = (struct webdav_server) {
    .http = http,
    .locks = LINKED_LIST_INITIALIZER,
    .fs = fs,
    .public_uri_root = public_uri_root_copy,
    .internal_root = internal_root_copy,
  };

  return serv;

 error:
  if (http) {
    const bool success_http_destroy = http_server_destroy(http);
    if (!success_http_destroy) {
      log_error("error while trying to destroy http server, leaking...");
    }
  }
  free(serv);
  free(public_uri_root_copy);
  free(internal_root_copy);

  return NULL;
}

bool
webdav_server_destroy(webdav_server_t ws) {
  struct webdav_server *serv = ws;

  const bool success_http_destroy = http_server_destroy(serv->http);
  if (!success_http_destroy) return false;

  linked_list_free(serv->locks, free_webdav_lock_descriptor);
  free(serv->public_uri_root);
  free(serv->internal_root);

  free(serv);

  return true;
}

bool
webdav_server_start(webdav_server_t ws) {
  return http_server_start(ws->http);
}

bool
webdav_server_stop(webdav_server_t ws) {
  return http_server_stop(ws->http);
}

void
webdav_server_disconnect_existing_clients(webdav_server_t ws) {
  return http_server_disconnect_existing_clients(ws->http);
}

/* private api, specifically helper functions for the xml implementation */

webdav_propfind_entry_t
webdav_new_propfind_entry(const char *relative_uri,
                          webdav_resource_time_t modified_time,
                          webdav_resource_time_t creation_time,
                          bool is_collection,
                          webdav_resource_size_t length) {
  struct webdav_propfind_entry *elt = malloc(sizeof(*elt));
  if (!elt) {
    return NULL;
  }

  char *relative_uri_copy = davfuse_util_strdup(relative_uri);
  if (!relative_uri_copy) {
    free(elt);
    return NULL;
  }

  *elt = (struct webdav_propfind_entry) {
    .relative_uri = relative_uri_copy,
    .modified_time = modified_time,
    .creation_time = creation_time,
    .is_collection = is_collection,
    .length = length,
  };

  return elt;
}

void
webdav_destroy_propfind_entry(struct webdav_propfind_entry *pfe) {
  free(pfe->relative_uri);
  free(pfe);
}

WebdavProperty *
create_webdav_property(const char *element_name, const char *ns_href) {
  EASY_ALLOC(WebdavProperty, elt);

  elt->element_name = davfuse_util_strdup(element_name);
  elt->ns_href = davfuse_util_strdup(ns_href);

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

  name_dup = davfuse_util_strdup(name);
  if (!name_dup) {
    goto error;
  }

  ns_href_dup = davfuse_util_strdup(ns_href);
  if (!ns_href_dup) {
    goto error;
  }

  if (value) {
    value_dup = davfuse_util_strdup(value);
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

const char *
webdav_error_to_string(webdav_error_t error) {
#define _EV(e) case e: return #e
  switch (error) {
    _EV(WEBDAV_ERROR_NONE);
    _EV(WEBDAV_ERROR_GENERAL);
    _EV(WEBDAV_ERROR_NO_MEM);
    _EV(WEBDAV_ERROR_IS_COL);
    _EV(WEBDAV_ERROR_DOES_NOT_EXIST);
    _EV(WEBDAV_ERROR_NOT_COLLECTION);
    _EV(WEBDAV_ERROR_DESTINATION_DOES_NOT_EXIST);
    _EV(WEBDAV_ERROR_DESTINATION_NOT_COLLECTION);
    _EV(WEBDAV_ERROR_DESTINATION_EXISTS);
    _EV(WEBDAV_ERROR_PERM);
    _EV(WEBDAV_ERROR_NO_SPACE);
    _EV(WEBDAV_ERROR_EXISTS);
  default: assert(false); return NULL;
  }
}
