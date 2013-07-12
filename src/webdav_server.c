/*
  A webdav compatible http file server out of the current directory
*/
#define _ISOC99_SOURCE

/* replace this by something that is X-platform */
#include <sys/time.h>

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "events.h"
#include "http_helpers.h"
#include "http_server.h"
#include "logging.h"
#include "uthread.h"
#include "util.h"

#include "webdav_server.h"

#define XMLSTR(a) ((const xmlChar *) (a))
#define STR(a) ((const char *) (a))

static const char *const DAV_XML_NS = "DAV:";

static const char *const WEBDAV_HEADER_DEPTH = "Depth";
static const char *const WEBDAV_HEADER_DESTINATION = "Destination";
static const char *const WEBDAV_HEADER_IF = "If";
static const char *const WEBDAV_HEADER_LOCK_TOKEN = "Lock-Token";
static const char *const WEBDAV_HEADER_OVERWRITE = "Overwrite";
static const char *const WEBDAV_HEADER_TIMEOUT = "Timeout";

enum {
  BUF_SIZE=4096,
};

typedef enum {
  PROPFIND_PROP,
  PROPFIND_ALLPROP,
  PROPFIND_PROPNAME,
} propfind_req_type_t;

typedef enum {
  XML_PARSE_ERROR_NONE,
  XML_PARSE_ERROR_SYNTAX,
  XML_PARSE_ERROR_STRUCTURE,
  XML_PARSE_ERROR_INTERNAL,
} xml_parse_code_t;

typedef unsigned webdav_timeout_t;

typedef struct {
  char *element_name;
  char *ns_href;
} WebdavProperty;

typedef struct {
  char *path;
  webdav_depth_t depth;
  bool is_exclusive;
  char *owner_xml;
  char *lock_token;
  webdav_timeout_t timeout_in_seconds;
} WebdavLockDescriptor;

struct webdav_fs {
  WebdavOperations *op;
  void *user_data;
};

struct webdav_server {
  HTTPServer http;
  FDEventLoop *loop;
  linked_list_t locks;
  webdav_fs_t fs;
  char *public_prefix;
};

struct handler_context {
  UTHR_CTX_BASE;
  struct webdav_server *serv;
  HTTPRequestHeaders rhs;
  HTTPResponseHeaders resp;
  http_request_handle_t rh;
  union {
    struct copy_context {
      coroutine_position_t pos;
      bool is_move;
      webdav_depth_t depth;
      char *response_body;
      size_t response_body_len;
      WebdavFileInfo src_file_info;
      WebdavFileInfo dst_file_info;
      char *dst_relative_uri;
      char *src_relative_uri;
      bool dst_existed;
    } copy;
    struct delete_context {
      coroutine_position_t pos;
      char *response_body;
      size_t response_body_len;
      char *request_relative_uri;
    } delete;
    struct get_context {
      coroutine_position_t pos;
      char buf[BUF_SIZE];
      void *file_handle;
      char *resource_uri;
    } get;
    struct lock_context {
      coroutine_position_t pos;
      char *response_body;
      size_t response_body_len;
      char *request_body;
      size_t request_body_len;
      linked_list_t headers;
      char *file_path;
      char *owner_xml;
      char *resource_tag;
      char *resource_tag_path;
      char *refresh_uri;
      bool is_locked;
      const char *lock_token;
      const char *status_path;
      bool is_exclusive;
      webdav_depth_t depth;
      bool created;
      webdav_timeout_t timeout_in_seconds;
    } lock;
    struct mkcol_context {
      coroutine_position_t pos;
      char *request_relative_uri;
    } mkcol;
    struct propfind_context {
      coroutine_position_t pos;
      char scratch_buf[BUF_SIZE];
      char *buf;
      size_t buf_used, buf_size;
      char *out_buf;
      size_t out_buf_size;
      linked_list_t props_to_get;
      propfind_req_type_t propfind_req_type;
    } propfind;
    struct {
      coroutine_position_t pos;
      char *request_body;
      size_t request_body_size;
      char *response_body;
      size_t response_body_size;
    } proppatch;
    struct put_context {
      coroutine_position_t pos;
      char *request_relative_uri;
      bool resource_existed;
      char read_buf[BUF_SIZE];
      void *file_handle;
      char *response_body;
      size_t response_body_len;
      size_t amount_read;
      size_t amount_written;
    } put;
    struct {
      coroutine_position_t pos;
      char *response_body;
      size_t response_body_len;
    } unlock;
  } sub;
};

typedef struct {
  webdav_error_t error;
  WebdavFileInfo file_info;
} WebdavStatDoneEvent;

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  webdav_fs_t fs;
  const char *relative_uri;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
  WebdavStatDoneEvent ev;
  void *file_handle;
} WebdavFsStatCtx;

static
UTHR_DEFINE(webdav_fs_stat_uthr) {
  UTHR_HEADER(WebdavFsStatCtx, ctx);

  ctx->file_handle = NULL;

  bool should_create = false;
  UTHR_YIELD(ctx,
             webdav_fs_open(ctx->fs, ctx->relative_uri, should_create,
                            webdav_fs_stat_uthr, ctx));
  UTHR_RECEIVE_EVENT(WEBDAV_OPEN_DONE_EVENT, WebdavOpenDoneEvent, open_done_ev);
  if (open_done_ev->error) {
    log_info("Couldn't open file (%s): %d",
             ctx->relative_uri,
             open_done_ev->error);
    ctx->ev.error = open_done_ev->error;
    goto done;
  }

  ctx->file_handle = open_done_ev->file_handle;

  UTHR_YIELD(ctx,
             webdav_fs_fstat(ctx->fs, ctx->file_handle,
                             webdav_fs_stat_uthr, ctx));
  UTHR_RECEIVE_EVENT(WEBDAV_FSTAT_DONE_EVENT, WebdavFstatDoneEvent, fstat_done_ev);
  if (fstat_done_ev->error) {
    log_info("Couldn't fstat file (%s): %d",
             ctx->relative_uri,
             fstat_done_ev->error);
    ctx->ev.error = fstat_done_ev->error;
    goto done;
  }

  /* save file info */
  ctx->ev.error = WEBDAV_ERROR_NONE;
  ctx->ev.file_info = fstat_done_ev->file_info;

 done:
  if (ctx->file_handle) {
    UTHR_YIELD(ctx,
               webdav_fs_close(ctx->fs, ctx->file_handle,
                               webdav_fs_stat_uthr, ctx));
    UTHR_RECEIVE_EVENT(WEBDAV_CLOSE_DONE_EVENT, WebdavCloseDoneEvent, close_done_ev);
    if (close_done_ev->error) {
      /* this kind of error is intolerable */
      log_critical("Couldn't close webdav file (%s): %d",
                   close_done_ev->error,
                   ctx->relative_uri);
      abort();
    }
  }

  UTHR_RETURN(ctx,
              ctx->cb(WEBDAV_STAT_DONE_EVENT, &ctx->ev, ctx->cb_ud));

  UTHR_FOOTER();
}

static void
webdav_fs_stat(webdav_fs_t fs,
               const char *relative_uri,
               event_handler_t cb, void *cb_ud) {
  UTHR_CALL4(webdav_fs_stat_uthr, WebdavFsStatCtx,
             .fs = fs,
             .relative_uri = relative_uri,
             .cb = cb,
             .cb_ud = cb_ud);
}

typedef struct {
  webdav_error_t error;
} WebdavTouchDoneEvent;

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  webdav_fs_t fs;
  const char *relative_uri;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
  WebdavTouchDoneEvent ev;
} WebdavFsTouchCtx;

static
UTHR_DEFINE(webdav_fs_touch_uthr) {
  UTHR_HEADER(WebdavFsTouchCtx, ctx);

  bool create_file = true;
  UTHR_YIELD(ctx,
             webdav_fs_open(ctx->fs, ctx->relative_uri, create_file,
                            webdav_fs_touch_uthr, ctx));
  UTHR_RECEIVE_EVENT(WEBDAV_OPEN_DONE_EVENT, WebdavOpenDoneEvent, open_done_ev);
  ctx->ev.error = open_done_ev->error;

  UTHR_YIELD(ctx,
             webdav_fs_close(ctx->fs, open_done_ev->file_handle,
                             webdav_fs_touch_uthr, ctx));
  UTHR_RECEIVE_EVENT(WEBDAV_CLOSE_DONE_EVENT, WebdavCloseDoneEvent, close_done_ev);

  if (close_done_ev->error) {
    /* failing on a close is unacceptable */
    abort();
  }

  UTHR_RETURN(ctx,
              ctx->cb(WEBDAV_TOUCH_DONE_EVENT, &ctx->ev, ctx->cb_ud));

  UTHR_FOOTER();
}

static void
webdav_fs_touch(webdav_fs_t fs,
                const char *relative_uri,
                event_handler_t cb, void *cb_ud) {
  UTHR_CALL4(webdav_fs_touch_uthr, WebdavFsTouchCtx,
             .fs = fs,
             .relative_uri = relative_uri,
             .cb = cb,
             .cb_ud = cb_ud);
}

static EVENT_HANDLER_DECLARE(handle_request);
static EVENT_HANDLER_DECLARE(handle_copy_request);
static EVENT_HANDLER_DECLARE(handle_delete_request);
static EVENT_HANDLER_DECLARE(handle_get_request);
static EVENT_HANDLER_DECLARE(handle_lock_request);
static EVENT_HANDLER_DECLARE(handle_mkcol_request);
static EVENT_HANDLER_DECLARE(handle_options_request);
static EVENT_HANDLER_DECLARE(handle_propfind_request);
static EVENT_HANDLER_DECLARE(handle_proppatch_request);
static EVENT_HANDLER_DECLARE(handle_put_request);
static EVENT_HANDLER_DECLARE(handle_unlock_request);

static WebdavProperty *
create_webdav_property(const char *element_name, const char *ns_href) {
  EASY_ALLOC(WebdavProperty, elt);

  elt->element_name = strdup_x(element_name);
  elt->ns_href = strdup_x(ns_href);

  return elt;
}

static void
free_webdav_property(WebdavProperty *wp) {
  free(wp->element_name);
  free(wp->ns_href);
  free(wp);
}

static bool PURE_FUNCTION
xml_str_equals(const xmlChar *restrict a, const char *restrict b) {
  return str_equals((const char *) a, b);
}

static char *
path_from_uri(struct handler_context *hc, const char *uri) {
  const char *real_uri;

  if (uri[0] != '/') {
    if (!str_startswith(uri, hc->serv->public_prefix)) {
      return NULL;
    }
    /* -1 to account for and incorporate the trailing slash */
    real_uri = &uri[strlen(hc->serv->public_prefix) - 1];
  }
  else {
    real_uri = uri;
  }

  /* if uri ends with '/' shave it off */
  size_t len = strlen(real_uri);
  if (real_uri[len - 1] == '/') {
    len -= 1;
  }

  /* TODO: de-urlencode `real_uri` */
  return strndup_x(real_uri, len);
}

static char *
uri_from_path(struct handler_context *hc, const char *path) {
  /* TODO: urlencode `path` */
  assert(path[0] == '/');

  /* NB: we intentionally do not use `asprintf()` */

  size_t public_prefix_len = strlen(hc->serv->public_prefix);
  size_t path_len = strlen(path) - 1;

  char *real_uri = malloc(public_prefix_len + path_len + 1);
  if (!real_uri) {
    return NULL;
  }

  memcpy(real_uri, hc->serv->public_prefix, public_prefix_len);
  memcpy(real_uri + public_prefix_len, path, path_len);
  real_uri[public_prefix_len + path_len] = '\0';

  return real_uri;
}

static webdav_depth_t
webdav_get_depth(const HTTPRequestHeaders *rhs) {
  webdav_depth_t depth;

  const char *depth_str = http_get_header_value(rhs, WEBDAV_HEADER_DEPTH);
  if (!depth_str || !strcasecmp(depth_str, "infinity")) {
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
webdav_get_if_lock_token(const HTTPRequestHeaders *rhs, char **resource_tag, char **lock_token) {
  const char *if_header = http_get_header_value(rhs, WEBDAV_HEADER_IF);
  if (!if_header) {
    return IF_LOCK_TOKEN_ERR_DOESNT_EXIST;
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
      return IF_LOCK_TOKEN_ERR_BAD_PARSE;
    }

    size_t len_of_uri = end_of_uri - (if_header + i);
    *resource_tag =
      strndup_x(if_header + i, len_of_uri);

    if (!*resource_tag) {
      return IF_LOCK_TOKEN_ERR_INTERNAL;
    }

    /* skip resource tag */
    i += len_of_uri + 1;
    i = skip_bnf_lws(if_header, i);
  }
  else {
    /* no resource tag passed in, this lock token is related to the method uri */
    *resource_tag = strdup_x(rhs->uri);
  }

  /* get left paren */
  if (if_header[i++] != ASCII_LEFT_PAREN) {
    free(*resource_tag);
    return IF_LOCK_TOKEN_ERR_BAD_PARSE;
  }

  i = skip_bnf_lws(if_header, i);

  /* get left bracket */
  if (if_header[i++] != ASCII_LEFT_BRACKET) {
    free(*resource_tag);
    return IF_LOCK_TOKEN_ERR_BAD_PARSE;
  }

  /* read uri */
  const char *end_of_uri = strchr(if_header + i, ASCII_RIGHT_BRACKET);
  if (!end_of_uri) {
    free(*resource_tag);
    return IF_LOCK_TOKEN_ERR_BAD_PARSE;
  }
  *lock_token =
    strndup_x(if_header + i, end_of_uri - (if_header + i));
  if (!*lock_token) {
    free(*resource_tag);
    return IF_LOCK_TOKEN_ERR_INTERNAL;
  }

  return IF_LOCK_TOKEN_ERR_SUCCESS;
}

static PURE_FUNCTION bool
is_parent_path(const char *potential_parent, const char *potential_child) {
  assert(potential_parent[strlen(potential_parent) - 1] != '/');
  assert(potential_child[strlen(potential_child) - 1] != '/');
  return (str_startswith(potential_child, potential_parent) &&
          potential_child[strlen(potential_parent)] == '/');
}

static bool
perform_write_lock(struct webdav_server *ws,
                   const char *file_path,
                   webdav_timeout_t timeout_in_seconds,
                   webdav_depth_t depth,
                   bool is_exclusive,
                   const char *owner_xml,
                   bool *is_locked,
                   const char **lock_token,
                   const char **status_path) {
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
      /* if the strdup_x failed then we return false */
      return *status_path;
    }
  }

  /* generate a lock token */
  struct timeval curtime;
  int ret = gettimeofday(&curtime, NULL);
  if (ret < 0 ) {
    return false;
  }

  char s_lock_token[256];
  int len = snprintf(s_lock_token, sizeof(s_lock_token), "x-this-lock-token:///%lld.%lld",
                     (long long) curtime.tv_sec, (long long) curtime.tv_usec);
  if (len == sizeof(s_lock_token) - 1) {
    /* lock token string was too long */
    return false;
  }

  /* okay we can lock this path, just add it to the lock list */
  EASY_ALLOC(WebdavLockDescriptor, new_lock);

  *new_lock = (WebdavLockDescriptor) {
    .path = strdup_x(file_path),
    .depth = depth,
    .is_exclusive = is_exclusive,
    .owner_xml = strdup_x(owner_xml),
    .lock_token = strdup_x(s_lock_token),
    .timeout_in_seconds = timeout_in_seconds,
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

  for (linked_list_t *llp = &ws->locks; *llp; llp = &(*llp)->next) {
    WebdavLockDescriptor *elt = (*llp)->elt;
    if (str_equals(elt->path, file_path) &&
        str_equals(elt->lock_token, lock_token)) {
      WebdavLockDescriptor *popped_elt = linked_list_pop_link(llp);
      free(popped_elt);
      *unlocked = true;
      break;
    }
  }

  return true;
}

static bool
refresh_lock(struct webdav_server *ws,
             const char *file_path, const char *lock_token,
             webdav_timeout_t new_timeout,
             bool *refreshed,
             char **owner_xml, bool *is_exclusive,
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
                   const char **locked_lock_token) {
  *is_locked = false;

  LINKED_LIST_FOR (WebdavLockDescriptor, elt, ws->locks) {
    if (str_equals(elt->path, file_path) ||
        (elt->depth == DEPTH_INF &&
         is_parent_path(elt->path, file_path))) {
      *is_locked = true;
      *locked_path = elt->path;
      *locked_lock_token = elt->lock_token;
      break;
    }
  }

  return true;
}

static bool
are_any_descendants_locked(struct webdav_server *ws,
                           const char *file_path,
                           bool *is_descendant_locked,
                           const char **locked_descendant) {
  *is_descendant_locked = false;

  LINKED_LIST_FOR (WebdavLockDescriptor, elt, ws->locks) {
    if (is_parent_path(file_path, elt->path)) {
      *is_descendant_locked = true;
      *locked_descendant = elt->path;
      break;
    }
  }

  return true;
}

static PURE_FUNCTION bool
ns_equals(xmlNodePtr elt, const char *href) {
  return (elt->ns &&
          str_equals(STR(elt->ns->href), href));
}

static PURE_FUNCTION bool
node_is(xmlNodePtr elt, const char *href, const char *tag) {
  return ((elt->ns ? str_equals(STR(elt->ns->href), href) : !href) &&
          str_equals(STR(elt->name), tag));
}

static xmlDocPtr
parse_xml_string(const char *req_data, size_t req_data_length) {
  xmlParserOption options = (XML_PARSE_COMPACT |
                             XML_PARSE_NOBLANKS |
                             XML_PARSE_NONET |
                             XML_PARSE_PEDANTIC);
#ifdef NDEBUG
  options |= XML_PARSE_NOERROR | XML_PARSER_NOWARNING;
#endif
  xmlResetLastError();
  xmlDocPtr doc = xmlReadMemory(req_data, req_data_length,
                                "noname.xml", NULL, options);
  if (!doc) {
    /* bad xml */
    return doc;
  }

  if (xmlGetLastError()) {
    xmlFreeDoc(doc);
    doc = NULL;
  }

  return doc;
}

static xml_parse_code_t
parse_propfind_request(const char *req_data,
                       size_t req_data_length,
                       propfind_req_type_t *out_propfind_req_type,
                       linked_list_t *out_props_to_get) {
  xml_parse_code_t toret;
  xmlDocPtr doc = NULL;
  *out_props_to_get = LINKED_LIST_INITIALIZER;

  /* process the type of prop request */
  if (!req_data) {
    *out_propfind_req_type = PROPFIND_ALLPROP;
  }
  else {
    doc = parse_xml_string(req_data, req_data_length);
    if (!doc) {
      /* TODO: could probably get a higher fidelity error */
      toret = XML_PARSE_ERROR_SYNTAX;
      goto done;
    }

    /* the root element should be DAV:propfind */
    xmlNodePtr root_element = xmlDocGetRootElement(doc);
    if (!(xml_str_equals(root_element->name, "propfind") &&
          root_element->ns &&
          xml_str_equals(root_element->ns->href, DAV_XML_NS))) {
      /* root element is not propfind, this is bad */
      log_info("root element is not DAV:, propfind");
      toret = XML_PARSE_ERROR_STRUCTURE;
      goto done;
    }
    log_debug("root element name: %s", root_element->name);

    /* check if this is prop, allprop, or propname request */
    xmlNodePtr first_child = root_element->children;
    if (node_is(first_child, DAV_XML_NS, "propname")) {
      *out_propfind_req_type = PROPFIND_PROPNAME;
    }
    else if (node_is(first_child, DAV_XML_NS, "allprop")) {
      *out_propfind_req_type = PROPFIND_ALLPROP;
    }
    else if (node_is(first_child, DAV_XML_NS, "prop")) {
      *out_propfind_req_type = PROPFIND_PROP;
      for (xmlNodePtr prop_elt = first_child->children;
           prop_elt; prop_elt = prop_elt->next) {
        *out_props_to_get = linked_list_prepend(*out_props_to_get,
                                                create_webdav_property((const char *) prop_elt->name,
                                                                       (const char *) prop_elt->ns->href));
      }
    }
    else {
      log_info("Invalid propname child: %s", first_child->name);
      toret = XML_PARSE_ERROR_STRUCTURE;
      goto done;
    }
  }

  toret = XML_PARSE_ERROR_NONE;

 done:
  if (toret) {
    linked_list_free(*out_props_to_get, (linked_list_elt_handler_t) free_webdav_property);
  }

  if (doc) {
    xmlFreeDoc(doc);
  }

  return toret;
}

typedef struct {
  WebdavFileInfo file_info;
  char *path;
} WebdavPropfindEntry;

static void
free_webdav_propfind_entry(WebdavPropfindEntry *pfe) {
  free(pfe->path);
  free(pfe);
}

typedef struct {
  bool error;
  linked_list_t entries;
} RunPropfindDoneEvent;

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  struct handler_context *hc;
  const char *uri;
  webdav_depth_t depth;
  propfind_req_type_t propfind_req_type;
  linked_list_t props_to_get;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
  RunPropfindDoneEvent ev;
  char *relative_uri;
  void *handle;
  WebdavCollectionEntry ce[1];
  int i;
} RunPropfindCtx;

static
UTHR_DEFINE(run_propfind_uthr) {
  UTHR_HEADER(RunPropfindCtx, ctx);

  ctx->relative_uri = path_from_uri(ctx->hc, ctx->uri);
  if (!ctx->relative_uri) {
    log_info("Couldn't make file path from %s", ctx->uri);
    ctx->ev.error = true;
    goto done;
  }

  /* open the resource */
  bool create_resource = false;
  UTHR_YIELD(ctx,
             webdav_fs_open(ctx->hc->serv->fs,
                            ctx->relative_uri, create_resource,
                            run_propfind_uthr, ctx));
  UTHR_RECEIVE_EVENT(WEBDAV_OPEN_DONE_EVENT, WebdavOpenDoneEvent, open_done_ev);
  if (open_done_ev->error) {
    ctx->ev.error = open_done_ev->error != WEBDAV_ERROR_DOES_NOT_EXIST;
    ctx->ev.entries = LINKED_LIST_INITIALIZER;
    goto done;
  }

  ctx->handle = open_done_ev->file_handle;

  /* first get info for root element */
  UTHR_YIELD(ctx,
             webdav_fs_fstat(ctx->hc->serv->fs, ctx->handle,
                             run_propfind_uthr, ctx));
  UTHR_RECEIVE_EVENT(WEBDAV_FSTAT_DONE_EVENT, WebdavFstatDoneEvent, fstat_done_ev);
  if (fstat_done_ev->error) {
    ctx->ev.error = true;
    goto done;
  }

  WebdavPropfindEntry *pfe = malloc(sizeof(*pfe));
  ASSERT_NOT_NULL(pfe);
  pfe->file_info = fstat_done_ev->file_info;
  pfe->path = strdup_x(ctx->relative_uri);

  ctx->ev.entries = linked_list_prepend(ctx->ev.entries, pfe);

  if (ctx->depth == DEPTH_1 &&
      fstat_done_ev->file_info.is_collection) {
    while (true) {
      UTHR_YIELD(ctx,
                 webdav_fs_readcol(ctx->hc->serv->fs, ctx->handle, ctx->ce, NELEMS(ctx->ce),
                                   run_propfind_uthr, ctx));
      UTHR_RECEIVE_EVENT(WEBDAV_READCOL_DONE_EVENT, WebdavReadcolDoneEvent, readcol_done_ev);
      if (readcol_done_ev->error) {
        ctx->ev.error = true;
        goto done;
      }

      for (ctx->i = 0; ctx->i < (int) NELEMS(ctx->ce); ++ctx->i) {
        WebdavCollectionEntry *ce = &ctx->ce[ctx->i];
        WebdavPropfindEntry *pfe = malloc(sizeof(*pfe));
        ASSERT_NOT_NULL(pfe);
        pfe->file_info = ce->file_info;

        /* TODO: move this out of the loop if it matters,
           although optimization should be smart enough */
        size_t relative_uri_len = strlen(ctx->relative_uri);
        size_t name_len = strlen(ce->name);

        /* NB: intentionally don't use `asprintf()` */
        pfe->path = malloc(relative_uri_len + 1 + name_len + 1);
        if (!pfe->path) { abort(); }
        memcpy(pfe->path, ctx->relative_uri, relative_uri_len);
        pfe->path[relative_uri_len] = '/';
        memcpy(pfe->path + relative_uri_len + 1, ce->name, name_len);
        pfe->path[relative_uri_len + 1 + name_len] = '\0';

        ctx->ev.entries = linked_list_prepend(ctx->ev.entries, pfe);
      }
    }
  }

  ctx->ev.error = false;

 done:
  if (ctx->ev.error) {
    linked_list_free(ctx->ev.entries,
                     (linked_list_elt_handler_t) free_webdav_propfind_entry);
  }

  if (ctx->handle) {
    UTHR_YIELD(ctx,
               webdav_fs_close(ctx->hc->serv->fs, ctx->handle,
                               run_propfind_uthr, ctx));
    UTHR_RECEIVE_EVENT(WEBDAV_CLOSE_DONE_EVENT, WebdavCloseDoneEvent, close_done_ev);
    if (close_done_ev->error) {
      abort();
    }
  }

  free(ctx->relative_uri);

  UTHR_RETURN(ctx,
              ctx->cb(RUN_PROPFIND_DONE_EVENT, &ctx->ev, ctx->cb_ud));

  UTHR_FOOTER();
}

static void
run_propfind(struct handler_context *hc,
             const char *uri, webdav_depth_t depth,
             propfind_req_type_t propfind_req_type,
             linked_list_t props_to_get,
             event_handler_t cb, void *cb_ud) {
  UTHR_CALL7(run_propfind_uthr, RunPropfindCtx,
             .hc = hc,
             .uri = uri,
             .depth = depth,
             .propfind_req_type = propfind_req_type,
             .props_to_get = props_to_get,
             .cb = cb,
             .cb_ud = cb_ud);
}

static bool
generate_propfind_response(struct handler_context *hc,
                           linked_list_t props_to_get,
                           linked_list_t entries,
                           char **out_data,
                           size_t *out_size,
                           http_status_code_t *out_status_code) {
  xmlDocPtr xml_response = xmlNewDoc(XMLSTR("1.0"));
  ASSERT_NOT_NULL(xml_response);
  xmlNodePtr multistatus_elt = xmlNewDocNode(xml_response, NULL, XMLSTR("multistatus"), NULL);
  ASSERT_NOT_NULL(multistatus_elt);
  xmlDocSetRootElement(xml_response, multistatus_elt);

  xmlNsPtr dav_ns = xmlNewNs(multistatus_elt, XMLSTR(DAV_XML_NS), XMLSTR("D"));
  assert(dav_ns);
  xmlSetNs(multistatus_elt, dav_ns);

  /* TODO: deal with the case where entries == NULL */
  LINKED_LIST_FOR (WebdavPropfindEntry, propfind_entry, entries) {
    xmlNodePtr response_elt = xmlNewChild(multistatus_elt, dav_ns, XMLSTR("response"), NULL);
    assert(response_elt);

    char *uri = uri_from_path(hc, propfind_entry->path);
    ASSERT_NOT_NULL(uri);
    xmlNodePtr href_elt = xmlNewTextChild(response_elt, dav_ns,
                                          XMLSTR("href"), XMLSTR(uri));
    assert(href_elt);
    free(uri);

    xmlNodePtr propstat_not_found_elt = xmlNewChild(response_elt, dav_ns, XMLSTR("propstat"), NULL);
    assert(propstat_not_found_elt);
    xmlNodePtr prop_not_found_elt = xmlNewChild(propstat_not_found_elt, dav_ns, XMLSTR("prop"), NULL);
    assert(prop_not_found_elt);
    xmlNodePtr status_not_found_elt = xmlNewTextChild(propstat_not_found_elt, dav_ns,
                                                      XMLSTR("status"),
                                                      XMLSTR("HTTP/1.1 404 Not Found"));
    assert(status_not_found_elt);

    xmlNodePtr propstat_success_elt = xmlNewChild(response_elt, dav_ns, XMLSTR("propstat"), NULL);
    assert(propstat_success_elt);
    xmlNodePtr prop_success_elt = xmlNewChild(propstat_success_elt, dav_ns, XMLSTR("prop"), NULL);
    assert(propstat_success_elt);
    xmlNodePtr status_success_elt = xmlNewTextChild(propstat_success_elt, dav_ns,
                                                    XMLSTR("status"),
                                                    XMLSTR("HTTP/1.1 200 OK"));
    assert(status_success_elt);

    xmlNodePtr propstat_failure_elt = xmlNewChild(response_elt, dav_ns, XMLSTR("propstat"), NULL);
    assert(propstat_failure_elt);
    xmlNodePtr prop_failure_elt = xmlNewChild(propstat_failure_elt, dav_ns, XMLSTR("prop"), NULL);
    assert(prop_failure_elt);
    xmlNodePtr status_failure_elt = xmlNewTextChild(propstat_failure_elt, dav_ns,
                                                    XMLSTR("status"),
                                                    XMLSTR("HTTP/1.1 500 Internal Server Error"));
    assert(status_failure_elt);

    LINKED_LIST_FOR (WebdavProperty, elt, props_to_get) {
      bool is_get_last_modified;
      if (str_equals(elt->ns_href, DAV_XML_NS) &&
          ((is_get_last_modified = str_equals(elt->element_name, "getlastmodified")) ||
           /* TODO: this should be configurable but for now we just
              set getlastmodified and creationdate to the same date
              because that's what apache mod_dav does */
           str_equals(elt->element_name, "creationdate"))) {
        time_t m_time = (time_t) propfind_entry->file_info.modified_time;
        struct tm *tm_ = gmtime(&m_time);
        char time_buf[400], *time_str;

        char *fmt = is_get_last_modified
          ? "%a, %d %b %Y %T GMT"
          : "%Y-%m-%dT%H:%M:%S-00:00";

        size_t num_chars = strftime(time_buf, sizeof(time_buf), fmt, tm_);
        xmlNodePtr xml_node;

        if (!num_chars) {
          log_error("strftime failed!");
          time_str = NULL;
          xml_node = prop_failure_elt;
        }
        else {
          time_str = time_buf;
          xml_node = prop_success_elt;
        }

        xmlNodePtr getlastmodified_elt = xmlNewTextChild(xml_node, dav_ns,
                                                         XMLSTR(elt->element_name), XMLSTR(time_str));
        assert(getlastmodified_elt);
      }
      else if (str_equals(elt->element_name, "getcontentlength") &&
               str_equals(elt->ns_href, DAV_XML_NS) &&
               !propfind_entry->file_info.is_collection) {
        char length_str[400];
        snprintf(length_str, sizeof(length_str), "%lld",
                 (long long) propfind_entry->file_info.length);
        xmlNodePtr getcontentlength_elt = xmlNewTextChild(prop_success_elt, dav_ns,
                                                          XMLSTR("getcontentlength"), XMLSTR(length_str));
        assert(getcontentlength_elt);
      }
      else if (str_equals(elt->element_name, "resourcetype") &&
               str_equals(elt->ns_href, DAV_XML_NS)) {
        xmlNodePtr resourcetype_elt = xmlNewChild(prop_success_elt, dav_ns,
                                                  XMLSTR("resourcetype"), NULL);
        assert(resourcetype_elt);

        if (propfind_entry->file_info.is_collection) {
          xmlNodePtr collection_elt = xmlNewChild(resourcetype_elt, dav_ns,
                                                  XMLSTR("collection"), NULL);
          assert(collection_elt);
        }
      }
      else {
        xmlNodePtr random_elt = xmlNewChild(prop_not_found_elt, NULL,
                                            XMLSTR(elt->element_name), NULL);
        ASSERT_NOT_NULL(random_elt);
        xmlNsPtr new_ns = xmlNewNs(random_elt, XMLSTR(elt->ns_href), NULL);
        xmlSetNs(random_elt, new_ns);
      }
    }

    if (!prop_not_found_elt->children) {
      xmlUnlinkNode(propstat_not_found_elt);
      xmlFreeNode(propstat_not_found_elt);
    }

    if (!prop_success_elt->children) {
      xmlUnlinkNode(propstat_success_elt);
      xmlFreeNode(propstat_success_elt);
    }

    if (!prop_failure_elt->children) {
      xmlUnlinkNode(propstat_failure_elt);
      xmlFreeNode(propstat_failure_elt);
    }
  }

  /* convert doc to text and send to client */
  xmlChar *out_buf;
  int out_buf_size;
  int format_xml = 1;
  xmlDocDumpFormatMemory(xml_response, &out_buf, &out_buf_size, format_xml);
  *out_data = (char *) out_buf;
  assert(out_buf_size >= 0);
  *out_size = out_buf_size;
  *out_status_code = HTTP_STATUS_CODE_MULTI_STATUS;

  if (xml_response) {
    xmlFreeDoc(xml_response);
  }

  return true;
}

static bool
generate_locked_response(struct handler_context *hc,
                         const char *locked_path,
                         http_status_code_t *status_code,
                         char **response_body,
                         size_t *response_body_len);

static bool
generate_locked_descendant_response(struct handler_context *hc,
                                    const char *locked_descendant,
                                    http_status_code_t *status_code,
                                    char **response_body,
                                    size_t *response_body_len);

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
  const char *locked_path;
  const char *locked_lock_token;
  bool is_locked;
  bool success_locked =
    is_resource_locked(hc->serv, fpath, &is_locked, &locked_path, &locked_lock_token);
  if (!success_locked) {
    *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    return;
  }

  char *lock_token_fpath = NULL;
  if (if_lock_token_err == IF_LOCK_TOKEN_ERR_SUCCESS) {
    lock_token_fpath = path_from_uri(hc, lock_resource_tag);
  }

  if (is_locked &&
      (if_lock_token_err != IF_LOCK_TOKEN_ERR_SUCCESS ||
       !str_equals(lock_token_fpath, locked_path) ||
       !str_equals(locked_lock_token, lock_token))) {
    /* this is locked, fail */
    bool success_generate =
      generate_locked_response(hc, locked_path,
                               status_code,
                               response_body,
                               response_body_len);
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
    webdav_get_if_lock_token(&hc->rhs, &lock_resource, &lock_token);

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
    webdav_get_if_lock_token(&hc->rhs, &lock_resource, &lock_token);

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

  if (!status_code) {
    /* check if any descendant is locked */
    bool is_descendant_locked;
    const char *locked_descendant;
    bool success_child_locked =
      are_any_descendants_locked(hc->serv, fpath,
                                 &is_descendant_locked, &locked_descendant);
    if (!success_child_locked) {
      *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
      goto done;
    }

    if (is_descendant_locked) {
      bool success_generate =
        generate_locked_descendant_response(hc, locked_descendant,
                                            status_code,
                                            response_body,
                                            response_body_len);
      if (!success_generate) {
        *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
      }
    }
  }

 done:
  free(lock_resource);
  free(lock_token);
}

static bool
generate_locked_response(struct handler_context *hc,
                         const char *locked_path,
                         http_status_code_t *status_code,
                         char **response_body,
                         size_t *response_body_len) {
  xmlDocPtr xml_response = xmlNewDoc(XMLSTR("1.0"));
  ASSERT_NOT_NULL(xml_response);

  xmlNodePtr error_elt = xmlNewDocNode(xml_response, NULL, XMLSTR("error"), NULL);
  ASSERT_NOT_NULL(error_elt);

  xmlDocSetRootElement(xml_response, error_elt);

  xmlNsPtr dav_ns = xmlNewNs(error_elt, XMLSTR(DAV_XML_NS), XMLSTR("D"));
  ASSERT_NOT_NULL(dav_ns);

  xmlSetNs(error_elt, dav_ns);

  xmlNodePtr lock_token_submitted_elt =
    xmlNewChild(error_elt, dav_ns, XMLSTR("lock-token-submitted"), NULL);
  ASSERT_NOT_NULL(lock_token_submitted_elt);

  char *uri = uri_from_path(hc, locked_path);
  ASSERT_NOT_NULL(uri);

  xmlNodePtr href_elt =
    xmlNewChild(error_elt, dav_ns, XMLSTR("href"), XMLSTR(uri));
  ASSERT_NOT_NULL(href_elt);

  free(uri);

  xmlChar *out_buf;
  int out_buf_size;
  int format_xml = 1;
  xmlDocDumpFormatMemory(xml_response, &out_buf, &out_buf_size, format_xml);
  *response_body = (char *) out_buf;
  assert(out_buf_size >= 0);
  *response_body_len = out_buf_size;

  xmlFreeDoc(xml_response);

  *status_code = HTTP_STATUS_CODE_LOCKED;

  return true;
}

static bool
generate_locked_descendant_response(struct handler_context *hc,
                                    const char *locked_descendant,
                                    http_status_code_t *status_code,
                                    char **response_body,
                                    size_t *response_body_len) {
  xmlDocPtr xml_response = xmlNewDoc(XMLSTR("1.0"));
  ASSERT_NOT_NULL(xml_response);

  xmlNodePtr multistatus_elt = xmlNewDocNode(xml_response, NULL, XMLSTR("multistatus"), NULL);
  ASSERT_NOT_NULL(multistatus_elt);

  xmlDocSetRootElement(xml_response, multistatus_elt);

  xmlNsPtr dav_ns = xmlNewNs(multistatus_elt, XMLSTR(DAV_XML_NS), XMLSTR("D"));
  ASSERT_NOT_NULL(dav_ns);

  xmlSetNs(multistatus_elt, dav_ns);

  xmlNodePtr response_elt = xmlNewChild(multistatus_elt, dav_ns, XMLSTR("response"), NULL);
  ASSERT_NOT_NULL(response_elt);

  char *uri = uri_from_path(hc, locked_descendant);
  ASSERT_NOT_NULL(uri);

  xmlNodePtr href_elt = xmlNewTextChild(response_elt, dav_ns, XMLSTR("href"), XMLSTR(uri));
  ASSERT_NOT_NULL(href_elt);

  free(uri);

  xmlNodePtr status_elt = xmlNewTextChild(response_elt, dav_ns, XMLSTR("status"),
                                          XMLSTR("HTTP/1.1 423 Locked"));
  ASSERT_NOT_NULL(status_elt);

  xmlNodePtr error_elt = xmlNewChild(response_elt, dav_ns, XMLSTR("error"), NULL);
  ASSERT_NOT_NULL(error_elt);

  xmlNodePtr lock_token_submitted_elt =
    xmlNewChild(error_elt, dav_ns, XMLSTR("lock-token-submitted"), NULL);
  ASSERT_NOT_NULL(lock_token_submitted_elt);

  xmlChar *out_buf;
  int out_buf_size;
  int format_xml = 1;
  xmlDocDumpFormatMemory(xml_response, &out_buf, &out_buf_size, format_xml);
  *response_body = (char *) out_buf;
  assert(out_buf_size >= 0);
  *response_body_len = out_buf_size;

  xmlFreeDoc(xml_response);

  *status_code = HTTP_STATUS_CODE_MULTI_STATUS;

  return true;
}

static
UTHR_DEFINE(request_proc) {
  UTHR_HEADER(struct handler_context, hc);

  log_info("New request!");

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
    goto done;
  }

  /* TODO: move to hash-based dispatch where each method
     maps to a different bucket
  */
  event_handler_t handler;
  if (str_case_equals(hc->rhs.method, "COPY")) {
    handler = handle_copy_request;
    hc->sub.copy.is_move = false;
  }
  else if (str_case_equals(hc->rhs.method, "DELETE")) {
    handler = handle_delete_request;
  }
  else if (str_case_equals(hc->rhs.method, "GET")) {
    handler = handle_get_request;
  }
  else if (str_case_equals(hc->rhs.method, "LOCK")) {
    handler = handle_lock_request;
  }
  else if (str_case_equals(hc->rhs.method, "MKCOL")) {
    handler = handle_mkcol_request;
  }
  else if (str_case_equals(hc->rhs.method, "MOVE")) {
    /* move is essentially copy, then delete source */
    /* allows for servers to optimize as well */
    handler = handle_copy_request;
    hc->sub.copy.is_move = true;
  }
  else if (str_case_equals(hc->rhs.method, "OPTIONS")) {
    handler = handle_options_request;
  }
  else if (str_case_equals(hc->rhs.method, "PROPFIND")) {
    handler = handle_propfind_request;
  }
  else if (str_case_equals(hc->rhs.method, "PROPPATCH")) {
    handler = handle_proppatch_request;
  }
  else if (str_case_equals(hc->rhs.method, "PUT")) {
    handler = handle_put_request;
  }
  else if (str_case_equals(hc->rhs.method, "UNLOCK")) {
    handler = handle_unlock_request;
  }
  else {
    handler = NULL;
  }

  bool ret = http_response_init(&hc->resp);
  assert(ret);

  if (handler) {
    UTHR_YIELD(hc, handler(GENERIC_EVENT, NULL, hc));
  }
  else {
    UTHR_YIELD(hc,
               http_request_string_response(hc->rh,
                                            HTTP_STATUS_CODE_NOT_IMPLEMENTED, "Not Implemented",
                                            request_proc, hc));
  }

 done:
  log_info("request done!");

  UTHR_RETURN(hc, http_request_end(hc->rh));

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
      log_debug("copy failed: " __VA_ARGS__);   \
      status_code = status_code_;               \
      goto done;                                \
    }                                           \
  }                                             \
  while (false)

  ctx->response_body = NULL;
  ctx->response_body_len = 0;
  ctx->dst_relative_uri = NULL;

  ctx->src_relative_uri = path_from_uri(hc, hc->rhs.uri);
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
  ctx->dst_relative_uri = path_from_uri(hc, destination_url);
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

  CRYIELD(ctx->pos,
          webdav_fs_stat(hc->serv->fs,
                         ctx->dst_relative_uri,
                         handle_copy_request, ud));
  assert(WEBDAV_STAT_DONE_EVENT == ev_type);
  WebdavStatDoneEvent *stat_done_ev = ev;
  ctx->dst_existed = stat_done_ev->error == WEBDAV_ERROR_NONE;

  /* overwrite */
  const char *overwrite_str = http_get_header_value(&hc->rhs, WEBDAV_HEADER_OVERWRITE);
  bool overwrite = !(overwrite_str && str_case_equals(overwrite_str, "f"));

  webdav_error_t err;
  if (ctx->is_move) {
    /* TODO: XXX: destroy all locks held for the source resource */

    CRYIELD(ctx->pos,
            webdav_fs_move(hc->serv->fs,
                           ctx->src_relative_uri, ctx->dst_relative_uri,
                           overwrite,
                           handle_copy_request, ud));
    assert(WEBDAV_MOVE_DONE_EVENT == ev_type);
    WebdavMoveDoneEvent *move_done_ev = ev;
    err = move_done_ev->error;
    linked_list_free(move_done_ev->failed_to_move, free);
  }
  else {
    CRYIELD(ctx->pos,
            webdav_fs_copy(hc->serv->fs,
                           ctx->src_relative_uri, ctx->dst_relative_uri,
                           overwrite, ctx->depth,
                           handle_copy_request, ud));
    assert(WEBDAV_COPY_DONE_EVENT == ev_type);
    WebdavCopyDoneEvent *copy_done_ev = ev;
    err = copy_done_ev->error;
    linked_list_free(copy_done_ev->failed_to_copy, free);
  }

  switch (err) {
  case WEBDAV_ERROR_NONE:
    status_code = ctx->dst_existed
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
    log_info("Error while %s \"%s\" to \"%s\": %d",
             ctx->is_move ? "moving" : "copying",
             ctx->src_relative_uri,
             ctx->dst_relative_uri,
             err);
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
                                       "application/xml",
                                       LINKED_LIST_INITIALIZER,
                                       handle_copy_request, hc));

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
  struct delete_context *ctx = &hc->sub.delete;
  http_status_code_t status_code = 0;

  CRBEGIN(ctx->pos);

  ctx->response_body = NULL;
  ctx->response_body_len = 0;

  ctx->request_relative_uri = path_from_uri(hc, hc->rhs.uri);
  if (!ctx->request_relative_uri) {
    log_info("Couldn't make file path from %s", hc->rhs.uri);
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  CRYIELD(ctx->pos,
          webdav_fs_stat(hc->serv->fs,
                         ctx->request_relative_uri,
                         handle_delete_request, ud));
  assert(WEBDAV_STAT_DONE_EVENT == ev_type);
  WebdavStatDoneEvent *stat_done_ev = ev;
  if (stat_done_ev->error == WEBDAV_ERROR_NONE) {
    /* check that we can "unlink" this path */
    can_unlink_path(hc, ctx->request_relative_uri,
                    &status_code,
                    &ctx->response_body,
                    &ctx->response_body_len);
    if (status_code) {
      goto done;
    }

    CRYIELD(ctx->pos,
            webdav_fs_delete(hc->serv->fs,
                             ctx->request_relative_uri,
                             handle_delete_request, ud));
    assert(WEBDAV_DELETE_DONE_EVENT == ev_type);
    WebdavDeleteDoneEvent *delete_done_ev = ev;

    if (delete_done_ev->error) {
      status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
      goto done;
    }

    /* TODO: return multi-status */
    if (delete_done_ev->failed_to_delete) {
      status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    }

    /* TODO: XXX: destroy all locks held for this resource */

    linked_list_free(delete_done_ev->failed_to_delete, free);
    status_code = HTTP_STATUS_CODE_OK;
  }
  else if (stat_done_ev->error == WEBDAV_ERROR_DOES_NOT_EXIST) {
    status_code = HTTP_STATUS_CODE_NOT_FOUND;
  }
  else {
    log_info("Couldn't check (%d) if path %s existed",
             stat_done_ev->error,
             ctx->request_relative_uri);
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
  }

 done:
  assert(status_code);
  free(ctx->request_relative_uri);

  CRYIELD(ctx->pos,
          http_request_simple_response(hc->rh,
                                       status_code,
                                       ctx->response_body,
                                       ctx->response_body_len,
                                       "application/xml",
                                       LINKED_LIST_INITIALIZER,
                                       handle_delete_request, hc));

  free(ctx->response_body);

  CRRETURN(ctx->pos,
           request_proc(GENERIC_EVENT, NULL, hc));

  CREND();
}

static
EVENT_HANDLER_DEFINE(handle_get_request, ev_type, ev, ud) {
  struct handler_context *hc = ud;
  struct get_context *ctx = &hc->sub.get;

  CRBEGIN(ctx->pos);

  http_status_code_t code;

  ctx->resource_uri = path_from_uri(hc, hc->rhs.uri);
  if (!ctx->resource_uri) {
    code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto error_response;
  }

  /* open file */
  bool create_file = false;
  CRYIELD(ctx->pos,
          webdav_fs_open(hc->serv->fs,
                         ctx->resource_uri, create_file,
                         handle_get_request, ud));
  assert(WEBDAV_OPEN_DONE_EVENT == ev_type);
  WebdavOpenDoneEvent *open_done_ev = ev;
  if (open_done_ev->error) {
    code = open_done_ev->error == WEBDAV_ERROR_DOES_NOT_EXIST
      ? HTTP_STATUS_CODE_NOT_FOUND
      : HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto error_response;
  }

  ctx->file_handle = open_done_ev->file_handle;

  CRYIELD(ctx->pos,
          webdav_fs_fstat(hc->serv->fs, ctx->file_handle,
                          handle_get_request, ud));
  assert(WEBDAV_FSTAT_DONE_EVENT == ev_type);
  WebdavFstatDoneEvent *fstat_done_ev = ev;
  if (fstat_done_ev->error) {
    code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto error_response;
  }

  size_t content_length = fstat_done_ev->file_info.length;

  bool ret;
  ret = http_response_set_code(&hc->resp, HTTP_STATUS_CODE_OK);
  assert(ret);
  ret = http_response_add_header(&hc->resp,
                                 HTTP_HEADER_CONTENT_LENGTH, "%zu", content_length);
  assert(ret);

  CRYIELD(ctx->pos,
          http_request_write_headers(hc->rh, &hc->resp,
                                     handle_get_request, hc));
  assert(ev_type == HTTP_REQUEST_WRITE_HEADERS_DONE_EVENT);
  HTTPRequestWriteHeadersDoneEvent *write_headers_ev = ev;
  assert(write_headers_ev->request_handle == hc->rh);
  if (write_headers_ev->err != HTTP_SUCCESS) {
    goto done;
  }

  log_debug("Sending file %s, length: %s", &hc->rhs.uri[1], hc->resp.headers[0].value);

  /* TODO: must send up to the content-length we sent */
  while (true) {
    CRYIELD(ctx->pos,
            webdav_fs_read(hc->serv->fs, ctx->file_handle,
                           ctx->buf, sizeof(ctx->buf),
                           handle_get_request, ud));
    assert(WEBDAV_READ_DONE_EVENT == ev_type);
    WebdavReadDoneEvent *read_done_ev = ev;
    if (read_done_ev->error) {
      log_error("Error while read()ing file");
      goto done;
    }

    ssize_t amt_read = read_done_ev->nbyte;
    if (!amt_read) {
      /* EOF */
      log_debug("EOF done reading file; %zu", sizeof(ctx->buf));
      break;
    }

    log_debug("Sending %zd bytes", amt_read);

    /* now write to socket */
    CRYIELD(ctx->pos,
            http_request_write(hc->rh, ctx->buf, amt_read,
                               handle_get_request, hc));
    assert(ev_type == HTTP_REQUEST_WRITE_DONE_EVENT);
    HTTPRequestWriteDoneEvent *write_ev = ev;
    assert(write_ev->request_handle == hc->rh);
    if (write_ev->err != HTTP_SUCCESS) {
      goto done;
    }
  }

  if (false) {
  error_response:
    CRYIELD(ctx->pos,
            http_request_simple_response(hc->rh,
                                         code,
                                         "", 0,
                                         "application/xml",
                                         LINKED_LIST_INITIALIZER,
                                         handle_get_request, ud));
  }

 done:
  free(ctx->resource_uri);

  if (ctx->file_handle) {
    CRYIELD(ctx->pos,
            webdav_fs_close(hc->serv->fs, ctx->file_handle,
                            handle_get_request, ud));
    assert(ev_type == WEBDAV_CLOSE_DONE_EVENT);
    WebdavCloseDoneEvent *close_done_ev = ev;
    if (close_done_ev->error) {
      abort();
    }
  }

  CRRETURN(ctx->pos,
           request_proc(GENERIC_EVENT, NULL, hc));

  CREND();
}

static bool
parse_lock_request_body(const char *body, size_t body_len,
                        bool *is_exclusive, char **owner_xml);

static bool
generate_failed_lock_response_body(struct handler_context *hc,
                                   const char *file_path,
                                   const char *status_path,
                                   http_status_code_t *status_code,
                                   char **response_body,
                                   size_t *response_body_len);

static bool
generate_success_lock_response_body(struct handler_context *hc,
                                    const char *file_path,
                                    webdav_timeout_t timeout_in_seconds,
                                    webdav_depth_t depth,
                                    bool is_exclusive,
                                    const char *owner_xml,
                                    const char *lock_token,
                                    bool created,
                                    http_status_code_t *status_code,
                                    char **response_body,
                                    size_t *response_body_len);

static
EVENT_HANDLER_DEFINE(handle_lock_request, ev_type, ev, ud) {
  /* set this variable before coroutine restarts */
  struct handler_context *hc = ud;
  struct lock_context *ctx = &hc->sub.lock;
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
    log_info("Error while reading body of request");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  ctx->request_body = rbev->body;
  ctx->request_body_len = rbev->length;

  log_debug("Incoming lock request XML:\n%*s",
            ctx->request_body_len, ctx->request_body);

  /* get timeout */
  ctx->timeout_in_seconds = webdav_get_timeout(&hc->rhs);

  /* get path */
  ctx->file_path = path_from_uri(hc, hc->rhs.uri);
  if (!ctx->file_path) {
    log_debug("Invalid file path %s", hc->rhs.uri);
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* read "If" header */
  if_lock_token_err_t if_lock_token_err =
    webdav_get_if_lock_token(&hc->rhs, &ctx->resource_tag, &ctx->refresh_uri);
  if (if_lock_token_err == IF_LOCK_TOKEN_ERR_BAD_PARSE) {
    status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }

  if (if_lock_token_err == IF_LOCK_TOKEN_ERR_INTERNAL) {
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  if (if_lock_token_err == IF_LOCK_TOKEN_ERR_SUCCESS) {
    ctx->resource_tag_path = path_from_uri(hc, ctx->resource_tag);
    if (!ctx->resource_tag_path) {
      status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
      goto done;
    }
  }

  if (!ctx->request_body &&
      if_lock_token_err == IF_LOCK_TOKEN_ERR_SUCCESS &&
      str_equals(ctx->resource_tag_path, ctx->file_path)) {
    char *owner_xml_not_owned;
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
    bool success_generate =
      generate_success_lock_response_body(hc, ctx->file_path, ctx->timeout_in_seconds,
                                          depth, is_exclusive, owner_xml_not_owned,
                                          ctx->refresh_uri, was_created,
                                          &status_code,
                                          &ctx->response_body,
                                          &ctx->response_body_len);

    if (!success_generate) {
      status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    }

    goto done;
  }

  /* get webdav depth */
  ctx->depth = webdav_get_depth(&hc->rhs);
  if (ctx->depth != DEPTH_0 && ctx->depth != DEPTH_INF) {
    log_debug("Invalid ctx->depth sent %d", ctx->depth);
    status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }

  /* parse request body */
  bool success_parse = ctx->request_body
    ? parse_lock_request_body(ctx->request_body, ctx->request_body_len,
                              &ctx->is_exclusive, &ctx->owner_xml)
    : false;
  if (!success_parse) {
    log_debug("Bad request body");
    status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }

  /* actually attempt to lock the resource */
  ctx->lock_token = NULL;
  ctx->status_path = NULL;
  bool success_perform =
    perform_write_lock(hc->serv,
                       ctx->file_path, ctx->timeout_in_seconds, ctx->depth, ctx->is_exclusive, ctx->owner_xml,
                       &ctx->is_locked, &ctx->lock_token, &ctx->status_path);
  if (!success_perform) {
    log_debug("Error while performing lock");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  ctx->created = false;
  if (!ctx->is_locked) {
    CRYIELD(ctx->pos,
            webdav_fs_stat(hc->serv->fs,
                           ctx->file_path,
                           handle_lock_request, ud));
    assert(WEBDAV_STAT_DONE_EVENT == ev_type);
    WebdavStatDoneEvent *stat_done_ev = ev;
    if (stat_done_ev->error == WEBDAV_ERROR_DOES_NOT_EXIST) {
      ctx->created = true;
      CRYIELD(ctx->pos,
              webdav_fs_touch(hc->serv->fs, ctx->file_path,
                              handle_lock_request, ud));
      /* NB: ignoring touch error */
      assert(WEBDAV_TOUCH_DONE_EVENT == ev_type);
    }
  }

  ctx->headers = LINKED_LIST_INITIALIZER;

  /* generate lock attempt response */
  bool success_generate;
  if (ctx->is_locked) {
    log_debug("Resource is already locked");
    if (str_equals(ctx->status_path, ctx->file_path)) {
      success_generate =
        generate_locked_response(hc, ctx->status_path,
                                 &status_code,
                                 &ctx->response_body,
                                 &ctx->response_body_len);
    }
    else {
      success_generate =
        generate_failed_lock_response_body(hc, ctx->file_path, ctx->status_path,
                                           &status_code,
                                           &ctx->response_body,
                                           &ctx->response_body_len);
    }
  }
  else {
    success_generate =
      generate_success_lock_response_body(hc, ctx->file_path, ctx->timeout_in_seconds,
                                          ctx->depth, ctx->is_exclusive, ctx->owner_xml,
                                          ctx->lock_token, ctx->created,
                                          &status_code,
                                          &ctx->response_body,
                                          &ctx->response_body_len);

    if (success_generate) {
      /* add lock token header if we were locked */
      EASY_ALLOC(HeaderPair, hp);
      hp->name = "Lock-Token";
      char lock_token_header_value[256];
      int len_written = snprintf(lock_token_header_value, sizeof(lock_token_header_value),
                                 "<%s>", ctx->lock_token);
      if (len_written == sizeof(lock_token_header_value) - 1) {
        /* TODO: Lazy */
        abort();
      }
      hp->value = strdup_x(lock_token_header_value);
      ctx->headers = linked_list_prepend(ctx->headers, hp);
    }
  }

  if (!success_generate) {
    log_debug("Error while sending back response");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
  }

 done:
  assert(status_code);
  log_debug("Response with status code: %d", status_code);
  log_debug("Outgoing lock response XML (%lld bytes):\n%*s",
            (long long) ctx->response_body_len,
            ctx->response_body_len,
            ctx->response_body);

  free(ctx->request_body);
  free(ctx->file_path);
  free(ctx->owner_xml);
  free(ctx->resource_tag);
  free(ctx->resource_tag_path);
  free(ctx->refresh_uri);

  CRYIELD(ctx->pos,
          http_request_simple_response(hc->rh,
                                       status_code,
                                       ctx->response_body,
                                       ctx->response_body_len,
                                       "application/xml",
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

static bool
parse_lock_request_body(const char *body, size_t body_len,
                        bool *is_exclusive, char **owner_xml) {
  UNUSED(body);
  UNUSED(is_exclusive);
  UNUSED(owner_xml);
  bool toret = true;
  bool saw_lockscope = false;
  bool saw_locktype = false;

  /* this is an optional request parameter */
  *owner_xml = NULL;

  xmlDocPtr doc = parse_xml_string(body, body_len);
  ASSERT_NOT_NULL(doc);

  xmlNodePtr root_element = xmlDocGetRootElement(doc);
  ASSERT_NOT_NULL(root_element);

  if (!node_is(root_element, DAV_XML_NS, "lockinfo")) {
    goto error;
  }

  for (xmlNodePtr child = root_element->children;
       child; child = child->next) {
    if (node_is(child, DAV_XML_NS, "lockscope")) {
      *is_exclusive = (child->children &&
                       node_is(child->children, DAV_XML_NS, "exclusive"));
      saw_lockscope = true;
    }
    /* we require a proper write lock entity */
    else if (node_is(child, DAV_XML_NS, "locktype") &&
             child->children &&
             node_is(child->children, DAV_XML_NS, "write")) {
      saw_locktype = true;
    }
    else if (node_is(child, DAV_XML_NS, "owner") &&
             child->children) {
      xmlBufferPtr buf = xmlBufferCreate();
      int format_level = 0;
      int should_format = 0;
      xmlNodeDump(buf, doc, child->children, format_level, should_format);
      *owner_xml = strdup_x(STR(xmlBufferContent(buf)));
      xmlBufferFree(buf);
    }
  }

  if (!saw_lockscope || !saw_locktype) {
  error:
    /* in case we found an owner */
    if (*owner_xml) {
      free(*owner_xml);
      *owner_xml = NULL;
    }
    toret = false;
  }

  xmlFreeDoc(doc);

  return toret;
}

static bool
generate_failed_lock_response_body(struct handler_context *hc,
                                   const char *file_path,
                                   const char *status_path,
                                   http_status_code_t *status_code,
                                   char **response_body,
                                   size_t *response_body_len) {
  xmlDocPtr xml_response = xmlNewDoc(XMLSTR("1.0"));
  ASSERT_NOT_NULL(xml_response);

  xmlNodePtr multistatus_elt = xmlNewDocNode(xml_response, NULL, XMLSTR("multistatus"), NULL);
  ASSERT_NOT_NULL(multistatus_elt);

  xmlDocSetRootElement(xml_response, multistatus_elt);

  xmlNsPtr dav_ns = xmlNewNs(multistatus_elt, XMLSTR(DAV_XML_NS), XMLSTR("D"));
  ASSERT_NOT_NULL(dav_ns);

  xmlSetNs(multistatus_elt, dav_ns);

  bool same_path = str_equals(file_path, status_path);
  const char *locked_status = "HTTP/1.1 423 Locked";

  if (!same_path) {
    xmlNodePtr response_elt = xmlNewChild(multistatus_elt, dav_ns, XMLSTR("response"), NULL);
    ASSERT_NOT_NULL(response_elt);

    char *status_uri = uri_from_path(hc, status_path);
    ASSERT_NOT_NULL(status_uri);

    xmlNodePtr href_elt = xmlNewTextChild(response_elt, dav_ns, XMLSTR("href"), XMLSTR(status_uri));
    ASSERT_NOT_NULL(href_elt);

    free(status_uri);

    xmlNodePtr status_elt = xmlNewTextChild(response_elt, dav_ns, XMLSTR("status"),
                                            XMLSTR(locked_status));
    ASSERT_NOT_NULL(status_elt);
  }

  xmlNodePtr response_elt = xmlNewChild(multistatus_elt, dav_ns, XMLSTR("response"), NULL);
  ASSERT_NOT_NULL(response_elt);

  char *file_uri = uri_from_path(hc, file_path);
  ASSERT_NOT_NULL(file_uri);

  xmlNodePtr href_elt = xmlNewTextChild(response_elt, dav_ns, XMLSTR("href"), XMLSTR(file_uri));
  ASSERT_NOT_NULL(href_elt);

  free(file_uri);

  xmlNodePtr status_elt = xmlNewTextChild(response_elt, dav_ns, XMLSTR("status"),
                                          XMLSTR(same_path ? locked_status : "HTTP/1.1 424 Failed Dependency"));
  ASSERT_NOT_NULL(status_elt);

  xmlChar *out_buf;
  int out_buf_size;
  int format_xml = 1;
  xmlDocDumpFormatMemory(xml_response, &out_buf, &out_buf_size, format_xml);
  *response_body = (char *) out_buf;
  assert(out_buf_size >= 0);
  *response_body_len = out_buf_size;

  xmlFreeDoc(xml_response);

  *status_code = HTTP_STATUS_CODE_MULTI_STATUS;

  return true;
}

static bool
generate_success_lock_response_body(struct handler_context *hc,
                                    const char *file_path,
                                    webdav_timeout_t timeout_in_seconds,
                                    webdav_depth_t depth,
                                    bool is_exclusive,
                                    const char *owner_xml,
                                    const char *lock_token,
                                    bool created,
                                    http_status_code_t *status_code,
                                    char **response_body,
                                    size_t *response_body_len) {
  xmlDocPtr xml_response = xmlNewDoc(XMLSTR("1.0"));
  ASSERT_NOT_NULL(xml_response);

  xmlNodePtr prop_elt = xmlNewDocNode(xml_response, NULL, XMLSTR("prop"), NULL);
  ASSERT_NOT_NULL(prop_elt);

  xmlDocSetRootElement(xml_response, prop_elt);

  xmlNsPtr dav_ns = xmlNewNs(prop_elt, XMLSTR(DAV_XML_NS), XMLSTR("D"));
  ASSERT_NOT_NULL(dav_ns);

  xmlSetNs(prop_elt, dav_ns);

  xmlNodePtr lockdiscovery_elt = xmlNewChild(prop_elt, dav_ns, XMLSTR("lockdiscovery"), NULL);
  ASSERT_NOT_NULL(lockdiscovery_elt);

  xmlNodePtr activelock_elt = xmlNewChild(lockdiscovery_elt, dav_ns, XMLSTR("activelock"), NULL);
  ASSERT_NOT_NULL(activelock_elt);

  xmlNodePtr locktype_elt = xmlNewChild(activelock_elt, dav_ns, XMLSTR("locktype"), NULL);
  ASSERT_NOT_NULL(locktype_elt);

  xmlNodePtr write_elt = xmlNewChild(locktype_elt, dav_ns, XMLSTR("write"), NULL);
  ASSERT_NOT_NULL(write_elt);

  xmlNodePtr lockscope_elt = xmlNewChild(activelock_elt, dav_ns, XMLSTR("lockscope"), NULL);
  ASSERT_NOT_NULL(lockscope_elt);

  if (is_exclusive) {
    xmlNodePtr exclusive_elt = xmlNewChild(lockscope_elt, dav_ns, XMLSTR("exclusive"), NULL);
    ASSERT_NOT_NULL(exclusive_elt);
  }
  else {
    xmlNodePtr shared_elt = xmlNewChild(lockscope_elt, dav_ns, XMLSTR("shared"), NULL);
    ASSERT_NOT_NULL(shared_elt);
  }

  assert(depth == DEPTH_0 || depth == DEPTH_INF);
  xmlNodePtr depth_elt = xmlNewTextChild(activelock_elt, dav_ns, XMLSTR("depth"),
                                         XMLSTR(depth == DEPTH_INF ? "infinity" : "0"));
  ASSERT_NOT_NULL(depth_elt);

  if (owner_xml) {
    /* TODO: need to make sure owner_xml conforms to XML */
    xmlNodePtr owner_elt = xmlNewChild(activelock_elt, dav_ns, XMLSTR("owner"), XMLSTR(owner_xml));
    ASSERT_NOT_NULL(owner_elt);
  }

  const char *timeout_str;
  char timeout_buf[256];
  if (!timeout_in_seconds) {
    timeout_str = "infinity";
  }
  else {
    int len = snprintf(timeout_buf, sizeof(timeout_buf),
                       "Second-%u", (unsigned) timeout_in_seconds);
    if (len == sizeof(timeout_buf) - 1) {
      /* TODO: lazy */
      abort();
    }
    timeout_str = timeout_buf;
  }

  xmlNodePtr timeout_elt = xmlNewTextChild(activelock_elt, dav_ns, XMLSTR("timeout"),
                                           XMLSTR(timeout_str));
  ASSERT_NOT_NULL(timeout_elt);

  xmlNodePtr locktoken_elt = xmlNewChild(activelock_elt, dav_ns, XMLSTR("locktoken"), NULL);
  ASSERT_NOT_NULL(locktoken_elt);

  xmlNodePtr href_elt = xmlNewTextChild(locktoken_elt, dav_ns, XMLSTR("href"),
                                        XMLSTR(lock_token));
  ASSERT_NOT_NULL(href_elt);

  xmlNodePtr lockroot_elt = xmlNewChild(activelock_elt, dav_ns, XMLSTR("lockroot"), NULL);
  ASSERT_NOT_NULL(lockroot_elt);

  char *lockroot_uri = uri_from_path(hc, file_path);
  ASSERT_NOT_NULL(lockroot_uri);

  xmlNodePtr lockroot_href_elt = xmlNewTextChild(lockroot_elt, dav_ns, XMLSTR("href"),
                                                 XMLSTR(file_path));
  ASSERT_NOT_NULL(lockroot_href_elt);

  free(lockroot_uri);

  xmlChar *out_buf;
  int out_buf_size;
  int format_xml = 1;
  xmlDocDumpFormatMemory(xml_response, &out_buf, &out_buf_size, format_xml);
  *response_body = (char *) out_buf;
  assert(out_buf_size >= 0);
  *response_body_len = out_buf_size;

  xmlFreeDoc(xml_response);

  *status_code = created ? HTTP_STATUS_CODE_CREATED : HTTP_STATUS_CODE_OK;

  return true;
}

static
EVENT_HANDLER_DEFINE(handle_mkcol_request, ev_type, ev, ud) {
  /* these are run on every re-entry */
  struct handler_context *hc = ud;
  struct mkcol_context *ctx = &hc->sub.mkcol;
  http_status_code_t status_code = 0;

  CRBEGIN(ctx->pos);

  /* read body first */
  CRYIELD(ctx->pos,
          http_request_ignore_body(hc->rh,
                                   handle_mkcol_request, hc));
  HTTPRequestReadBodyDoneEvent *rbev = ev;
  if (rbev->error) {
    log_info("Error while reading body of request");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  if (rbev->length) {
    log_info("Request had a body!");
    status_code = HTTP_STATUS_CODE_UNSUPPORTED_MEDIA_TYPE;
    goto done;
  }

  ctx->request_relative_uri = path_from_uri(hc, hc->rhs.uri);
  if (!ctx->request_relative_uri) {
    log_info("Couldn't make file path from %s", hc->rhs.uri);
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  CRYIELD(ctx->pos,
          webdav_fs_mkcol(hc->serv->fs,
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

  struct handler_context *hc = ud;
  bool ret;

  ret = http_response_set_code(&hc->resp, HTTP_STATUS_CODE_OK);
  assert(ret);

  ret = http_response_add_header(&hc->resp, "DAV", "1,2");
  assert(ret);

  ret = http_response_add_header(&hc->resp, "Allow",
                                 "GET,HEAD,PUT,DELETE,MKCOL,COPY,MOVE,PROPFIND,LOCK,OPTIONS");
  assert(ret);

  ret = http_response_add_header(&hc->resp, HTTP_HEADER_CONTENT_LENGTH, "0");
  assert(ret);

  http_request_write_headers(hc->rh, &hc->resp,
                             request_proc, ud);
}

static
EVENT_HANDLER_DEFINE(handle_propfind_request, ev_type, ev, ud) {
  UNUSED(ev_type);
  UNUSED(ev);

  struct handler_context *hc = ud;
  struct propfind_context *ctx = &hc->sub.propfind;
  http_status_code_t status_code = 0;

  CRBEGIN(ctx->pos);

  ctx->buf = NULL;
  ctx->buf_used = 0;
  ctx->out_buf = NULL;
  ctx->out_buf_size = 0;

  /* read all posted data */
  CRYIELD(ctx->pos,
          http_request_read_body(hc->rh, handle_propfind_request, hc));
  HTTPRequestReadBodyDoneEvent *rbev = ev;
  if (rbev->error) {
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }
  ctx->buf = rbev->body;
  ctx->buf_used = rbev->length;

  /* figure out depth */
  webdav_depth_t depth = webdav_get_depth(&hc->rhs);
  if (depth == DEPTH_INVALID) {
    status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }

  /* TODO: support this */
  if (depth == DEPTH_INF) {
    log_info("We don't support infinity propfind requests");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  assert(ctx->buf_used <= INT_MAX);
  log_debug("XML request: Depth: %d, %.*s",
            depth, (int) ctx->buf_used, ctx->buf);

  /* parse request */
  xml_parse_code_t success_parse =
    parse_propfind_request(ctx->buf,
                           ctx->buf_used,
                           &ctx->propfind_req_type,
                           &ctx->props_to_get);
  if (success_parse == XML_PARSE_ERROR_SYNTAX ||
      success_parse == XML_PARSE_ERROR_STRUCTURE) {
    status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }
  else if (success_parse == XML_PARSE_ERROR_INTERNAL) {
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  if (ctx->propfind_req_type != PROPFIND_PROP) {
    log_info("We only support 'prop' requests");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* run the request */
  CRYIELD(ctx->pos,
          run_propfind(hc, hc->rhs.uri, depth,
                       ctx->propfind_req_type,
                       ctx->props_to_get,
                       handle_propfind_request, hc));
  assert(ev_type == RUN_PROPFIND_DONE_EVENT);
  RunPropfindDoneEvent *run_propfind_ev = ev;
  if (run_propfind_ev->error) {
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* now generate response */
  bool success_generate =
    generate_propfind_response(hc,
                               ctx->props_to_get,
                               run_propfind_ev->entries,
                               &ctx->out_buf,
                               &ctx->out_buf_size,
                               &status_code);
  linked_list_free(run_propfind_ev->entries,
                   (linked_list_elt_handler_t) free_webdav_propfind_entry);

  if (!success_generate) {
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

 done:
  linked_list_free(ctx->props_to_get,
                   (linked_list_elt_handler_t) free_webdav_property);

  assert(status_code);
  log_debug("Responding with status: %d", status_code);
  assert(ctx->out_buf_size <= INT_MAX);
  log_debug("XML response will be: %.*s",
            (int) ctx->out_buf_size, ctx->out_buf);

  CRYIELD(ctx->pos,
          http_request_simple_response(hc->rh,
                                       status_code,
                                       ctx->out_buf,
                                       ctx->out_buf_size,
                                       "application/xml",
                                       LINKED_LIST_INITIALIZER,
                                       handle_propfind_request, hc));

  if (ctx->out_buf) {
    /* TODO: use a generic returned free function */
    xmlFree(ctx->out_buf);
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
  CRYIELD(hc->sub.proppatch.pos,
          http_request_simple_response(hc->rh,
                                       status_code,
                                       hc->sub.proppatch.response_body,
                                       hc->sub.proppatch.response_body_size,
                                       "application/xml",
                                       LINKED_LIST_INITIALIZER,
                                       handle_proppatch_request, hc));

  if (hc->sub.proppatch.response_body) {
    /* TODO: use a generic returned free function */
    xmlFree(hc->sub.proppatch.response_body);
  }
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

  xmlDocPtr doc = NULL;

  /* NB: litmus "lock" tests fail because we don't support
     setting arbitrary properties */
  char *file_path = path_from_uri(hc, uri);
  if (!file_path) {
    log_warning("Couldn't make file path from %s", uri);
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
  log_debug("XML request:\n%.*s", (int) input_size, input);

  doc = parse_xml_string(input, input_size);
  if (!doc) {
    *status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }

  xmlNodePtr root_element = xmlDocGetRootElement(doc);
  if (!(str_equals(STR(root_element->name), "propertyupdate") &&
        ns_equals(root_element, DAV_XML_NS))) {
    /* root element is not propertyupdate, this is bad */
    log_info("root element is not DAV:, propertyupdate %s",
             root_element->name);
    *status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }

  /* build response */
  xmlDocPtr xml_response = xmlNewDoc(XMLSTR("1.0"));
  assert(xml_response);
  xmlNodePtr multistatus_elt = xmlNewDocNode(xml_response, NULL,
                                             XMLSTR("multistatus"), NULL);
  assert(multistatus_elt);
  xmlDocSetRootElement(xml_response, multistatus_elt);

  xmlNsPtr dav_ns = xmlNewNs(multistatus_elt, XMLSTR(DAV_XML_NS), XMLSTR("D"));
  assert(dav_ns);
  xmlSetNs(multistatus_elt, dav_ns);

  xmlNodePtr response_elt = xmlNewChild(multistatus_elt, dav_ns,
                                        XMLSTR("response"), NULL);
  assert(response_elt);

  xmlNodePtr href_elt = xmlNewTextChild(response_elt, dav_ns,
                                        XMLSTR("href"), XMLSTR(uri));
  assert(href_elt);

  xmlNodePtr propstat_elt = xmlNewChild(response_elt, dav_ns,
                                        XMLSTR("propstat"), NULL);
  xmlNodePtr new_prop_elt = xmlNewChild(propstat_elt, dav_ns,
                                        XMLSTR("prop"), NULL);
  xmlNodePtr new_status_elt = xmlNewTextChild(propstat_elt, dav_ns,
                                              XMLSTR("status"),
                                              XMLSTR("HTTP/1.1 403 Forbidden"));
  assert(new_status_elt);

  /* now iterate over every propertyupdate directive */
  /* TODO: for now we don't support setting anything */
  /* we don't support arbitrary dead properties */
  for (xmlNodePtr cur_child = root_element->children; cur_child;
       cur_child = cur_child->next) {
    if (ns_equals(cur_child, DAV_XML_NS) &&
        (str_equals(STR(cur_child->name), "set") ||
         str_equals(STR(cur_child->name), "remove"))) {
      /* get the prop elt */
      xmlNodePtr prop_elt = cur_child->children;
      for (; prop_elt; prop_elt = prop_elt->next) {
        if (ns_equals(prop_elt, DAV_XML_NS) &&
            str_equals(STR(prop_elt->name), "prop")) {
          break;
        }
      }

      /* now iterate over each prop being modified in
         this directive (either set/remove) */
      if (prop_elt) {
        for (xmlNodePtr xml_prop = prop_elt->children; xml_prop;
             xml_prop = xml_prop->next) {
          /* add this element to the proppatch response */
          xmlNodePtr new_xml_prop = xmlNewChild(new_prop_elt, NULL,
                                                xml_prop->name, NULL);
          assert(new_xml_prop);
          if (xml_prop->ns) {
            xmlNsPtr ns_ptr = xmlNewNs(new_xml_prop, xml_prop->ns->href, xml_prop->ns->prefix);
            xmlSetNs(new_xml_prop, ns_ptr);
          }
        }
      }
    }
    else {
      /* this is just bad input XML schema */
      /* we'll ignore it for now though, doesn't really hurt anything */
    }
  }

  int format_xml = 1;
  int out_size;
  xmlDocDumpFormatMemory(xml_response, (xmlChar **) output, &out_size, format_xml);
  log_debug("XML response will be:\n%.*s", out_size, *output);
  *output_size = out_size;

  if (xml_response) {
    xmlFreeDoc(xml_response);
  }
  *status_code = HTTP_STATUS_CODE_MULTI_STATUS;

 done:
  free(file_path);

  if (doc) {
    xmlFreeDoc(doc);
  }
}

static
EVENT_HANDLER_DEFINE(handle_put_request, ev_type, ev, ud) {
  /* re-init these before restarting the coroutine */
  struct handler_context *hc = ud;
  struct put_context *ctx = &hc->sub.put;
  http_status_code_t status_code = 0;

  CRBEGIN(ctx->pos);

  ctx->response_body = NULL;
  ctx->response_body_len = 0;
  ctx->file_handle = NULL;

  ctx->request_relative_uri = path_from_uri(hc, hc->rhs.uri);
  if (!ctx->request_relative_uri) {
    log_warning("Couldn't make file path from %s", hc->rhs.uri);
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
          webdav_fs_stat(hc->serv->fs,
                         ctx->request_relative_uri,
                         handle_put_request, ud));
  assert(WEBDAV_STAT_DONE_EVENT == ev_type);
  WebdavStatDoneEvent *stat_done_ev = ev;
  if (stat_done_ev->error == WEBDAV_ERROR_DOES_NOT_EXIST) {
    ctx->resource_existed = false;
  }
  else if (stat_done_ev->error == WEBDAV_ERROR_NONE) {
    ctx->resource_existed = true;
  }
  else {
    log_error("Couldn't stat resource (%d) at %s",
              stat_done_ev->error,
              ctx->request_relative_uri);
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  bool create_file = true;
  CRYIELD(ctx->pos,
          webdav_fs_open(hc->serv->fs,
                         ctx->request_relative_uri, create_file,
                         handle_put_request, ud));
  assert(WEBDAV_OPEN_DONE_EVENT == ev_type);
  WebdavOpenDoneEvent *open_done_ev = ev;
  if (open_done_ev->error) {
    if (open_done_ev->error == WEBDAV_ERROR_DOES_NOT_EXIST ||
        open_done_ev->error == WEBDAV_ERROR_NOT_COLLECTION) {
      status_code = HTTP_STATUS_CODE_CONFLICT;
    }
    else {
      log_error("Couldn't open resource (%d) at %s",
                open_done_ev->error,
                ctx->request_relative_uri);
      status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    }
    goto done;
  }

  ctx->file_handle = open_done_ev->file_handle;

  /* check if this is a collection */
  CRYIELD(ctx->pos,
          webdav_fs_fstat(hc->serv->fs, ctx->file_handle,
                          handle_put_request, ud));
  assert(ev_type == WEBDAV_FSTAT_DONE_EVENT);
  WebdavFstatDoneEvent *fstat_done_ev = ev;
  if (fstat_done_ev->error) {
    log_info("Couldn't fstat file (%s): %d",
             ctx->request_relative_uri,
             fstat_done_ev->error);
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* can't put on a collection */
  if (fstat_done_ev->file_info.is_collection) {
    status_code = HTTP_STATUS_CODE_METHOD_NOT_ALLOWED;
    goto done;
  }

  while (true) {
    CRYIELD(ctx->pos,
            http_request_read(hc->rh,
                              ctx->read_buf, sizeof(ctx->read_buf),
                              handle_put_request, hc));
    HTTPRequestReadDoneEvent *read_done_ev = ev;
    if (read_done_ev->err != HTTP_SUCCESS) {
      goto error;
    }

    /* EOF */
    if (!read_done_ev->nbyte) {
      break;
    }

    ctx->amount_read = read_done_ev->nbyte;
    ctx->amount_written = 0;
    while (ctx->amount_written < ctx->amount_read) {
      CRYIELD(ctx->pos,
              webdav_fs_write(hc->serv->fs, ctx->file_handle,
                              ctx->read_buf + ctx->amount_written,
                              ctx->amount_read - ctx->amount_written,
                              handle_put_request, ud));
      assert(WEBDAV_WRITE_DONE_EVENT == ev_type);
      WebdavWriteDoneEvent *write_done_ev = ev;
      if (write_done_ev->error) {
        log_error("Couldn't write to resource (%d) at %s",
                  write_done_ev->error,
                  ctx->request_relative_uri);
        status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
        goto done;
      }
      ctx->amount_written += write_done_ev->nbyte;
    }
  }

  status_code = ctx->resource_existed
    ? HTTP_STATUS_CODE_OK
    : HTTP_STATUS_CODE_CREATED;

 done:
  assert(status_code);

  CRYIELD(ctx->pos,
          http_request_simple_response(hc->rh,
                                       status_code,
                                       ctx->response_body,
                                       ctx->response_body_len,
                                       "application/xml",
                                       LINKED_LIST_INITIALIZER,
                                       handle_put_request, ud));

 error:
  free(ctx->response_body);
  free(ctx->request_relative_uri);

  if (ctx->file_handle) {
    CRYIELD(ctx->pos,
            webdav_fs_close(hc->serv->fs, ctx->file_handle,
                            handle_put_request, ud));
    assert(WEBDAV_CLOSE_DONE_EVENT == ev_type);
    WebdavCloseDoneEvent *close_done_ev = ev;
    if (close_done_ev->error) {
      /* this kind of error is intolerable */
      log_critical("Couldn't close webdav file: %s", ctx->request_relative_uri);
      abort();
    }
  }

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

  /* set this variable before coroutine restarts */
  struct handler_context *hc = ud;

  CRBEGIN(hc->sub.lock.pos);

  http_status_code_t status_code = HTTP_STATUS_CODE___INVALID;
  char *lock_token = NULL;

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
  char *file_path = path_from_uri(hc, hc->rhs.uri);
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
  assert(status_code != HTTP_STATUS_CODE___INVALID);

  CRYIELD(hc->sub.unlock.pos,
          http_request_string_response(hc->rh,
                                       status_code, "",
                                       handle_unlock_request, hc));

  CRRETURN(hc->sub.unlock.pos,
           request_proc(GENERIC_EVENT, NULL, hc));

  CREND();
}

static
EVENT_HANDLER_DEFINE(handle_request, ev_type, ev, ud) {
  assert(ev_type == HTTP_NEW_REQUEST_EVENT);
  HTTPNewRequestEvent *new_request_ev = ev;

  UTHR_CALL3(request_proc, struct handler_context,
             .rh = new_request_ev->request_handle,
             .serv = ud);
}

webdav_fs_t
webdav_fs_new(WebdavOperations *op,
              size_t op_size,
              void *user_data) {
  UNUSED(op_size);

  struct webdav_fs *toret = malloc(sizeof(*toret));
  if (!toret) {
    return NULL;
  }

  *toret = (struct webdav_fs) {
    .op = op,
    .user_data = user_data,
  };

  return toret;
}

void
webdav_fs_open(webdav_fs_t fs,
               const char *relative_uri,
               bool create,
               event_handler_t cb, void *cb_ud) {
  return fs->op->open(fs->user_data,
                      relative_uri, create,
                      cb, cb_ud);
}

void
webdav_fs_fstat(webdav_fs_t fs,
                void *file_handle,
                event_handler_t cb, void *cb_ud) {
  return fs->op->fstat(fs->user_data,
                       file_handle,
                       cb, cb_ud);
}

void
webdav_fs_read(webdav_fs_t fs, void *file_handle,
               void *buf, size_t buf_size,
               event_handler_t cb, void *cb_ud) {
  return fs->op->read(fs->user_data, file_handle,
                      buf, buf_size,
                      cb, cb_ud);
}

void
webdav_fs_write(webdav_fs_t fs, void *file_handle,
                const void *buf, size_t buf_size,
                event_handler_t cb, void *cb_ud) {
  return fs->op->write(fs->user_data, file_handle,
                       buf, buf_size,
                       cb, cb_ud);
}

void
webdav_fs_readcol(webdav_fs_t fs,
                  void *col_handle,
                  WebdavCollectionEntry *ce, size_t nentries,
                  event_handler_t cb, void *ud) {
  return fs->op->readcol(fs->user_data, col_handle, ce, nentries,
                         cb, ud);
}

void
webdav_fs_close(webdav_fs_t fs,
                void *file_handle,
                event_handler_t cb, void *cb_ud) {
  return fs->op->close(fs->user_data, file_handle,
                       cb, cb_ud);
}

void
webdav_fs_mkcol(webdav_fs_t fs,
                const char *relative_uri,
                event_handler_t cb, void *cb_ud) {
  return fs->op->mkcol(fs->user_data, relative_uri, cb, cb_ud);
}

void
webdav_fs_delete(webdav_fs_t fs,
                 const char *relative_uri,
                 event_handler_t cb, void *cb_ud) {
  return fs->op->delete(fs->user_data, relative_uri, cb, cb_ud);
}

void
webdav_fs_move(webdav_fs_t fs,
               const char *src_relative_uri, const char *dst_relative_uri,
               bool overwrite,
               event_handler_t cb, void *cb_ud) {
  return fs->op->move(fs->user_data,
                      src_relative_uri, dst_relative_uri,
                      overwrite,
                      cb, cb_ud);
}

void
webdav_fs_copy(webdav_fs_t fs,
               const char *src_relative_uri, const char *dst_relative_uri,
               bool overwrite, webdav_depth_t depth,
               event_handler_t cb, void *cb_ud) {
  return fs->op->copy(fs->user_data,
                      src_relative_uri, dst_relative_uri,
                      overwrite, depth,
                      cb, cb_ud);
}

webdav_server_t
webdav_server_start(FDEventLoop *loop,
                    int server_fd,
                    const char *public_prefix,
                    webdav_fs_t fs) {
  struct webdav_server *serv = malloc(sizeof(*serv));
  if (!serv) {
    goto error;
  }

  *serv = (struct webdav_server) {
    .loop = loop,
    .locks = LINKED_LIST_INITIALIZER,
    .fs = fs,
    .public_prefix = strdup_x(public_prefix),
  };

  bool ret = http_server_start(&serv->http, loop, server_fd,
                               handle_request, serv);
  if (!ret) {
    goto error;
  }

  return serv;

 error:
  free(serv);
  return NULL;
}

bool
webdav_server_stop(webdav_server_t ws) {
  struct webdav_server *serv = ws;

  bool ret = http_server_stop(&serv->http);
  if (!ret) {
    return false;
  }

  /* TODO: actually free each WebdavLockDescriptor */
  linked_list_free(serv->locks, NULL);

  return true;
}
