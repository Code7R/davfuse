/*
  A webdav compatible http file server out of the current directory
 */
#define _ISOC99_SOURCE
#define _BSD_SOURCE

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <assert.h>
#include <dirent.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "events.h"
#include "fdevent.h"
#include "fd_utils.h"
#include "file_utils.h"
#include "http_helpers.h"
#include "http_server.h"
#include "logging.h"
#include "uthread.h"
#include "util.h"

#define XMLSTR(a) ((const xmlChar *) (a))
#define STR(a) ((const char *) (a))

const char *DAV_XML_NS = "DAV:";

const char *WEBDAV_HEADER_DEPTH = "Depth";
const char *WEBDAV_HEADER_DESTINATION = "Destination";
const char *WEBDAV_HEADER_IF = "If";
const char *WEBDAV_HEADER_OVERWRITE = "Overwrite";
const char *WEBDAV_HEADER_TIMEOUT = "Timeout";

enum {
  BUF_SIZE=4096,
};

typedef enum {
  DEPTH_0,
  DEPTH_1,
  DEPTH_INF,
  DEPTH_INVALID,
} webdav_depth_t;

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

struct webdav_server {
  HTTPServer *http;
  FDEventLoop *loop;
  char *base_path;
  size_t base_path_len;
  linked_list_t locks;
};

struct handler_context {
  UTHR_CTX_BASE;
  struct webdav_server *serv;
  HTTPRequestHeaders rhs;
  HTTPResponseHeaders resp;
  http_request_handle_t rh;
  union {
    struct {
      coroutine_position_t pos;
      bool is_move;
    } copy;
    struct {
      coroutine_position_t pos;
    } delete;
    struct {
      coroutine_position_t pos;
      char buf[BUF_SIZE];
      int fd;
    } get;
    struct {
      coroutine_position_t pos;
      char *response_body;
      size_t response_body_len;
      linked_list_t headers;
    } lock;
    struct {
      coroutine_position_t pos;
    } mkcol;
    struct {
      coroutine_position_t pos;
      char scratch_buf[BUF_SIZE];
      char *buf;
      size_t buf_used, buf_size;
      char *out_buf;
      size_t out_buf_size;
    } propfind;
    struct {
      coroutine_position_t pos;
      char *request_body;
      size_t request_body_size;
      char *response_body;
      size_t response_body_size;
    } proppatch;
    struct {
      coroutine_position_t pos;
      char read_buf[BUF_SIZE];
      http_status_code_t success_status_code;
      int fd;
    } put;
  } sub;
};

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

static WebdavProperty *
create_webdav_property(const char *element_name, const char *ns_href) {
  EASY_ALLOC(WebdavProperty, elt);

  elt->element_name = strdup(element_name);
  elt->ns_href = strdup(ns_href);

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
  UNUSED(hc);

  const char *real_uri;

  if (uri[0] != '/') {
    /* can't parse this */
    const char *host_header = http_get_header_value(&hc->rhs, HTTP_HEADER_HOST);
    /* this is guaranteed to be exist */
    if (!host_header) {
      abort();
    }
    size_t http_len = strlen("http://");
    size_t host_len = strlen(host_header);
    char *prefix = malloc(http_len + host_len + 2);
    if (!prefix) {
      abort();
    }
    memcpy(prefix, "http://", http_len);
    memcpy(prefix + http_len, host_header, host_len);
    /* intentionally copying the trailing null byte here */
    memcpy(prefix + http_len + host_len, "/", sizeof("/"));

    if (str_startswith(uri, prefix)) {
      real_uri = &uri[strlen(prefix) - 1];
      free(prefix);
    }
    else {
      free(prefix);
      return NULL;
    }
  }
  else {
    real_uri = uri;
  }

  size_t uri_len = strlen(real_uri);
  if (str_equals(real_uri, "/")) {
    uri_len = 0;
  }
  /* return relative path (no leading slash), but also
     don't include trailing slash, since posix treats that like "/." */
  else if (real_uri[uri_len - 1] == '/') {
    uri_len -= 1;
  }

  /* TODO: de-urlencode `real_uri` */

  char *toret = malloc(hc->serv->base_path_len + uri_len + 1);
  if (!toret) {
    return NULL;
  }
  memcpy(toret, hc->serv->base_path, hc->serv->base_path_len);
  memcpy(toret + hc->serv->base_path_len, real_uri, uri_len);
  toret[hc->serv->base_path_len + uri_len] = '\0';

  return toret;
}

static char *
uri_from_path(struct handler_context *hc, const char *file_path) {
  /* this is simple */
  return strdup(file_path + hc->serv->base_path_len);
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
  /* just lock for 60 seconds for now,
     we don't have to honor timeout headers */
  /* TODO: fix this */
  return 60;
}

static void
ASSERT_NOT_NULL(void *foo) {
  if (!foo) {
    log_critical("Illegal null value");
    abort();
  }
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

static PURE_FUNCTION bool
is_parent_path(const char *potential_parent, const char *potential_child) {
  assert(potential_parent[strlen(potential_parent) - 1] != '/');
  assert(potential_child[strlen(potential_child) - 1] != '/');
  return (str_startswith(potential_child, potential_parent) &&
          potential_child[strlen(potential_parent)] == '/');
}

static void
add_propstat_response_for_path(const char *uri,
                               int fd,
                               linked_list_t props_to_get,
                               xmlNodePtr multistatus_elt,
                               xmlNsPtr dav_ns) {
  struct stat st;
  int my_errno = 0;
  int statret = fstat(fd, &st);

  if (statret < 0) {
    log_info("fstat(%d) failed: %s", fd, strerror(errno));
    my_errno = errno;
  }

  xmlNodePtr response_elt = xmlNewChild(multistatus_elt, dav_ns, XMLSTR("response"), NULL);
  assert(response_elt);

  xmlNodePtr href_elt = xmlNewTextChild(response_elt, dav_ns,
                                        XMLSTR("href"), XMLSTR(uri));
  assert(href_elt);

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

  LINKED_LIST_FOR(WebdavProperty, elt, props_to_get) {
    xmlNodePtr correct_prop_elt = prop_not_found_elt;
    if (statret < 0) {
      if (!(my_errno == ENOENT ||
            my_errno == ENOTDIR)) {
        correct_prop_elt = prop_failure_elt;
      }

      goto not_found_elt;
    }

    if (str_equals(elt->ns_href, DAV_XML_NS) &&
        (str_equals(elt->element_name, "getlastmodified") ||
         /* TODO: this should be configurable but for now we just
            set it to the same because that's what apache mod_dav does */
         /* TODO: this should be an RFC3339 date... */
         str_equals(elt->element_name, "creationdate"))) {
      time_t m_time = (time_t) st.st_mtime;
      struct tm *tm_ = gmtime(&m_time);
      char time_buf[400], *time_str;
      size_t num_chars = strftime(time_buf, sizeof(time_buf),
                                  "%a, %d %b %Y %T GMT", tm_);
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
             !S_ISDIR(st.st_mode)) {
      char time_str[400];
      snprintf(time_str, sizeof(time_str), "%lld", (long long) st.st_size);
      xmlNodePtr getcontentlength_elt = xmlNewTextChild(prop_success_elt, dav_ns,
                                                        XMLSTR("getcontentlength"), XMLSTR(time_str));
      assert(getcontentlength_elt);
    }
    else if (str_equals(elt->element_name, "resourcetype") &&
             str_equals(elt->ns_href, DAV_XML_NS)) {
      xmlNodePtr resourcetype_elt = xmlNewChild(prop_success_elt, dav_ns,
                                                XMLSTR("resourcetype"), NULL);
      assert(resourcetype_elt);

      if (S_ISDIR(st.st_mode)) {
        xmlNodePtr collection_elt = xmlNewChild(resourcetype_elt, dav_ns,
                                                XMLSTR("collection"), NULL);
        assert(collection_elt);
      }
    }
    else {
      xmlNodePtr random_elt;
    not_found_elt:
      random_elt = xmlNewChild(correct_prop_elt, NULL,
                               XMLSTR(elt->element_name), NULL);
      assert(random_elt);
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

static void
run_propfind(struct handler_context *hc,
             const char *uri, webdav_depth_t depth,
             const char *req_data, size_t req_data_length,
             char **out_data, size_t *out_size,
             http_status_code_t *status_code) {
  enum {
    PROPFIND_PROP,
    PROPFIND_ALLPROP,
    PROPFIND_PROPNAME,
  } propfind_req_type;

  char *file_path = NULL;
  xmlDocPtr xml_response = NULL;
  linked_list_t props_to_get = LINKED_LIST_INITIALIZER;
  xmlDocPtr doc = NULL;
  DIR *dir = NULL;
  int root_fd = -1;
  int cwd = -1;

  assert(req_data_length <= INT_MAX);
  log_debug("XML request: Depth: %d, %.*s", depth, (int)req_data_length, req_data);

  /* TODO: support this */
  if (depth == DEPTH_INF) {
    log_info("We don't support infinity propfind requests");
    *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto local_exit;
  }

  /* build up response */
  file_path = path_from_uri(hc, uri);
  if (!file_path) {
    log_info("Couldn't make file path from %s", uri);
    *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto local_exit;
  }

  /* try keeping a single fd open for the duration of the directory iteration */
  if (depth == DEPTH_1) {
    /* depth one, try directory by default first */
    dir = opendir(file_path);
    if (!dir) {
      log_info("Depth 1 but couldn't open directory: %s", strerror(errno));
      *status_code = (errno == ENOENT)
        ? HTTP_STATUS_CODE_NOT_FOUND
        : HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
      goto local_exit;
    }
  }

  if (dir) {
    root_fd = dirfd(dir);
  }
  else {
    root_fd = open(file_path, O_RDONLY);
  }

  if (root_fd < 0) {
    log_info("Couldn't get descriptor of file \"%s\": %s",
             file_path, strerror(errno));
    *status_code = (errno == ENOENT)
      ? HTTP_STATUS_CODE_NOT_FOUND
      : HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto local_exit;
  }

  /* process the type of prop request */
  if (!req_data) {
    propfind_req_type = PROPFIND_ALLPROP;
  }
  else {
    doc = parse_xml_string(req_data, req_data_length);
    if (!doc) {
      log_info("Client sent up invalid xml");
      *status_code = HTTP_STATUS_CODE_BAD_REQUEST;
      goto local_exit;
    }

    /* the root element should be DAV:propfind */
    xmlNodePtr root_element = xmlDocGetRootElement(doc);
    if (!(xml_str_equals(root_element->name, "propfind") &&
          root_element->ns &&
          xml_str_equals(root_element->ns->href, DAV_XML_NS))) {
      /* root element is not propfind, this is bad */
      log_info("root element is not DAV:, propfind");
      *status_code = HTTP_STATUS_CODE_BAD_REQUEST;
      goto local_exit;
    }
    log_debug("root element name: %s", root_element->name);

    /* check if this is prop, allprop, or propname request */
    xmlNodePtr first_child = root_element->children;
    /* TODO: check for multiple children, that is invalid */
    if (!first_child ||
        !first_child->ns ||
        !first_child->ns->href ||
        !xml_str_equals(first_child->ns->href, DAV_XML_NS)) {
      log_info("propfind element contains no child, or has bad namespace");
      *status_code = HTTP_STATUS_CODE_BAD_REQUEST;
      goto local_exit;
    }
    else if (xml_str_equals(first_child->name, "propname")) {
      log_info("don't yet support propname requests");
      propfind_req_type = PROPFIND_PROPNAME;
    }
    else if (xml_str_equals(first_child->name, "allprop")) {
      propfind_req_type = PROPFIND_ALLPROP;
    }
    else if (xml_str_equals(first_child->name, "prop")) {
      propfind_req_type = PROPFIND_PROP;
      xmlNodePtr prop_elt = first_child->children;
      for (; prop_elt; prop_elt = prop_elt->next) {
        props_to_get = linked_list_prepend(props_to_get,
                                           create_webdav_property((const char *) prop_elt->name,
                                                                  (const char *) prop_elt->ns->href));
      }
    }
    /* TODO: also handle the case where there are multiple top-level tags,
       we should return 400 in that case
     */
    else {
      log_info("Invalid propname child: %s", first_child->name);
      *status_code = HTTP_STATUS_CODE_BAD_REQUEST;
      goto local_exit;
    }
  }

  /* now that's we've parsed the propfind request, do it */

  if (propfind_req_type != PROPFIND_PROP) {
    log_info("We only support 'prop' requests");
    *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto local_exit;
  }

  xml_response = xmlNewDoc(XMLSTR("1.0"));
  assert(xml_response);
  xmlNodePtr multistatus_elt = xmlNewDocNode(xml_response, NULL, XMLSTR("multistatus"), NULL);
  assert(multistatus_elt);
  xmlDocSetRootElement(xml_response, multistatus_elt);

  xmlNsPtr dav_ns = xmlNewNs(multistatus_elt, XMLSTR(DAV_XML_NS), XMLSTR("D"));
  assert(dav_ns);
  xmlSetNs(multistatus_elt, dav_ns);

  add_propstat_response_for_path(uri, root_fd, props_to_get, multistatus_elt, dav_ns);

  if (root_fd >= 0 && dir && depth == DEPTH_1) {
    /* preserve cwd so we can go back to it */
    cwd = open(".", O_RDONLY);
    if (cwd < 0) {
      /* things are fucked */
      *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
      goto local_exit;
    }

    /* add status for every child of this directory */
    struct dirent *d;
    while ((d = readdir(dir)) != NULL) {
      if (str_equals(d->d_name, ".") ||
          str_equals(d->d_name, "..")) {
        continue;
      }

      /* always chdir back to avoid race */
      if (fchdir(root_fd) < 0) {
        *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
        goto local_exit;
      }

      int fd = open(d->d_name, O_RDONLY);

      if (fd >= 0) {
        char new_uri[1024];
        size_t len = strlen(uri);
        memcpy(new_uri, uri, len);
        strcpy(new_uri + len, d->d_name);

        add_propstat_response_for_path(new_uri, fd, props_to_get, multistatus_elt, dav_ns);
        close(fd);
      }
      else {
        /* directory entry couldn't be opened */
        log_info("open(%s/%s) failed: %s",
                 file_path, d->d_name, strerror(errno));
      }
    }

    if (fchdir(cwd) < 0) {
      /* the program won't operate correctly in this case */
      log_critical("Couldn't chdir back to original directlry: %s", strerror(errno));
      abort();
    }
  }

  /* convert doc to text and send to client */
  xmlChar *out_buf;
  int out_buf_size;
  int format_xml = 1;
  xmlDocDumpFormatMemory(xml_response, &out_buf, &out_buf_size,
			 format_xml);
  *out_data = (char *) out_buf;
  assert(out_buf_size >= 0);
  *out_size = out_buf_size;
  log_debug("XML response will be:\n%.*s", out_buf_size, *out_data);
  *status_code = HTTP_STATUS_CODE_MULTI_STATUS;

 local_exit:
  if (cwd >= 0) {
    close(cwd);
  }
  if (dir) {
    closedir(dir);
  }
  else if (root_fd >= 0) {
    close(root_fd);
  }

  if (xml_response) {
    xmlFreeDoc(xml_response);
  }
  linked_list_free(props_to_get, (linked_list_elt_handler_t) free_webdav_property);
  if (doc) {
    xmlFreeDoc(doc);
  }
  free(file_path);
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
  http_status_code_t status_code;

  CRBEGIN(hc->sub.copy.pos);

#define HANDLE_ERROR(if_err, status_code_, ...) \
  do {                                               \
    if (if_err) {                                    \
      log_debug("copy failed: " __VA_ARGS__);        \
      status_code = status_code_;                    \
      goto done;                                     \
    }                                                \
  }                                                  \
  while (false)

  const char *destination_url = NULL;
  char *destination_path = NULL;
  char *file_path = path_from_uri(hc, hc->rhs.uri);
  HANDLE_ERROR(!file_path, HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR,
               "couldn't get source path");

  /* destination */
  destination_url = http_get_header_value(&hc->rhs, WEBDAV_HEADER_DESTINATION);
  HANDLE_ERROR(!destination_url, HTTP_STATUS_CODE_BAD_REQUEST,
               "request didn't have destination");

  /* destination file path */
  destination_path = path_from_uri(hc, destination_url);
  HANDLE_ERROR(!destination_path, HTTP_STATUS_CODE_BAD_REQUEST,
               "couldn't get path from destination URI");

  /* check if destination path parent exists, otherwise 409 */
  char *destination_path_copy = strdup(destination_path);
  char *destination_path_dirname = dirname(destination_path_copy);
  bool an_error = !file_exists(destination_path_dirname);
  free(destination_path_copy);
  HANDLE_ERROR(an_error, HTTP_STATUS_CODE_CONFLICT,
               "destination parent did not exist");

  /* depth */
  webdav_depth_t depth = webdav_get_depth(&hc->rhs);
  HANDLE_ERROR(depth == DEPTH_INVALID, HTTP_STATUS_CODE_BAD_REQUEST,
               "bad depth header");

  struct stat src_st;
  int src_ret = stat(file_path, &src_st);
  HANDLE_ERROR(src_ret < 0, errno == ENOENT
               ? HTTP_STATUS_CODE_NOT_FOUND
               : HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR,
               "couldn't stat source %s: %s",
               file_path, strerror(errno));

  struct stat dst_st;
  int dst_ret = stat(destination_path, &dst_st);
  HANDLE_ERROR(dst_ret < 0 && errno != ENOENT,
               HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR,
               "couldn't stat destination %s: %s",
               destination_path, strerror(errno));
  bool dst_existed = !dst_ret;

  const char *overwrite_str = http_get_header_value(&hc->rhs, WEBDAV_HEADER_OVERWRITE);
  bool overwrite = !(overwrite_str && str_case_equals(overwrite_str, "f"));

  /* kill directory if we're overwriting it */
  if (dst_existed) {
    if (overwrite) {
      linked_list_t failed_to_remove = rmtree(destination_path);
      linked_list_free(failed_to_remove, free);
    }
    else {
      HANDLE_ERROR(true, HTTP_STATUS_CODE_PRECONDITION_FAILED,
                   "%s already existed and overwrite is false",
                   destination_path);
    }
  }

  /* TODO: use NBIO/coroutine_io.h */
  bool copy_failed = true;
  if (hc->sub.copy.is_move) {
    /* first try moving */
    int ret = rename(file_path, destination_path);
    HANDLE_ERROR(ret < 0 && errno != EXDEV, HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR,
                 "couldn't move %s to %s: %s", file_path, destination_path,
                 strerror(errno));
    copy_failed = ret < 0;
  }

  if (copy_failed) {
    linked_list_t failed_to_copy = copytree(file_path, destination_path,
                                            hc->sub.copy.is_move);
    copy_failed = failed_to_copy;
    linked_list_free(failed_to_copy, free);
  }

  if (copy_failed) {
    /* TODO: should do a multi response */
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
  }
  else {
    status_code = dst_existed
      ? HTTP_STATUS_CODE_NO_CONTENT
      : HTTP_STATUS_CODE_CREATED;
  }

 done:
  free(file_path);
  free(destination_path);

  CRYIELD(hc->sub.copy.pos,
          http_request_string_response(hc->rh,
                                       status_code, "",
                                       handle_copy_request, hc));

  CRRETURN(hc->sub.copy.pos,
           request_proc(GENERIC_EVENT, NULL, hc));

#undef HANDLE_ERROR

  CREND();
}

static
EVENT_HANDLER_DEFINE(handle_delete_request, ev_type, ev, ud) {
  UNUSED(ev_type);
  UNUSED(ev);

  struct handler_context *hc = ud;

  CRBEGIN(hc->sub.delete.pos);

  http_status_code_t status_code = HTTP_STATUS_CODE_OK;

  char *fpath = path_from_uri(hc, hc->rhs.uri);
  if (!fpath) {
    log_info("Couldn't make file path from %s", hc->rhs.uri);
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* TODO: yield after every delete */
  int ret = file_exists(fpath);
  if (ret < 0) {
    log_info("Couldn't check if path %s existed, (errno %d) %s",
	     fpath, errno, strerror(errno));
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
  }
  else if (ret) {
    linked_list_t failed_to_delete = rmtree(fpath);

    /* TODO: return multi-status */
    if (failed_to_delete) {
      status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    }

    linked_list_free(failed_to_delete, free);
  }
  else {
    status_code = HTTP_STATUS_CODE_NOT_FOUND;
  }

 done:
  free(fpath);

  CRYIELD(hc->sub.delete.pos,
          http_request_string_response(hc->rh,
                                       status_code, "",
                                       handle_delete_request, hc));

  CRRETURN(hc->sub.delete.pos,
           request_proc(GENERIC_EVENT, NULL, hc));

  CREND();
}

static
EVENT_HANDLER_DEFINE(handle_get_request, ev_type, ev, ud) {
  struct handler_context *hc = ud;

  CRBEGIN(hc->sub.get.pos);

  size_t content_length;
  off_t pos;
  http_status_code_t code;

  static const char toret[] = "SORRY BRO";

  char *path = path_from_uri(hc, hc->rhs.uri);
  if (path &&
      (hc->sub.get.fd = open(path, O_RDONLY | O_NONBLOCK)) >= 0 &&
      (pos = lseek(hc->sub.get.fd, 0, SEEK_END)) >= 0) {
    code = HTTP_STATUS_CODE_OK;
    content_length = pos;
  }
  else {
    /* we couldn't open find just respond */
    code = HTTP_STATUS_CODE_NOT_FOUND;
    content_length = sizeof(toret) - 1;
  }

  if (path) {
    free(path);
  }

  bool ret;
  ret = http_response_set_code(&hc->resp, code);
  assert(ret);
  ret = http_response_add_header(&hc->resp,
                                 HTTP_HEADER_CONTENT_LENGTH, "%zu", content_length);
  assert(ret);

  CRYIELD(hc->sub.get.pos,
          http_request_write_headers(hc->rh, &hc->resp,
                                     handle_get_request, hc));
  assert(ev_type == HTTP_REQUEST_WRITE_HEADERS_DONE_EVENT);
  HTTPRequestWriteHeadersDoneEvent *write_headers_ev = ev;
  assert(write_headers_ev->request_handle == hc->rh);
  if (write_headers_ev->err != HTTP_SUCCESS) {
    goto done;
  }

  log_debug("Sent headers!");

  if (hc->resp.code == HTTP_STATUS_CODE_OK) {
    log_debug("Sending file %s, length: %s", &hc->rhs.uri[1], hc->resp.headers[0].value);

    /* seek back to beginning of file */
    int ret = lseek(hc->sub.get.fd, 0, SEEK_SET);
    UNUSED(ret);
    assert(!ret);

    /* TODO: must send up to the content-length we sent */
    while (true) {
      ssize_t amt_read = read(hc->sub.get.fd, hc->sub.get.buf, sizeof(hc->sub.get.buf));
      if (amt_read < 0 && errno == EAGAIN) {
        bool ret = fdevent_add_watch(hc->serv->loop, hc->sub.get.fd,
                                     create_stream_events(true, false),
                                     handle_get_request, hc,
                                     NULL);
        UNUSED(ret);
        assert(ret);
        CRYIELD(hc->sub.get.pos, (void) 0);
        assert(ev_type == FD_EVENT);
        continue;
      }
      else if (amt_read < 0) {
        log_error_errno("Error while read()ing file");
        /* error while reading the file */
        goto done;
      }
      else if (!amt_read) {
        /* EOF */
        log_debug("EOF done reading file; %zu", sizeof(hc->sub.get.buf));
        break;
      }

      log_debug("Sending %zd bytes", amt_read);

      /* now write to socket */
      CRYIELD(hc->sub.get.pos,
              http_request_write(hc->rh, hc->sub.get.buf, amt_read,
                                 handle_get_request, hc));
      assert(ev_type == HTTP_REQUEST_WRITE_DONE_EVENT);
      HTTPRequestWriteDoneEvent *write_ev = ev;
      UNUSED(write_ev);
      assert(write_ev->request_handle == hc->rh);
      if (write_ev->err != HTTP_SUCCESS) {
        goto done;
      }
    }
  }
  else {
    CRYIELD(hc->sub.get.pos,
            http_request_write(hc->rh, toret, sizeof(toret) - 1,
                               handle_get_request, hc));
    assert(ev_type == HTTP_REQUEST_WRITE_DONE_EVENT);
    HTTPRequestWriteDoneEvent *write_ev = ev;
    UNUSED(write_ev);
    assert(write_ev->request_handle == hc->rh);
    if (write_ev->err != HTTP_SUCCESS) {
      goto done;
    }
  }

 done:
  if (hc->sub.get.fd >= 0) {
    close(hc->sub.get.fd);
  }

  CRRETURN(hc->sub.get.pos,
           request_proc(GENERIC_EVENT, NULL, hc));

  CREND();
}

static bool
parse_lock_request_body(const char *body, size_t body_len,
                        bool *is_exclusive, char **owner_xml);

static bool
perform_write_lock(struct webdav_server *ws,
                   const char *file_path,
                   webdav_timeout_t timeout_in_seconds,
                   webdav_depth_t depth,
                   bool is_exclusive,
                   const char *owner_xml,
                   bool *is_locked,
                   char **lock_token,
                   bool *created,
                   char **status_path);

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

  CRBEGIN(hc->sub.lock.pos);

  /* read body first */
  CRYIELD(hc->sub.lock.pos,
          http_request_read_body(hc->rh,
                                 handle_lock_request,
                                 ud));
  assert(ev_type == GENERIC_EVENT);

  http_status_code_t status_code = 0;
  char *file_path = NULL;
  char *owner_xml = NULL;
  char *lock_token = NULL;
  char *status_path = NULL;
  hc->sub.lock.response_body = NULL;

  HTTPRequestReadBodyDoneEvent *rbev = ev;
  if (rbev->error) {
    log_info("Error while reading body of request");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  log_debug("Incoming lock request XML:\n%*s", rbev->length, rbev->body);

  /* read "If" header */
  const char *if_header = http_get_header_value(&hc->rhs, WEBDAV_HEADER_IF);
  if (if_header) {
    /* TODO: if header isn't supported right now,
       maybe there is a better status code to send back? */
    log_debug("If request header not supported");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* get webdav depth */
  webdav_depth_t depth = webdav_get_depth(&hc->rhs);
  if (depth != DEPTH_0 && depth != DEPTH_INF) {
    log_debug("Invalid depth sent %d", depth);
    status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }

  /* get timeout */
  webdav_timeout_t timeout_in_seconds = webdav_get_timeout(&hc->rhs);

  /* get path */
  file_path = path_from_uri(hc, hc->rhs.uri);
  if (!file_path) {
    log_debug("Invalid file path %s", hc->rhs.uri);
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* parse request body */
  bool is_exclusive;
  bool success_parse =
    parse_lock_request_body(rbev->body, rbev->length,
                            &is_exclusive, &owner_xml);
  if (!success_parse) {
    log_debug("Bad request body");
    status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }

  /* actually attempt to lock the resource */
  bool is_locked;
  bool created;
  bool success_perform =
    perform_write_lock(hc->serv,
                       file_path, timeout_in_seconds, depth, is_exclusive, owner_xml,
                       &is_locked, &lock_token, &created, &status_path);
  if (!success_perform) {
    log_debug("Error while performing lock");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* generate lock attempt response */
  bool success_generate;
  if (is_locked) {
    log_debug("Resource is already locked");
    success_generate =
      generate_failed_lock_response_body(hc, file_path, status_path,
                                         &status_code,
                                         &hc->sub.lock.response_body,
                                         &hc->sub.lock.response_body_len);
  }
  else {
    success_generate =
      generate_success_lock_response_body(hc, file_path, timeout_in_seconds,
                                          depth, is_exclusive, owner_xml,
                                          lock_token, created,
                                          &status_code,
                                          &hc->sub.lock.response_body,
                                          &hc->sub.lock.response_body_len);
  }

  if (!success_generate) {
    log_debug("Error while sending back response");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
  }

 done:
  assert(status_code);
  log_debug("Response with status code: %d", status_code);
  log_debug("Outgoing lock response XML (%lld bytes):\n%*s",
            (long long) hc->sub.lock.response_body_len,
            hc->sub.lock.response_body_len,
            hc->sub.lock.response_body);

  EASY_ALLOC(HeaderPair, hp);
  hp->name = "Lock-Token";
  char lock_token_header_value[256];
  int len_written = snprintf(lock_token_header_value, sizeof(lock_token_header_value),
                             "<%s>", lock_token);
  if (len_written == sizeof(lock_token_header_value) - 1) {
    /* TODO: Lazy */
    abort();
  }
  hp->value = strdup(lock_token_header_value);
  hc->sub.lock.headers = linked_list_prepend(hc->sub.lock.headers, hp);

  free(rbev->body);
  free(file_path);
  free(owner_xml);
  free(lock_token);
  free(status_path);

  CRYIELD(hc->sub.lock.pos,
          http_request_simple_response(hc->rh,
                                       status_code,
                                       hc->sub.lock.response_body,
                                       hc->sub.lock.response_body_len,
                                       "application/xml",
                                       hc->sub.lock.headers,
                                       handle_lock_request, ud));
  assert(ev_type == GENERIC_EVENT);
  /* if there is an error sending, oh well, just let the request end */

  free(hc->sub.lock.response_body);
  free(((HeaderPair *) hc->sub.lock.headers->elt)->value);
  free(hc->sub.lock.headers->elt);
  linked_list_free(hc->sub.lock.headers, NULL);

  CRRETURN(hc->sub.lock.pos,
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
      *owner_xml = strdup(STR(xmlBufferContent(buf)));
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
perform_write_lock(struct webdav_server *ws,
                   const char *file_path,
                   webdav_timeout_t timeout_in_seconds,
                   webdav_depth_t depth,
                   bool is_exclusive,
                   const char *owner_xml,
                   bool *is_locked,
                   char **lock_token,
                   bool *created,
                   char **status_path) {
  /* go through lock list and see if this path (or any descendants if depth != 0)
     have an incompatible lock
     if so then set that path as the status_path and return *is_locked = true
   */
  LINKED_LIST_FOR(WebdavLockDescriptor, elt, ws->locks) {
    bool parent_locks_us = false;
    if ((str_equals(elt->path, file_path) ||
         (depth == DEPTH_INF && is_parent_path(file_path, elt->path)) ||
         (parent_locks_us = (elt->depth == DEPTH_INF && is_parent_path(elt->path, file_path)))) &&
        (is_exclusive || elt->is_exclusive)) {
      *is_locked = true;
      *status_path = strdup(parent_locks_us ? file_path : elt->path);
      /* if the strdup failed then we return false */
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

  *lock_token = strdup(s_lock_token);
  if (!*lock_token) {
    return false;
  }

  /* okay we can lock this path, just add it to the lock list */
  EASY_ALLOC(WebdavLockDescriptor, new_lock);

  *new_lock = (WebdavLockDescriptor) {
    .path = strdup(file_path),
    .depth = depth,
    .is_exclusive = is_exclusive,
    .owner_xml = strdup(owner_xml),
    .lock_token = strdup(*lock_token),
    .timeout_in_seconds = timeout_in_seconds,
  };

  if (!new_lock->path ||
      !new_lock->owner_xml ||
      !new_lock->lock_token) {
    /* just die on ENOMEM */
    abort();
  }

  ws->locks = linked_list_prepend(ws->locks, new_lock);

  *is_locked = false;
  if ((*created = !file_exists(file_path))) {
    /* NB: ignoring touch error */
    touch(file_path);
  }

  return true;
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

  /* TODO: need to make sure owner_xml conforms to XML */
  xmlNodePtr owner_elt = xmlNewChild(activelock_elt, dav_ns, XMLSTR("owner"), XMLSTR(owner_xml));
  ASSERT_NOT_NULL(owner_elt);

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
  UNUSED(ev_type);

  struct handler_context *hc = ud;
  http_status_code_t status_code = 0;

  CRBEGIN(hc->sub.mkcol.pos);

  /* read body first */
  CRYIELD(hc->sub.mkcol.pos,
          http_request_ignore_body(hc->rh,
                                   handle_mkcol_request, hc));

  char *file_path = NULL;

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

  file_path = path_from_uri(hc, hc->rhs.uri);
  if (!file_path) {
    log_info("Couldn't make file path from %s", hc->rhs.uri);
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  int ret = mkdir(file_path, 0777);
  if (ret < 0) {
    log_debug("ERRNOR is %d", errno);
    if (errno == ENOENT) {
      status_code = HTTP_STATUS_CODE_CONFLICT;
    }
    else if (errno == ENOSPC ||
             errno == EDQUOT) {
      status_code = HTTP_STATUS_CODE_INSUFFICIENT_STORAGE;
    }
    else if (errno == ENOTDIR) {
      status_code = HTTP_STATUS_CODE_FORBIDDEN;
    }
    else if (errno == EACCES) {
      status_code = HTTP_STATUS_CODE_METHOD_NOT_ALLOWED;
    }
    else if (errno == EEXIST) {
      struct stat st;
      ret = stat(file_path, &st);
      if (ret < 0) {
        status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
      }
      else if (S_ISDIR(st.st_mode)) {
        status_code = HTTP_STATUS_CODE_METHOD_NOT_ALLOWED;
      }
      else {
        status_code = HTTP_STATUS_CODE_FORBIDDEN;
      }
    }
    else {
      status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    }
  }
  else {
    status_code = HTTP_STATUS_CODE_CREATED;
  }

 done:
  assert(status_code);

  free(file_path);

  CRYIELD(hc->sub.mkcol.pos,
          http_request_string_response(hc->rh,
                                       status_code, "",
                                       handle_mkcol_request, hc));

  CRRETURN(hc->sub.mkcol.pos,
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
  http_status_code_t status_code = 0;

  CRBEGIN(hc->sub.propfind.pos);

  hc->sub.propfind.buf = NULL;
  hc->sub.propfind.buf_used = 0;
  hc->sub.propfind.out_buf = NULL;
  hc->sub.propfind.out_buf_size = 0;

  /* read all posted data */
  CRYIELD(hc->sub.propfind.pos,
          http_request_read_body(hc->rh, handle_propfind_request, hc));
  HTTPRequestReadBodyDoneEvent *rbev = ev;
  if (rbev->error) {
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }
  hc->sub.propfind.buf = rbev->body;
  hc->sub.propfind.buf_used = rbev->length;

  /* figure out depth */
  webdav_depth_t depth = webdav_get_depth(&hc->rhs);
  if (depth == DEPTH_INVALID) {
    status_code = HTTP_STATUS_CODE_BAD_REQUEST;
    goto done;
  }

  /* run the request */
  run_propfind(hc, hc->rhs.uri, depth,
               hc->sub.propfind.buf, hc->sub.propfind.buf_used,
               &hc->sub.propfind.out_buf, &hc->sub.propfind.out_buf_size,
               &status_code);

 done:
  assert(status_code);
  log_debug("Responding with status: %d", status_code);

  CRYIELD(hc->sub.propfind.pos,
          http_request_simple_response(hc->rh,
                                       status_code,
                                       hc->sub.propfind.out_buf,
                                       hc->sub.propfind.out_buf_size,
                                       "application/xml",
                                       LINKED_LIST_INITIALIZER,
                                       handle_propfind_request, hc));

  if (hc->sub.propfind.out_buf) {
    /* TODO: use a generic returned free function */
    xmlFree(hc->sub.propfind.out_buf);
  }
  free(hc->sub.propfind.buf);
  CRRETURN(hc->sub.propfind.pos, request_proc(GENERIC_EVENT, NULL, hc));

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

  /* first parse the xml */
  assert(input_size <= INT_MAX);
  log_debug("XML request:\n%.*s", (int) input_size, input);

  xmlDocPtr doc = parse_xml_string(input, input_size);
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
                                              XMLSTR("HTTP/1.1 409 Conflict"));
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
  if (doc) {
    xmlFreeDoc(doc);
  }
}

static
EVENT_HANDLER_DEFINE(handle_put_request, ev_type, ev, ud) {
  UNUSED(ev_type);

  struct handler_context *hc = ud;
  /* always re-init to 0 */
  http_status_code_t status_code = 0;

  CRBEGIN(hc->sub.put.pos);

  hc->sub.put.fd = -1;

  const char *uri = hc->rhs.uri;
  const char *file_path = path_from_uri(hc, uri);
  if (!file_path) {
    log_warning("Couldn't make file path from %s", uri);
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  hc->sub.put.success_status_code = (file_exists(file_path) > 0
                                     ? HTTP_STATUS_CODE_OK
                                     : HTTP_STATUS_CODE_CREATED);

  hc->sub.put.fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK, 0666);
  if (hc->sub.put.fd < 0) {
    log_debug("ERRNO is %d", errno);
    if (errno == ENOTDIR) {
      status_code = HTTP_STATUS_CODE_CONFLICT;
      goto done;
    }
    else if (errno == EACCES) {
      status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
      goto done;
    }
  }

  /* TODO: implement `sendfile()` in http_request_* */
  while (true) {
    CRYIELD(hc->sub.put.pos,
            http_request_read(hc->rh,
                              hc->sub.put.read_buf, sizeof(hc->sub.put.read_buf),
                              handle_put_request, hc));
    HTTPRequestReadDoneEvent *read_done_ev = ev;
    if (read_done_ev->err != HTTP_SUCCESS) {
      goto error;
    }

    /* EOF */
    if (!read_done_ev->nbyte) {
      break;
    }

    CRYIELD(hc->sub.put.pos,
            c_write_all(hc->serv->loop, hc->sub.put.fd,
                        hc->sub.put.read_buf,
                        read_done_ev->nbyte,
                        handle_put_request,
                        hc));
    CWriteAllDoneEvent *c_write_all_done_ev = ev;
    if (c_write_all_done_ev->error_number) {
      status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
      goto done;
    }
  }

  status_code = hc->sub.put.success_status_code;

 done:
  assert(status_code);

  if (hc->sub.put.fd >= 0) {
    close(hc->sub.put.fd);
  }

  CRYIELD(hc->sub.put.pos,
          http_request_string_response(hc->rh,
                                       status_code, "",
                                       handle_put_request, hc));

 error:
  CRRETURN(hc->sub.put.pos,
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

int
main(int argc, char *argv[]) {
  port_t port;

  /* TODO: make configurable */
  log_level_t log_level = LOG_DEBUG;

  init_logging(stdout, log_level);
  log_info("Logging initted.");

  /* ignore SIGPIPE */
  signal(SIGPIPE, SIG_IGN);

  if (argc > 1) {
    long to_port = strtol(argv[1], NULL, 10);
    if ((to_port == 0 && errno) ||
	to_port < 0 ||
	to_port > MAX_PORT) {
      log_critical("Bad port: %s", argv[1]);
      return -1;
    }
    port = (port_t) to_port;
  }
  else {
    port = 8080;
  }

  /* create server socket */
  int server_fd = create_ipv4_bound_socket(port);
  assert(server_fd >= 0);

  /* create event loop */
  FDEventLoop loop;
  bool ret = fdevent_init(&loop);
  assert(ret);

  /* start http server */
  HTTPServer http;
  struct webdav_server serv = {
    .http = &http,
    .loop = &loop,
    .base_path = getcwd(NULL, 0),
    .locks = LINKED_LIST_INITIALIZER,
  };
  assert(serv.base_path);
  serv.base_path_len = strlen(serv.base_path);
  ret = http_server_start(&http, &loop, server_fd,
			  handle_request, &serv);
  assert(ret);

  log_info("Starting main loop");
  fdevent_main_loop(&loop);

  return 0;
}

