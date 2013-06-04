/*
  A webdav compatible http file server out of the current directory
 */
#define _ISOC99_SOURCE
#define _BSD_SOURCE

#include <fcntl.h>
#include <sys/stat.h>
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

#define XMLSTR(a) ((const xmlChar *) a)
#define STR(a) ((char *) a)

const char *DAV_XML_NS = "DAV:";

const char *WEBDAV_HEADER_DEPTH = "Depth";
const char *WEBDAV_HEADER_DESTINATION = "Destination";
const char *WEBDAV_HEADER_OVERWRITE = "Overwrite";

enum {
  BUF_SIZE=4096,
};

typedef enum {
  DEPTH_0,
  DEPTH_1,
  DEPTH_INF,
  DEPTH_INVALID,
} webdav_depth_t;

typedef struct {
  char *element_name;
  char *ns_href;
} WebdavProperty;

struct webdav_server {
  HTTPServer *http;
  FDEventLoop *loop;
  char *base_path;
  size_t base_path_len;
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

  char *toret = malloc(hc->serv->base_path_len + uri_len + 1);
  if (!toret) {
    return NULL;
  }
  memcpy(toret, hc->serv->base_path, hc->serv->base_path_len);
  memcpy(toret + hc->serv->base_path_len, real_uri, uri_len);
  toret[hc->serv->base_path_len + uri_len] = '\0';

  return toret;
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

static void
add_propstat_response_for_path(const char *uri,
                               int fd,
                               linked_list_t props_to_get,
                               xmlNodePtr multistatus_elt,
                               xmlNsPtr dav_ns) {
  struct stat st;
  int my_errno = 0;
  int statret = -1;
  if (fd < 0 ||
      (statret = fstat(fd, &st)) < 0) {
    /* TODO: the file could not be found, 404 is also valid */
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

    if (str_equals(elt->element_name, "getlastmodified") &&
        str_equals(elt->ns_href, DAV_XML_NS)) {
      time_t m_time = (time_t) st.st_mtime;
      struct tm *tm_ = gmtime(&m_time);
      char time_str[400];
      size_t num_chars = strftime(time_str, sizeof(time_str),
                                  "%a, %d %b %Y %T GMT", tm_);
      if (!num_chars) {
        log_error("strftime failed!");
        xmlNodePtr getlastmodified_elt = xmlNewTextChild(prop_failure_elt, dav_ns,
                                                         XMLSTR("getlastmodified"), NULL);
        assert(getlastmodified_elt);
      }
      else {
        /* TODO place content in string */
        xmlNodePtr getlastmodified_elt = xmlNewTextChild(prop_success_elt, dav_ns,
                                                         XMLSTR("getlastmodified"), XMLSTR(time_str));
        assert(getlastmodified_elt);
      }
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
             str_equals(elt->ns_href, DAV_XML_NS) &&
             S_ISDIR(st.st_mode)) {
      xmlNodePtr resourcetype_elt = xmlNewChild(prop_success_elt, dav_ns,
                                                XMLSTR("resourcetype"), NULL);
      assert(resourcetype_elt);

      xmlNodePtr collection_elt = xmlNewChild(resourcetype_elt, dav_ns,
                                              XMLSTR("collection"), NULL);
      assert(collection_elt);
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

  /* build up response */
  file_path = path_from_uri(hc, uri);
  if (!file_path) {
    log_info("Couldn't make file path from %s", uri);
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

  /* try keeping a single fd open for the duration of the directory iteration */
  if (depth == DEPTH_1) {
    /* depth one, try directory by default first */
    dir = opendir(file_path);
    if (!dir) {
      log_info("Depth 1 but couldn't open directory: %s", strerror(errno));
    }
  }

  if (dir) {
    root_fd = dirfd(dir);
  }
  else {
    root_fd = open(file_path, O_RDONLY);
  }

  /* negative fd means check errno */
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
      char new_uri[1024];
      size_t len = strlen(uri);
      memcpy(new_uri, uri, len);
      strcpy(new_uri + len, d->d_name);

      add_propstat_response_for_path(new_uri, fd, props_to_get, multistatus_elt, dav_ns);
      if (fd >= 0) {
        close(fd);
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
                                       handle_proppatch_request, hc));

  if (hc->sub.proppatch.response_body) {
    /* TODO: use a generic returned free function */
    xmlFree(hc->sub.proppatch.response_body);
  }
  free(hc->sub.proppatch.request_body);
  CRRETURN(hc->sub.proppatch.pos, request_proc(GENERIC_EVENT, NULL, hc));

  CREND();
}

static PURE_FUNCTION bool
ns_equals(xmlNodePtr elt, const char *href) {
  return (elt->ns &&
          str_equals(STR(elt->ns->href), href));
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

