/*
  A webdav compatible http file server out of the current directory
 */
#define _ISOC99_SOURCE

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "events.h"
#include "fdevent.h"
#include "fd_utils.h"
#include "http_server.h"
#include "logging.h"
#include "uthread.h"
#include "util.h"

enum {
  BUF_SIZE=4096,
};

typedef struct {
  char *element_name;
  char *ns_href;
} WebdavProperty;

#define XMLSTR(a) ((const xmlChar *) a)

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
str_equals(const char *a, const char *b) {
  return !strcmp(a, b);
}

static bool PURE_FUNCTION
xml_str_equals(const xmlChar *restrict a, const char *restrict b) {
  return str_equals((const char *) a, b);
}

static char *
path_from_uri(const char *uri) {
  /* todo make this not suck, and use server context */
  if (uri[0] != '/') {
    /* can't parse this */
    return NULL;
  }

  //if  uri == "/"
  if (uri[1] == '\0') {
    return strdup(".");
  }

  /* return relative path */
  return strdup(&uri[1]);
}

static void
run_propfind(const char *uri,
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

  log_debug("XML request: %s", req_data);

  if (!req_data) {
    propfind_req_type = PROPFIND_ALLPROP;
  }
  else {
    xmlParserOption options = XML_PARSE_COMPACT | XML_PARSE_NOBLANKS;
#ifdef NDEBUG
    options |= XML_PARSE_NOERROR | XML_PARSER_NOWARNING;
#endif
    doc = xmlReadMemory(req_data, req_data_length,
                        "noname.xml", NULL, options);
    if (!doc) {
      /* bad xml */
      log_info("Client sent up invalid xml");
      *status_code = HTTP_STATUS_CODE_BAD_REQUEST;
      goto local_exit;
    }

    /* the root element should be DAV:propfind */
    xmlNodePtr root_element = xmlDocGetRootElement(doc);
    if (!(xml_str_equals(root_element->name, "propfind") &&
          xml_str_equals(root_element->ns->href, "DAV:"))) {
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
        !xml_str_equals(first_child->ns->href, "DAV:")) {
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
    else {
      log_info("Invalid propname child: %s", first_child->name);
      *status_code = HTTP_STATUS_CODE_BAD_REQUEST;
      goto local_exit;
    }
  }

  if (propfind_req_type != PROPFIND_PROP) {
    log_info("We only support 'prop' requests");
    *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto local_exit;
  }

  /* build up response */
  file_path = path_from_uri(uri);
  if (!file_path) {
    log_info("Couldn't make file path from %s", uri);
    *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto local_exit;
  }
  struct stat st;
  int statret = stat(file_path, &st);
  if (statret < 0) {
    /* TODO: the file could not be found, 404 is also valid */
    log_info("stat(%s) failed: %s", file_path, strerror(errno));
    if (errno == ENOENT) {
      *status_code = HTTP_STATUS_CODE_NOT_FOUND;
    }
    else {
      *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    }
    goto local_exit;
  }

  xml_response = xmlNewDoc(XMLSTR("1.0"));
  assert(xml_response);
  xmlNodePtr multistatus_elt = xmlNewDocNode(xml_response, NULL, XMLSTR("multistatus"), NULL);
  assert(multistatus_elt);
  xmlDocSetRootElement(xml_response, multistatus_elt);

  xmlNsPtr dav_ns = xmlNewNs(multistatus_elt, XMLSTR("DAV:"), XMLSTR("D"));
  assert(dav_ns);
  xmlSetNs(multistatus_elt, dav_ns);
  xmlNodePtr response_elt = xmlNewChild(multistatus_elt, dav_ns, XMLSTR("response"), NULL);
  assert(response_elt);

  xmlNodePtr href_elt = xmlNewTextChild(response_elt, dav_ns,
                                        XMLSTR("href"), XMLSTR(uri));
  assert(href_elt);
  xmlNodePtr propstat_success_elt = xmlNewChild(response_elt, dav_ns, XMLSTR("propstat"), NULL);
  assert(propstat_success_elt);
  xmlNodePtr propstat_failure_elt = xmlNewChild(response_elt, dav_ns, XMLSTR("propstat"), NULL);
  assert(propstat_failure_elt);

  xmlNodePtr prop_success_elt = xmlNewChild(propstat_success_elt, dav_ns, XMLSTR("prop"), NULL);
  assert(propstat_success_elt);
  xmlNodePtr status_success_elt = xmlNewTextChild(propstat_success_elt, dav_ns,
                                                  XMLSTR("status"),
                                                  XMLSTR("HTTP/1.1 200 OK"));
  assert(status_success_elt);
  xmlNodePtr prop_failure_elt = xmlNewChild(propstat_failure_elt, dav_ns, XMLSTR("prop"), NULL);
  assert(prop_failure_elt);
  xmlNodePtr status_failure_elt = xmlNewTextChild(propstat_failure_elt, dav_ns,
                                                  XMLSTR("status"),
                                                  XMLSTR("HTTP/1.1 404 Not Found"));
  assert(status_failure_elt);

  LINKED_LIST_FOR(WebdavProperty, elt, props_to_get) {
    if (str_equals(elt->element_name, "getlastmodified") &&
        str_equals(elt->ns_href, "DAV:")) {
      time_t m_time = (time_t) st.st_mtime;
      struct tm *tm_ = gmtime(&m_time);
      char time_str[400];
      size_t num_chars = strftime(time_str, sizeof(time_str),
                                  "%a, %d %b %Y %T GMT", tm_);
      if (!num_chars) {
        log_error("strftime failed!");
        *status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
        goto local_exit;
      }

      /* TODO place content in string */
      xmlNodePtr getlastmodified_elt = xmlNewTextChild(prop_success_elt, dav_ns,
                                                       XMLSTR("getlastmodified"), XMLSTR(time_str));
      assert(getlastmodified_elt);
    }
    else if (str_equals(elt->element_name, "getcontentlength") &&
             str_equals(elt->ns_href, "DAV:") &&
             !S_ISDIR(st.st_mode)) {
      char time_str[400];
      snprintf(time_str, sizeof(time_str), "%lld", (long long) st.st_size);
      xmlNodePtr getcontentlength_elt = xmlNewTextChild(prop_success_elt, dav_ns,
                                                        XMLSTR("getcontentlength"), XMLSTR(time_str));
      assert(getcontentlength_elt);
    }
    else if (str_equals(elt->element_name, "resourcetype") &&
             str_equals(elt->ns_href, "DAV:") &&
             S_ISDIR(st.st_mode)
             ) {
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
      /* not implemented for this file system */
      xmlNodePtr creationdate_elt = xmlNewChild(prop_failure_elt, NULL,
                                                XMLSTR(elt->element_name), NULL);
      assert(creationdate_elt);
      xmlNsPtr new_ns = xmlNewNs(creationdate_elt, XMLSTR(elt->ns_href), NULL);
      xmlSetNs(creationdate_elt, new_ns);
    }
  }

  /* convert doc to text and send to client */
  xmlChar *out_buf;
  int out_buf_size;
  xmlDocDumpFormatMemory(xml_response, &out_buf, &out_buf_size, 1);
  *out_data = (char *) out_buf;
  assert(out_buf_size >= 0);
  *out_size = out_buf_size;

  log_debug("XML response will be %s", out_buf);

 local_exit:
  if (xml_response) {
    xmlFreeDoc(xml_response);
  }
  linked_list_free(props_to_get, (linked_list_elt_handler_t) free_webdav_property);
  if (doc) {
    xmlFreeDoc(doc);
  }
  free(file_path);
}

struct handler_context {
  UTHR_CTX_BASE;
  HTTPServer *server;
  FDEventLoop *loop;
  HTTPRequestHeaders rhs;
  HTTPResponseHeaders resp;
  http_request_handle_t rh;
  union {
    struct {
      coroutine_position_t pos;
      char buf[BUF_SIZE];
      int fd;
    } get;
    struct {
      coroutine_position_t pos;
      char scratch_buf[BUF_SIZE];
      char *buf;
      size_t buf_used, buf_size;
      char *out_buf;
      size_t out_buf_size;
    } propfind;
  } sub;
};

static EVENT_HANDLER_DECLARE(handle_request);
static EVENT_HANDLER_DECLARE(handle_get_request);
static EVENT_HANDLER_DECLARE(handle_options_request);
static EVENT_HANDLER_DECLARE(handle_propfind_request);

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

  /* "GET", not supported */
  event_handler_t handler;
  if (!strcasecmp(hc->rhs.method, "GET")) {
    handler = handle_get_request;
  }
  else if (!strcasecmp(hc->rhs.method, "OPTIONS")) {
    handler = handle_options_request;
  }
  else if (!strcasecmp(hc->rhs.method, "PROPFIND")) {
    handler = handle_propfind_request;
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
               http_request_simple_response(hc->rh,
                                            HTTP_STATUS_CODE_METHOD_NOT_ALLOWED, "Not allowed",
                                            request_proc, hc));
  }

 done:
  log_info("request done!");

  UTHR_RETURN(hc, http_request_end(hc->rh));

  UTHR_FOOTER();
}

static
EVENT_HANDLER_DEFINE(handle_get_request, ev_type, ev, ud) {
  struct handler_context *hc = ud;

  CRBEGIN(hc->sub.get.pos);

  size_t content_length;
  off_t pos;
  http_status_code_t code;

  static const char toret[] = "SORRY BRO";

  char *path = path_from_uri(hc->rhs.uri);
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
        bool ret = fdevent_add_watch(hc->loop, hc->sub.get.fd,
                                     create_stream_events(true, false),
                                     handle_get_request, hc,
                                     NULL);
        UNUSED(ret);
        assert(ret);
        CRYIELD(hc->sub.get.pos, 0);
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
EVENT_HANDLER_DEFINE(handle_options_request, ev_type, ev, ud) {
  UNUSED(ev_type);
  UNUSED(ev);

  struct handler_context *hc = ud;
  bool ret;

  ret = http_response_set_code(&hc->resp, HTTP_STATUS_CODE_OK);
  assert(ret);

  ret = http_response_add_header(&hc->resp, "DAV", "1");
  assert(ret);

  ret = http_response_add_header(&hc->resp, "Allow",
                                 "GET,HEAD,PUT,DELETE,MKCOL,COPY,MOVE,PROPFIND,OPTIONS");
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
  /* reset upon re-entry */
  http_status_code_t status_code = HTTP_STATUS_CODE_OK;

  CRBEGIN(hc->sub.propfind.pos);

  hc->sub.propfind.buf = NULL;
  hc->sub.propfind.out_buf = NULL;

  /* read all posted data */
  /* TODO: abstract this out */
  while (true) {
    CRYIELD(hc->sub.propfind.pos,
            http_request_read(hc->rh,
                              hc->sub.propfind.scratch_buf,
                              sizeof(hc->sub.propfind.scratch_buf),
                              handle_propfind_request, ud));
    assert(ev_type == HTTP_REQUEST_READ_DONE_EVENT);
    HTTPRequestReadDoneEvent *read_done_ev = ev;
    if (!read_done_ev->nbyte) {
      /* EOF */
      break;
    }

    if (hc->sub.propfind.buf_size - hc->sub.propfind.buf_used < read_done_ev->nbyte) {
      size_t new_buf_size = MAX(1, hc->sub.propfind.buf_size);
      while (new_buf_size - hc->sub.propfind.buf_used < read_done_ev->nbyte) {
        new_buf_size *= 2;
      }

      void *new_ptr = realloc(hc->sub.propfind.buf, new_buf_size);
      if (!new_ptr) {
        status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
        goto done;
      }

      hc->sub.propfind.buf = new_ptr;
      hc->sub.propfind.buf_size = new_buf_size;
    }

    /* defensive coding, make sure we're still handling the same event */
    assert(ev_type == HTTP_REQUEST_READ_DONE_EVENT);
    memcpy(hc->sub.propfind.buf + hc->sub.propfind.buf_used,
           hc->sub.propfind.scratch_buf, read_done_ev->nbyte);
    hc->sub.propfind.buf_used += read_done_ev->nbyte;
  }

  /* figure out depth */
  enum {
    DEPTH_0,
    DEPTH_1,
    DEPTH_INF,
  } depth;

  const char *depth_str = http_get_header_value(&hc->rhs, "depth");
  if (!depth_str || !strcasecmp(depth_str, "infinity")) {
    depth = DEPTH_INF;
  }
  else {
    long ret = strtol(depth_str, NULL, 10);
    if ((ret == 0 && errno == EINVAL) ||
        (ret != 0 && ret != 1)) {
      log_info("Client sent up bad depth header: %s", depth_str);
      status_code = HTTP_STATUS_CODE_BAD_REQUEST;
      goto done;
    }
    depth = ret ? DEPTH_1 : DEPTH_0;
  }

  /* TODO: support this */
  if (depth != DEPTH_0) {
    log_info("We don't support non-depth 0 propfind requests");
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  /* run the request */
  run_propfind(hc->rhs.uri,
               hc->sub.propfind.buf, hc->sub.propfind.buf_used,
               &hc->sub.propfind.out_buf, &hc->sub.propfind.out_buf_size,
               &status_code);

 done:
  log_debug("Responding with status: %d", status_code);
  /* send headers */
  bool ret = http_response_set_code(&hc->resp, status_code);
  assert(ret);

  size_t content_length;
  if (status_code == HTTP_STATUS_CODE_OK) {
    content_length = hc->sub.propfind.out_buf_size;
  }
  else {
    content_length = 0;
  }

  ret = http_response_add_header(&hc->resp, HTTP_HEADER_CONTENT_LENGTH,
                                 "%zu", content_length);
  assert(ret);
  CRYIELD(hc->sub.get.pos,
          http_request_write_headers(hc->rh, &hc->resp,
                                     handle_propfind_request, hc));
  assert(ev_type == HTTP_REQUEST_WRITE_HEADERS_DONE_EVENT);
  HTTPRequestWriteHeadersDoneEvent *write_headers_ev = ev;
  assert(write_headers_ev->request_handle == hc->rh);
  if (write_headers_ev->err != HTTP_SUCCESS) {
    goto totally_done;
  }

  if (status_code == HTTP_STATUS_CODE_OK) {
    assert(hc->sub.propfind.out_buf);
    CRYIELD(hc->sub.propfind.pos,
            http_request_write(hc->rh,
                               hc->sub.propfind.out_buf,
                               hc->sub.propfind.out_buf_size,
                               handle_propfind_request, hc));
    assert(ev_type == HTTP_REQUEST_WRITE_DONE_EVENT);
    HTTPRequestWriteDoneEvent *write_ev = ev;
    if (write_ev->err != HTTP_SUCCESS) {
      goto totally_done;
    }
  }

 totally_done:
  if (hc->sub.propfind.out_buf) {
    /* TODO: use a generic returned free function */
    xmlFree(hc->sub.propfind.out_buf);
  }
  free(hc->sub.propfind.buf);
  CRRETURN(hc->sub.propfind.pos, request_proc(GENERIC_EVENT, NULL, hc));

  CREND();
}

static
EVENT_HANDLER_DEFINE(handle_request, ev_type, ev, ud) {
  assert(ev_type == HTTP_NEW_REQUEST_EVENT);
  HTTPNewRequestEvent *new_request_ev = ev;

  UTHR_CALL2(request_proc, struct handler_context,
             .server = new_request_ev->server,
             .rh = new_request_ev->request_handle,
             .loop = ud);
}

int main(int argc, char *argv[]) {
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
  ret = http_server_start(&http, &loop, server_fd,
			  handle_request, &loop);
  assert(ret);

  log_info("Starting main loop");
  fdevent_main_loop(&loop);

  return 0;
}

