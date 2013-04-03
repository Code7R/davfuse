/*
  A webdav compatible http file server out of the current directory
 */
#define _ISOC99_SOURCE

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <assert.h>
#include <dirent.h>
#include <signal.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "events.h"
#include "fdevent.h"
#include "fd_utils.h"
#include "http_helpers.h"
#include "http_server.h"
#include "logging.h"
#include "uthread.h"
#include "util.h"

enum {
  BUF_SIZE=4096,
};

typedef enum {
  DEPTH_0,
  DEPTH_1,
  DEPTH_INF,
} webdav_depth_t;

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
str_startswith(const char *a, const char *b) {
  size_t len_a = strlen(a);
  size_t len_b = strlen(b);
  if (len_a < len_b) {
    return false;
  }

  return !memcmp(a, b, len_b);
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
        str_equals(elt->ns_href, "DAV:")) {
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

static void
run_propfind(const char *uri, webdav_depth_t depth,
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

  log_debug("XML request: Depth: %d, %s", depth, req_data);

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
  file_path = path_from_uri(uri);
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

  xmlNsPtr dav_ns = xmlNewNs(multistatus_elt, XMLSTR("DAV:"), XMLSTR("D"));
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
  xmlDocDumpFormatMemory(xml_response, &out_buf, &out_buf_size, 1);
  *out_data = (char *) out_buf;
  assert(out_buf_size >= 0);
  *out_size = out_buf_size;
  log_debug("XML response will be %s", out_buf);
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
    struct {
      coroutine_position_t pos;
    } mkcol;
    struct {
      coroutine_position_t pos;
    } delete;
  } sub;
};

static EVENT_HANDLER_DECLARE(handle_request);
static EVENT_HANDLER_DECLARE(handle_delete_request);
static EVENT_HANDLER_DECLARE(handle_get_request);
static EVENT_HANDLER_DECLARE(handle_mkcol_request);
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
  else if (!strcasecmp(hc->rhs.method, "DELETE")) {
    handler = handle_delete_request;
  }
  else if (!strcasecmp(hc->rhs.method, "MKCOL")) {
    handler = handle_mkcol_request;
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
EVENT_HANDLER_DEFINE(handle_delete_request, ev_type, ev, ud) {
  UNUSED(ev_type);
  UNUSED(ev);

  struct handler_context *hc = ud;

  CRBEGIN(hc->sub.delete.pos);

  /* recursive delete, this should be fun */
  linked_list_t failed_to_delete = LINKED_LIST_INITIALIZER;
  linked_list_t delete_queue = LINKED_LIST_INITIALIZER;
  http_status_code_t status_code = HTTP_STATUS_CODE_OK;
  DIR *dir = NULL;

  char *fpath = path_from_uri(hc->rhs.uri);
  if (!fpath) {
    log_info("Couldn't make file path from %s", hc->rhs.uri);
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }

  delete_queue = linked_list_prepend(delete_queue, fpath);
  while (delete_queue) {
    char *path;
    delete_queue = linked_list_popleft(delete_queue, (void **) &path);

    struct stat st;
    int ret = stat(path, &st);
    if (ret < 0) {
      log_debug("Error while stat(\"%s\"): %s", path, strerror(errno));
      goto minidone;
    }

    log_debug("Deleting %s", path);
    if (S_ISDIR(st.st_mode)) {
      /* if we're a directory, attempt to delete first */
      ret = rmdir(path);
      if (ret < 0) {
        if (errno == ENOTEMPTY) {
          /* not empty... if the top of the failed_to_delete stack is an descendant of ours,
             then add ourselves to it, otherwise, add ourselves back to the queue an all of
             our children */
          char *top_child = linked_list_peekleft(failed_to_delete);

          log_debug("TOP CHILD: %s", top_child);
          log_debug("path: %s", path);
          if (top_child && str_startswith(top_child, path)) {
            failed_to_delete = linked_list_prepend(failed_to_delete, path);
            path = NULL;
          }
          else {
            char *path_alias = path;
            /* keep the dir around, try to delete later */
            delete_queue = linked_list_prepend(delete_queue, path);
            /* don't free path, now that it's back on the top of the delete queue */
            path = NULL;

            struct dirent *d;
            dir = opendir(path_alias);
            if (!dir) {
              log_debug("Error while opendir(%s): %s", path_alias, strerror(errno));
              goto minidone;
            }

            size_t len_of_dirname = strlen(path_alias);
            while ((d = readdir(dir)) != NULL) {
              if (str_equals(d->d_name, "..") ||
                  str_equals(d->d_name, ".")) {
                continue;
              }

              size_t len_of_basename = strlen(d->d_name);
              char *new_child = malloc(len_of_dirname + 1 + len_of_basename + 1);
              if (!new_child) {
                goto minidone;
              }

              memcpy(new_child, path_alias, len_of_dirname);
              new_child[len_of_dirname] = '/';
              memcpy(new_child + len_of_dirname + 1, d->d_name, len_of_basename);
              new_child[len_of_dirname + 1 + len_of_basename] = '\0';

              delete_queue = linked_list_prepend(delete_queue, new_child);
            }

            closedir(dir);
            dir = NULL;
          }
        }
        else {
          /* failed to delete, just move on */
          failed_to_delete = linked_list_prepend(failed_to_delete, path);
          path = NULL;
        }
      }
    }
    else {
      ret = unlink(path);
      if (ret < 0) {
        /* failed to delete, just move on */
        failed_to_delete = linked_list_prepend(failed_to_delete, path);
        path = NULL;
      }
    }

    if (false) {
  minidone:
      free(path);
      status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
      goto done;
    }
  }

 done:
  if (dir) {
    closedir(dir);
  }

  linked_list_free(failed_to_delete, free);
  linked_list_free(delete_queue, free);

  CRYIELD(hc->sub.delete.pos,
          http_request_string_response(hc->rh,
                                       status_code, "",
                                       handle_delete_request, hc));

  CRRETURN(hc->sub.delete.pos,
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

  const char *uri = hc->rhs.uri;
  const char *file_path = path_from_uri(uri);
  if (!file_path) {
    log_info("Couldn't make file path from %s", uri);
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
        status_code = HTTP_STATUS_CODE_CREATED;
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
  /* TODO: abstract this out */
  http_request_read_body(hc->rh, handle_propfind_request, hc);
  HTTPRequestReadBodyDoneEvent *rbev = ev;
  if (rbev->error) {
    status_code = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    goto done;
  }
  hc->sub.propfind.buf = rbev->body;
  hc->sub.propfind.buf_used = rbev->length;

  /* figure out depth */
  webdav_depth_t depth;

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

  /* run the request */
  run_propfind(hc->rhs.uri, depth,
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

