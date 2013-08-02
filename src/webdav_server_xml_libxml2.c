#define _ISOC99_SOURCE

#include <time.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "webdav_server_common.h"
#include "_webdav_server_private_types.h"

#include "webdav_server_xml.h"

#define XMLSTR(a) ((const xmlChar *) (a))
#define STR(a) ((const char *) (a))

static const char *const DAV_XML_NS = "DAV:";

/* utilities */

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
  options |= XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
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

/* owner xml abstraction */

void
owner_xml_free(owner_xml_t a) {
  xmlFreeNode(a);
}

owner_xml_t
owner_xml_copy(owner_xml_t a) {
  return xmlCopyNode(a, 1);
}

/* PROPFIND method XML functions */

xml_parse_code_t
parse_propfind_request(const char *req_data,
                       size_t req_data_length,
                       webdav_propfind_req_type_t *out_propfind_req_type,
                       linked_list_t *out_props_to_get) {
  xml_parse_code_t toret;
  xmlDocPtr doc = NULL;
  *out_props_to_get = LINKED_LIST_INITIALIZER;

  /* process the type of prop request */
  if (!req_data) {
    *out_propfind_req_type = WEBDAV_PROPFIND_ALLPROP;
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
    if (!(node_is(root_element, DAV_XML_NS, "propfind"))) {
      /* root element is not propfind, this is bad */
      log_info("root element is not DAV:, propfind");
      toret = XML_PARSE_ERROR_STRUCTURE;
      goto done;
    }
    log_debug("root element name: %s", root_element->name);

    /* check if this is prop, allprop, or propname request */
    xmlNodePtr first_child = root_element->children;
    if (node_is(first_child, DAV_XML_NS, "propname")) {
      *out_propfind_req_type = WEBDAV_PROPFIND_PROPNAME;
    }
    else if (node_is(first_child, DAV_XML_NS, "allprop")) {
      *out_propfind_req_type = WEBDAV_PROPFIND_ALLPROP;
    }
    else if (node_is(first_child, DAV_XML_NS, "prop")) {
      *out_propfind_req_type = WEBDAV_PROPFIND_PROP;
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

bool
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
  ASSERT_NOT_NULL(dav_ns);
  xmlSetNs(multistatus_elt, dav_ns);

  /* TODO: deal with the case where entries == NULL */
  LINKED_LIST_FOR (struct webdav_propfind_entry, propfind_entry, entries) {
    xmlNodePtr response_elt = xmlNewChild(multistatus_elt, dav_ns, XMLSTR("response"), NULL);
    assert(response_elt);

    char *uri = uri_from_path(hc, propfind_entry->relative_uri);
    ASSERT_NOT_NULL(uri);
    xmlNodePtr href_elt = xmlNewTextChild(response_elt, dav_ns,
                                          XMLSTR("href"), XMLSTR(uri));
    ASSERT_NOT_NULL(href_elt);
    free(uri);

    xmlNodePtr propstat_not_found_elt = xmlNewChild(response_elt, dav_ns, XMLSTR("propstat"), NULL);
    ASSERT_NOT_NULL(propstat_not_found_elt);
    xmlNodePtr prop_not_found_elt = xmlNewChild(propstat_not_found_elt, dav_ns, XMLSTR("prop"), NULL);
    ASSERT_NOT_NULL(prop_not_found_elt);
    xmlNodePtr status_not_found_elt = xmlNewTextChild(propstat_not_found_elt, dav_ns,
                                                      XMLSTR("status"),
                                                      XMLSTR("HTTP/1.1 404 Not Found"));
    ASSERT_NOT_NULL(status_not_found_elt);

    xmlNodePtr propstat_success_elt = xmlNewChild(response_elt, dav_ns, XMLSTR("propstat"), NULL);
    ASSERT_NOT_NULL(propstat_success_elt);
    xmlNodePtr prop_success_elt = xmlNewChild(propstat_success_elt, dav_ns, XMLSTR("prop"), NULL);
    ASSERT_NOT_NULL(propstat_success_elt);
    xmlNodePtr status_success_elt = xmlNewTextChild(propstat_success_elt, dav_ns,
                                                    XMLSTR("status"),
                                                    XMLSTR("HTTP/1.1 200 OK"));
    ASSERT_NOT_NULL(status_success_elt);

    xmlNodePtr propstat_failure_elt = xmlNewChild(response_elt, dav_ns, XMLSTR("propstat"), NULL);
    ASSERT_NOT_NULL(propstat_failure_elt);
    xmlNodePtr prop_failure_elt = xmlNewChild(propstat_failure_elt, dav_ns, XMLSTR("prop"), NULL);
    ASSERT_NOT_NULL(prop_failure_elt);
    xmlNodePtr status_failure_elt = xmlNewTextChild(propstat_failure_elt, dav_ns,
                                                    XMLSTR("status"),
                                                    XMLSTR("HTTP/1.1 500 Internal Server Error"));
    ASSERT_NOT_NULL(status_failure_elt);

    LINKED_LIST_FOR (WebdavProperty, elt, props_to_get) {
      bool is_get_last_modified;
      if (str_equals(elt->ns_href, DAV_XML_NS) &&
          ((is_get_last_modified = str_equals(elt->element_name, "getlastmodified")) ||
           /* TODO: this should be configurable but for now we just
              set getlastmodified and creationdate to the same date
              because that's what apache mod_dav does */
           str_equals(elt->element_name, "creationdate"))) {
        time_t m_time = (time_t) propfind_entry->modified_time;
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
        ASSERT_NOT_NULL(getlastmodified_elt);
      }
      else if (str_equals(elt->element_name, "getcontentlength") &&
               str_equals(elt->ns_href, DAV_XML_NS) &&
               !propfind_entry->is_collection) {
        char length_str[400];
        snprintf(length_str, sizeof(length_str), "%lld",
                 (long long) propfind_entry->length);
        xmlNodePtr getcontentlength_elt = xmlNewTextChild(prop_success_elt, dav_ns,
                                                          XMLSTR("getcontentlength"), XMLSTR(length_str));
        ASSERT_NOT_NULL(getcontentlength_elt);
      }
      else if (str_equals(elt->element_name, "resourcetype") &&
               str_equals(elt->ns_href, DAV_XML_NS)) {
        xmlNodePtr resourcetype_elt = xmlNewChild(prop_success_elt, dav_ns,
                                                  XMLSTR("resourcetype"), NULL);
        ASSERT_NOT_NULL(resourcetype_elt);

        if (propfind_entry->is_collection) {
          xmlNodePtr collection_elt = xmlNewChild(resourcetype_elt, dav_ns,
                                                  XMLSTR("collection"), NULL);
          ASSERT_NOT_NULL(collection_elt);
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

/* LOCK method XML functions */

bool
parse_lock_request_body(const char *body, size_t body_len,
                        bool *is_exclusive, owner_xml_t *owner_xml) {
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
      *owner_xml = xmlCopyNode(child->children, 1);
    }
  }

  if (!saw_lockscope || !saw_locktype) {
  error:
    /* in case we found an owner */
    if (*owner_xml) {
      owner_xml_free(*owner_xml);
      *owner_xml = NULL;
    }
    toret = false;
  }

  xmlFreeDoc(doc);

  return toret;
}

bool
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

bool
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

bool
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

bool
generate_success_lock_response_body(struct handler_context *hc,
                                    const char *file_path,
                                    webdav_timeout_t timeout_in_seconds,
                                    webdav_depth_t depth,
                                    bool is_exclusive,
                                    const owner_xml_t owner_xml,
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
    xmlNodePtr owner_elt = xmlNewChild(activelock_elt, dav_ns, XMLSTR("owner"), NULL);
    ASSERT_NOT_NULL(owner_elt);
    xmlNodePtr owner_xml_2 = xmlCopyNode(owner_xml, 1);
    xmlAddChild(owner_elt, owner_xml_2);
    xmlReconciliateNs(xml_response, owner_xml_2);
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

xml_parse_code_t
parse_proppatch_request(const char *body, size_t body_len,
                        linked_list_t *out_proppatch_directives) {
  xml_parse_code_t toret;

  xmlDocPtr doc = parse_xml_string(body, body_len);
  if (!doc) {
    toret = XML_PARSE_ERROR_SYNTAX;
    goto done;
  }

  xmlNodePtr root_element = xmlDocGetRootElement(doc);
  if (!(str_equals(STR(root_element->name), "propertyupdate") &&
        ns_equals(root_element, DAV_XML_NS))) {
    /* root element is not propertyupdate, this is bad */
    log_info("root element is not DAV:, propertyupdate %s",
             root_element->name);
    toret = XML_PARSE_ERROR_STRUCTURE;
    goto done;
  }

  *out_proppatch_directives = LINKED_LIST_INITIALIZER;

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
          webdav_proppatch_directive_type_t type = str_equals(STR(cur_child->name), "set")
            ? WEBDAV_PROPPATCH_DIRECTIVE_SET
            : WEBDAV_PROPPATCH_DIRECTIVE_REMOVE;

          WebdavProppatchDirective *directive =
            create_webdav_proppatch_directive(type,
                                              STR(xml_prop->name),
                                              STR(xml_prop->ns ? xml_prop->ns->href : NULL),
                                              NULL);
          if (!directive) {
            abort();
          }

          *out_proppatch_directives =
            linked_list_prepend(*out_proppatch_directives, directive);
        }
      }
    }
    else {
      /* this is just bad input XML schema */
      /* we'll ignore it for now though, doesn't really hurt anything */
    }
  }

  toret = XML_PARSE_ERROR_NONE;

 done:
  if (doc) {
    xmlFreeDoc(doc);
  }

  return toret;
}

bool
generate_proppatch_response(const char *uri,
                            linked_list_t props_to_patch,
                            char **output, size_t *output_size,
                            http_status_code_t *status_code) {
  xmlDocPtr xml_response = xmlNewDoc(XMLSTR("1.0"));
  ASSERT_NOT_NULL(xml_response);
  xmlNodePtr multistatus_elt = xmlNewDocNode(xml_response, NULL,
                                             XMLSTR("multistatus"), NULL);
  ASSERT_NOT_NULL(multistatus_elt);
  xmlDocSetRootElement(xml_response, multistatus_elt);

  xmlNsPtr dav_ns = xmlNewNs(multistatus_elt, XMLSTR(DAV_XML_NS), XMLSTR("D"));
  ASSERT_NOT_NULL(dav_ns);
  xmlSetNs(multistatus_elt, dav_ns);

  xmlNodePtr response_elt = xmlNewChild(multistatus_elt, dav_ns,
                                        XMLSTR("response"), NULL);
  ASSERT_NOT_NULL(response_elt);

  xmlNodePtr href_elt = xmlNewTextChild(response_elt, dav_ns,
                                        XMLSTR("href"), XMLSTR(uri));
  ASSERT_NOT_NULL(href_elt);

  xmlNodePtr propstat_elt = xmlNewChild(response_elt, dav_ns,
                                        XMLSTR("propstat"), NULL);
  xmlNodePtr new_prop_elt = xmlNewChild(propstat_elt, dav_ns,
                                        XMLSTR("prop"), NULL);
  xmlNodePtr new_status_elt = xmlNewTextChild(propstat_elt, dav_ns,
                                              XMLSTR("status"),
                                              XMLSTR("HTTP/1.1 403 Forbidden"));
  ASSERT_NOT_NULL(new_status_elt);

  /* now iterate over every propertyupdate directive */
  /* TODO: for now we don't support setting anything */
  /* we don't support arbitrary dead properties */
  LINKED_LIST_FOR (WebdavProppatchDirective, elt, props_to_patch) {
    /* add this element to the proppatch response */
    xmlNodePtr new_xml_prop = xmlNewChild(new_prop_elt, NULL,
                                          XMLSTR(elt->name), NULL);
    ASSERT_NOT_NULL(new_xml_prop);
    if (elt->ns_href) {
      xmlNsPtr ns_ptr = xmlNewNs(new_xml_prop, XMLSTR(elt->ns_href), XMLSTR("mypref"));
      ASSERT_NOT_NULL(ns_ptr);
      xmlSetNs(new_xml_prop, ns_ptr);
    }
  }

  int format_xml = 1;
  int out_size;
  xmlDocDumpFormatMemory(xml_response, (xmlChar **) output, &out_size, format_xml);
  assert(out_size >= 0);
  *output_size = out_size;

  if (xml_response) {
    xmlFreeDoc(xml_response);
  }

  *status_code = HTTP_STATUS_CODE_MULTI_STATUS;

  return true;
}

void
shutdown_xml_parser(void) {
  xmlCleanupParser();
}
