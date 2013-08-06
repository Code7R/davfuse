#include <cstring>
#include <ctime>

#include <stack>

#include "tinyxml2.h"

#include "http_server.h"
#include "util.h"
#include "webdav_server_common.h"
#include "_webdav_server_types.h"
#include "_webdav_server_private_types.h"

#include "webdav_server_xml.h"

using namespace tinyxml2;

#define XMLSTR(a) ((const xmlChar *) (a))
#define STR(a) ((const char *) (a))

static const char *const DAV_XML_NS = "DAV:";

/* utilities */

static PURE_FUNCTION bool
safe_str_equals(const char *a, const char *b) {
  return a && b ? str_equals(a, b) : !a && !b;
}

static PURE_FUNCTION const char *
get_ns_name(const char *elt_name) {
  const char *start_of_colon = strchr(elt_name, ':');
  if (start_of_colon) {
    elt_name = start_of_colon + 1;
  }

  return elt_name;
}

static PURE_FUNCTION const char *
get_ns_name(const XMLElement *elt) {
  return get_ns_name(elt->Name());
}

static PURE_FUNCTION const char *
get_ns_href(const XMLElement *elt, const char *raw_elt_name=NULL) {
  if (!raw_elt_name) {
    raw_elt_name = elt->Name();
  }

  const char *elt_href = NULL;
  const char *start_of_colon = strchr(raw_elt_name, ':');
  if (start_of_colon) {
    char *attr_to_query = (char *) malloc_or_abort(sizeof("xmlns:") + start_of_colon - raw_elt_name);
    memcpy(attr_to_query, "xmlns:", sizeof("xmlns:") - 1);
    memcpy(attr_to_query + sizeof("xmlns:") - 1, raw_elt_name, start_of_colon - raw_elt_name);
    attr_to_query[sizeof("xmlns:") + start_of_colon - raw_elt_name - 1] = '\0';

    /* okay now find the href for this ns, start at this elt and go up */
    const XMLElement *start_elt = elt;
    while (start_elt && !elt_href) {
      /* find the xmlns:<ns> attributes */
      elt_href = start_elt->Attribute(attr_to_query);
      start_elt = start_elt->Parent()->ToElement();
    }

    if (!elt_href) {
      /* TODO: change the interface to account for this type of invalid xml */
      log_warning("Element \"%s\" had a namespace but no HREF",
                  attr_to_query);
    }

    free(attr_to_query);
  }
  else {
    /* no explicitly designated namespace, look for the nearest empty xmlns */
    const XMLElement *start_elt = elt;
    while (start_elt && !elt_href) {
      elt_href = start_elt->Attribute("xmlns");
      start_elt = start_elt->Parent()->ToElement();
    }
  }

  return elt_href;
}

static PURE_FUNCTION bool
ns_equals(const XMLElement *elt, const char *test_href) {
  const char *ns_href = get_ns_href(elt);
  return safe_str_equals(test_href, ns_href);
}

static PURE_FUNCTION bool
node_is(const XMLElement *elt, const char *test_href, const char *test_name) {
  const char *elt_name = get_ns_name(elt);
  return (str_equals(elt_name, test_name) &&
          ns_equals(elt, test_href));
}

static XMLElement *
newChildElement(XMLNode *parent, const char *tag_name, const char *text=NULL) {
  auto new_element = parent->GetDocument()->NewElement(tag_name);
  parent->InsertEndChild(new_element);

  if (text) {
    auto new_text = parent->GetDocument()->NewText(text);
    new_element->InsertEndChild(new_text);
  }

  return new_element;
}

static void
unlinkNode(XMLNode *elt) {
  elt->Parent()->DeleteChild(elt);
}

/* This class is responsible for flattening out XML namespaces
   so that you can copy past XML easily. This is used for the Owner XML
   element in WebDAV (which needs to be preserved exactly). For Example,
   it turns this:

   <elt xmlns:D="HAI">
       <D:Yo D:sup="1" xmlns:H="LOL">
           <H:sick D:word="2" />
       </D>
   </elt>

   into:

   <elt>
       <Yo xmlns="HAI" xmlns:a0="HAI" a0:sup="1">
           <sick xmlns="LOL" xmlns:a0="HAI" a0:word="2" />
       </Yo>
   </elt>
*/
class _OwnerXmlStorer : public XMLVisitor {
public:
  _OwnerXmlStorer(XMLNode *initNode) {
    m_stack.push(initNode);
  }

  ~_OwnerXmlStorer() {
  }

  bool
  VisitEnter(const XMLElement & elt, const XMLAttribute *attrs) override;

  bool
  VisitExit(const XMLElement & elt) override;

  bool
  Visit(const XMLText & elt) override;

private:
  std::stack<XMLNode *> m_stack;
};

bool
_OwnerXmlStorer::VisitEnter(const XMLElement & elt, const XMLAttribute *attrs) {
  const char *elt_name = get_ns_name(&elt);
  const char *elt_href = get_ns_href(&elt);
  if (elt_href && str_equals(elt_href, "")) {
    /* the current interface doesn't handle this bad XML, so just die
       TODO: fix this */
    abort();
  }

  auto new_elt = newChildElement(m_stack.top(), elt_name);
  new_elt->SetAttribute("xmlns", elt_href ? elt_href : "");

  uintmax_t start = 0;
  for (const XMLAttribute *curattrs = attrs; curattrs;
       curattrs = curattrs->Next()) {
    const char *attr_ns_name = get_ns_name(curattrs->Name());
    if (str_equals(attr_ns_name, "xmlns")) {
      /* ignore xmlns declarations */
      continue;
    }

    const char *attr_ns_href = get_ns_href(&elt, curattrs->Name());
    if (attr_ns_href && str_equals(attr_ns_href, "")) {
      /* the current interface doesn't handle this bad XML, so just die
         TODO: fix this */
      abort();
    }

    if (attr_ns_href) {
      char long_str[200];
      int ret = snprintf(long_str, sizeof(long_str), "xmlns:a%lu",
                         (unsigned long) start);
      if (ret < 0 || ret == sizeof(long_str) - 1) {
        /* formatted string was too long */
        abort();
      }
      new_elt->SetAttribute(long_str, attr_ns_href);

      int ret2 = snprintf(long_str, sizeof(long_str), "a%lu:%s",
                          (unsigned long) start, attr_ns_name);
      if (ret2 < 0 || ret2 == sizeof(long_str) - 1) {
        /* formatted string was too long */
        abort();
      }

      new_elt->SetAttribute(long_str, curattrs->Value());
    }
    else {
      new_elt->SetAttribute(curattrs->Name(), curattrs->Value());
    }
  }

  m_stack.push(new_elt);
  return true;
}

bool
_OwnerXmlStorer::VisitExit(const XMLElement & elt) {
  UNUSED(elt);
  m_stack.pop();
  return true;
}

bool
_OwnerXmlStorer::Visit(const XMLText & elt) {
  auto new_elt = elt.ShallowClone(m_stack.top()->GetDocument());
  m_stack.top()->InsertEndChild(new_elt);
  return true;
}

static void
storeOwnerChildren(XMLElement *owner_elt, owner_xml_t *owner_xml) {
  /* goal here is to make a new xml document with the children of owner_elt */
  XMLDocument *doc = new XMLDocument();

  _OwnerXmlStorer a(doc);

  owner_elt->Accept(&a);

  *owner_xml = (void *) doc;
}

static void
loadOwnerChildren(XMLElement *owner_parent, owner_xml_t owner_xml) {
  XMLDocument *owner_doc = (XMLDocument *) owner_xml;

  _OwnerXmlStorer storer(owner_parent);

  owner_doc->Accept(&storer);
}

static void
serializeDoc(const XMLDocument &doc, char **out_data, size_t *out_size) {
  XMLPrinter streamer;
  doc.Print(&streamer);

  /* copy the data in streamer to a pointer that the caller
     can own,
     TODO: make this more efficient */
  *out_data = (char *) malloc(streamer.CStrSize() - 1);
  if (!out_data) {
    abort();
  }

  memcpy(*out_data, streamer.CStr(), streamer.CStrSize() - 1);
  *out_size = streamer.CStrSize() - 1;
}

/* owner xml abstraction */

void
owner_xml_free(owner_xml_t a) {
  delete ((XMLDocument *) a);
}



class _DocumentCopier : public XMLVisitor {
public:
  _DocumentCopier() {
    m_stack.push(new XMLDocument());
  }

  ~_DocumentCopier() {
  }

  XMLDocument *
  getCopy() const {
    return m_stack.top()->ToDocument();
  }

  bool
  VisitEnter(const XMLElement & elt, const XMLAttribute *attrs) override;

  bool
  VisitExit(const XMLElement & elt) override;

  bool
  Visit(const XMLText & elt) override;

private:
  std::stack<XMLNode *> m_stack;
};

bool
_DocumentCopier::VisitEnter(const XMLElement & elt, const XMLAttribute *attrs) {
  UNUSED(attrs);
  auto new_elt = elt.ShallowClone(m_stack.top()->GetDocument());
  m_stack.top()->InsertEndChild(new_elt);
  m_stack.push(new_elt);
  return true;
}

bool
_DocumentCopier::VisitExit(const XMLElement & elt) {
  UNUSED(elt);
  m_stack.pop();
  return true;
}

bool
_DocumentCopier::Visit(const XMLText & elt) {
  auto new_elt = elt.ShallowClone(m_stack.top()->GetDocument());
  m_stack.top()->InsertEndChild(new_elt);
  return true;
}

owner_xml_t
owner_xml_copy(owner_xml_t a) {
  XMLDocument *doc = (XMLDocument *) a;

  _DocumentCopier copier;

  doc->Accept(&copier);

  return copier.getCopy();
}

/* PROPFIND method XML functions */

xml_parse_code_t
parse_propfind_request(const char *req_data,
                       size_t req_data_length,
                       webdav_propfind_req_type_t *out_propfind_req_type,
                       linked_list_t *out_props_to_get) {
  xml_parse_code_t toret;

  XMLDocument doc;

  *out_props_to_get = LINKED_LIST_INITIALIZER;

  /* process the type of prop request */
  if (!req_data) {
    *out_propfind_req_type = WEBDAV_PROPFIND_ALLPROP;
  }
  else {
    auto error_parse = doc.Parse(req_data, req_data_length);
    if (error_parse) {
      /* TODO: could probably get a higher fidelity error */
      toret = XML_PARSE_ERROR_SYNTAX;
      goto done;
    }

    /* the root element should be DAV:propfind */
    auto root_element = doc.RootElement();
    if (!root_element ||
        !node_is(root_element, DAV_XML_NS, "propfind")) {
      /* root element is not propfind, this is bad */
      log_info("root element is not DAV:propfind: %s",
               root_element->Name());
      toret = XML_PARSE_ERROR_STRUCTURE;
      goto done;
    }
    log_debug("root element name: %s", root_element->Name());

    /* check if this is prop, allprop, or propname request */
    auto first_child = root_element->FirstChildElement();
    if (!first_child) {
      log_info("DAV:propfind has no child");
      toret = XML_PARSE_ERROR_STRUCTURE;
      goto done;
    }

    const char *propfind_elt_ns_href = get_ns_href(first_child);
    if (!safe_str_equals(propfind_elt_ns_href, DAV_XML_NS)) {
      log_info("Invalid propname child: %s", first_child->Name());
      toret = XML_PARSE_ERROR_STRUCTURE;
      goto done;
    }

    const char *propfind_elt_ns_name = get_ns_name(first_child);
    if (str_equals("propname", propfind_elt_ns_name)) {
      *out_propfind_req_type = WEBDAV_PROPFIND_PROPNAME;
    }
    else if (str_equals("allprop", propfind_elt_ns_name)) {
      *out_propfind_req_type = WEBDAV_PROPFIND_ALLPROP;
    }
    else if (str_equals("prop", propfind_elt_ns_name)) {
      *out_propfind_req_type = WEBDAV_PROPFIND_PROP;
      for (auto prop_elt = first_child->FirstChildElement();
           prop_elt; prop_elt = prop_elt->NextSiblingElement()) {
        const char *ns_name = get_ns_name(prop_elt);
        const char *ns_href = get_ns_href(prop_elt);
        if (ns_href && str_equals(ns_href, "")) {
          /* empty ns_hrefs are bad XML */
          toret = XML_PARSE_ERROR_STRUCTURE;
          goto done;
        }

        *out_props_to_get =
          linked_list_prepend(*out_props_to_get,
                              create_webdav_property(ns_name, ns_href));
      }
    }
    else {
      log_info("Invalid propname child: %s", first_child->Name());
      toret = XML_PARSE_ERROR_STRUCTURE;
      goto done;
    }
  }

  toret = XML_PARSE_ERROR_NONE;

 done:
  if (toret) {
    linked_list_free(*out_props_to_get,
                     (linked_list_elt_handler_t) free_webdav_property);
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
  XMLDocument doc;

  auto multistatus_elt = newChildElement(&doc, "multistatus");
  multistatus_elt->SetAttribute("xmlns", DAV_XML_NS);

  /* TODO: deal with the case where entries == NULL */
  LINKED_LIST_FOR (struct webdav_propfind_entry, propfind_entry, entries) {
    auto response_elt = newChildElement(multistatus_elt, "response");

    char *uri = uri_from_path(hc, propfind_entry->relative_uri);
    ASSERT_NOT_NULL(uri);
    newChildElement(response_elt, "href", uri);
    free(uri);

    auto propstat_not_found_elt = newChildElement(response_elt, "propstat");
    auto prop_not_found_elt = newChildElement(propstat_not_found_elt, "prop");
    newChildElement(propstat_not_found_elt, "status",
                    "HTTP/1.1 404 Not Found");

    auto propstat_success_elt = newChildElement(response_elt, "propstat");
    auto prop_success_elt = newChildElement(propstat_success_elt, "prop");
    newChildElement(propstat_success_elt, "status",
                    "HTTP/1.1 200 OK");

    auto propstat_failure_elt = newChildElement(response_elt, "propstat");
    auto prop_failure_elt = newChildElement(propstat_failure_elt, "prop");
    newChildElement(propstat_failure_elt, "status",
                    "HTTP/1.1 500 Internal Server Error");

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

        const char *fmt = is_get_last_modified
          ? "%a, %d %b %Y %T GMT"
          : "%Y-%m-%dT%H:%M:%S-00:00";

        size_t num_chars = strftime(time_buf, sizeof(time_buf), fmt, tm_);
        XMLElement *xml_node;

        if (!num_chars) {
          log_error("strftime failed!");
          time_str = NULL;
          xml_node = prop_failure_elt;
        }
        else {
          time_str = time_buf;
          xml_node = prop_success_elt;
        }

        newChildElement(xml_node, elt->element_name, time_str);
      }
      else if (str_equals(elt->element_name, "getcontentlength") &&
               str_equals(elt->ns_href, DAV_XML_NS) &&
               !propfind_entry->is_collection) {
        char length_str[400];
        snprintf(length_str, sizeof(length_str), "%lu",
                 (unsigned long) propfind_entry->length);
        newChildElement(prop_success_elt, "getcontentlength", length_str);
      }
      else if (str_equals(elt->element_name, "resourcetype") &&
               str_equals(elt->ns_href, DAV_XML_NS)) {
        auto resourcetype_elt = newChildElement(prop_success_elt, "resourcetype");

        if (propfind_entry->is_collection) {
          newChildElement(resourcetype_elt, "collection");
        }
      }
      else {
        auto random_elt = newChildElement(prop_not_found_elt, elt->element_name);
        random_elt->SetAttribute("xmlns", elt->ns_href);
      }
    }

    if (!prop_not_found_elt->FirstChildElement()) {
      unlinkNode(prop_not_found_elt);
    }

    if (!prop_success_elt->FirstChildElement()) {
      unlinkNode(propstat_success_elt);
    }

    if (!prop_failure_elt->FirstChildElement()) {
      unlinkNode(propstat_failure_elt);
    }
  }

  serializeDoc(doc, out_data, out_size);
  *out_status_code = HTTP_STATUS_CODE_MULTI_STATUS;

  return true;
}

/* LOCK method XML functions */

xml_parse_code_t
parse_lock_request_body(const char *body, size_t body_len,
                        bool *is_exclusive, owner_xml_t *owner_xml) {
  xml_parse_code_t toret;

  bool saw_lockscope = false;
  bool saw_locktype = false;
  XMLElement *root_element = NULL;

  /* this is an optional request parameter */
  *owner_xml = NULL;

  XMLDocument doc;
  auto error_parse = doc.Parse(body, body_len);
  if (error_parse) {
    toret = XML_PARSE_ERROR_SYNTAX;
    goto error;
  }

  root_element = doc.RootElement();
  if (!node_is(root_element, DAV_XML_NS, "lockinfo")) {
    toret = XML_PARSE_ERROR_STRUCTURE;
    goto error;
  }

  for (auto child = root_element->FirstChildElement();
       child; child = child->NextSiblingElement()) {
    if (node_is(child, DAV_XML_NS, "lockscope")) {
      *is_exclusive = (child->FirstChildElement() &&
                       node_is(child->FirstChildElement(), DAV_XML_NS, "exclusive"));
      saw_lockscope = true;
    }
    /* we require a proper write lock entity */
    else if (node_is(child, DAV_XML_NS, "locktype") &&
             child->FirstChildElement() &&
             node_is(child->FirstChildElement(), DAV_XML_NS, "write")) {
      saw_locktype = true;
    }
    else if (node_is(child, DAV_XML_NS, "owner")) {
      storeOwnerChildren(child, owner_xml);
    }
  }

  if (!saw_lockscope || !saw_locktype) {
    toret = XML_PARSE_ERROR_STRUCTURE;
  error:
    /* in case we found an owner */
    if (*owner_xml) {
      owner_xml_free(*owner_xml);
      *owner_xml = NULL;
    }
  }
  else {
    toret = XML_PARSE_ERROR_NONE;
  }

  return toret;
}

bool
generate_locked_response(struct handler_context *hc,
                         const char *locked_path,
                         http_status_code_t *status_code,
                         char **response_body,
                         size_t *response_body_len) {
  XMLDocument doc;

  auto error_elt = newChildElement(&doc, "error");
  error_elt->SetAttribute("xmlns", DAV_XML_NS);

  newChildElement(error_elt, "lock-token-submitted");

  char *uri = uri_from_path(hc, locked_path);
  ASSERT_NOT_NULL(uri);
  newChildElement(error_elt, "href", uri);
  free(uri);

  serializeDoc(doc, response_body, response_body_len);

  *status_code = HTTP_STATUS_CODE_LOCKED;

  return true;
}

bool
generate_locked_descendant_response(struct handler_context *hc,
                                    const char *locked_descendant,
                                    http_status_code_t *status_code,
                                    char **response_body,
                                    size_t *response_body_len) {
  XMLDocument doc;

  auto multistatus_elt = newChildElement(&doc, "multistatus");
  multistatus_elt->SetAttribute("xmlns", DAV_XML_NS);

  auto response_elt = newChildElement(multistatus_elt, "response");

  char *uri = uri_from_path(hc, locked_descendant);
  ASSERT_NOT_NULL(uri);
  newChildElement(response_elt, "href", uri);
  free(uri);

  newChildElement(response_elt, "status", "HTTP/1.1 423 Locked");

  auto error_elt = newChildElement(response_elt, "error");
  newChildElement(error_elt, "lock-token-submitted");

  serializeDoc(doc, response_body, response_body_len);

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
  XMLDocument doc;

  auto multistatus_elt = newChildElement(&doc, "multistatus");
  multistatus_elt->SetAttribute("xmlns", DAV_XML_NS);

  bool same_path = str_equals(file_path, status_path);
  const char *locked_status = "HTTP/1.1 423 Locked";

  if (!same_path) {
    auto response_elt = newChildElement(multistatus_elt, "response");

    char *status_uri = uri_from_path(hc, status_path);
    ASSERT_NOT_NULL(status_uri);
    newChildElement(response_elt, "href", status_uri);
    free(status_uri);

    newChildElement(response_elt, "status", locked_status);
  }

  auto response_elt = newChildElement(multistatus_elt, "response");

  char *file_uri = uri_from_path(hc, file_path);
  ASSERT_NOT_NULL(file_uri);
  newChildElement(response_elt, "href", file_uri);
  free(file_uri);

  newChildElement(response_elt, "status",
                  same_path ? locked_status : "HTTP/1.1 424 Failed Dependency");


  serializeDoc(doc, response_body, response_body_len);

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
  XMLDocument doc;

  auto prop_elt = newChildElement(&doc, "prop");
  prop_elt->SetAttribute("xmlns", DAV_XML_NS);

  auto lockdiscovery_elt = newChildElement(prop_elt, "lockdiscovery");

  auto activelock_elt = newChildElement(lockdiscovery_elt, "activelock");

  auto locktype_elt = newChildElement(activelock_elt, "locktype");

  newChildElement(locktype_elt, "write");

  auto lockscope_elt = newChildElement(activelock_elt, "lockscope");

  if (is_exclusive) {
    newChildElement(lockscope_elt, "exclusive");
  }
  else {
    newChildElement(lockscope_elt, "shared");
  }

  assert(depth == DEPTH_0 || depth == DEPTH_INF);
  newChildElement(activelock_elt, "depth",
                  depth == DEPTH_INF ? "infinity" : "0");

  if (owner_xml) {
    loadOwnerChildren(activelock_elt, owner_xml);
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

  newChildElement(activelock_elt, "timeout", timeout_str);
  auto locktoken_elt = newChildElement(activelock_elt, "locktoken");
  newChildElement(locktoken_elt, "href", lock_token);

  auto lockroot_elt = newChildElement(activelock_elt, "lockroot");

  char *lockroot_uri = uri_from_path(hc, file_path);
  ASSERT_NOT_NULL(lockroot_uri);
  newChildElement(lockroot_elt, "href", file_path);
  free(lockroot_uri);


  serializeDoc(doc, response_body, response_body_len);

  *status_code = created ? HTTP_STATUS_CODE_CREATED : HTTP_STATUS_CODE_OK;

  return true;
}

xml_parse_code_t
parse_proppatch_request(const char *body, size_t body_len,
                        linked_list_t *out_proppatch_directives) {
  xml_parse_code_t toret;
  XMLElement *root_element;

  XMLDocument doc;

  auto error_parse = doc.Parse(body, body_len);
  if (error_parse) {
    toret = XML_PARSE_ERROR_SYNTAX;
    goto done;
  }

  root_element = doc.RootElement();
  if (!node_is(root_element, DAV_XML_NS, "propertyupdate")) {
    /* root element is not propertyupdate, this is bad */
    log_info("root element is not DAV:, propertyupdate %s",
             root_element->Name());
    toret = XML_PARSE_ERROR_STRUCTURE;
    goto done;
  }

  *out_proppatch_directives = LINKED_LIST_INITIALIZER;

  /* now iterate over every propertyupdate directive */
  /* TODO: for now we don't support setting anything */
  /* we don't support arbitrary dead properties */
  for (auto cur_child = root_element->FirstChildElement(); cur_child;
       cur_child = cur_child->NextSiblingElement()) {
    const char *ns_href = get_ns_href(cur_child);
    const char *ns_name = get_ns_name(cur_child);

    if (!safe_str_equals(ns_href, DAV_XML_NS) ||
        (!str_equals(ns_name, "set") &&
         !str_equals(ns_name, "remove"))) {
      /* this is just bad input XML schema */
      /* we'll ignore it for now though, doesn't really hurt anything */
      continue;
    }

    webdav_proppatch_directive_type_t type = str_equals(ns_name, "set")
      ? WEBDAV_PROPPATCH_DIRECTIVE_SET
      : WEBDAV_PROPPATCH_DIRECTIVE_REMOVE;

    /* get the prop elt */
    auto prop_elt = cur_child->FirstChildElement();
    for (; prop_elt; prop_elt = prop_elt->NextSiblingElement()) {
      if (node_is(prop_elt, DAV_XML_NS, "prop")) {
        break;
      }
    }

    /* now iterate over each prop being modified in
       this directive (either set/remove) */
    if (prop_elt) {
      for (auto xml_prop = prop_elt->FirstChildElement(); xml_prop;
           xml_prop = xml_prop->NextSiblingElement()) {
        const char *ns_href = get_ns_href(xml_prop);
        if (ns_href && str_equals(ns_href, "")) {
          /* empty ns_hrefs are bad XML */
          toret = XML_PARSE_ERROR_STRUCTURE;
          goto done;
        }

        const char *ns_name = get_ns_name(xml_prop);

        WebdavProppatchDirective *directive =
          create_webdav_proppatch_directive(type, ns_name, ns_href, NULL);
        if (!directive) {
          abort();
        }

        *out_proppatch_directives =
          linked_list_prepend(*out_proppatch_directives, directive);
      }
    }
  }

  toret = XML_PARSE_ERROR_NONE;

 done:
  if (toret) {
    linked_list_free(*out_proppatch_directives,
                     (linked_list_elt_handler_t) free_webdav_proppatch_directive);
  }

  return toret;
}

bool
generate_proppatch_response(const char *uri,
                            linked_list_t props_to_patch,
                            char **output, size_t *output_size,
                            http_status_code_t *status_code) {
  XMLDocument doc;

  auto multistatus_elt = newChildElement(&doc, "multistatus");
  multistatus_elt->SetAttribute("xmlns", DAV_XML_NS);

  auto response_elt = newChildElement(multistatus_elt, "response");

  newChildElement(response_elt, "href", uri);

  auto propstat_elt = newChildElement(response_elt, "propstat");
  auto new_prop_elt = newChildElement(propstat_elt, "prop");
  newChildElement(propstat_elt, "status",
                  "HTTP/1.1 403 Forbidden");

  /* now iterate over every propertyupdate directive */
  /* TODO: for now we don't support setting anything */
  /* we don't support arbitrary dead properties */
  LINKED_LIST_FOR (WebdavProppatchDirective, elt, props_to_patch) {
    /* add this element to the proppatch response */
    auto new_xml_prop = newChildElement(new_prop_elt, elt->name);
    new_xml_prop->SetAttribute("xmlns", elt->ns_href ? elt->ns_href : "");
  }

  serializeDoc(doc, output, output_size);

  *status_code = HTTP_STATUS_CODE_MULTI_STATUS;

  return true;
}

void
init_xml_parser(void) {
  /* our character constants must be ascii */
  static_assert(' ' == 32, "Character constants aren't ASCII!");
  /* bad runtime locale */
  if (!isspace(' ')) {
    abort();
  }
}

void
shutdown_xml_parser(void) {
  /* DO NOTHING */
}
