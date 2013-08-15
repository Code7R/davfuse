#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <ctime>

#include <deque>
#include <memory>
#include <stack>
#include <string>
#include <unordered_set>

#include "tinyxml2.h"

#include "http_server.h"
#include "util.h"
#include "_webdav_server_types.h"
#include "_webdav_server_private_types.h"

#include "webdav_server_xml.h"

using namespace tinyxml2;

static const char *const DAV_XML_NS = "DAV:";
static const char *const DAV_XML_NS_PREFIX = "D";

/* utilities */

/* this little class allows us to get C++ RAII with C based data structures */
template <class T, void (*func)(T)>
class CFreer {
private:
  T & myt;
public:
  CFreer(T & var) : myt(var) {}
  ~CFreer() {
    func(myt);
  }
};

void free_str(char *f) {
  return free((void *) f);
}

void free_linked_list_of_propfind_entries(linked_list_t ents) {
  return linked_list_free(ents,
                          (linked_list_elt_handler_t) webdav_destroy_propfind_entry);

}

typedef CFreer<char *, free_str> CStringFreer;

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
    CStringFreer free_attr_to_query(attr_to_query);
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
  }
  else {
    /* no explicitly designated namespace, look for the nearest empty xmlns */
    const XMLElement *start_elt = elt;
    while (start_elt && !elt_href) {
      elt_href = start_elt->Attribute("xmlns");
      start_elt = start_elt->Parent()->ToElement();
    }
  }

  /* we stopped at the first relevant namespace attribute
     but an empty namespace href means there is no namespace */
  if (elt_href && str_equals(elt_href, "")) {
    elt_href = NULL;
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
newChildElement(XMLNode *parent, const char *one, const char *two=NULL) {
  const char *ns_prefix;
  const char *pure_tag_name;
  const char *tag_name;
  char *copied_tag_name = NULL;
  CStringFreer free_copied_tag_name(copied_tag_name);

  if (two) {
    ns_prefix = one;
    pure_tag_name = two;
  }
  else {
    ns_prefix = NULL;
    pure_tag_name = one;
  }

  if (ns_prefix) {
    copied_tag_name = super_strcat(ns_prefix, ":", pure_tag_name, NULL);
    ASSERT_NOT_NULL(copied_tag_name);
    tag_name = copied_tag_name;
  }
  else {
    tag_name = pure_tag_name;
  }

  auto new_element = parent->GetDocument()->NewElement(tag_name);
  parent->InsertEndChild(new_element);

  return new_element;
}

static XMLElement *
newChildElementWithText(XMLNode *parent, const char *one, const char *two,
                        const char *three=NULL) {
  const char *ns_prefix;
  const char *tag_name;
  const char *text;

  if (three) {
    ns_prefix = one;
    tag_name = two;
    text = three;
  }
  else {
    ns_prefix = NULL;
    tag_name = one;
    text = two;
  }

  auto new_element = ns_prefix
    ? newChildElement(parent, ns_prefix, tag_name)
    : newChildElement(parent, tag_name);

  auto new_text = parent->GetDocument()->NewText(text);
  new_element->InsertEndChild(new_text);

  return new_element;
}

static void
unlinkNode(XMLNode *elt) {
  elt->Parent()->DeleteChild(elt);
}

static bool
serializeDoc(const XMLDocument &doc, char **out_data, size_t *out_size) {
  XMLPrinter streamer;
  doc.Print(&streamer);

  /* copy the data in streamer to a pointer that the caller
     can own,
     TODO: make this more efficient */
  *out_data = (char *) malloc(streamer.CStrSize() - 1);
  if (!out_data) {
    return false;
  }

  memcpy(*out_data, streamer.CStr(), streamer.CStrSize() - 1);
  *out_size = streamer.CStrSize() - 1;

  return true;
}

/* owner xml abstraction */

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
  _OwnerXmlStorer(XMLNode *initNode)
  : m_stack(std::deque<XMLNode *>({initNode})),
    m_ns_count(0)
  {}

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
  uintmax_t m_ns_count;

  const char *FindOrCreatePrefix(XMLElement *start_at, const char *ns_href);
};

static bool
is_xmlns_attr(const XMLAttribute *a) {
  const char *attr_name = a->Name();
  return (str_equals(attr_name, "xmlns") ||
          str_startswith(attr_name, "xmlns:"));
}

struct c_str_pred {
  bool
  operator()(const char *s1, const char *s2) const {
    return str_equals(s1, s2);
  }
};

struct c_str_hash {
  size_t
  operator()(const char *p) const {
    return std::hash<std::string>()(p);
  }
};

static const char *
findPrefix(XMLElement *start_at, const char *ns_href) {
  assert(!str_equals(ns_href, ""));

  const char *prefix = NULL;

  std::unordered_set<const char *, c_str_hash, c_str_pred> prefixes_seen;

  XMLElement *search = start_at;
  while (search && !prefix) {
    /* search each xmlns declaration for the href */
    for (const XMLAttribute *attr = search->FirstAttribute();
         attr && !prefix; attr = attr->Next()) {
      if (!is_xmlns_attr(attr)) {
        continue;
      }

      const char *potential_prefix = str_equals(attr->Name(), "xmlns")
        ? ""
        : strchr(attr->Name(), ':') + 1;
      assert(potential_prefix != (void *) 1);

      /* check that this prefix hasn't been invalidated anywhere below */
      if (!prefixes_seen.count(potential_prefix) &
          str_equals(attr->Value(), ns_href)) {
        /* whoa we found it */
        prefix = potential_prefix;
      }
      else {
        /* higher up prefix values won't count,
           since they will be overshadowed by this */
        prefixes_seen.insert(potential_prefix);
      }
    }

    search = search->Parent()->ToElement();
  }

  return prefix;
}

const char *
_OwnerXmlStorer::FindOrCreatePrefix(XMLElement *start_at, const char *ns_href) {
  const char *prefix = findPrefix(start_at, ns_href);

  if (!prefix) {
    /* prefix didn't exist for this href, create a new one */
    /* we don't worry about shadowing an existing parent xmlns declaration
       (a collision of xmlns:ns%d) because findPrefix will keep track of that */
    char buf[40];
    int ret_sprintf2 = snprintf(buf, sizeof(buf), "xmlns:ns%" PRIuMAX, m_ns_count);
    ASSERT_TRUE(ret_sprintf2 >= 0 && ((size_t) ret_sprintf2) < sizeof(buf));
    m_ns_count += 1;
    start_at->SetAttribute(buf, ns_href);

    /* requery attribute to get pointer to prefix string that's is managed
       by the document */
    const XMLAttribute *new_attribute = ((const XMLElement *) start_at)->FindAttribute(buf);
    assert(new_attribute);
    prefix = strchr(new_attribute->Name(), ':') + 1;
  }

  assert(prefix);

  return prefix;
}

bool
_OwnerXmlStorer::VisitEnter(const XMLElement & elt, const XMLAttribute *attrs) {
  const char *elt_name = get_ns_name(&elt);
  const char *elt_href = get_ns_href(&elt);

  /* find an xml tag namespace prefix for the current namespace href */
  XMLElement *parent_element = m_stack.top()->ToElement();

  const char *prefix = elt_href
    ? (parent_element
       ? FindOrCreatePrefix(parent_element, elt_href)
       /* our parent is the doc, we're adding the root element
          so we have to bootstrap our own prefix */
       : "ns0")
    : NULL;

  auto new_elt = newChildElement(m_stack.top(), prefix, elt_name);
  if (elt_href && !parent_element) {
    new_elt->SetAttribute("xmlns:ns0", elt_href);
  }

  for (const XMLAttribute *curattrs = attrs; curattrs;
       curattrs = curattrs->Next()) {
    if (is_xmlns_attr(curattrs)) {
      /* ignore xmlns declarations */
      continue;
    }

    const char *attr_ns_name = get_ns_name(curattrs->Name());
    const char *attr_ns_href = get_ns_href(&elt, curattrs->Name());

    if (attr_ns_href) {
      const char *prefix = FindOrCreatePrefix(new_elt, attr_ns_href);
      assert(prefix);
      char *new_attr_name = super_strcat(prefix, ":", attr_ns_name, NULL);
      ASSERT_NOT_NULL(new_attr_name);
      CStringFreer free_new_attr_name(new_attr_name);
      new_elt->SetAttribute(new_attr_name, curattrs->Value());
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

void
owner_xml_free(owner_xml_t a) {
  delete ((XMLDocument *) a);
}

class _DocumentCopier : public XMLVisitor {
public:
  _DocumentCopier()
    : m_stack(std::deque<XMLNode *>({new XMLDocument()}))
  {}

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

static linked_list_t
default_props_to_get(void) {
  linked_list_t toret = LINKED_LIST_INITIALIZER;

  toret =
    linked_list_prepend(toret,
                        create_webdav_property("getlastmodified", DAV_XML_NS));

  toret =
    linked_list_prepend(toret,
                        create_webdav_property("creationdate", DAV_XML_NS));

  toret =
    linked_list_prepend(toret,
                        create_webdav_property("getcontentlength", DAV_XML_NS));

  toret =
    linked_list_prepend(toret,
                        create_webdav_property("resourcetype", DAV_XML_NS));

  return toret;
}

bool
generate_propfind_response(struct handler_context *hc,
                           webdav_propfind_req_type_t req_type,
                           linked_list_t props_to_get_,
                           linked_list_t entries,
                           char **out_data,
                           size_t *out_size,
                           http_status_code_t *out_status_code) {
  if (req_type == WEBDAV_PROPFIND_PROPNAME) {
    /* TODO: not supported yet */
    return false;
  }

  linked_list_t allocated_props_to_get = req_type == WEBDAV_PROPFIND_ALLPROP
    ? default_props_to_get()
    : 0;
  CFreer<linked_list_t, free_linked_list_of_propfind_entries> free_props_to_get(allocated_props_to_get);

  linked_list_t props_to_get = req_type == WEBDAV_PROPFIND_ALLPROP
    ? allocated_props_to_get
    : props_to_get_;

  XMLDocument doc;
  doc.InsertEndChild(doc.NewDeclaration());

  auto multistatus_elt = newChildElement(&doc, DAV_XML_NS_PREFIX, "multistatus");

  char *xmlns_attr_name = super_strcat("xmlns:", DAV_XML_NS_PREFIX, NULL);
  ASSERT_NOT_NULL(xmlns_attr_name);
  CStringFreer free_xmlns_attr_name(xmlns_attr_name);
  multistatus_elt->SetAttribute(xmlns_attr_name, DAV_XML_NS);

  /* TODO: deal with the case where entries == NULL */
  ASSERT_NOT_NULL(entries);
  LINKED_LIST_FOR (struct webdav_propfind_entry, propfind_entry, entries) {
    auto response_elt = newChildElement(multistatus_elt, DAV_XML_NS_PREFIX, "response");

    char *uri = uri_from_path(hc, propfind_entry->relative_uri);
    ASSERT_NOT_NULL(uri);
    CStringFreer free_uri(uri);

    newChildElementWithText(response_elt, DAV_XML_NS_PREFIX, "href", uri);

    auto propstat_not_found_elt = newChildElement(response_elt, DAV_XML_NS_PREFIX, "propstat");
    auto prop_not_found_elt = newChildElement(propstat_not_found_elt, DAV_XML_NS_PREFIX, "prop");
    newChildElementWithText(propstat_not_found_elt, DAV_XML_NS_PREFIX, "status",
                            "HTTP/1.1 404 Not Found");

    auto propstat_success_elt = newChildElement(response_elt, DAV_XML_NS_PREFIX, "propstat");
    auto prop_success_elt = newChildElement(propstat_success_elt, DAV_XML_NS_PREFIX, "prop");
    newChildElementWithText(propstat_success_elt, DAV_XML_NS_PREFIX, "status",
                            "HTTP/1.1 200 OK");

    auto propstat_failure_elt = newChildElement(response_elt, DAV_XML_NS_PREFIX, "propstat");
    auto prop_failure_elt = newChildElement(propstat_failure_elt, DAV_XML_NS_PREFIX, "prop");
    newChildElementWithText(propstat_failure_elt, DAV_XML_NS_PREFIX, "status",
                            "HTTP/1.1 500 Internal Server Error");

    LINKED_LIST_FOR (WebdavProperty, elt, props_to_get) {
      bool is_get_last_modified;
      if (str_equals(elt->ns_href, DAV_XML_NS) &&
          (((is_get_last_modified = str_equals(elt->element_name, "getlastmodified")) &&
            propfind_entry->modified_time != INVALID_WEBDAV_RESOURCE_TIME) ||
           (str_equals(elt->element_name, "creationdate") &&
            propfind_entry->creation_time != INVALID_WEBDAV_RESOURCE_TIME))) {
        time_t m_time = (time_t) (is_get_last_modified
                                  ? propfind_entry->modified_time
                                  : propfind_entry->creation_time);
        struct tm *tm_ = gmtime(&m_time);
        char time_buf[400], *time_str;

        const char *fmt = is_get_last_modified
          ? "%a, %d %b %Y %H:%M:%S GMT"
          : "%Y-%m-%dT%H:%M:%SZ";

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

        newChildElementWithText(xml_node, DAV_XML_NS_PREFIX, elt->element_name, time_str);
      }
      else if (str_equals(elt->element_name, "getcontentlength") &&
               str_equals(elt->ns_href, DAV_XML_NS) &&
               propfind_entry->length != INVALID_WEBDAV_RESOURCE_SIZE) {
        char length_str[400];
        snprintf(length_str, sizeof(length_str), "%lu",
                 (unsigned long) propfind_entry->length);
        newChildElementWithText(prop_success_elt, DAV_XML_NS_PREFIX,
                                "getcontentlength", length_str);
      }
      else if (str_equals(elt->element_name, "resourcetype") &&
               str_equals(elt->ns_href, DAV_XML_NS)) {
        auto resourcetype_elt = newChildElement(prop_success_elt, DAV_XML_NS_PREFIX, "resourcetype");

        if (propfind_entry->is_collection) {
          newChildElement(resourcetype_elt, DAV_XML_NS_PREFIX, "collection");
        }
      }
      else if (req_type == WEBDAV_PROPFIND_PROP) {
        auto random_elt = newChildElement(prop_not_found_elt, "random", elt->element_name);
        random_elt->SetAttribute("xmlns:random", elt->ns_href);
      }
    }

    /* NB: here we also add write lock info,
       this is expected of us in this interface between us and the server */
    if (req_type == WEBDAV_PROPFIND_ALLPROP) {
      auto supported_lock_elt =
        newChildElement(prop_success_elt, DAV_XML_NS_PREFIX, "supportedlock");

      auto lockentry_exclusive_elt =
        newChildElement(supported_lock_elt, DAV_XML_NS_PREFIX, "lockentry");
      auto lockscope_exclusive_elt =
        newChildElement(lockentry_exclusive_elt, DAV_XML_NS_PREFIX, "lockscope");
      newChildElement(lockscope_exclusive_elt, DAV_XML_NS_PREFIX, "exclusive");
      auto locktype_exclusive_elt =
        newChildElement(lockentry_exclusive_elt, DAV_XML_NS_PREFIX, "locktype");
      newChildElement(locktype_exclusive_elt, DAV_XML_NS_PREFIX, "write");

      auto lockentry_shared_elt =
        newChildElement(supported_lock_elt, DAV_XML_NS_PREFIX, "lockentry");
      auto lockscope_shared_elt =
        newChildElement(lockentry_shared_elt, DAV_XML_NS_PREFIX, "lockscope");
      newChildElement(lockscope_shared_elt, DAV_XML_NS_PREFIX, "shared");
      auto locktype_shared_elt =
        newChildElement(lockentry_shared_elt, DAV_XML_NS_PREFIX, "locktype");
      newChildElement(locktype_shared_elt, DAV_XML_NS_PREFIX, "write");
    }

    if (!prop_not_found_elt->FirstChildElement()) {
      unlinkNode(propstat_not_found_elt);
    }

    if (!prop_success_elt->FirstChildElement()) {
      unlinkNode(propstat_success_elt);
    }

    if (!prop_failure_elt->FirstChildElement()) {
      unlinkNode(propstat_failure_elt);
    }
  }

  const bool success_serialize = serializeDoc(doc, out_data, out_size);
  if (!success_serialize) {
    return false;
  }

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
  doc.InsertEndChild(doc.NewDeclaration());

  auto error_elt = newChildElement(&doc, DAV_XML_NS_PREFIX, "error");

  char *xmlns_attr_name = super_strcat("xmlns:", DAV_XML_NS_PREFIX, NULL);
  ASSERT_NOT_NULL(xmlns_attr_name);
  CStringFreer free_xmlns_attr_name(xmlns_attr_name);
  error_elt->SetAttribute(xmlns_attr_name, DAV_XML_NS);

  newChildElement(error_elt, DAV_XML_NS_PREFIX, "lock-token-submitted");

  char *uri = uri_from_path(hc, locked_path);
  ASSERT_NOT_NULL(uri);
  CStringFreer free_uri(uri);

  newChildElementWithText(error_elt, DAV_XML_NS_PREFIX, "href", uri);

  bool success_serialize =
    serializeDoc(doc, response_body, response_body_len);
  if (!success_serialize) {
    return false;
  }

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
  doc.InsertEndChild(doc.NewDeclaration());

  auto multistatus_elt = newChildElement(&doc, DAV_XML_NS_PREFIX, "multistatus");

  char *xmlns_attr_name = super_strcat("xmlns:", DAV_XML_NS_PREFIX, NULL);
  ASSERT_NOT_NULL(xmlns_attr_name);
  CStringFreer free_xmlns_attr_name(xmlns_attr_name);
  multistatus_elt->SetAttribute(xmlns_attr_name, DAV_XML_NS);

  auto response_elt = newChildElement(multistatus_elt, DAV_XML_NS_PREFIX, "response");

  char *uri = uri_from_path(hc, locked_descendant);
  ASSERT_NOT_NULL(uri);
  CStringFreer free_uri(uri);

  newChildElementWithText(response_elt, DAV_XML_NS_PREFIX, "href", uri);
  newChildElementWithText(response_elt, DAV_XML_NS_PREFIX, "status", "HTTP/1.1 423 Locked");

  auto error_elt = newChildElement(response_elt, DAV_XML_NS_PREFIX, "error");
  newChildElement(error_elt, DAV_XML_NS_PREFIX, "lock-token-submitted");

  bool success_serialize =
    serializeDoc(doc, response_body, response_body_len);
  if (!success_serialize) {
    return false;
  }

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
  doc.InsertEndChild(doc.NewDeclaration());

  auto multistatus_elt = newChildElement(&doc, DAV_XML_NS_PREFIX, "multistatus");

  char *xmlns_attr_name = super_strcat("xmlns:", DAV_XML_NS_PREFIX, NULL);
  ASSERT_NOT_NULL(xmlns_attr_name);
  CStringFreer free_xmlns_attr_name(xmlns_attr_name);
  multistatus_elt->SetAttribute(xmlns_attr_name, DAV_XML_NS);

  bool same_path = str_equals(file_path, status_path);
  const char *locked_status = "HTTP/1.1 423 Locked";

  if (!same_path) {
    auto response_elt = newChildElement(multistatus_elt, DAV_XML_NS_PREFIX, "response");

    char *status_uri = uri_from_path(hc, status_path);
    ASSERT_NOT_NULL(status_uri);
    CStringFreer free_status_uri(status_uri);

    newChildElementWithText(response_elt, DAV_XML_NS_PREFIX, "href", status_uri);
    newChildElementWithText(response_elt, DAV_XML_NS_PREFIX, "status", locked_status);
  }

  auto response_elt = newChildElement(multistatus_elt, DAV_XML_NS_PREFIX, "response");

  char *file_uri = uri_from_path(hc, file_path);
  ASSERT_NOT_NULL(file_uri);
  CStringFreer free_file_uri(file_uri);

  newChildElementWithText(response_elt, DAV_XML_NS_PREFIX, "href", file_uri);
  newChildElementWithText(response_elt, DAV_XML_NS_PREFIX,
                          "status",
                          same_path ? locked_status : "HTTP/1.1 424 Failed Dependency");

  bool success_serialize =
    serializeDoc(doc, response_body, response_body_len);
  if (!success_serialize) {
    return false;
  }

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
  doc.InsertEndChild(doc.NewDeclaration());

  auto prop_elt = newChildElement(&doc, DAV_XML_NS_PREFIX, "prop");

  char *xmlns_attr_name = super_strcat("xmlns:", DAV_XML_NS_PREFIX, NULL);
  ASSERT_NOT_NULL(xmlns_attr_name);
  CStringFreer free_xmlns_attr_name(xmlns_attr_name);
  prop_elt->SetAttribute(xmlns_attr_name, DAV_XML_NS);

  auto lockdiscovery_elt = newChildElement(prop_elt, DAV_XML_NS_PREFIX, "lockdiscovery");

  auto activelock_elt = newChildElement(lockdiscovery_elt, DAV_XML_NS_PREFIX, "activelock");

  auto locktype_elt = newChildElement(activelock_elt, DAV_XML_NS_PREFIX, "locktype");

  newChildElement(locktype_elt, DAV_XML_NS_PREFIX, "write");

  auto lockscope_elt = newChildElement(activelock_elt, DAV_XML_NS_PREFIX, "lockscope");

  newChildElement(lockscope_elt, DAV_XML_NS_PREFIX,
                  is_exclusive ? "exclusive" : "shared");

  assert(depth == DEPTH_0 || depth == DEPTH_INF);
  newChildElementWithText(activelock_elt,  DAV_XML_NS_PREFIX, "depth",
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

  newChildElementWithText(activelock_elt,  DAV_XML_NS_PREFIX, "timeout", timeout_str);
  auto locktoken_elt = newChildElement(activelock_elt, DAV_XML_NS_PREFIX, "locktoken");
  newChildElementWithText(locktoken_elt,  DAV_XML_NS_PREFIX, "href", lock_token);

  auto lockroot_elt = newChildElement(activelock_elt,  DAV_XML_NS_PREFIX, "lockroot");

  char *lockroot_uri = uri_from_path(hc, file_path);
  ASSERT_NOT_NULL(lockroot_uri);
  CStringFreer free_lockroot_uri(lockroot_uri);
  newChildElementWithText(lockroot_elt, DAV_XML_NS_PREFIX, "href", file_path);

  bool success_serialize =
    serializeDoc(doc, response_body, response_body_len);
  if (!success_serialize) {
    return false;
  }

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
  doc.InsertEndChild(doc.NewDeclaration());

  auto multistatus_elt = newChildElement(&doc, DAV_XML_NS_PREFIX, "multistatus");

  char *xmlns_attr_name = super_strcat("xmlns:", DAV_XML_NS_PREFIX, NULL);
  ASSERT_NOT_NULL(xmlns_attr_name);
  CStringFreer free_xmlns_attr_name(xmlns_attr_name);
  multistatus_elt->SetAttribute(xmlns_attr_name, DAV_XML_NS);

  auto response_elt = newChildElement(multistatus_elt, DAV_XML_NS_PREFIX, "response");

  newChildElementWithText(response_elt, DAV_XML_NS_PREFIX, "href", uri);

  auto propstat_elt = newChildElement(response_elt, DAV_XML_NS_PREFIX, "propstat");
  auto new_prop_elt = newChildElement(propstat_elt, DAV_XML_NS_PREFIX, "prop");
  newChildElementWithText(propstat_elt, DAV_XML_NS_PREFIX, "status",
                          "HTTP/1.1 403 Forbidden");

  /* now iterate over every propertyupdate directive */
  /* TODO: for now we don't support setting anything */
  /* we don't support arbitrary dead properties */
  LINKED_LIST_FOR (WebdavProppatchDirective, elt, props_to_patch) {
    /* add this element to the proppatch response */
    auto new_xml_prop = newChildElement(new_prop_elt, "random", elt->name);
    new_xml_prop->SetAttribute("xmlns:random", elt->ns_href ? elt->ns_href : "");
  }

  bool success_serialize =
    serializeDoc(doc, output, output_size);
  if (!success_serialize) {
    return false;
  }

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
