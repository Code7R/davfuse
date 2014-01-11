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

#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <ctime>

#include <deque>
#include <memory>
#include <stack>
#include <string>
#include <unordered_set>
#include <utility>

#include "tinyxml2.h"

#include "c_util.h"
#include "http_server.h"
#include "util.h"
#include "_webdav_server_types.h"
#include "_webdav_server_private_types.h"

#include "webdav_server_xml.h"

static const char *const DAV_XML_NS = "DAV:";
static const char *const DAV_XML_NS_PREFIX = "D";
static const char * const XML_XML_NS = "http://www.w3.org/XML/1998/namespace";
static const char * const XMLNS_XML_NS = "http://www.w3.org/2000/xmlns/";

/* utilities */

/* this little class allows us to get C++ RAII with C based data structures */

template <class T, void (*func)(T)>
class CFreer {
private:
  const T & myt;
public:
  CFreer(const T & var) : myt(var) {
  }
  CFreer(const CFreer & var) = delete;
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

/* special hash<Key> for the standard pair type, since the
   standard library doesn't do this forus.
   used below */
namespace std {
template<typename U, typename V>
struct hash<std::pair<U,V> > {
  std::size_t
  operator()(const std::pair<U,V> & s) const {
    std::size_t h1 = std::hash<U>()(s.first);
    std::size_t h2 = std::hash<V>()(s.second);
    return h1 ^  (h2 << 1);
  }
};
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

static PURE_FUNCTION bool
not_empty_no_colon(const char *a) {
  return (!str_equals(a, "") && !strchr(a, ':'));
}

static PURE_FUNCTION bool
safe_str_equals(const char *a, const char *b) {
  return a && b ? str_equals(a, b) : !a && !b;
}

static bool
is_xmlns_attr(const tinyxml2::XMLAttribute *a) {
  const char *attr_name = a->Name();
  return (str_equals(attr_name, "xmlns") ||
          str_startswith(attr_name, "xmlns:"));
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
get_ns_name(const tinyxml2::XMLElement *elt) {
  return get_ns_name(elt->Name());
}

static char *
make_ns_prefix(const char *tag_name) {
  const char *first_colon = strchr(tag_name, ':');
  if (!first_colon) {
    return NULL;
  }

  return strndup_x(tag_name, first_colon - tag_name);
}

/* this is an internal function used for parsing,
   do not add special cases to this */
static const char *
get_ns_href_for_prefix(const tinyxml2::XMLElement *elt, const char *prefix) {
  char *allocated_attr_to_query = NULL;
  CStringFreer free_allocated_attr_to_query(allocated_attr_to_query);

  const char *attr_to_query;
  if (!prefix) {
    attr_to_query = "xmlns";
  }
  else {
    assert(not_empty_no_colon(prefix));
    allocated_attr_to_query = super_strcat("xmlns:", prefix, NULL);
    attr_to_query = allocated_attr_to_query;
  }

  /* okay now find the href for this ns, start at this elt and go up */
  const char *elt_href = NULL;
  const tinyxml2::XMLElement *start_elt = elt;
  while (start_elt && !elt_href) {
    /* find the xmlns/xmlns:<ns> attributes */
    elt_href = start_elt->Attribute(attr_to_query);
    start_elt = start_elt->Parent()->ToElement();
  }

  return elt_href;
}

static const char *
get_ns_href(const tinyxml2::XMLElement *elt, const tinyxml2::XMLAttribute *attr=NULL) {
  const char *raw_elt_name = attr
    ? attr->Name()
    : elt->Name();

  const char *elt_href = NULL;
  char *const prefix = make_ns_prefix(raw_elt_name);
  CStringFreer free_prefix(prefix);
  if (prefix) {
    if (str_equals(prefix, "xmlns")) {
      /* only attributes can have the xmlns prefix */
      assert(attr);
      elt_href = XMLNS_XML_NS;
    }
    else if (str_equals(prefix, "xml")) {
      elt_href = XML_XML_NS;
    }
    else {
      elt_href = get_ns_href_for_prefix(elt, prefix);
      /* if a prefix was specified, there must be namespace name
         associated with it */
      assert(elt_href);
    }
  }
  else if (!attr) {
    /* check default namespace if this isn't an attr */
    elt_href = get_ns_href_for_prefix(elt, NULL);
  }

  /* namespace undeclarations should not be possible */
  assert(!elt_href || !str_equals(elt_href, ""));

  return elt_href;
}

static PURE_FUNCTION bool
ns_equals(const tinyxml2::XMLElement *elt, const char *test_href) {
  const char *ns_href = get_ns_href(elt);
  return safe_str_equals(test_href, ns_href);
}

static PURE_FUNCTION bool
node_is(const tinyxml2::XMLElement *elt, const char *test_href, const char *test_name) {
  const char *elt_name = get_ns_name(elt);
  return (str_equals(elt_name, test_name) &&
          ns_equals(elt, test_href));
}

static tinyxml2::XMLElement *
newChildElement(tinyxml2::XMLNode *parent, const char *one, const char *two=NULL) {
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

  /* the tag should not have a colon in it */
  assert(!ns_prefix || not_empty_no_colon(ns_prefix));
  assert(not_empty_no_colon(pure_tag_name));

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

static tinyxml2::XMLElement *
newChildElementWithText(tinyxml2::XMLNode *parent, const char *one, const char *two,
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
unlinkNode(tinyxml2::XMLNode *elt) {
  elt->Parent()->DeleteChild(elt);
}

NON_NULL_ARGS2(2, 3)
static bool
serializeDoc(const tinyxml2::XMLDocument & doc, char **out_data, size_t *out_size) {
  assert(out_data);
  assert(out_size);

  /* Windows XP can't handle newlines in XML gracefully... */
  bool compact = true;
  tinyxml2::XMLPrinter streamer(NULL, compact);
  doc.Print(&streamer);

  /* copy the data in streamer to a pointer that the caller
     can own,
     TODO: make this more efficient */
  *out_data = (char *) malloc(streamer.CStrSize() - 1);
  if (!*out_data) {
    return false;
  }

  memcpy(*out_data, streamer.CStr(), streamer.CStrSize() - 1);
  *out_size = streamer.CStrSize() - 1;

  return true;
}

static void
initDoc(tinyxml2::XMLDocument & doc) {
  doc.InsertEndChild(doc.NewDeclaration("xml version=\"1.0\" encoding=\"utf-8\""));
}

/* owner xml abstraction */

/* This class is responsible moving XML to new documents while preserving
   namespace / prefix mappings. This is used for the Owner XML
   element in WebDAV (which needs to be preserved exactly).
*/
class _OwnerXmlStorer : public tinyxml2::XMLVisitor {
public:
  _OwnerXmlStorer(tinyxml2::XMLNode *initNode)
    : m_stack(std::deque<tinyxml2::XMLNode *>(1, initNode)),
      m_ns_count(0)
  {}

  ~_OwnerXmlStorer() {
  }

  bool
  VisitEnter(const tinyxml2::XMLElement & elt, const tinyxml2::XMLAttribute *attrs) override;

  bool
  VisitExit(const tinyxml2::XMLElement & elt) override;

  bool
  Visit(const tinyxml2::XMLText & elt) override;

private:
  std::stack<tinyxml2::XMLNode *> m_stack;
  uintmax_t m_ns_count;

  const char *FindOrCreatePrefix(tinyxml2::XMLElement *start_at, const char *ns_href);
};

static const char *
findPrefix(const tinyxml2::XMLElement *start_at, const char *ns_href) {
  assert(ns_href &&
         !str_equals(ns_href, "") &&
         !str_equals(ns_href, XMLNS_XML_NS));

  /* ensure consistency with `get_ns_href()`
     (the logical inverse of this function)
   */
  if (str_equals(ns_href, XML_XML_NS)) {
    /* this is always the prefix */
    return "xml";
  }
  else if (str_equals(ns_href, XMLNS_XML_NS)) {
    return "xmlns";
  }

  const char *prefix = NULL;

  std::unordered_set<const char *, c_str_hash, c_str_pred> prefixes_seen;

  const tinyxml2::XMLElement *search = start_at;
  while (search && !prefix) {
    /* search each xmlns declaration for the href */
    for (const tinyxml2::XMLAttribute *attr = search->FirstAttribute();
         attr && !prefix; attr = attr->Next()) {
      /* normal xmlns isn't relevant, since there is no prefix there */
      if (!str_startswith(attr->Name(), "xmlns:")) {
        continue;
      }

      const char *const potential_prefix  = strchr(attr->Name(), ':') + 1;
      assert(potential_prefix != (void *) 1);
      assert(potential_prefix[0] != '\0');

      /* check that this prefix hasn't been invalidated anywhere below */
      if (!prefixes_seen.count(potential_prefix) &
          str_equals(attr->Value(), ns_href)) {
        /* whoa we found it */
        prefix = potential_prefix;
      }
      else {
        /* higher up prefix values won't count,
           since they will be overshadowed by this */
        prefixes_seen.insert(std::move(potential_prefix));
      }
    }

    search = search->Parent()->ToElement();
  }

  return prefix;
}

const char *
_OwnerXmlStorer::FindOrCreatePrefix(tinyxml2::XMLElement *start_at, const char *ns_href) {
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
    const tinyxml2::XMLAttribute *new_attribute = ((const tinyxml2::XMLElement *) start_at)->FindAttribute(buf);
    assert(new_attribute);
    prefix = strchr(new_attribute->Name(), ':') + 1;
  }

  assert(prefix);

  return prefix;
}

bool
_OwnerXmlStorer::VisitEnter(const tinyxml2::XMLElement & elt, const tinyxml2::XMLAttribute *attrs) {
  const char *elt_name = get_ns_name(&elt);
  const char *elt_href = get_ns_href(&elt);

  /* find an xml tag namespace prefix for the current namespace href */
  tinyxml2::XMLElement *parent_element = m_stack.top()->ToElement();

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

  for (const tinyxml2::XMLAttribute *curattrs = attrs; curattrs;
       curattrs = curattrs->Next()) {
    if (is_xmlns_attr(curattrs)) {
      /* ignore xmlns declarations */
      continue;
    }

    const char *attr_ns_name = get_ns_name(curattrs->Name());
    const char *attr_ns_href = get_ns_href(&elt, curattrs);

    if (attr_ns_href) {
      const char *const prefix = FindOrCreatePrefix(new_elt, attr_ns_href);
      assert(prefix && not_empty_no_colon(prefix));
      char *const new_attr_name = super_strcat(prefix, ":", attr_ns_name, NULL);
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
_OwnerXmlStorer::VisitExit(const tinyxml2::XMLElement & elt) {
  UNUSED(elt);
  m_stack.pop();
  return true;
}

bool
_OwnerXmlStorer::Visit(const tinyxml2::XMLText & elt) {
  auto new_elt = elt.ShallowClone(m_stack.top()->GetDocument());
  m_stack.top()->InsertEndChild(new_elt);
  return true;
}

static void
storeOwnerChildren(tinyxml2::XMLElement *owner_elt, owner_xml_t *owner_xml) {
  /* goal here is to make a new xml document with the children of owner_elt */
  tinyxml2::XMLDocument *doc = new tinyxml2::XMLDocument();

  _OwnerXmlStorer a(doc);

  owner_elt->Accept(&a);

  *owner_xml = (void *) doc;
}

static void
loadOwnerChildren(tinyxml2::XMLElement *owner_parent, owner_xml_t owner_xml) {
  tinyxml2::XMLDocument *owner_doc = (tinyxml2::XMLDocument *) owner_xml;

  _OwnerXmlStorer storer(owner_parent);

  owner_doc->Accept(&storer);
}

void
owner_xml_free(owner_xml_t a) {
  delete ((tinyxml2::XMLDocument *) a);
}

class _DocumentCopier : public tinyxml2::XMLVisitor {
public:
  _DocumentCopier()
    : m_stack(std::deque<tinyxml2::XMLNode *>(1, new tinyxml2::XMLDocument()))
  {}

  ~_DocumentCopier() {
  }

  tinyxml2::XMLDocument *
  getCopy() const {
    return m_stack.top()->ToDocument();
  }

  bool
  VisitEnter(const tinyxml2::XMLElement & elt, const tinyxml2::XMLAttribute *attrs) override;

  bool
  VisitExit(const tinyxml2::XMLElement & elt) override;

  bool
  Visit(const tinyxml2::XMLText & elt) override;

private:
  std::stack<tinyxml2::XMLNode *> m_stack;
};

bool
_DocumentCopier::VisitEnter(const tinyxml2::XMLElement & elt, const tinyxml2::XMLAttribute *attrs) {
  UNUSED(attrs);
  auto new_elt = elt.ShallowClone(m_stack.top()->GetDocument());
  m_stack.top()->InsertEndChild(new_elt);
  m_stack.push(new_elt);
  return true;
}

bool
_DocumentCopier::VisitExit(const tinyxml2::XMLElement & elt) {
  UNUSED(elt);
  m_stack.pop();
  return true;
}

bool
_DocumentCopier::Visit(const tinyxml2::XMLText & elt) {
  auto new_elt = elt.ShallowClone(m_stack.top()->GetDocument());
  m_stack.top()->InsertEndChild(new_elt);
  return true;
}

owner_xml_t
owner_xml_copy(owner_xml_t a) {
  tinyxml2::XMLDocument *doc = (tinyxml2::XMLDocument *) a;

  _DocumentCopier copier;

  doc->Accept(&copier);

  return copier.getCopy();
}

/* XML namespace syntax verifier */

class XMLNamespaceVerifier : public tinyxml2::XMLVisitor {
public:
  XMLNamespaceVerifier()
    : m_is_valid(true)
  {}

  bool
  VisitEnter(const tinyxml2::XMLDocument &) override { return m_is_valid; }

  bool
  VisitExit(const tinyxml2::XMLDocument &) override { return m_is_valid; }

  bool
  VisitEnter(const tinyxml2::XMLElement & elt, const tinyxml2::XMLAttribute *attrs) override;

  bool
  VisitExit(const tinyxml2::XMLElement &) override { return m_is_valid; }

  bool
  Visit(const tinyxml2::XMLDeclaration &) override { return m_is_valid; }

  bool
  Visit(const tinyxml2::XMLText &) override { return m_is_valid; }

  bool
  Visit(const tinyxml2::XMLComment &) override { return m_is_valid; }

  bool
  Visit(const tinyxml2::XMLUnknown &) override { return m_is_valid; }

private:
  bool m_is_valid;
};

static bool
is_valid_element(const tinyxml2::XMLElement & elt) {
  const char *const tag_name = elt.Name();
  const char *const first_colon = strchr(tag_name, ':');

  if (first_colon) {
    if ((first_colon == tag_name ||
         first_colon[1] == '\0' ||
         strchr(first_colon + 1, ':'))) {
      log_info("Tag was invalid: %s", tag_name);
      return false;
    }

    /* tag name is syntactically valid at this point */
    char *const prefix = strndup_x(tag_name, first_colon - tag_name);
    ASSERT_NOT_NULL(prefix);
    CStringFreer free_prefix(prefix);

    if (str_equals(prefix, "xmlns")) {
      log_info("The prefix 'xmlns' cannot be used in element names");
      return false;
    }

    const char *const elt_href = get_ns_href_for_prefix(&elt, prefix);

    if (str_equals(prefix, "xml")) {
      /* this is checked in `is_valid_attribute` */
      assert(!elt_href || str_equals(elt_href, XML_XML_NS));
    }
    else {
      if (!elt_href) {
        log_info("No namespace name was bound for prefix: %s", prefix);
        return false;
      }

      /* this is checked in `is_valid_attribute` */
      assert(!str_equals(elt_href, ""));
    }
  }

  return true;
}

static bool
is_valid_namespace_declaration_name(const char *name) {
  return (!str_equals(name, XML_XML_NS) &&
          !str_equals(name, XMLNS_XML_NS) &&
          !str_equals(name, ""));
}

static bool
is_valid_attribute(const tinyxml2::XMLElement & elt, const tinyxml2::XMLAttribute & attr) {
  const char *const tag_name = attr.Name();
  const char *const first_colon = strchr(tag_name, ':');

  if (first_colon) {
    if ((first_colon == tag_name ||
         !not_empty_no_colon(first_colon + 1))) {
      log_info("Tag was invalid: %s", tag_name);
      return false;
    }

    /* tag name is syntactically valid at this point */
    char *const prefix = strndup_x(tag_name, first_colon - tag_name);
    ASSERT_NOT_NULL(prefix);
    CStringFreer free_prefix(prefix);

    if (str_equals(prefix, "xmlns")) {
      /* namespace decl */
      const char *const pure_name = first_colon + 1;

      if (str_equals(pure_name, "xmlns")) {
        log_info("can't declare the prefix 'xmlns'!");
        return false;
      }

      if (str_equals(pure_name, "xml")) {
        if (!str_equals(attr.Value(), XML_XML_NS)) {
          log_info("Can only declare the prefix 'xml' "
                   "to have the namespace name: %s, not %s",
                   XML_XML_NS, elt.Value());
          return false;
        }
      }
      else if (!is_valid_namespace_declaration_name(attr.Value())) {
        log_info("Invalid namespace name! %s", elt.Value());
        return false;
      }
    }
    else  {
      /* normal attribute */
      const char *const elt_href = get_ns_href_for_prefix(&elt, prefix);
      if (!elt_href && !str_equals(prefix, "xml")) {
        log_info("no namespace name was declared for the prefix: %s", prefix);
        return false;
      }
    }
  }
  else if (str_equals(tag_name, "xmlns")) {
    /* default namespace decl */
    if (!is_valid_namespace_declaration_name(attr.Value())) {
      log_info("Invalid namespace name! %s", attr.Value());
      return false;
    }
  }

  return true;
}

bool
XMLNamespaceVerifier::VisitEnter(const tinyxml2::XMLElement & elt, const tinyxml2::XMLAttribute *attrs) {
  /* verify tag name and all attributes names */

  /* first check if all attributes are valid */
  {
    std::unordered_set<std::pair<std::string,std::string> > seen_attrs;
    for (const tinyxml2::XMLAttribute *curattrs = attrs;
         curattrs && m_is_valid;
         curattrs = curattrs->Next()) {
      if (!is_valid_attribute(elt, *curattrs)) {
        m_is_valid = false;
      }
      else {
        /* this is a valid attr, check if we've already
           seen it */
        const char *const ns_href = get_ns_href(&elt, curattrs);
        const char *const pure_name = get_ns_name(curattrs->Name());
        /* we use empty string to mean no namespace since an
           empty namespace name is not valid in the first place */
        assert(!ns_href || !str_equals(ns_href, ""));
        auto fully_qualified_name = std::make_pair(std::string(ns_href ? ns_href : ""),
                                                   std::string(pure_name));
        if (seen_attrs.count(fully_qualified_name)) {
          log_info("Duplicate attr name: %s:%s", ns_href, pure_name);
          m_is_valid = false;
        }
        else {
          seen_attrs.insert(std::move(fully_qualified_name));
        }
      }
    }
  }

  /* then check if tag is valid
   (this is because tag checking depends on first check attributes) */
  if (m_is_valid && !is_valid_element(elt)) m_is_valid = false;

  return m_is_valid;
}

static tinyxml2::XMLError
parseXML(tinyxml2::XMLDocument & doc, const char *xml, size_t xml_len) {
  auto xml_error = doc.Parse(xml, xml_len);
  if (xml_error) {
    return xml_error;
  }

  XMLNamespaceVerifier verifier;

  return (doc.Accept(&verifier)
          ? tinyxml2::XML_NO_ERROR
          : tinyxml2::XML_ERROR_PARSING);
}

/* PROPFIND method XML functions */

xml_parse_code_t
parse_propfind_request(const char *req_data,
                       size_t req_data_length,
                       webdav_propfind_req_type_t *out_propfind_req_type,
                       linked_list_t *out_props_to_get) {
  xml_parse_code_t toret;

  tinyxml2::XMLDocument doc;

  *out_props_to_get = LINKED_LIST_INITIALIZER;

  /* process the type of prop request */
  if (!req_data) {
    *out_propfind_req_type = WEBDAV_PROPFIND_ALLPROP;
  }
  else {
    auto error_parse = parseXML(doc, req_data, req_data_length);
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
               root_element ? root_element->Name() : NULL);
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
generate_propfind_response(webdav_propfind_req_type_t req_type,
                           linked_list_t props_to_get_,
                           linked_list_t entries,
                           char **out_data,
                           size_t *out_size,
                           http_status_code_t *out_status_code) {
  if (req_type == WEBDAV_PROPFIND_PROPNAME) {
    /* TODO: not supported yet */
    return false;
  }

  const linked_list_t allocated_props_to_get = req_type == WEBDAV_PROPFIND_ALLPROP
    ? default_props_to_get()
    : 0;
  CFreer<linked_list_t, free_linked_list_of_propfind_entries> free_props_to_get(allocated_props_to_get);

  linked_list_t props_to_get = req_type == WEBDAV_PROPFIND_ALLPROP
    ? allocated_props_to_get
    : props_to_get_;

  tinyxml2::XMLDocument doc;
  initDoc(doc);

  auto multistatus_elt = newChildElement(&doc, DAV_XML_NS_PREFIX, "multistatus");

  char *const xmlns_attr_name = super_strcat("xmlns:", DAV_XML_NS_PREFIX, NULL);
  ASSERT_NOT_NULL(xmlns_attr_name);
  CStringFreer free_xmlns_attr_name(xmlns_attr_name);
  multistatus_elt->SetAttribute(xmlns_attr_name, DAV_XML_NS);

  /* TODO: deal with the case where entries == NULL */
  ASSERT_NOT_NULL(entries);
  LINKED_LIST_FOR (struct webdav_propfind_entry, propfind_entry, entries) {
    auto response_elt = newChildElement(multistatus_elt, DAV_XML_NS_PREFIX, "response");

    newChildElementWithText(response_elt, DAV_XML_NS_PREFIX, "href",
                            propfind_entry->relative_uri);

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
        tinyxml2::XMLElement *xml_node;

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
        int ret_snprintf = snprintf(length_str, sizeof(length_str), "%lu",
                                    (unsigned long) propfind_entry->length);
        ASSERT_TRUE(!(ret_snprintf < 0 || (size_t) ret_snprintf >= sizeof(length_str)));
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
        const char *prefix = NULL;
        bool set_prefix = false;
        if (elt->ns_href) {
          prefix = findPrefix(prop_not_found_elt, elt->ns_href);
        }
        if (!prefix) {
          prefix = "random";
          set_prefix = true;
        }
        auto random_elt = newChildElement(prop_not_found_elt, prefix, elt->element_name);

        if (set_prefix) {
          random_elt->SetAttribute("xmlns:random",
                                   /* clear the random prefix if there is no href */
                                   elt->ns_href ? elt->ns_href : "");
        }
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

    /* TODO: add lock discovery here */

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
  tinyxml2::XMLElement *root_element = NULL;

  /* this is an optional request parameter */
  *owner_xml = NULL;

  tinyxml2::XMLDocument doc;
  auto error_parse = parseXML(doc, body, body_len);
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
generate_locked_response(const char *locked_path,
                         http_status_code_t *status_code,
                         char **response_body,
                         size_t *response_body_len) {
  tinyxml2::XMLDocument doc;
  initDoc(doc);

  auto error_elt = newChildElement(&doc, DAV_XML_NS_PREFIX, "error");

  char *const xmlns_attr_name = super_strcat("xmlns:", DAV_XML_NS_PREFIX, NULL);
  ASSERT_NOT_NULL(xmlns_attr_name);
  CStringFreer free_xmlns_attr_name(xmlns_attr_name);
  error_elt->SetAttribute(xmlns_attr_name, DAV_XML_NS);

  newChildElement(error_elt, DAV_XML_NS_PREFIX, "lock-token-submitted");

  newChildElementWithText(error_elt, DAV_XML_NS_PREFIX, "href", locked_path);

  bool success_serialize =
    serializeDoc(doc, response_body, response_body_len);
  if (!success_serialize) {
    return false;
  }

  *status_code = HTTP_STATUS_CODE_LOCKED;

  return true;
}

bool
generate_locked_descendant_response(const char *locked_descendant,
                                    http_status_code_t *status_code,
                                    char **response_body,
                                    size_t *response_body_len) {
  tinyxml2::XMLDocument doc;
  initDoc(doc);

  auto multistatus_elt = newChildElement(&doc, DAV_XML_NS_PREFIX, "multistatus");

  char *const xmlns_attr_name = super_strcat("xmlns:", DAV_XML_NS_PREFIX, NULL);
  ASSERT_NOT_NULL(xmlns_attr_name);
  CStringFreer free_xmlns_attr_name(xmlns_attr_name);
  multistatus_elt->SetAttribute(xmlns_attr_name, DAV_XML_NS);

  auto response_elt = newChildElement(multistatus_elt, DAV_XML_NS_PREFIX, "response");

  newChildElementWithText(response_elt, DAV_XML_NS_PREFIX, "href", locked_descendant);
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
generate_failed_lock_response_body(const char *file_uri,
                                   const char *status_uri,
                                   http_status_code_t *status_code,
                                   char **response_body,
                                   size_t *response_body_len) {
  tinyxml2::XMLDocument doc;
  initDoc(doc);

  auto multistatus_elt = newChildElement(&doc, DAV_XML_NS_PREFIX, "multistatus");

  char *const xmlns_attr_name = super_strcat("xmlns:", DAV_XML_NS_PREFIX, NULL);
  ASSERT_NOT_NULL(xmlns_attr_name);
  CStringFreer free_xmlns_attr_name(xmlns_attr_name);
  multistatus_elt->SetAttribute(xmlns_attr_name, DAV_XML_NS);

  bool same_path = str_equals(file_uri, status_uri);
  const char *locked_status = "HTTP/1.1 423 Locked";

  if (!same_path) {
    auto response_elt = newChildElement(multistatus_elt, DAV_XML_NS_PREFIX, "response");

    newChildElementWithText(response_elt, DAV_XML_NS_PREFIX, "href", status_uri);
    newChildElementWithText(response_elt, DAV_XML_NS_PREFIX, "status", locked_status);
  }

  auto response_elt = newChildElement(multistatus_elt, DAV_XML_NS_PREFIX, "response");

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
generate_success_lock_response_body(const char *file_uri,
                                    webdav_timeout_t timeout_in_seconds,
                                    webdav_depth_t depth,
                                    bool is_exclusive,
                                    const owner_xml_t owner_xml,
                                    const char *lock_token,
                                    bool created,
                                    http_status_code_t *status_code,
                                    char **response_body,
                                    size_t *response_body_len) {
  tinyxml2::XMLDocument doc;
  initDoc(doc);

  auto prop_elt = newChildElement(&doc, DAV_XML_NS_PREFIX, "prop");

  char *const xmlns_attr_name = super_strcat("xmlns:", DAV_XML_NS_PREFIX, NULL);
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
    /* TODO: lazy */
    ASSERT_TRUE(!(len < 0 || (size_t) len >= sizeof(timeout_buf)));
    timeout_str = timeout_buf;
  }

  newChildElementWithText(activelock_elt,  DAV_XML_NS_PREFIX, "timeout", timeout_str);
  auto locktoken_elt = newChildElement(activelock_elt, DAV_XML_NS_PREFIX, "locktoken");
  newChildElementWithText(locktoken_elt,  DAV_XML_NS_PREFIX, "href", lock_token);

  auto lockroot_elt = newChildElement(activelock_elt,  DAV_XML_NS_PREFIX, "lockroot");

  newChildElementWithText(lockroot_elt, DAV_XML_NS_PREFIX, "href", file_uri);

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
  tinyxml2::XMLElement *root_element;

  tinyxml2::XMLDocument doc;

  auto error_parse = parseXML(doc, body, body_len);
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
  tinyxml2::XMLDocument doc;
  initDoc(doc);

  auto multistatus_elt = newChildElement(&doc, DAV_XML_NS_PREFIX, "multistatus");

  char *const xmlns_attr_name = super_strcat("xmlns:", DAV_XML_NS_PREFIX, NULL);
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
    const char *prefix = NULL;
    bool set_prefix = false;
    if (elt->ns_href) {
      prefix = findPrefix(new_prop_elt, elt->ns_href);
    }
    if (!prefix) {
      prefix = "random";
      set_prefix = true;
    }
    auto new_xml_prop =
      newChildElement(new_prop_elt, prefix, elt->name);
    if (set_prefix) {
      new_xml_prop->SetAttribute("xmlns:random",
                                 /* clear random what means if there is no href*/
                                 elt->ns_href ? elt->ns_href : "");
    }
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

void
pretty_print_xml(const char *xml_body, size_t len, log_level_t level) {
  if (!logging_should_print(level)) {
    return;
  }

  if (!len) {
    logging_log(level, "<empty xml body>");
    return;
  }

  tinyxml2::XMLDocument doc;

  auto xml_error = doc.Parse(xml_body, len);
  if (xml_error) {
    assert(len <= INT_MAX);
    logging_log(level, "%.*s", (int) len, xml_body);
    return;
  }

  tinyxml2::XMLPrinter printer;

  doc.Print(&printer);

  logging_log(level, "%s", printer.CStr());

  return;
}
