/* NOTE TO IMPLEMENTORS:
   every tag of all generated XML must have an explicit prefix
   otherwise the Microsoft Windows client will not be able to parse */

#ifndef _WEBDAV_SERVER_XML_H
#define _WEBDAV_SERVER_XML_H

#include <stddef.h>

#include "http_server.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "_webdav_server_private_types.h"
#include "_webdav_server_types.h"

typedef enum {
  XML_PARSE_ERROR_NONE,
  XML_PARSE_ERROR_SYNTAX,
  XML_PARSE_ERROR_STRUCTURE,
  XML_PARSE_ERROR_INTERNAL,
} xml_parse_code_t;

/* owner xml abstraction */

void
owner_xml_free(owner_xml_t a);

owner_xml_t
owner_xml_copy(owner_xml_t a);


/* PROPFIND method XML functions */
xml_parse_code_t
parse_propfind_request(const char *req_data,
                       size_t req_data_length,
                       webdav_propfind_req_type_t *out_propfind_req_type,
                       linked_list_t *out_props_to_get);

bool
generate_propfind_response(struct handler_context *hc,
                           webdav_propfind_req_type_t req_type,
                           linked_list_t props_to_get,
                           linked_list_t entries,
                           char **out_data,
                           size_t *out_size,
                           http_status_code_t *out_status_code);

/* LOCK method XML functions */
xml_parse_code_t
parse_lock_request_body(const char *body, size_t body_len,
                        bool *is_exclusive, owner_xml_t *owner_xml);

bool
generate_locked_response(struct handler_context *hc,
                         const char *locked_path,
                         http_status_code_t *status_code,
                         char **response_body,
                         size_t *response_body_len);

bool
generate_locked_descendant_response(struct handler_context *hc,
                                    const char *locked_descendant,
                                    http_status_code_t *status_code,
                                    char **response_body,
                                    size_t *response_body_len);

bool
generate_failed_lock_response_body(struct handler_context *hc,
                                   const char *file_path,
                                   const char *status_path,
                                   http_status_code_t *status_code,
                                   char **response_body,
                                   size_t *response_body_len);

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
                                    size_t *response_body_len);

/* PROPPATCH method XML functions */
xml_parse_code_t
parse_proppatch_request(const char *body, size_t body_len,
                        linked_list_t *out_proppatch_directives);

bool
generate_proppatch_response(const char *uri,
                            linked_list_t props_to_patch,
                            char **output, size_t *output_size,
                            http_status_code_t *status_code);


void
init_xml_parser(void);

void
shutdown_xml_parser(void);

#ifdef __cplusplus
}
#endif

#endif
