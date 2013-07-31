#ifndef _WEBDAV_SERVER_COMMON_H
#define _WEBDAV_SERVER_COMMON_H

#include "_webdav_server_private_types.h"

#ifdef __cplusplus
extern "C" {
#endif

WebdavProperty *
create_webdav_property(const char *element_name, const char *ns_href);

void
free_webdav_property(WebdavProperty *wp);

WebdavProppatchDirective *
create_webdav_proppatch_directive(webdav_proppatch_directive_type_t type,
                                  const char *name,
                                  const char *ns_href,
                                  const char *value);

void
free_webdav_proppatch_directive(WebdavProppatchDirective *wp);

char *
uri_from_path(struct handler_context *hc, const char *path);

#ifdef __cplusplus

}
#endif

#endif
