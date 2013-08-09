typedef struct webdav_backend *webdav_backend_t;

typedef struct {
  void (*copy)(void *backend_user_data,
	       const char *src_uri, const char *dst_uri,
	       bool overwrite, webdav_depth_t depth,
	       event_handler_t cb, void *ud);
  void (*delete_x)(void *backend_user_data,
                 const char *relative_uri,
                 event_handler_t cb, void *ud);
  void (*get)(void *backend_user_data,
              const char *relative_uri,
              webdav_get_request_ctx_t get_ctx);
  void (*mkcol)(void *backend_user_data,
                const char *relative_uri,
                event_handler_t cb, void *ud);
  void (*move)(void *backend_user_data,
               const char *src_uri, const char *dst_uri,
	       bool overwrite,
	       event_handler_t cb, void *ud);
  void (*propfind)(void *backend_user_data,
                   const char *relative_uri, webdav_depth_t depth,
                   webdav_propfind_req_type_t propfind_req_type,
                   event_handler_t cb, void *user_data);
  void (*put)(void *backend_user_data,
              const char *relative_uri,
              webdav_put_request_ctx_t put_ctx);
  /* for LOCK */
  void (*touch)(void *backend_user_data,
                const char *relative_uri,
                event_handler_t cb, void *user_data);

} WebdavBackendOperations;
