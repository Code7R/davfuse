/*
 * Implements a WebDAV server using a set of FUSE callbacks
 */

#define _ISOC99_SOURCE
#define _POSIX_C_SOURCE 199309L

#include <errno.h>
#include <libgen.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* We import the public FUSE header because we interact
   with code that uses the public API */
#define FUSE_USE_VERSION 26
#include "fuse.h"
#undef FUSE_USE_VERSION

#include "async_fuse_fs.h"
#include "async_fuse_fs_helpers.h"
#include "c_util.h"
#include "coroutine.h"
#include "fd_utils.h"
#include "fdevent.h"
#include "http_server.h"
#include "logging.h"
#include "webdav_server.h"
#include "uthread.h"
#include "util.h"

typedef struct {
  bool singlethread : 1;
} FuseOptions;

typedef struct {
  log_level_t log_level;
  char *listen_str;
  char *public_prefix;
} DavOptions;

typedef struct {
  async_fuse_fs_t async_fuse_fs;
  char *listen_str;
  char *public_prefix;
  FDEventLoop *loop;
} HTTPThreadArguments;

typedef struct {
  async_fuse_fs_t fuse_fs;
} FuseBackendCtx;

static char *
path_from_uri(FuseBackendCtx *ctx, const char *relative_uri) {
  UNUSED(ctx);
  /* TODO: no translation seems necessary yet */
  return strdup_x(relative_uri);
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  FuseBackendCtx *fbctx;
  bool is_move;
  const char *src_relative_uri;
  const char *dst_relative_uri;
  bool overwrite;
  webdav_depth_t depth;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
  char *file_path;
  char *destination_path;
  char *destination_path_copy;
  struct stat src_stat;
  struct stat dst_stat;
  bool dst_existed;
  bool copy_failed;
} FuseCopyMoveCtx;

UTHR_DEFINE(_fuse_copy_move_uthr) {
  UTHR_HEADER(FuseCopyMoveCtx, ctx);

  assert(ctx->depth == DEPTH_INF ||
	 (ctx->depth == DEPTH_0 && !ctx->is_move));

  webdav_error_t err;

  ctx->file_path = path_from_uri(ctx->fbctx, ctx->src_relative_uri);
  ctx->destination_path = path_from_uri(ctx->fbctx, ctx->dst_relative_uri);

  ctx->destination_path_copy = strdup_x(ctx->destination_path);
  char *destination_path_dirname = dirname(ctx->destination_path_copy);

  /* check if destination directory exists */
  UTHR_YIELD(ctx,
             async_fuse_fs_getattr(ctx->fbctx->fuse_fs, destination_path_dirname,
                                   &ctx->src_stat,
                                   _fuse_copy_move_uthr, ctx));
  UTHR_RECEIVE_EVENT(ASYNC_FUSE_FS_GETATTR_DONE_EVENT,
                     FuseFsOpDoneEvent, getattr_done_ev);
  if (getattr_done_ev->ret) {
    err = getattr_done_ev->ret == -ENOENT
      ? WEBDAV_ERROR_DESTINATION_DOES_NOT_EXIST
      : WEBDAV_ERROR_GENERAL;
    goto done;
  }

  /* check if source exists */
  UTHR_YIELD(ctx,
             async_fuse_fs_getattr(ctx->fbctx->fuse_fs, ctx->file_path,
                                   &ctx->src_stat,
                                   _fuse_copy_move_uthr, ctx));
  UTHR_RECEIVE_EVENT(ASYNC_FUSE_FS_GETATTR_DONE_EVENT,
                     FuseFsOpDoneEvent, getattr_done_ev_2);
  if (getattr_done_ev_2->ret) {
    if (-getattr_done_ev_2->ret != ENOENT) {
      log_info("Error while calling stat(\"%s\"): %s",
	       ctx->file_path, strerror(-getattr_done_ev_2->ret));
      err = WEBDAV_ERROR_GENERAL;
    }
    else {
      err = WEBDAV_ERROR_DOES_NOT_EXIST;
    }
    goto done;
  }

  /* check if destination exists */
  UTHR_YIELD(ctx,
             async_fuse_fs_getattr(ctx->fbctx->fuse_fs, ctx->destination_path,
                                   &ctx->dst_stat,
                                   _fuse_copy_move_uthr, ctx));
  UTHR_RECEIVE_EVENT(ASYNC_FUSE_FS_GETATTR_DONE_EVENT,
                     FuseFsOpDoneEvent, getattr_done_ev_3);
  if (getattr_done_ev_3->ret && -getattr_done_ev_3->ret != ENOENT) {
    log_info("Error while calling stat(\"%s\"): %s",
	     ctx->destination_path, strerror(-getattr_done_ev_3->ret));
    err = WEBDAV_ERROR_GENERAL;
    goto done;
  }
  ctx->dst_existed = !getattr_done_ev_3->ret;

  /* kill directory if we're overwriting it */
  if (ctx->dst_existed) {
    if (!ctx->overwrite) {
      err = WEBDAV_ERROR_DESTINATION_EXISTS;
      goto done;
    }

    UTHR_YIELD(ctx,
               async_fuse_fs_rmtree(ctx->fbctx->fuse_fs, ctx->destination_path,
                                    _fuse_copy_move_uthr, ctx));
    UTHR_RECEIVE_EVENT(ASYNC_FUSE_FS_RMTREE_DONE_EVENT, void, _throw_away_ev);
    /* we ignore the error here because we rely on a subsequent failure */
    UNUSED(_throw_away_ev);
  }

  ctx->copy_failed = true;
  if (ctx->is_move) {
    /* first try moving */
    UTHR_SUBCALL(ctx,
                 async_fuse_fs_rename(ctx->fbctx->fuse_fs,
                                      ctx->file_path, ctx->destination_path,
                                      _fuse_copy_move_uthr, ctx),
                 ASYNC_FUSE_FS_RENAME_DONE_EVENT,
                 FuseFsOpDoneEvent,
                 rename_done_ev);

    if (rename_done_ev->ret < 0 && -rename_done_ev->ret != EXDEV) {
      log_info("Error while calling rename(\"%s\", \"%s\"): %s",
	       ctx->file_path, ctx->destination_path,
	       strerror(-rename_done_ev->ret));
      err = WEBDAV_ERROR_GENERAL;
      goto done;
    }

    ctx->copy_failed = rename_done_ev->ret < 0;
  }

  if (ctx->copy_failed) {
    if (ctx->depth == DEPTH_0) {
      if (S_ISDIR(ctx->src_stat.st_mode)) {
        UTHR_SUBCALL(ctx,
                     async_fuse_fs_mkdir(ctx->fbctx->fuse_fs,
                                         ctx->destination_path, 0777,
                                         _fuse_copy_move_uthr, ctx),
                     ASYNC_FUSE_FS_MKDIR_DONE_EVENT,
                     FuseFsOpDoneEvent,
                     mkdir_done_ev);
	if (mkdir_done_ev->ret < 0) {
	  log_info("Failure to mkdir(\"%s\"): %s",
		   ctx->destination_path, strerror(-mkdir_done_ev->ret));
	  err = WEBDAV_ERROR_GENERAL;
	  goto done;
	}
      }
      else {
        UTHR_SUBCALL(ctx,
                     async_fuse_fs_copyfile(ctx->fbctx->fuse_fs,
                                            ctx->file_path, ctx->destination_path,
                                            _fuse_copy_move_uthr, ctx),
                     ASYNC_FUSE_FS_COPYFILE_DONE_EVENT,
                     FuseFsOpDoneEvent,
                     copyfile_done_ev);
	if (copyfile_done_ev->ret < 0) {
	  log_info("Failure to copyfile(\"%s\", \"%s\"): %s",
		   ctx->file_path, ctx->destination_path,
                   strerror(-copyfile_done_ev->ret));
	  err = WEBDAV_ERROR_GENERAL;
	  goto done;
	}
      }
    }
    else {
      UTHR_SUBCALL(ctx,
                   async_fuse_fs_copytree(ctx->fbctx->fuse_fs,
                                          ctx->file_path, ctx->destination_path,
                                          ctx->is_move,
                                          _fuse_copy_move_uthr, ctx),
                   ASYNC_FUSE_FS_COPYTREE_DONE_EVENT,
                   AsyncFuseFsCopytreeDoneEvent,
                   copytree_done_ev);
      /* we don't handle errors here yet */
      ASSERT_TRUE(!copytree_done_ev->error);
    }
  }

  err = WEBDAV_ERROR_NONE;

 done:
  free(ctx->file_path);
  free(ctx->destination_path);
  free(ctx->destination_path_copy);

  if (ctx->is_move) {
    WebdavMoveDoneEvent move_done_ev = {
      .error = err,
      /* TODO: implement */
      .failed_to_move = LINKED_LIST_INITIALIZER,
      .dst_existed = ctx->dst_existed,
    };
    UTHR_RETURN(ctx,
                ctx->cb(WEBDAV_MOVE_DONE_EVENT, &move_done_ev, ctx->cb_ud));
  }
  else {
    WebdavCopyDoneEvent copy_done_ev = {
      .error = err,
      /* TODO: implement */
      .failed_to_copy = LINKED_LIST_INITIALIZER,
      .dst_existed = ctx->dst_existed,
    };
    UTHR_RETURN(ctx,
                ctx->cb(WEBDAV_COPY_DONE_EVENT, &copy_done_ev, ctx->cb_ud));
  }

  UTHR_FOOTER();
}


static void
fuse_copy(void *backend_ctx,
          const char *src_relative_uri, const char *dst_relative_uri,
          bool overwrite, webdav_depth_t depth,
          event_handler_t cb, void *cb_ud) {
  UTHR_CALL8(_fuse_copy_move_uthr, FuseCopyMoveCtx,
             .is_move = false,
             .fbctx = backend_ctx,
             .src_relative_uri = src_relative_uri,
             .dst_relative_uri = dst_relative_uri,
             .overwrite = overwrite,
             .depth = depth,
             .cb = cb,
             .cb_ud = cb_ud);
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  FuseBackendCtx *fbctx;
  const char *relative_uri;
  event_handler_t cb;
  void *ud;
  /* ctx */
  struct stat st;
  WebdavDeleteDoneEvent ev;
  char *file_path;
} FuseDeleteCtx;

static
UTHR_DEFINE(_fuse_delete_uthr) {
  UTHR_HEADER(FuseDeleteCtx, ctx);


  ctx->file_path = path_from_uri(ctx->fbctx, ctx->relative_uri);
  if (!ctx->file_path) {
    ctx->ev.error = WEBDAV_ERROR_GENERAL;
    goto done;
  }

  UTHR_SUBCALL(ctx,
               async_fuse_fs_getattr(ctx->fbctx->fuse_fs,
                                     ctx->file_path, &ctx->st,
                                     _fuse_delete_uthr, ctx),
               ASYNC_FUSE_FS_GETATTR_DONE_EVENT,
               FuseFsOpDoneEvent,
               getattr_done_ev);
  if (getattr_done_ev->ret < 0) {
    ctx->ev.error = -getattr_done_ev->ret == ENOENT
      ? WEBDAV_ERROR_DOES_NOT_EXIST
      : WEBDAV_ERROR_GENERAL;
    goto done;
  }

  UTHR_SUBCALL(ctx,
               async_fuse_fs_rmtree(ctx->fbctx->fuse_fs,
                                    ctx->file_path,
                                    _fuse_delete_uthr, ctx),
               ASYNC_FUSE_FS_RMTREE_DONE_EVENT, void, _throw_away_ev);
  UNUSED(_throw_away_ev);

  ctx->ev = (WebdavDeleteDoneEvent) {
    .error = WEBDAV_ERROR_NONE,
    .failed_to_delete = LINKED_LIST_INITIALIZER,
  };

 done:
  free(ctx->file_path);

  UTHR_RETURN(ctx,
              ctx->cb(WEBDAV_DELETE_DONE_EVENT, &ctx->ev, ctx->ud));

  UTHR_FOOTER();
}

static void
fuse_delete(void *backend_ctx,
            const char *relative_uri,
            event_handler_t cb, void *ud) {
  UTHR_CALL4(_fuse_delete_uthr, FuseDeleteCtx,
             .fbctx = backend_ctx,
             .relative_uri = relative_uri,
             .cb = cb,
             .ud = ud);
}

static void
fuse_get(void *backend_ctx,
         const char *relative_uri,
         webdav_get_request_ctx_t get_ctx) {
  UNUSED(backend_ctx);
  UNUSED(relative_uri);
  UNUSED(get_ctx);
  abort();
}

static void
fuse_mkcol(void *backend_ctx, const char *relative_uri,
           event_handler_t cb, void *ud) {
  UNUSED(backend_ctx);
  UNUSED(relative_uri);
  UNUSED(cb);
  UNUSED(ud);
  abort();
}

static void
fuse_move(void *backend_ctx,
          const char *src_relative_uri, const char *dst_relative_uri,
          bool overwrite,
          event_handler_t cb, void *cb_ud) {
  UTHR_CALL8(_fuse_copy_move_uthr, FuseCopyMoveCtx,
             .is_move = true,
             .fbctx = backend_ctx,
             .src_relative_uri = src_relative_uri,
             .dst_relative_uri = dst_relative_uri,
             .overwrite = overwrite,
             .cb = cb,
             .cb_ud = cb_ud);
}

static void
fuse_propfind(void *backend_ctx,
              const char *relative_uri, webdav_depth_t depth,
              webdav_propfind_req_type_t propfind_req_type,
              event_handler_t cb, void *user_data) {
  UNUSED(backend_ctx);
  UNUSED(relative_uri);
  UNUSED(depth);
  UNUSED(propfind_req_type);
  UNUSED(cb);
  UNUSED(user_data);
  abort();
}

static void
fuse_put(void *backend_ctx,
         const char *relative_uri,
         webdav_put_request_ctx_t put_ctx) {
  UNUSED(backend_ctx);
  UNUSED(relative_uri);
  UNUSED(put_ctx);
  abort();
}

static void
fuse_touch(void *backend_ctx,
           const char *relative_uri,
           event_handler_t cb, void *user_data) {
  UNUSED(backend_ctx);
  UNUSED(relative_uri);
  UNUSED(cb);
  UNUSED(user_data);
  abort();
}

static WebdavBackendOperations
fuse_backend_operations = {
  .copy = fuse_copy,
  .delete = fuse_delete,
  .get = fuse_get,
  .mkcol = fuse_mkcol,
  .move = fuse_move,
  .propfind = fuse_propfind,
  .put = fuse_put,
  .touch = fuse_touch,
};

static bool
parse_command_line(int argc, char *argv[], FuseOptions *options) {
  for (int i = 1; i < argc; ++i) {
    char *arg = argv[i];

    /* don't case about non options for now */
    if (arg[0] != '-') {
      continue;
    }

    switch (arg[1]) {
    case 's':
      options->singlethread = true;
      break;
    default:
      break;
    }
  }

  return true;
}

static bool
parse_environment(DavOptions *options) {
  /* default for now */
  options->log_level = LOG_DEBUG;
  options->listen_str = NULL;
  options->public_prefix = strdup_x("http://localhost:8080/");

  return true;
}

int
create_server_socket(char *listen_str) {
  UNUSED(listen_str);
  assert(!listen_str);
  /* TODO: parse `listen_str` */
  return create_ipv4_bound_socket(8080);
}

static void *
http_thread(void *ud) {
  HTTPThreadArguments *args = (HTTPThreadArguments *) ud;
  int server_fd = -1;
  webdav_backend_t webdav_backend = 0;

  /* create server socket */
  server_fd = create_server_socket(args->listen_str);
  if (server_fd < 0) {
    log_critical_errno("Couldn't create server socket");
    goto done;
  }

  /* start webdav server */
  FuseBackendCtx ctx = {
    .fuse_fs = args->async_fuse_fs,
  };

  webdav_backend = webdav_backend_new(&fuse_backend_operations,
                                      sizeof(fuse_backend_operations), &ctx);
  if (!webdav_backend) {
    log_critical("Couldn't create WebDAV backend");
    goto done;
  }

  webdav_server_t wd_serv = webdav_server_start(args->loop,
                                                server_fd, args->public_prefix,
                                                webdav_backend);
  /* the server owns the fd now */
  server_fd = -1;
  if (!wd_serv) {
    log_critical("Couldn't start webdav server!");
    goto done;
  }

  log_info("Starting WebDAV server loop");

  fdevent_main_loop(args->loop);

  /* this will end if a handler stops the server */
  log_info("Ending WebDAV server loop");

 done:
  if (webdav_backend) {
    webdav_backend_destroy(webdav_backend);
  }

  if (server_fd >= 0) {
    close(server_fd);
  }

  /* okay tell the main thread we're done here */
  bool success_async_fuse_fs_stop_blocking =
    async_fuse_fs_stop_blocking(args->async_fuse_fs);
  if (!success_async_fuse_fs_stop_blocking) {
    log_critical("Can't stop fuse fs thread");
    abort();
  }

  return NULL;
}

/* From "fuse_versionscript" the version of this symbol is FUSE_2.6 */
int
fuse_main_real(int argc,
	       char *argv[],
	       const struct fuse_operations *op,
	       size_t op_size,
	       void *user_data) {
  DavOptions dav_options;
  FuseOptions fuse_options;
  HTTPThreadArguments http_thread_args;
  async_fuse_fs_t async_fuse_fs = 0;

  UNUSED(op);
  UNUSED(op_size);
  UNUSED(user_data);

  /* Initialize options to 0 */
  memset(&fuse_options, 0, sizeof(fuse_options));
  memset(&dav_options, 0, sizeof(dav_options));

  bool success_parse_environment = parse_environment(&dav_options);
  if (!success_parse_environment) {
    log_critical("Error parsing DAVFUSE_OPTIONS environment variable");
    goto error;
  }

  http_thread_args.listen_str = dav_options.listen_str;
  http_thread_args.public_prefix = dav_options.public_prefix;

  init_logging(stderr, dav_options.log_level);

  bool success_parse_command_line = parse_command_line(argc, argv, &fuse_options);
  if (!success_parse_command_line) {
    log_critical("Error parsing command line");
    goto error;
  }

  if (!fuse_options.singlethread) {
    log_critical("We only support single threaded mode right now");
    goto error;
  }

  /* create event loop */
  FDEventLoop loop;
  bool success_fdevent_init = fdevent_init(&loop);
  if (!success_fdevent_init) {
    log_critical_errno("Couldn't initialize fdevent loop");
    goto error;
  }

  /* create async fuse system */
  log_info("Starting WebDAV server thread");
  async_fuse_fs = async_fuse_fs_new(&loop);
  if (!async_fuse_fs){
    log_critical("Couldn't create async fuse fs");
    goto error;
  }

  http_thread_args.loop = &loop;
  http_thread_args.async_fuse_fs = async_fuse_fs;

  pthread_t new_thread;
  int ret_pthread_create =
    pthread_create(&new_thread, NULL, http_thread, &http_thread_args);
  if (ret_pthread_create) {
    log_critical("Couldn't create http thread: %s",
                 strerror(ret_pthread_create));
    goto error;
  }

  log_info("Starting async FUSE worker main loop");

  async_fuse_worker_main_loop(async_fuse_fs, op, op_size, user_data);

  /* wait on server thread to complete */
  pthread_join(new_thread, NULL);

  int toret = 0;
  if (false) {
  error:
    toret = -1;
  }

  free(dav_options.listen_str);
  free(dav_options.public_prefix);

  if (async_fuse_fs) {
    async_fuse_fs_destroy(async_fuse_fs);
  }

  return toret;
}

struct fuse_context *
fuse_get_context(void) {
  /* TODO: implement */
  assert(false);
  return NULL;
}

void
fuse_unmount_compat22(const char *mountpoint, struct fuse_chan *ch) {
  /* TODO: implement */
  UNUSED(mountpoint);
  UNUSED(ch);
  assert(false);
}
