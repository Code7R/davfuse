/*
 * Implements a WebDAV server using a set of FUSE callbacks
 */

#define _ISOC99_SOURCE

#include <errno.h>
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
#include "c_util.h"
#include "coroutine.h"
#include "fd_utils.h"
#include "fdevent.h"
#include "http_server.h"
#include "logging.h"
#include "webdav_server.h"
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
  char *file_path;
  uint64_t fh;
} FuseOpenFile;

typedef struct {
  async_fuse_fs_t fuse_fs;
  linked_list_t open_file_list;
} FuseFsCtx;

static FuseOpenFile *
fuse_create_open_file(const char *file_path, uint64_t fh) {
  char *file_path_dup = strdup_x(file_path);
  if (!file_path_dup) {
    return NULL;
  }

  FuseOpenFile *of = malloc(sizeof(*of));
  if (!of) {
    free(file_path_dup);
    return NULL;
  }

  *of = (FuseOpenFile) {
    .file_path = file_path_dup,
    .fh = fh,
  };

  return of;
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  FuseFsCtx *fs_ctx;
  const char *relative_uri;
  bool create;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
  struct fuse_file_info fi;
} FuseOpenCtx;

static
UTHR_DEFINE(_fuse_open_uthr) {
  UTHR_HEADER(FuseOpenCtx, ctx);

  memset(&ctx->fi, sizeof(ctx->fi), 0);
  ctx->fi.flags = O_RDWR | (ctx->create ? O_CREAT : 0);
  UTHR_YIELD(ctx,
             async_fuse_fs_open(ctx->fs_ctx->fuse_fs,
                                ctx->relative_uri, &ctx->fi,
                                _fuse_open_uthr, ctx));
  UTHR_RECEIVE_EVENT(ASYNC_FUSE_FS_OPEN_DONE_EVENT,
                     FuseFsOpDoneEvent, op_done_ev);

  WebdavOpenDoneEvent ev;
  if (op_done_ev->ret) {
    ev.error = op_done_ev->ret == -ENOSYS
      ? WEBDAV_ERROR_DOES_NOT_EXIST
      : WEBDAV_ERROR_GENERAL;
  }
  else {
    /* add file to list of open files */
    FuseOpenFile *of = fuse_create_open_file(ctx->relative_uri, ctx->fi.fh);
    /* TODO: this can't fail for now */
    ASSERT_NOT_NULL(of);

    ctx->fs_ctx->open_file_list =
      linked_list_prepend(ctx->fs_ctx->open_file_list, of);

    ev = (WebdavOpenDoneEvent) {
      .error = WEBDAV_ERROR_NONE,
      .file_handle = of,
    };
  }

  UTHR_RETURN(ctx,
              ctx->cb(WEBDAV_OPEN_DONE_EVENT, &ev, ctx->cb_ud));

  UTHR_FOOTER();
}

static void
fuse_open(void *fs_ctx,
          const char *relative_uri, bool create,
          event_handler_t cb, void *cb_ud) {
  UTHR_CALL5(_fuse_open_uthr, FuseOpenCtx,
             .fs_ctx = (FuseFsCtx *) fs_ctx,
             .relative_uri = relative_uri,
             .create = create,
             .cb = cb,
             .cb_ud = cb_ud);
}

static void
fuse_fstat(void *fs_ctx,
           void *handle,
           event_handler_t cb, void *ud) {
  UNUSED(fs_ctx);
  UNUSED(handle);
  UNUSED(cb);
  UNUSED(ud);
}

static void
fuse_read(void *fs_ctx,
          void *handle,
          void *buf, size_t nbyte,
          event_handler_t cb, void *ud) {
  UNUSED(fs_ctx);
  UNUSED(handle);
  UNUSED(buf);
  UNUSED(nbyte);
  UNUSED(cb);
  UNUSED(ud);
}

static void
fuse_write(void *fs_ctx,
           void *handle,
           const void *buf, size_t nbyte,
           event_handler_t cb, void *ud) {
  UNUSED(fs_ctx);
  UNUSED(handle);
  UNUSED(buf);
  UNUSED(nbyte);
  UNUSED(cb);
  UNUSED(ud);
}

static void
fuse_readcol(void *fs_ctx,
             void *handle,
             WebdavCollectionEntry *ce, size_t nentries,
             event_handler_t cb, void *ud) {
  UNUSED(fs_ctx);
  UNUSED(handle);
  UNUSED(ce);
  UNUSED(nentries);
  UNUSED(cb);
  UNUSED(ud);
}

static void
fuse_close(void *fs_ctx,
           void *handle,
           event_handler_t cb, void *ud) {
  UNUSED(fs_ctx);
  UNUSED(handle);
  UNUSED(cb);
  UNUSED(ud);
}

static void
fuse_mkcol(void *fs_ctx, const char *relative_uri,
           event_handler_t cb, void *ud) {
  UNUSED(fs_ctx);
  UNUSED(relative_uri);
  UNUSED(cb);
  UNUSED(ud);
}

static void
fuse_delete(void *fs_ctx,
            const char *relative_uri,
            event_handler_t cb, void *ud) {
  UNUSED(fs_ctx);
  UNUSED(relative_uri);
  UNUSED(cb);
  UNUSED(ud);
}

static void
fuse_copy(void *fs_ctx,
          const char *src_relative_uri, const char *dst_relative_uri,
          bool overwrite, webdav_depth_t depth,
          event_handler_t cb, void *ud) {
  UNUSED(fs_ctx);
  UNUSED(src_relative_uri);
  UNUSED(dst_relative_uri);
  UNUSED(overwrite);
  UNUSED(depth);
  UNUSED(cb);
  UNUSED(ud);
}

static void
fuse_move(void *fs_ctx,
          const char *src_relative_uri, const char *dst_relative_uri,
          bool overwrite,
          event_handler_t cb, void *ud) {
  UNUSED(fs_ctx);
  UNUSED(src_relative_uri);
  UNUSED(dst_relative_uri);
  UNUSED(overwrite);
  UNUSED(cb);
  UNUSED(ud);
}

static WebdavOperations
fuse_operations = {
  .open = fuse_open,
  .fstat = fuse_fstat,
  .read = fuse_read,
  .write = fuse_write,
  .readcol = fuse_readcol,
  .close = fuse_close,
  .mkcol = fuse_mkcol,
  .delete = fuse_delete,
  .copy = fuse_copy,
  .move = fuse_move,
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
  assert(!listen_str);
  /* TODO: parse `listen_str` */
  return create_ipv4_bound_socket(8080);
}

static void *
http_thread(void *ud) {
  HTTPThreadArguments *args = (HTTPThreadArguments *) ud;
  int server_fd = -1;
  webdav_fs_t fs = 0;

  /* create server socket */
  server_fd = create_server_socket(args->listen_str);
  if (server_fd < 0) {
    log_critical_errno("Couldn't create server socket");
    goto done;
  }

  /* start webdav server */
  FuseFsCtx ctx = {
    .fuse_fs = args->async_fuse_fs,
  };

  fs = webdav_fs_new(&fuse_operations, sizeof(fuse_operations), &ctx);
  if (!fs) {
    log_critical("Couldn't create WebDAV file system");
    goto done;
  }

  webdav_server_t wd_serv = webdav_server_start(args->loop, server_fd, args->public_prefix, fs);
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
  if (fs) {
    webdav_fs_destroy(fs);
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
