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

#define _ISOC99_SOURCE
#define _POSIX_C_SOURCE 199309L
#define _BSD_SOURCE

#include <unistd.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

#define FUSE_USE_VERSION 26
#include "fuse.h"
#undef FUSE_USE_VERSION

#include "async_rdwr_lock.h"
#include "event_loop.h"
#include "fd_utils.h"
#include "logging.h"
#include "uthread.h"
#include "util.h"

#include "async_fuse_fs.h"

typedef union {
  int all[2];
  struct {
    /* read from out */
    int out;
    /* write to in */
    int in;
  } named;
} Channel;

#define CHANNEL_INITIALIZER ((Channel) {.all = {-1, -1}})

static bool
channel_init(Channel *chan) {
  int ret = pipe(chan->all);
  return !ret;
}

static bool
channel_deinit(Channel *chan) {
  if (chan->named.in >= 0) {
    int ret_1 = close(chan->named.in);
    if (ret_1) {
      return false;
    }
  }

  if (chan->named.out >= 0) {
    close_or_abort(chan->named.out);
  }

  return true;
}

struct async_fuse_fs {
  Channel to_worker;
  Channel to_server;
  event_loop_handle_t loop;
  /* TODO: get rid of this */
  async_rdwr_lock_t to_server_lock;
};

typedef enum {
  MESSAGE_TYPE_QUIT,
  MESSAGE_TYPE_OPEN,
  MESSAGE_TYPE_READ,
  MESSAGE_TYPE_GETATTR,
  MESSAGE_TYPE_MKDIR,
  MESSAGE_TYPE_MKNOD,
  MESSAGE_TYPE_REPLY,
  MESSAGE_TYPE_GETDIR,
  MESSAGE_TYPE_UNLINK,
  MESSAGE_TYPE_RMDIR,
  MESSAGE_TYPE_WRITE,
  MESSAGE_TYPE_RELEASE,
  MESSAGE_TYPE_FGETATTR,
  MESSAGE_TYPE_RENAME,
} worker_message_type_t;

#define MESSAGE_HDR worker_message_type_t type
#define REQUEST_MESSAGE_HDR worker_message_type_t type; Channel *reply_chan

typedef struct {
  MESSAGE_HDR;
} QuitMessage;

typedef struct {
  REQUEST_MESSAGE_HDR;
  const char *path;
  struct fuse_file_info *fi;
} OpenMessage;

typedef struct {
  REQUEST_MESSAGE_HDR;
  const char *path;
  char *buf;
  size_t size;
  off_t off;
  struct fuse_file_info *fi;
} ReadMessage;

typedef struct {
  REQUEST_MESSAGE_HDR;
  const char *path;
  struct stat *st;
} GetattrMessage;

typedef struct {
  REQUEST_MESSAGE_HDR;
  const char *path;
  mode_t mode;
} MkdirMessage;

typedef struct {
  REQUEST_MESSAGE_HDR;
  const char *path;
  mode_t mode;
  dev_t dev;
} MknodMessage;

typedef struct {
  REQUEST_MESSAGE_HDR;
  const char *path;
  fuse_dirh_t h;
  fuse_dirfil_t fn;
} GetdirMessage;

typedef struct {
  REQUEST_MESSAGE_HDR;
  const char *path;
} UnlinkMessage;

typedef struct {
  REQUEST_MESSAGE_HDR;
  const char *path;
} RmdirMessage;

typedef struct {
  REQUEST_MESSAGE_HDR;
  const char *path;
  const char *buf;
  size_t size;
  off_t off;
  struct fuse_file_info *fi;
} WriteMessage;

typedef struct {
  REQUEST_MESSAGE_HDR;
  const char *path;
  struct fuse_file_info *fi;
} ReleaseMessage;

typedef struct {
  REQUEST_MESSAGE_HDR;
  const char *path;
  struct stat *buf;
  struct fuse_file_info *fi;
} FgetattrMessage;

typedef struct {
  REQUEST_MESSAGE_HDR;
  const char *src;
  const char *dst;
} RenameMessage;

typedef struct {
  MESSAGE_HDR;
  int ret;
} ReplyMessage;

typedef union {
  struct {
    MESSAGE_HDR;
  } generic;
  struct {
    REQUEST_MESSAGE_HDR;
  } request;
  QuitMessage quit;
  OpenMessage open;
  ReadMessage read;
  GetattrMessage getattr;
  MkdirMessage mkdir;
  MknodMessage mknod;
  GetdirMessage getdir;
  ReplyMessage reply;
  UnlinkMessage unlink;
  RmdirMessage rmdir;
  WriteMessage write;
  ReleaseMessage release;
  FgetattrMessage fgetattr;
  RenameMessage rename;
} Message;

typedef struct {
  bool error;
} SendMessageDoneEvent;

typedef struct {
  bool error;
  ReplyMessage msg;
} ReceiveReplyMessageDoneEvent;

static bool
send_atomic_message(Channel *chan, Message *msg) {
  assert(sizeof(*msg) <= PIPE_BUF);
  /* TODO: read the necessary size depending on the message type */
  ssize_t ret;
  while (true) {
    ret = write(chan->named.in, msg, sizeof(*msg));
    if (!(ret < 0 && errno == EINTR)) {
      break;
    }
  }
  if (ret < 0) {
    log_error("Erroring while sending atomic message: %s", strerror(errno));
  }
  assert(ret < 0 || ret == sizeof(*msg));
  return ret >= 0;
}

static bool
receive_atomic_message(Channel *chan, Message *msg) {
  assert(sizeof(*msg) <= PIPE_BUF);
  /* TODO: send the necessary size depending on the message type */
  ssize_t ret;
  while (true) {
    ret = read(chan->named.out, msg, sizeof(*msg));
    if (!(ret < 0 && errno == EINTR)) {
      break;
    }
  }
  if (ret < 0) {
    log_error("Erroring while receiving atomic message: %s", strerror(errno));
  }
  assert(ret < 0 || ret == sizeof(*msg));
  return ret >= 0;
}

static bool
send_quit_message_blocking(Channel *chan) {
  bool success_set_blocking = set_blocking(chan->named.in);
  if (!success_set_blocking) {
    return false;
  }

  Message msg = {.quit = {.type = MESSAGE_TYPE_QUIT}};
  int ret_send_atomic_message = send_atomic_message(chan, &msg);

  bool success_set_non_blocking = set_non_blocking(chan->named.in);
  if (!success_set_non_blocking) {
    /* this can't fail */
    abort();
  }

  return ret_send_atomic_message >= 0;
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  event_loop_handle_t loop;
  Channel *to_chan;
  Message *msg;
  event_handler_t cb;
  void *ud;
  /* ctx */
} SendMessageCtx;

static
UTHR_DEFINE(_send_message) {
  bool error;

  UTHR_HEADER(SendMessageCtx, ctx);

  while (true) {
    bool success_sent = send_atomic_message(ctx->to_chan, ctx->msg);
    if (success_sent) {
      error = false;
      break;
    }

    if (errno == EAGAIN) {
      bool ret = event_loop_fd_watch_add(ctx->loop, ctx->to_chan->named.in,
                                         create_stream_events(false, true),
                                         _send_message,
                                         ctx,
                                         NULL);
      ASSERT_TRUE(ret);
      UTHR_YIELD(ctx, 0);
      UTHR_RECEIVE_EVENT(EVENT_LOOP_FD_EVENT, EventLoopFdEvent, fd_ev);
      if (fd_ev->error) {
        log_error("error during fd watch");
        error = true;
        break;
      }
    }
    else {
      error = true;
      break;
    }
  }

  SendMessageDoneEvent ev = {
    .error = error,
  };
  UTHR_RETURN(ctx,
              ctx->cb(SEND_MESSAGE_DONE_EVENT, &ev, ctx->ud));

  UTHR_FOOTER();
}

static void
send_message(event_loop_handle_t loop,
             Channel *to_chan,
             Message *msg,
             event_handler_t cb, void *ud) {
  UTHR_CALL6(_send_message, SendMessageCtx,
             .loop = loop,
             .to_chan = to_chan,
             .msg = msg,
             .cb = cb,
             .ud = ud);
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  event_loop_handle_t loop;
  Channel *from_chan;
  event_handler_t cb;
  void *ud;
  /* ctx */
  Message msg;
} ReceiveReplyMessageCtx;

static
UTHR_DEFINE(_receive_reply_message) {
  bool error;

  UTHR_HEADER(ReceiveReplyMessageCtx, ctx);

  while (true) {
    bool success_receive =
      receive_atomic_message(ctx->from_chan, &ctx->msg);
    if (success_receive) {
      error = false;
      break;
    }

    if (errno == EAGAIN) {
      bool ret = event_loop_fd_watch_add(ctx->loop, ctx->from_chan->named.out,
                                         create_stream_events(true, false),
                                         _receive_reply_message,
                                         ctx,
                                         NULL);
      ASSERT_TRUE(ret);
      UTHR_YIELD(ctx, 0);
      UTHR_RECEIVE_EVENT(EVENT_LOOP_FD_EVENT, EventLoopFdEvent, fd_ev);
      if (fd_ev->error) {
        log_error("error during fd watch");
        error = true;
        break;
      }
    }
    else {
      error = true;
      break;
    }
  }

  ReceiveReplyMessageDoneEvent ev = {
    .error = error,
    .msg = ctx->msg.reply,
  };
  UTHR_RETURN(ctx,
              ctx->cb(RECEIVE_REPLY_MESSAGE_DONE_EVENT, &ev, ctx->ud));

  UTHR_FOOTER();
}

static void
receive_reply_message(event_loop_handle_t loop,
                      Channel *from_chan,
                      event_handler_t cb, void *ud) {
  UTHR_CALL4(_receive_reply_message, ReceiveReplyMessageCtx,
             .loop = loop,
             .from_chan = from_chan,
             .cb = cb,
             .ud = ud);
}

static bool
_async_fuse_fs_destroy(async_fuse_fs_t fs) {
  assert(fs);

  if (fs->to_server_lock) {
    bool success_destroy =
      async_rdwr_destroy_sync(fs->to_server_lock);
    /* this can't fail */
    ASSERT_TRUE_MSG(success_destroy, "Couldn't destroy read write lock");
  }

  int ret_chan_deinit_1 = channel_deinit(&fs->to_worker);
  if (!ret_chan_deinit_1) {
    /* can't recover from this */
    log_critical("Couldn't deinit \"to worker\" channel");
    abort();
  }

  int ret_chan_deinit_2 = channel_deinit(&fs->to_server);
  if (!ret_chan_deinit_2) {
    /* can't recover from this */
    log_critical("Couldn't deinit \"to server\" channel");
    abort();
  }

  free(fs);

  return true;
}

async_fuse_fs_t
async_fuse_fs_new(event_loop_handle_t loop) {
  struct async_fuse_fs *toret = malloc(sizeof(*toret));
  if (!toret) {
    log_error("Couldn't allocate async_fuse_fs_t");
    goto error;
  }

  toret->to_server_lock = async_rdwr_new();
  if (!toret->to_server_lock) {
    log_error("Couldn't create async read write lock");
    goto error;
  }

  toret->to_worker = CHANNEL_INITIALIZER;
  toret->to_server = CHANNEL_INITIALIZER;

  bool success_channel_init_1 = channel_init(&toret->to_worker);
  if (!success_channel_init_1) {
    log_error("Couldn't create \"to worker\" channel");
    goto error;
  }

  bool success_channel_init_2 = channel_init(&toret->to_server);
  if (!success_channel_init_2) {
    log_error("Couldn't create \"to server\" channel");
    goto error;
  }

  /* set to_server.read and to_worker.write as non-blocking */
  bool success_set_non_blocking_1 =
    set_non_blocking(toret->to_worker.named.in);
  if (!success_set_non_blocking_1) {
    log_error("Couldn't make `to_worker.write` non-blocking");
    goto error;
  }

  bool success_set_non_blocking_2 =
    set_non_blocking(toret->to_server.named.out);
  if (!success_set_non_blocking_2) {
    log_error("Couldn't make `to_server.read` non-blocking");
    goto error;
  }

  toret->loop = loop;

  return toret;

 error:
  if (toret) {
    _async_fuse_fs_destroy(toret);
  }

  return NULL;
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  struct async_fuse_fs *fs;
  Message msg;
  event_type_t done_event_type;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
  bool set_in_use;
} SendRequestCtx;

static
UTHR_DEFINE(_send_request_uthr) {
  FuseFsOpDoneEvent ev;

  UTHR_HEADER(SendRequestCtx, ctx);

  ctx->set_in_use = false;

  UTHR_SUBCALL(ctx,
               async_rdwr_write_lock(ctx->fs->to_server_lock,
                                     _send_request_uthr, ctx),
               ASYNC_RDWR_WRITE_LOCK_DONE_EVENT,
               AsyncRdwrWriteLockDoneEvent, lock_done_ev);
  if (!lock_done_ev->success) {
    ev.ret = -ENOMEM;
    goto done;
  }

  ctx->set_in_use = true;

  ctx->msg.request.reply_chan = &ctx->fs->to_server;

  UTHR_YIELD(ctx,
             send_message(ctx->fs->loop,
                          &ctx->fs->to_worker,
                          &ctx->msg,
                          _send_request_uthr, ctx));
  UTHR_RECEIVE_EVENT(SEND_MESSAGE_DONE_EVENT,
                     SendMessageDoneEvent, send_msg_done_ev);
  if (send_msg_done_ev->error) {
    ev.ret = -EIO;
    goto done;
  }

  /* okay now that we sent off message, wait for the reply */
  UTHR_YIELD(ctx,
             receive_reply_message(ctx->fs->loop,
                                   &ctx->fs->to_server,
                                   _send_request_uthr, ctx));
  UTHR_RECEIVE_EVENT(RECEIVE_REPLY_MESSAGE_DONE_EVENT,
                     ReceiveReplyMessageDoneEvent,
                     receive_reply_message_done_ev);
  if (receive_reply_message_done_ev->error) {
    /* this is pretty hard to recover from, just abort for now */
    abort();
  }

  ev.ret = receive_reply_message_done_ev->msg.ret;

  event_handler_t cb;
 done:
  cb = ctx->cb;
  void *cb_ud = ctx->cb_ud;
  event_type_t ev_type = ctx->done_event_type;
  bool set_in_use = ctx->set_in_use;
  async_rdwr_lock_t to_server_lock = ctx->fs->to_server_lock;

  free(ctx);

  cb(ev_type, &ev, cb_ud);

  /* unlock after calling the callback,
     otherwise we won't call our callback until every other locked
     send_request method is complete */
  if (set_in_use) {
    async_rdwr_write_unlock(to_server_lock);
  }

  return;

  UTHR_FOOTER();
}

void
async_fuse_fs_open(async_fuse_fs_t fs,
                   const char *path, struct fuse_file_info *fi,
                   event_handler_t cb, void *cb_ud) {
  Message msg = {
    .open = {
      .type = MESSAGE_TYPE_OPEN,
      .path = path,
      .fi = fi,
    }
  };

  UTHR_CALL5(_send_request_uthr, SendRequestCtx,
             .fs = fs,
             .msg = msg,
             .done_event_type = ASYNC_FUSE_FS_OPEN_DONE_EVENT,
             .cb = cb,
             .cb_ud = cb_ud);
}

void
async_fuse_fs_fgetattr(async_fuse_fs_t fs,
                       const char *path, struct stat *buf,
                       struct fuse_file_info *fi,
                       event_handler_t cb, void *cb_ud) {
  Message msg = {
    .fgetattr = {
      .type = MESSAGE_TYPE_FGETATTR,
      .path = path,
      .buf = buf,
      .fi = fi,
    }
  };

  UTHR_CALL5(_send_request_uthr, SendRequestCtx,
             .fs = fs,
             .msg = msg,
             .done_event_type = ASYNC_FUSE_FS_FGETATTR_DONE_EVENT,
             .cb = cb,
             .cb_ud = cb_ud);
}

void
async_fuse_fs_read(async_fuse_fs_t fs,
                   const char *path, char *buf, size_t size,
                   off_t off, struct fuse_file_info *fi,
                   event_handler_t cb, void *cb_ud) {
  Message msg = {
    .read = {
      .type = MESSAGE_TYPE_READ,
      .path = path,
      .buf = buf,
      .size = size,
      .off = off,
      .fi = fi,
    },
  };

  UTHR_CALL5(_send_request_uthr, SendRequestCtx,
             .fs = fs,
             .msg = msg,
             .done_event_type = ASYNC_FUSE_FS_READ_DONE_EVENT,
             .cb = cb,
             .cb_ud = cb_ud);
}

void
async_fuse_fs_write(async_fuse_fs_t fs,
                    const char *path, const char *buf,
                    size_t size, off_t off, struct fuse_file_info *fi,
                    event_handler_t cb, void *cb_ud) {
  Message msg = {
    .write = {
      .type = MESSAGE_TYPE_WRITE,
      .path = path,
      .buf = buf,
      .size = size,
      .off = off,
      .fi = fi,
    },
  };

  UTHR_CALL5(_send_request_uthr, SendRequestCtx,
             .fs = fs,
             .msg = msg,
             .done_event_type = ASYNC_FUSE_FS_WRITE_DONE_EVENT,
             .cb = cb,
             .cb_ud = cb_ud);
}

void
async_fuse_fs_getattr(async_fuse_fs_t fs,
                      const char *path, struct stat *st,
                      event_handler_t cb, void *cb_ud) {
  Message msg = {
    .getattr = {
      .type = MESSAGE_TYPE_GETATTR,
      .path = path,
      .st = st,
    },
  };

  UTHR_CALL5(_send_request_uthr, SendRequestCtx,
             .fs = fs,
             .msg = msg,
             .done_event_type = ASYNC_FUSE_FS_GETATTR_DONE_EVENT,
             .cb = cb,
             .cb_ud = cb_ud);
}

void
async_fuse_fs_mkdir(async_fuse_fs_t fs,
                    const char *path,
                    mode_t mode,
                    event_handler_t cb, void *cb_ud) {
  Message msg = {
    .mkdir = {
      .type = MESSAGE_TYPE_MKDIR,
      .path = path,
      .mode = mode,
    },
  };

  UTHR_CALL5(_send_request_uthr, SendRequestCtx,
             .fs = fs,
             .msg = msg,
             .done_event_type = ASYNC_FUSE_FS_MKDIR_DONE_EVENT,
             .cb = cb,
             .cb_ud = cb_ud);
}

void
async_fuse_fs_mknod(async_fuse_fs_t fs,
                    const char *path, mode_t mode, dev_t dev,
                    event_handler_t cb, void *cb_ud) {
  Message msg = {
    .mknod = {
      .type = MESSAGE_TYPE_MKNOD,
      .path = path,
      .mode = mode,
      .dev = dev,
    },
  };

  UTHR_CALL5(_send_request_uthr, SendRequestCtx,
             .fs = fs,
             .msg = msg,
             .done_event_type = ASYNC_FUSE_FS_MKNOD_DONE_EVENT,
             .cb = cb,
             .cb_ud = cb_ud);
}


void
async_fuse_fs_getdir(async_fuse_fs_t fs,
                     const char *path, fuse_dirh_t h, fuse_dirfil_t fn,
                     event_handler_t cb, void *cb_ud) {
  Message msg = {
    .getdir = {
      .type = MESSAGE_TYPE_GETDIR,
      .path = path,
      .h = h,
      .fn = fn,
    },
  };

  UTHR_CALL5(_send_request_uthr, SendRequestCtx,
             .fs = fs,
             .msg = msg,
             .done_event_type = ASYNC_FUSE_FS_GETDIR_DONE_EVENT,
             .cb = cb,
             .cb_ud = cb_ud);
}

void
async_fuse_fs_unlink(async_fuse_fs_t fs,
                     const char *path,
                     event_handler_t cb, void *cb_ud) {
  Message msg = {
    .unlink = {
      .type = MESSAGE_TYPE_UNLINK,
      .path = path,
    },
  };

  UTHR_CALL5(_send_request_uthr, SendRequestCtx,
             .fs = fs,
             .msg = msg,
             .done_event_type = ASYNC_FUSE_FS_UNLINK_DONE_EVENT,
             .cb = cb,
             .cb_ud = cb_ud);
}

void
async_fuse_fs_rmdir(async_fuse_fs_t fs,
                    const char *path,
                    event_handler_t cb, void *cb_ud) {
  Message msg = {
    .rmdir = {
      .type = MESSAGE_TYPE_RMDIR,
      .path = path,
    },
  };

  UTHR_CALL5(_send_request_uthr, SendRequestCtx,
             .fs = fs,
             .msg = msg,
             .done_event_type = ASYNC_FUSE_FS_RMDIR_DONE_EVENT,
             .cb = cb,
             .cb_ud = cb_ud);
}

void
async_fuse_fs_release(async_fuse_fs_t fs,
                      const char *path, struct fuse_file_info *fi,
                      event_handler_t cb, void *cb_ud) {
  Message msg = {
    .release = {
      .type = MESSAGE_TYPE_RELEASE,
      .path = path,
      .fi = fi,
    },
  };

  UTHR_CALL5(_send_request_uthr, SendRequestCtx,
             .fs = fs,
             .msg = msg,
             .done_event_type = ASYNC_FUSE_FS_RELEASE_DONE_EVENT,
             .cb = cb,
             .cb_ud = cb_ud);
}

void
async_fuse_fs_rename(async_fuse_fs_t fs,
                     const char *src, const char *dst,
                     event_handler_t cb, void *cb_ud) {
  Message msg = {
    .rename = {
      .type = MESSAGE_TYPE_RENAME,
      .src = src,
      .dst = dst,
    },
  };

  UTHR_CALL5(_send_request_uthr, SendRequestCtx,
             .fs = fs,
             .msg = msg,
             .done_event_type = ASYNC_FUSE_FS_RENAME_DONE_EVENT,
             .cb = cb,
             .cb_ud = cb_ud);
}

void
async_fuse_worker_main_loop(async_fuse_fs_t fs,
                            const struct fuse_operations *op,
                            size_t op_size,
                            void *user_data) {
  UNUSED(op_size);
  UNUSED(user_data);

  /* call init method first */
  fuse_get_context()->private_data = user_data;
  struct fuse_conn_info conn = {
    .proto_major = 2,
    .proto_minor = 6,
    .async_read = 0,
    /* TODO */
  };

  void *init_ret = NULL;
  if (op->init) {
    init_ret = op->init(&conn);
    fuse_get_context()->private_data = init_ret;
  }

  while (true) {
    Message msg;

    log_debug("Waiting for worker request");
    bool success_receive_atomic_message =
      receive_atomic_message(&fs->to_worker, &msg);
    if (!success_receive_atomic_message) {
      log_critical("Error while reading worker msg");
      abort();
    }

    if (msg.generic.type == MESSAGE_TYPE_QUIT) {
      log_info("Received quit message, quitting...");
      break;
    }

    int ret;
    switch (msg.request.type) {
    case MESSAGE_TYPE_OPEN:
      log_debug("Peforming fuse open(path=\"%s\", fi=%p)",
                msg.open.path, msg.open.fi);
      ret = op->open(msg.open.path, msg.open.fi);
      break;
    case MESSAGE_TYPE_READ:
      log_debug("Peforming fuse read(path=\"%s\", buf=%p, size=%ju, off=%jd, fi=%p)",
                msg.read.path,
                msg.read.buf,
                (uintmax_t) msg.read.size,
                (intmax_t) msg.read.off,
                msg.read.fi);
      ret = op->read(msg.read.path,
                     msg.read.buf, msg.read.size, msg.read.off,
                     msg.read.fi);
      break;
    case MESSAGE_TYPE_GETATTR:
      log_debug("Peforming fuse getattr(path=\"%s\", st=%p)",
                msg.getattr.path, msg.getattr.st);
      ret = op->getattr(msg.getattr.path, msg.getattr.st);
      break;
    case MESSAGE_TYPE_MKDIR:
      log_debug("Peforming fuse mkdir(path=\"%s\", mode=0%o)",
                msg.mkdir.path, msg.mkdir.mode);
      ret = op->mkdir(msg.mkdir.path, msg.mkdir.mode);
      break;
    case MESSAGE_TYPE_MKNOD:
      log_debug("Peforming fuse mknod(path=\"%s\", mode=0%o, dev=%lld)",
                msg.mknod.path, msg.mknod.mode, (long long) msg.mknod.dev);
      ret = op->mknod(msg.mknod.path, msg.mknod.mode, msg.mknod.dev);
      break;
    case MESSAGE_TYPE_GETDIR:
      log_debug("Peforming fuse getdir(path=\"%s\", h=%p, fn=%p)",
                msg.getdir.path, msg.getdir.h, msg.getdir.fn);
      ret = op->getdir(msg.getdir.path, msg.getdir.h, msg.getdir.fn);
      break;
    case MESSAGE_TYPE_UNLINK:
      log_debug("Peforming fuse getdir(path=\"%s\")",
                msg.unlink.path);
      ret = op->unlink(msg.unlink.path);
      break;
    case MESSAGE_TYPE_RMDIR:
      log_debug("Peforming fuse rmdir(path=\"%s\")",
                msg.rmdir.path);
      ret = op->rmdir(msg.rmdir.path);
      break;
    case MESSAGE_TYPE_WRITE:
      log_debug("Peforming fuse write(path=\"%s\", buf=%p, size=%ju, off=%jd, fi=%p)",
                msg.write.path, msg.write.buf, (uintmax_t) msg.write.size,
                (intmax_t) msg.write.off, msg.write.fi);
      ret = op->write(msg.write.path, msg.write.buf, msg.write.size,
                      msg.write.off, msg.write.fi);
      break;
    case MESSAGE_TYPE_RELEASE:
      log_debug("Peforming fuse release(path=\"%s\", fi=%p)",
                msg.release.path, msg.release.fi);
      ret = op->release(msg.release.path, msg.release.fi);
      break;
    case MESSAGE_TYPE_FGETATTR:
      log_debug("Peforming fuse fgetattr(path=\"%s\", buf=%p, fi=%p)",
                msg.fgetattr.path, msg.fgetattr.buf, msg.fgetattr.fi);
      ret = op->fgetattr(msg.fgetattr.path, msg.fgetattr.buf, msg.fgetattr.fi);
      break;
    case MESSAGE_TYPE_RENAME:
      log_debug("Peforming fuse rename(src=\"%s\", dst=\"%s\")",
                msg.rename.src, msg.rename.dst);
      ret = op->rename(msg.rename.src, msg.rename.dst);
      break;
    default:
      log_critical("Received unknown message type: %d", msg.request.type);
      abort();
      break;
    }

    if (ret < 0) {
      log_debug("Return code was (error) %d: %s", ret, strerror(-ret));
    }
    else {
      log_debug("Return code was %d", ret);
    }


    Message reply_msg = {
      .reply = {
        .type = MESSAGE_TYPE_REPLY,
        .ret = ret,
      },
    };
    bool success_send_atomic_message =
      send_atomic_message(msg.request.reply_chan, &reply_msg);
    if (!success_send_atomic_message) {
      /* this can't fail because it's a reply message */
      abort();
    }
  }

  if (op->destroy) {
    op->destroy(init_ret);
  }

  return;
}

bool
async_fuse_fs_stop_blocking(async_fuse_fs_t fs) {
  return send_quit_message_blocking(&fs->to_worker);
}

bool
async_fuse_fs_destroy(async_fuse_fs_t fs) {
  return _async_fuse_fs_destroy(fs);
}
