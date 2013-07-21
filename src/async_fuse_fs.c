#include <unistd.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>

#include "fdevent.h"
#include "fd_utils.h"
#include "logging.h"
#include "uthread.h"

#include "async_fuse.h"

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
    int ret_2 = close(chan->named.out);
    if (ret_2) {
      /* can't recover from this */
      abort();
    }
  }

  return true;
}

struct async_fuse_fs {
  Channel to_worker;
  Channel to_server;
  bool from_in_use;
  FDEventLoop *loop;
};

typedef enum {
  MESSAGE_TYPE_QUIT,
  MESSAGE_TYPE_OPEN,
  MESSAGE_TYPE_READ,
  MESSAGE_TYPE_REPLY,
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
  ReplyMessage reply;
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
  ssize_t ret = write(chan->named.in, msg, sizeof(*msg));
  assert(ret < 0 || ret == sizeof(*msg));
  return ret >= 0;
}

static bool
receive_atomic_message(Channel *chan, Message *msg) {
  assert(sizeof(*msg) <= PIPE_BUF);
  /* TODO: send the necessary size depending on the message type */
  ssize_t ret = read(chan->named.out, msg, sizeof(*msg));
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
  FDEventLoop *loop;
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
      bool ret = fdevent_add_watch(ctx->loop, ctx->to_chan->named.in,
                                   create_stream_events(false, true),
                                   _send_message,
                                   ctx,
                                   NULL);
      if (!ret) { abort(); }
      UTHR_YIELD(ctx, 0);
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
send_message(FDEventLoop *loop,
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
  FDEventLoop *loop;
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
      bool ret = fdevent_add_watch(ctx->loop, ctx->from_chan->named.out,
                                   create_stream_events(true, false),
                                   _receive_reply_message,
                                   ctx,
                                   NULL);
      if (!ret) { abort(); }
      UTHR_YIELD(ctx, 0);
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
receive_reply_message(FDEventLoop *loop,
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

  int ret_chan_deinit_1 = channel_deinit(&fs->to_worker);
  if (!ret_chan_deinit_1) {
    /* can't recover from this */
    abort();
  }

  int ret_chan_deinit_2 = channel_deinit(&fs->to_worker);
  if (!ret_chan_deinit_2) {
    /* can't recover from this */
    abort();
  }

  return true;
}

async_fuse_fs_t
async_fuse_fs_new(FDEventLoop *loop) {
  struct async_fuse_fs *toret = malloc(sizeof(*toret));
  if (toret) {
    log_error("Couldn't allocate async_fuse_fs_t");
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

  toret->from_in_use = false;
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

  /* fail fast if we have no more reply channels */
  if (ctx->fs->from_in_use) {
    ev.ret = -ENOMEM;
    goto done;
  }

  ctx->fs->from_in_use = true;
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

 done:
  if (ctx->set_in_use) {
    ctx->fs->from_in_use = false;
  }

  UTHR_RETURN(ctx,
              ctx->cb(ctx->done_event_type, &ev, ctx->cb_ud));

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
async_fuse_worker_main_loop(async_fuse_fs_t fs,
                            const struct fuse_operations *op,
                            size_t op_size,
                            void *user_data) {
  UNUSED(op);
  UNUSED(op_size);
  UNUSED(user_data);

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
      ret = op->open(msg.open.path, msg.open.fi);
      break;
    case MESSAGE_TYPE_READ:
      ret = op->read(msg.read.path,
                     msg.read.buf, msg.read.size, msg.read.off,
                     msg.read.fi);
      break;
    default:
      log_critical("Received unknown message type: %d", msg.request.type);
      abort();
      break;
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
