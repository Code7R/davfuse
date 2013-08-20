#include <stdlib.h>
#include <string.h>

#include "events.h"
#include "fdevent.h"
#include "sockets.h"
#include "uthread.h"
#include "util.h"
#include "util_sockets.h"

#include "http_backend.h"

/* forward decl */
struct _accept_ctx;

typedef struct _http_backend {
  fdevent_loop_t loop;
  fd_t serv_socket;
  struct _accept_ctx *cur_accept;
} HTTPBackend;

http_backend_sockets_fdevent_t
http_backend_sockets_fdevent_new(fdevent_loop_t loop,
                                 const struct sockaddr *addr, socklen_t addr_len) {
  HTTPBackend *serv = NULL;
  fd_t serv_socket = INVALID_SOCKET;

  serv = malloc(sizeof(*serv));
  if (!serv){
    goto error;
  }

  serv_socket = create_bound_socket(addr, addr_len);
  if (serv_socket == INVALID_SOCKET){
    goto error;
  }

  bool success_non_blocking =
    set_socket_non_blocking(serv_socket);
  if (!success_non_blocking) {
    goto error;
  }

  *serv = (HTTPBackend) {
    .loop = loop,
    .serv_socket = serv_socket,
  };

  return serv;

 error:
  if (serv_socket != INVALID_SOCKET) {
    int ret_close = closesocket(serv_socket);
    ASSERT_TRUE(!ret_close);
  }

  if (serv) {
    free(serv);
  }

  return NULL;
}

void
http_backend_sockets_fdevent_destroy(http_backend_sockets_fdevent_t backend) {
  int ret = closesocket(backend->serv_socket);
  ASSERT_TRUE(!ret);
  free(backend);
}

typedef struct _accept_ctx {
  UTHR_CTX_BASE;
  /* args */
  http_backend_sockets_fdevent_t backend;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
  fdevent_watch_key_t accept_key;
} HTTPBackendAcceptCtx;

UTHR_DEFINE(_http_backend_sockets_fdevent_accept_uthr) {
  UTHR_HEADER(HTTPBackendAcceptCtx, ctx);

  ctx->accept_key = FDEVENT_INVALID_WATCH_KEY;

  fd_t socket;
  while (true) {
    socket = accept(ctx->backend->serv_socket, NULL, NULL);
    if (socket != INVALID_SOCKET) {
      break;
    }

    if (last_socket_error() == SOCKET_EWOULDBLOCK) {
      bool success_watch = fdevent_add_watch(ctx->backend->loop,
                                             ctx->backend->serv_socket,
                                             create_stream_events(true, false),
                                             _http_backend_sockets_fdevent_accept_uthr,
                                             ctx,
                                             &ctx->accept_key);
      if (!success_watch) {
        log_error("Couldn't add fdevent watch!");
        break;
      }
      else {
        ctx->backend->cur_accept = ctx;
        UTHR_YIELD(ctx, 0);
        ctx->accept_key = FDEVENT_INVALID_WATCH_KEY;
        ctx->backend->cur_accept = NULL;
      }
    }
    else {
      log_error("Error while calling accept(): %d",
                last_socket_error());
      break;
    }
  }

  if (socket != INVALID_SOCKET) {
    bool success_non_blocking =
      set_socket_non_blocking(socket);
    if (!success_non_blocking) {
      const int ret_close = closesocket(socket);
      ASSERT_TRUE(!ret_close);
      socket = INVALID_SOCKET;
    }
  }

  HttpBackendAcceptDoneEvent ev = {
    .error = (socket == INVALID_SOCKET
              ? HTTP_BACKEND_SOCKETS_FDEVENT_ERROR_UNKNOWN
              : HTTP_BACKEND_SOCKETS_FDEVENT_ERROR_NONE),
    .handle = socket,
  };
  UTHR_RETURN(ctx,
              ctx->cb(HTTP_BACKEND_SOCKETS_FDEVENT_ACCEPT_DONE_EVENT,
                      &ev, ctx->cb_ud));

  UTHR_FOOTER();
}

void
http_backend_sockets_fdevent_accept(http_backend_sockets_fdevent_t backend,
                                    event_handler_t cb,
                                    void *cb_ud) {
  if (backend->cur_accept) {
    HttpBackendAcceptDoneEvent ev = {
      /* TODO: get better error code */
      .error = HTTP_BACKEND_SOCKETS_FDEVENT_ERROR_UNKNOWN,
    };
    return cb(HTTP_BACKEND_SOCKETS_FDEVENT_ACCEPT_DONE_EVENT, &ev, cb_ud);
  }

  UTHR_CALL3(_http_backend_sockets_fdevent_accept_uthr, HTTPBackendAcceptCtx,
             .backend = backend,
             .cb = cb,
             .cb_ud = cb_ud);
}

void
http_backend_sockets_fdevent_stop_accept(http_backend_sockets_fdevent_t backend) {
  if (backend->cur_accept) {
    assert(backend->cur_accept->accept_key != FDEVENT_INVALID_WATCH_KEY);
    const bool success_remove =
      fdevent_remove_watch(backend->loop, backend->cur_accept->accept_key);
    ASSERT_TRUE(success_remove);
    free(backend->cur_accept);
    backend->cur_accept = NULL;
  }
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  http_backend_sockets_fdevent_t backend;
  http_backend_sockets_fdevent_handle_t handle;
  void *buf;
  size_t nbyte;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
} HTTPBackendReadCtx;

UTHR_DEFINE(_http_backend_sockets_fdevent_read_uthr) {
  UTHR_HEADER(HTTPBackendReadCtx, ctx);

  socket_ssize_t ret;
  while (true) {
    ret = recv(ctx->handle, ctx->buf, ctx->nbyte, 0);
    if (ret != SOCKET_ERROR) {
      break;
    }

    if (last_socket_error() == SOCKET_EAGAIN) {
      bool success_watch = fdevent_add_watch(ctx->backend->loop,
                                             ctx->handle,
                                             create_stream_events(true, false),
                                             _http_backend_sockets_fdevent_read_uthr,
                                             ctx,
                                             NULL);
      if (!success_watch) {
        log_error("Couldn't add fdevent watch!");
        break;
      }
      else {
        UTHR_YIELD(ctx, 0);
      }
    }
    else {
      log_error("Error while calling read(): %s",
                last_socket_error_message());
      break;
    }
  }

  HttpBackendReadDoneEvent ev = {
    .error = (ret == SOCKET_ERROR
              ? HTTP_BACKEND_SOCKETS_FDEVENT_ERROR_UNKNOWN
              : HTTP_BACKEND_SOCKETS_FDEVENT_ERROR_NONE),
    .nbyte = (size_t) ret,
  };
  UTHR_RETURN(ctx,
              ctx->cb(HTTP_BACKEND_SOCKETS_FDEVENT_READ_DONE_EVENT,
                      &ev, ctx->cb_ud));

  UTHR_FOOTER();
}

void
http_backend_sockets_fdevent_read(http_backend_sockets_fdevent_t backend,
                                  http_backend_sockets_fdevent_handle_t handle,
                                  void *buf, size_t nbyte,
                                  event_handler_t cb,
                                  void *cb_ud) {
  UTHR_CALL6(_http_backend_sockets_fdevent_read_uthr, HTTPBackendReadCtx,
             .backend = backend,
             .handle = handle,
             .buf = buf,
             .nbyte = nbyte,
             .cb = cb,
             .cb_ud = cb_ud);
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  http_backend_sockets_fdevent_t backend;
  http_backend_sockets_fdevent_handle_t handle;
  const void *buf;
  size_t nbyte;
  event_handler_t cb;
  void *cb_ud;
  /* state */
  const void *buf_loc;
  size_t count_left;
} HTTPBackendWriteCtx;

UTHR_DEFINE(_http_backend_sockets_fdevent_write_uthr) {
  UTHR_HEADER(HTTPBackendWriteCtx, state);

  state->buf_loc = state->buf;
  state->count_left = state->nbyte;

  socket_ssize_t ret;
  while (state->count_left) {
    ret = send(state->handle, state->buf_loc, state->count_left, 0);
    if (ret == SOCKET_ERROR) {
      if (last_socket_error() == SOCKET_EAGAIN) {
        bool success_watch = fdevent_add_watch(state->backend->loop,
                                               state->handle,
                                               create_stream_events(false, true),
                                               _http_backend_sockets_fdevent_write_uthr,
                                               state,
                                               NULL);
        if (!success_watch) {
          log_error("Couldn't add fdevent watch!");
          break;
        }
        else {
          UTHR_YIELD(state, 0);
          continue;
        }
      }
      else {
        log_error("Error while calling send(): %d",
                  last_socket_error());
        break;
      }
    }

    assert(state->count_left >= (size_t) ret);
    state->count_left -= ret;
    state->buf_loc += ret;
  }

  HttpBackendWriteDoneEvent ev = {
    .error = (state->count_left
              ? HTTP_BACKEND_SOCKETS_FDEVENT_ERROR_UNKNOWN
              : HTTP_BACKEND_SOCKETS_FDEVENT_ERROR_NONE),
    .nbyte = state->nbyte - state->count_left,
  };
  UTHR_RETURN(state,
              state->cb(HTTP_BACKEND_SOCKETS_FDEVENT_WRITE_DONE_EVENT,
                        &ev, state->cb_ud));

  UTHR_FOOTER();
}

void
http_backend_sockets_fdevent_write(http_backend_sockets_fdevent_t backend,
                                   http_backend_sockets_fdevent_handle_t handle,
                                   const void *buf, size_t nbyte,
                                   event_handler_t cb,
                                   void *cb_ud) {
  UTHR_CALL6(_http_backend_sockets_fdevent_write_uthr, HTTPBackendWriteCtx,
             .backend = backend,
             .handle = handle,
             .buf = buf,
             .nbyte = nbyte,
             .cb = cb,
             .cb_ud = cb_ud);
}

bool
http_backend_sockets_fdevent_close(http_backend_sockets_fdevent_t backend,
                                   http_backend_sockets_fdevent_handle_t handle) {
  UNUSED(backend);
  const int ret_shutdown = shutdown(handle, SD_BOTH);
  if (ret_shutdown == SOCKET_ERROR &&
      last_socket_error() != SOCKET_ENOTCONN) {
    log_warning("Error while trying to shutdown socket...");
  }
  const int ret_closesocket = closesocket(handle);
  return ret_closesocket != SOCKET_ERROR;
}
