#include <stdlib.h>
#include <string.h>

#include "events.h"
#include "fdevent.h"
#include "socket.h"
#include "socket_utils.h"
#include "uthread.h"
#include "util.h"

#include "http_backend.h"

typedef struct _http_backend {
  fdevent_loop_t loop;
  fd_t serv_socket;
  fdevent_watch_key_t accept_key;
} HTTPBackend;

http_backend_t
http_backend_fdevent_new(fdevent_loop_t loop,
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
http_backend_fdevent_destroy(http_backend_t backend) {
  int ret = closesocket(backend->serv_socket);
  ASSERT_TRUE(!ret);
  free(backend);
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  http_backend_t backend;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
} HTTPBackendAcceptCtx;

UTHR_DEFINE(_http_backend_accept_uthr) {
  UTHR_HEADER(HTTPBackendAcceptCtx, ctx);

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
                                             _http_backend_accept_uthr,
                                             ctx,
                                             &ctx->backend->accept_key);
      if (!success_watch) {
        log_error("Couldn't add fdevent watch!");
        break;
      }
      else {
        UTHR_YIELD(ctx, 0);
        ctx->backend->accept_key = FDEVENT_INVALID_WATCH_KEY;
      }
    }
    else {
      log_error("Error while calling accept(): %d",
                last_socket_error());
      break;
    }
  }

  HTTPBackendAcceptDoneEvent ev = {
    .error = (socket == INVALID_SOCKET
              ? HTTP_BACKEND_ERROR_UNKNOWN
              : HTTP_BACKEND_ERROR_NONE),
    .handle = socket,
  };
  UTHR_RETURN(ctx,
              ctx->cb(HTTP_BACKEND_ACCEPT_DONE_EVENT,
                      &ev, ctx->cb_ud));

  UTHR_FOOTER();
}

void
http_backend_accept(http_backend_t backend,
                    event_handler_t cb,
                    void *cb_ud) {
  UTHR_CALL3(_http_backend_accept_uthr, HTTPBackendAcceptCtx,
             .backend = backend,
             .cb = cb,
             .cb_ud = cb_ud);
}

void
http_backend_stop_accept(http_backend_t backend) {
  UNUSED(backend);
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  http_backend_t backend;
  http_backend_handle_t handle;
  void *buf;
  size_t nbyte;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
} HTTPBackendReadCtx;

UTHR_DEFINE(_http_backend_read_uthr) {
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
                                             _http_backend_read_uthr,
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

  HTTPBackendReadDoneEvent ev = {
    .error = (ret == SOCKET_ERROR
              ? HTTP_BACKEND_ERROR_UNKNOWN
              : HTTP_BACKEND_ERROR_NONE),
    .nbyte = (size_t) ret,
  };
  UTHR_RETURN(ctx,
              ctx->cb(HTTP_BACKEND_READ_DONE_EVENT,
                      &ev, ctx->cb_ud));

  UTHR_FOOTER();
}

void
http_backend_read(http_backend_t backend,
                  http_backend_handle_t handle,
                  void *buf, size_t nbyte,
                  event_handler_t cb,
                  void *cb_ud) {
  UTHR_CALL6(_http_backend_read_uthr, HTTPBackendReadCtx,
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
  http_backend_t backend;
  http_backend_handle_t handle;
  const void *buf;
  size_t nbyte;
  event_handler_t cb;
  void *cb_ud;
  /* state */
  const void *buf_loc;
  size_t count_left;
} HTTPBackendWriteCtx;

UTHR_DEFINE(_http_backend_write_uthr) {
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
                                               _http_backend_write_uthr,
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

  HTTPBackendWriteDoneEvent ev = {
    .error = (state->count_left
              ? HTTP_BACKEND_ERROR_UNKNOWN
              : HTTP_BACKEND_ERROR_NONE),
    .nbyte = state->nbyte - state->count_left,
  };
  UTHR_RETURN(state,
              state->cb(HTTP_BACKEND_WRITE_DONE_EVENT,
                        &ev, state->cb_ud));

  UTHR_FOOTER();
}

void
http_backend_write(http_backend_t backend,
                   http_backend_handle_t handle,
                   const void *buf, size_t nbyte,
                   event_handler_t cb,
                   void *cb_ud) {
  UTHR_CALL6(_http_backend_write_uthr, HTTPBackendWriteCtx,
             .backend = backend,
             .handle = handle,
             .buf = buf,
             .nbyte = nbyte,
             .cb = cb,
             .cb_ud = cb_ud);
}

bool
http_backend_close(http_backend_t backend,
                   http_backend_handle_t handle) {
  UNUSED(backend);
  return !closesocket(handle);
}
