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

#include "util_event_loop.h"

#include "events.h"
#include "sockets.h"
#include "logging.h"
#include "uthread.h"
#include "util_sockets.h"

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  event_loop_handle_t loop;
  socket_t sock;
  void *buf;
  size_t nbyte;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
} SocketReadCtx;

UTHR_DEFINE(_util_event_loop_socket_read_uthr) {
  UTHR_HEADER(SocketReadCtx, ctx);

  socket_ssize_t ret;
  while (true) {
    ret = recv(ctx->sock, ctx->buf, ctx->nbyte, 0);
    if (ret != SOCKET_ERROR) {
      break;
    }

    if (last_socket_error() == SOCKET_EAGAIN) {
      bool success_watch = event_loop_socket_watch_add(ctx->loop,
                                                       ctx->sock,
                                                       create_stream_events(true, false),
                                                       _util_event_loop_socket_read_uthr,
                                                       ctx,
                                                       NULL);
      if (!success_watch) {
        log_error("Couldn't add fdevent watch!");
        break;
      }
      else {
        UTHR_YIELD(ctx, 0);
        UTHR_RECEIVE_EVENT(EVENT_LOOP_SOCKET_EVENT, EventLoopSocketEvent, socket_ev);
        if (socket_ev->error) {
          log_error("error during socket watch");
          ret = SOCKET_ERROR;
          break;
        }
      }
    }
    else {
      log_error("Error while calling read(): %s",
                last_socket_error_message());
      break;
    }
  }

  UtilEventLoopSocketReadDoneEvent ev = {
    .error = ret == SOCKET_ERROR,
    .nbyte = (size_t) ret,
  };
  UTHR_RETURN(ctx,
              ctx->cb(UTIL_EVENT_LOOP_SOCKET_READ_DONE_EVENT,
                      &ev, ctx->cb_ud));

  UTHR_FOOTER();
}

void
util_event_loop_socket_read(event_loop_handle_t loop,
                            socket_t sock,
                            void *buf, size_t nbyte,
                            event_handler_t cb,
                            void *cb_ud) {
  UTHR_CALL6(_util_event_loop_socket_read_uthr, SocketReadCtx,
             .loop = loop,
             .sock = sock,
             .buf = buf,
             .nbyte = nbyte,
             .cb = cb,
             .cb_ud = cb_ud);
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  event_loop_handle_t loop;
  socket_t sock;
  const void *buf;
  size_t nbyte;
  event_handler_t cb;
  void *cb_ud;
  /* state */
  const void *buf_loc;
  size_t count_left;
} SocketWriteCtx;

UTHR_DEFINE(_util_event_loop_write_uthr) {
  UTHR_HEADER(SocketWriteCtx, state);

  state->buf_loc = state->buf;
  state->count_left = state->nbyte;

  socket_ssize_t ret;
  while (state->count_left) {
    ret = send(state->sock, state->buf_loc, state->count_left, 0);
    if (ret == SOCKET_ERROR) {
      if (last_socket_error() == SOCKET_EAGAIN) {
        bool success_watch =
          event_loop_socket_watch_add(state->loop,
                                      state->sock,
                                      create_stream_events(false, true),
                                      _util_event_loop_write_uthr,
                                      state,
                                      NULL);
        if (!success_watch) {
          log_error("Couldn't add fdevent watch!");
          break;
        }
        else {
          UTHR_YIELD(state, 0);
          UTHR_RECEIVE_EVENT(EVENT_LOOP_SOCKET_EVENT, EventLoopSocketEvent, socket_ev);
          if (socket_ev->error) {
            log_error("error during socket watch");
            ret = SOCKET_ERROR;
            break;
          } else continue;
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

  UtilEventLoopSocketWriteDoneEvent ev = {
    .error = state->count_left,
    .nbyte = state->nbyte - state->count_left,
  };
  UTHR_RETURN(state,
              state->cb(UTIL_EVENT_LOOP_SOCKET_WRITE_DONE_EVENT,
                        &ev, state->cb_ud));

  UTHR_FOOTER();
}

void
util_event_loop_socket_write(event_loop_handle_t loop,
                             socket_t sock,
                             const void *buf, size_t nbyte,
                             event_handler_t cb,
                             void *cb_ud) {
  UTHR_CALL6(_util_event_loop_write_uthr, SocketWriteCtx,
             .loop = loop,
             .sock = sock,
             .buf = buf,
             .nbyte = nbyte,
             .cb = cb,
             .cb_ud = cb_ud);
}
