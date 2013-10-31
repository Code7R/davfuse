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

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "coroutine.h"
#include "coroutine_io.h"
#include "events.h"
#include "logging.h"
#include "uthread.h"

int
fbgetc(ReadBuffer *f) {
  int ret;
  FBGETC(f, &ret);
  return ret;
}

int
fbpeek(ReadBuffer *f) {
  int ret;
  FBPEEK(f, &ret);
  return ret;
}

static
UTHR_DEFINE(_c_fbgetc) {
  UTHR_HEADER(GetCState, state);
  C_FBGETC(state, state->f, state->out, _c_fbgetc, state);
  UTHR_RETURN(state, state->cb(C_FBGETC_DONE_EVENT, NULL, state->ud));
  UTHR_FOOTER();
}

void
c_fbgetc(ReadBuffer *f, int *out,
         event_handler_t handler, void *ud) {
  UTHR_CALL5(_c_fbgetc, GetCState,
             .f = f,
             .out = out,
             .cb = handler,
             .ud = ud);
}

static
UTHR_DEFINE(_c_fbpeek) {
  UTHR_HEADER(PeekState, state);
  C_FBPEEK(state, state->f, state->out, _c_fbpeek, state);
  UTHR_RETURN(state, state->cb(C_FBPEEK_DONE_EVENT, NULL, state->ud));
  UTHR_FOOTER();
}

void
c_fbpeek(ReadBuffer *f, int *out,
         event_handler_t cb, void *ud) {
  UTHR_CALL5(_c_fbpeek, PeekState,
             .f = f,
             .out = out,
             .cb = cb,
             .ud = ud);
}

void
fbungetc(ReadBuffer *f, int c) {
  f->buf_start -= 1;
  *f->buf_start = c;
}

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  event_handler_t cb;
  void *ud;
  ReadBuffer *f;
  char *buf;
  size_t buf_size;
  match_function_t match_fn;
  size_t *out;
  /* state */
  char *buf_end;
  int peeked_char;
} GetWhileState;

static
UTHR_DEFINE(_c_getwhile) {
  UTHR_HEADER(GetWhileState, state);
  state->buf_end = state->buf;
  *state->out = 0;

  /* find terminator in existing buffer */
  do {
    /* we only call fbgetc in one place here, so we force an inline */
    C_FBGETC(state, state->f, &state->peeked_char, _c_getwhile, state);
    if (state->peeked_char == EOF) {
      break;
    }

    /* pain! we make an indirect function call here to accomodate multiple uses
       it definitely slows done this loop,
       maybe we can optimized this in the future */
    if (!(*state->match_fn)(state->peeked_char)) {
      fbungetc(state->f, state->peeked_char);
      break;
    }

    if (state->buf_end < state->buf + state->buf_size) {
      *state->buf_end++ = state->peeked_char;
    }

    *state->out +=1;
  }
  while (true);

  UTHR_RETURN(state, state->cb(C_GETWHILE_DONE_EVENT, NULL, state->ud));

  UTHR_FOOTER();
}

void
c_getwhile(ReadBuffer *f,
           char *buf, size_t buf_size,
           match_function_t match_fn, size_t *parsed,
           event_handler_t cb, void *ud) {
  UTHR_CALL8(_c_getwhile, GetWhileState,
             .f = f,
             .buf = buf,
             .buf_size = buf_size,
             .match_fn = match_fn,
             .out = parsed,
             .cb = cb,
             .ud = ud);
}

static
UTHR_DEFINE(_c_read) {
  UTHR_HEADER(CReadState, state);
  bool error;

  state->amt_read = 0;
  error = false;
  while (state->nbyte != state->amt_read) {
    /* fill fdbuffer if we need to */
    if (state->f->buf_end == state->f->buf_start) {
      io_ret_t ret;
      _FILL_BUF(state, state->f, &ret, _c_read, state);
      if (ret <= 0) {
        error = true;
        break;
      }
      error = false;
    }

    /* copy in buffer from fdbuffer */
    assert(state->f->buf_end >= state->f->buf_start);
    assert(state->nbyte > state->amt_read);
    state->amt_read += read_from_fd_buffer(state->f, state->buf + state->amt_read,
                                           state->nbyte - state->amt_read);
  }

  CReadDoneEvent read_done_ev = {
    .error_number = error ? 1 : 0,
    .nbyte = state->amt_read,
  };
  UTHR_RETURN(state, state->cb(C_READ_DONE_EVENT, &read_done_ev, state->ud));

  UTHR_FOOTER();
}

void
c_read(ReadBuffer *f,
       void *buf, size_t nbyte,
       event_handler_t cb, void *ud) {
  UTHR_CALL6(_c_read, CReadState,
             .f = f,
             .buf = buf,
             .nbyte = nbyte,
             .cb = cb,
             .ud = ud);
}
