#include <errno.h>
#include <unistd.h>

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
fbgetc(FDBuffer *f) {
  int ret;
  FBGETC(f, &ret);
  return ret;
}

int
fbpeek(FDBuffer *f) {
  int ret;
  FBPEEK(f, &ret);
  return ret;
}

static
UTHR_DEFINE(_c_fbgetc) {
  UTHR_HEADER(GetCState, state);
  C_FBGETC(state, state->loop, state->f, state->out, _c_fbgetc, state);
  UTHR_RETURN(state, state->cb(C_FBGETC_DONE_EVENT, NULL, state->ud));
  UTHR_FOOTER();
}

void
c_fbgetc(FDEventLoop *loop, FDBuffer *f, int *out,
         event_handler_t handler, void *ud) {
  UTHR_CALL5(_c_fbgetc, GetCState,
             .loop = loop,
             .f = f,
             .out = out,
             .cb = handler,
             .ud = ud);
}

static
UTHR_DEFINE(_c_fbpeek) {
  UTHR_HEADER(PeekState, state);
  C_FBPEEK(state, state->loop, state->f, state->out, _c_fbpeek, state);
  UTHR_RETURN(state, state->cb(C_FBPEEK_DONE_EVENT, NULL, state->ud));
  UTHR_FOOTER();
}

void
c_fbpeek(FDEventLoop *loop, FDBuffer *f, int *out,
         event_handler_t cb, void *ud) {
  UTHR_CALL5(_c_fbpeek, PeekState,
             .loop = loop,
             .f = f,
             .out = out,
             .cb = cb,
             .ud = ud);
}

void
fbungetc(FDBuffer *f, int c) {
  f->buf_start -= 1;
  *f->buf_start = c;
}

static
UTHR_DEFINE(_c_getwhile) {
  UTHR_HEADER(GetWhileState, state);
  state->buf_end = state->buf;

  /* find terminator in existing buffer */
  do {
    /* we only call fbgetc in one place here, so we force an inline */
    C_FBGETC(state, state->loop, state->f, &state->peeked_char,
	     _c_getwhile, state);
    if (state->peeked_char == EOF) {
      log_error_errno("Error while expecting a character");
      break;
    }

    /* pain! we make an indirect function call here to accomodate multiple uses
       it definitely slows done this loop,
       maybe we can optimized this in the future */
    if (!(*state->match_fn)(state->peeked_char)) {
      fbungetc(state->f, state->peeked_char);
      break;
    }

    *state->buf_end++ = state->peeked_char;
  }
  while (state->buf_end < state->buf + state->buf_size);

  /* TODO: move this to event finish, also errors */
  *state->out = state->buf_end - state->buf;

  UTHR_RETURN(state, state->cb(C_GETWHILE_DONE_EVENT, NULL, state->ud));

  UTHR_FOOTER();
}

void
c_getwhile(FDEventLoop *loop, FDBuffer *f,
           char *buf, size_t buf_size,
           match_function_t match_fn, size_t *parsed,
           event_handler_t cb, void *ud) {
  UTHR_CALL8(_c_getwhile, GetWhileState,
             .loop = loop,
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
  int myerrno;

  state->amt_read = 0;
  myerrno = 0;
  while (state->nbyte != state->amt_read) {
    /* fill fdbuffer if we need to */
    if (state->f->buf_end == state->f->buf_start) {
      ssize_t ret;
      _FILL_BUF(state, state->loop, state->f, &ret, _c_read, state);
      if (ret <= 0) {
        myerrno = (ret < 0) ? errno : 0;
        break;
      }
      myerrno = 0;
    }

    /* copy in buffer from fdbuffer */
    assert(state->f->buf_end >= state->f->buf_start);
    assert(state->nbyte > state->amt_read);
    state->amt_read += read_from_fd_buffer(state->f, state->buf + state->amt_read,
                                           state->nbyte - state->amt_read);
  }

  CReadDoneEvent read_done_ev = {
    .error_number = myerrno,
    .nbyte = state->amt_read,
  };
  UTHR_RETURN(state, state->cb(C_READ_DONE_EVENT, &read_done_ev, state->ud));

  UTHR_FOOTER();
}

void
c_read(FDEventLoop *loop, FDBuffer *f,
       void *buf, size_t nbyte,
       event_handler_t cb, void *ud) {
  UTHR_CALL6(_c_read, CReadState,
             .loop = loop,
             .f = f,
             .buf = buf,
             .nbyte = nbyte,
             .cb = cb,
             .ud = ud);
}

UTHR_DEFINE(_c_write_all) {
  UTHR_HEADER(WriteAllState, state);
  int myerrno;

  state->buf_loc = state->buf;
  state->count_left = state->count;

  while (state->count_left) {
    myerrno = 0;
    ssize_t ret2 = write(state->fd, state->buf_loc, state->count_left);
    if (ret2 < 0) {
      if (errno == EAGAIN) {
        bool ret = fdevent_add_watch(state->loop,
                                     state->fd,
                                     create_stream_events(false, true),
                                     _c_write_all,
                                     state,
                                     NULL);
        if (!ret) { abort(); }
        UTHR_YIELD(state, 0);
        assert(UTHR_EVENT_TYPE() == FD_EVENT);
        continue;
      }
      else {
        myerrno = errno;
        break;
      }
    }

    assert(state->count_left >= (size_t) ret2);
    state->count_left -= ret2;
    state->buf_loc += ret2;
  }

  CWriteAllDoneEvent c_write_all_done_ev = {
    .error_number = myerrno,
    .nbyte = state->count - state->count_left,
  };
  UTHR_RETURN(state,
              state->cb(C_WRITEALL_DONE_EVENT,
                        &c_write_all_done_ev,
                        state->ud));
  UTHR_FOOTER();
}

void
c_write_all(FDEventLoop *loop,
            int fd,
            const void *buf,
            size_t nbyte,
            event_handler_t cb,
            void *cb_ud) {
  UTHR_CALL6(_c_write_all, WriteAllState,
             .loop = loop,
             .fd = fd,
             .buf = buf,
             .count = nbyte,
             .cb = cb,
             .ud = cb_ud);
}
