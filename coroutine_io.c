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

void
c_fbgetc(event_type_t ev_type, void *ev, void *ud) {
  GetCState *state = ud;
  UNUSED(ev_type);
  UNUSED(ev);
  CRBEGIN(state->coropos);
  assert(ev_type == START_COROUTINE_EVENT);
  C_FBGETC(state->coropos, state->loop, state->f, state->out, c_fbgetc, state);
  CRRETURN(state->coropos, state->cb(C_FBGETC_DONE_EVENT, NULL, state->ud));
  CREND();
}

void
c_fbpeek(event_type_t ev_type, void *ev, void *ud) {
  /* set before CRBEGIN */
  PeekState *state = ud;
  UNUSED(ev_type);
  UNUSED(ev);
  CRBEGIN(state->coropos);
  assert(ev_type == START_COROUTINE_EVENT);
  C_FBPEEK(state->coropos, state->loop, state->f, state->out, c_fbpeek, state);
  CRRETURN(state->coropos, state->cb(C_FBPEEK_DONE_EVENT, NULL, state->ud));
  CREND();
}

void
fbungetc(FDBuffer *f, int c) {
  f->buf_start -= 1;
  *f->buf_start = c;
}

void
c_getwhile(event_type_t ev_type, void *ev, void *ud) {
  /* set before CRBEGIN */
  GetWhileState *state = ud;
  UNUSED(ev_type);
  UNUSED(ev);
  CRBEGIN(state->coropos);
  assert(ev_type == START_COROUTINE_EVENT);
  state->buf_end = state->buf;

  /* find terminator in existing buffer */
  do {
    /* we only call fbgetc in one place here, so we force an inline */
    C_FBGETC(state->coropos, state->loop, state->f, &state->peeked_char,
	     c_getwhile, state);
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

  CRRETURN(state->coropos, state->cb(C_GETWHILE_DONE_EVENT, NULL, state->ud));

  CREND();
}

void
c_read(event_type_t ev_type, void *ev, void *ud) {
  CReadState *state = ud;
  int myerrno;
  CRBEGIN(state->coropos);

  assert(ev_type == START_COROUTINE_EVENT);
  UNUSED(ev_type);
  UNUSED(ev);

  state->amt_read = 0;
  myerrno = 0;
  while (state->nbyte != state->amt_read) {
    /* fill fdbuffer if we need to */
    if (state->f->buf_end == state->f->buf_start) {
      ssize_t ret;
      _FILL_BUF(state->coropos, state->loop, state->f, &ret, c_read, state);
      if (ret <= 0) {
        myerrno = (ret < 0) ? errno : 0;
        break;
      }
      myerrno = 0;
    }

    /* copy in buffer from fdbuff */
    assert(state->f->buf_end >= state->f->buf_start);
    assert(state->nbyte > state->amt_read);
    size_t to_copy = read_from_fd_buffer(state->f, state->buf + state->amt_read,
                                         state->nbyte - state->amt_read);
    state->amt_read += to_copy;
  }

  CReadDoneEvent read_done_ev = {
    .error_number = myerrno,
    .nbyte = state->amt_read,
  };
  CRRETURN(state->coropos, state->cb(C_READ_DONE_EVENT, &read_done_ev, state->ud));

  CREND();
}

void
c_write_all(event_type_t ev_type, void *ev, void *ud) {
  /* set before CRBEGIN */
  WriteAllState *state = ud;
  int myerrno;

  UNUSED(ev_type);
  UNUSED(ev);
  CRBEGIN(state->coropos);

  assert(ev_type == START_COROUTINE_EVENT);

  state->buf_loc = state->buf;
  state->count_left = state->count;

  while (state->count_left) {
    myerrno = 0;
    ssize_t ret2 = write(state->fd, state->buf_loc, state->count_left);
    if (ret2 < 0) {
      if (errno == EAGAIN) {
        CRYIELD(state->coropos,
		fdevent_add_watch(state->loop,
				  state->fd,
				  create_stream_events(false, true),
				  c_write_all,
				  state,
				  NULL));
        assert(ev_type == FD_EVENT);
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
  CRRETURN(state->coropos,
           state->cb(C_WRITEALL_DONE_EVENT,
                     &c_write_all_done_ev,
                     state->ud));

  CREND();
}
