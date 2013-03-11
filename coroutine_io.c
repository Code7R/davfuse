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
  UNUSED(ev);
  CRBEGIN(state->coropos);
  assert(ev_type == START_COROUTINE_EVENT);
  C_FBGETC(state->coropos, state->loop, state->f, state->out, c_fbgetc, state);
  CRRETURN(state->coropos, state->cb(C_FBGETC_DONE_EVENT, NULL, state->ud));
  CREND();
}

void
c_fbpeek(event_type_t ev_type, void *ev, void *ud) {
  PeekState *state = ud;
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
  GetWhileState *state = ud;
  UNUSED(ev);
  CRBEGIN(state->coropos);
  assert(ev_type == START_COROUTINE_EVENT);
  state->buf_end = state->buf;

  /* find terminator in existing buffer */
  do {
    /* we only call fbgetc in one place here, so we force an inline */
    C_FBGETC(state->coropos, state->loop, state->f, &state->peeked_char, c_getwhile, state);

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

  *state->out = state->buf_end - state->buf;

  CRRETURN(state->coropos, state->cb(C_GETWHILE_DONE_EVENT, NULL, state->ud));
  
  CREND();
}

void
c_write_all(event_type_t ev_type, void *ev, void *ud) {
  WriteAllState *state = ud;
  UNUSED(ev);
  CRBEGIN(state->coropos);

  assert(ev_type == START_COROUTINE_EVENT);

  state->buf_loc = state->buf;
  state->count_left = state->count;

  while (state->count_left) {
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
        continue;
      }
      else {
        assert(state->count >= state->count_left);
        *state->ret = state->count - state->count_left;
      }
    }

    assert(state->count_left >= (size_t) ret2);
    state->count_left -= ret2;
    state->buf_loc += ret2;
  }

  *state->ret = 0;

  CRRETURN(state->coropos, state->cb(C_WRITEALL_DONE_EVENT, NULL, state->ud));

  CREND();
}
