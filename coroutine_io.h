#ifndef COROUTINE_IO_H
#define COROUTINE_IO_H

#include <errno.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "c_util.h"
#include "coroutine.h"
#include "events.h"
#include "fdevent.h"

#define BUF_SIZE 4096

typedef struct {
  int fd;
  char *buf_start;
  char *buf_end;
  char buf[BUF_SIZE];
} FDBuffer;

typedef struct {
  coroutine_position_t coropos;
  /* args */
  event_handler_t cb;
  void *ud;
  FDEventLoop *loop;
  FDBuffer *f;
  int *out;
  /* state */
} GetCState;

typedef GetCState PeekState;

HEADER_FUNCTION void
init_c_fbgetc_state(GetCState *state,
                    FDEventLoop *loop, FDBuffer *f, int *out,
                    event_handler_t cb, void *ud) {
  *state = (GetCState) {
    .coropos = CORO_POS_INIT,
    .loop = loop,
    .f = f,
    .out = out,
    .cb = cb,
    .ud = ud,
  };
}

HEADER_FUNCTION void
init_c_fbpeek_state(PeekState *state,
                    FDEventLoop *loop, FDBuffer *f, int *out,
                    event_handler_t cb, void *ud) {
  return init_c_fbgetc_state(state, loop, f, out, cb, ud);
}

typedef bool (*match_function_t)(char);

typedef struct {
  coroutine_position_t coropos;
  /* args */
  event_handler_t cb;
  void *ud;
  FDEventLoop *loop;
  FDBuffer *f;
  char *buf;
  size_t buf_size;
  bool (*match_fn)(char);
  size_t *out;
  /* state */
  char *buf_end;
  int peeked_char;
} GetWhileState;

HEADER_FUNCTION void
init_c_getwhile_state(GetWhileState *state,
                      FDEventLoop *loop, FDBuffer *f,
                      char *buf, size_t buf_size,
                      match_function_t match_fn, size_t *parsed,
                      event_handler_t cb, void *ud) {
  *state = (GetWhileState) {
    .loop = loop,
    .f = f,
    .buf = buf,
    .buf_size = buf_size,
    .match_fn = match_fn,
    .out = parsed,
    .cb = cb,
    .ud = ud,
  };
}

typedef struct {
  coroutine_position_t coropos;
  const void *buf_loc;
  size_t count_left;
  /* args */
  FDEventLoop *loop;
  int fd;
  const void *buf;
  size_t count;
  ssize_t *ret;
  event_handler_t cb;
  void *ud;
} WriteAllState;

#define _C_FBPEEK(coropos, loop, f, out, _func, _func_ud, peek)		\
  do {                                                                  \
    ssize_t ret;                                                        \
    									\
    if (f->buf_start < f->buf_end) {					\
      *out = (unsigned char) *f->buf_start;				\
      f->buf_start += peek ? 1 : 0;					\
      break;                                                            \
    }                                                                   \
                                                                        \
    assert(f->buf_start == f->buf_end);					\
    assert(sizeof(f->buf));						\
                                                                        \
    ret = read(f->fd, f->buf,						\
               sizeof(f->buf));						\
    if (ret < 0 && errno == EAGAIN) {                                   \
      CRYIELD(coropos,							\
              fdevent_add_watch(loop,					\
                                f->fd,					\
                                create_stream_events(true, false),      \
                                _func,                                  \
                                _func_ud,                               \
                                NULL));                                 \
      continue;                                                         \
    }                                                                   \
    else if (ret <= 0) {                                                \
      *out = EOF;							\
      break;                                                            \
    }                                                                   \
                                                                        \
    f->buf_start = f->buf;						\
    f->buf_end = f->buf + ret;						\
  }                                                                     \
  while (true)

#define C_FBPEEK(coropos, loop, f, out, _func, _func_ud)	\
  _C_FBPEEK(coropos, loop, f, out, _func, _func_ud, 0)
#define C_FBGETC(coropos, loop, f, out, _func, _func_ud)	\
  _C_FBPEEK(coropos, loop, f, out, _func, _func_ud, 1)

void
c_fbpeek(event_type_t ev_type, void *ev, void *ud);
void
c_getwhile(event_type_t ev_type, void *ev, void *ud);
void
c_fbgetc(event_type_t ev_type, void *ev, void *ud);
void
c_write_all(event_type_t ev_type, void *ev, void *ud);

HEADER_FUNCTION CONST_FUNCTION bool
match_seperator(char c) {
#define N(l) l == c ||
  /* these are lots of independent checks but the CPU should plow through
     this since it's not a loop and doesn't access memory */
  return (N('(') N(')') N('<') N('>') N('@') N(',') N(';') N(':')
          N('\\') N('/') N('[') N(']') N('?') N('=') N('{') N('}')
          N(' ') '\t' == c);
#undef N
}

HEADER_FUNCTION CONST_FUNCTION bool
match_token(char c) {
  /* token          = 1*<any CHAR except CTLs or separators> */
  return (32 < c && c < 127 && !match_seperator(c));
}

HEADER_FUNCTION CONST_FUNCTION bool
match_non_null_or_space(char c) {
  return c && c != ' ';
}

HEADER_FUNCTION CONST_FUNCTION bool
match_non_null_or_colon(char c) {
  return c && c != ':';
}

HEADER_FUNCTION CONST_FUNCTION bool
match_non_null_or_carriage_return(char c) {
  return c && c != '\r';
}

HEADER_FUNCTION CONST_FUNCTION bool
match_digit(char c) {
  return '0' <= c && c <= '9';
}

#endif /* COROUTINE_IO_H */
