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
#include <string.h>

#include "c_util.h"
#include "coroutine.h"
#include "events.h"
#include "fdevent.h"

enum {
  _FD_BUFFER_BUF_SIZE=4096,
};

typedef struct {
  int fd;
  char *buf_start;
  char *buf_end;
  char buf[_FD_BUFFER_BUF_SIZE];
  bool in_use;
} FDBuffer;

HEADER_FUNCTION size_t
read_from_fd_buffer(FDBuffer *f, void *buf, size_t nbyte) {
  assert(!f->in_use);
  size_t to_copy = MIN((size_t) (f->buf_end - f->buf_start), nbyte);
  memmove(buf, f->buf_start, to_copy);
  f->buf_start += to_copy;
  return to_copy;
}

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

typedef struct {
  coroutine_position_t coropos;
  size_t amt_read;
  /* args */
  FDEventLoop *loop;
  FDBuffer *f;
  size_t nbyte;
  void *buf;
  event_handler_t cb;
  void *ud;
} CReadState;

HEADER_FUNCTION void
init_c_read_state(CReadState *state,
                  FDEventLoop *loop, FDBuffer *f,
                  void *buf, size_t nbyte,
                  event_handler_t cb, void *ud) {
  *state = (CReadState) {
    .coropos = CORO_POS_INIT,
    .loop = loop,
    .f = f,
    .buf = buf,
    .nbyte = nbyte,
    .cb = cb,
    .ud = ud,
  };
}

typedef struct {
  int error_number;
  size_t nbyte;
} CReadDoneEvent;

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

HEADER_FUNCTION void
init_c_write_all_state(WriteAllState *state,
                       FDEventLoop *loop,
                       int fd,
                       const void *buf,
                       size_t nbyte,
                       event_handler_t cb,
                       void *cb_ud) {
  *state = (WriteAllState) {
    .coropos = CORO_POS_INIT,
    .loop = loop,
    .fd = fd,
    .buf = buf,
    .count = nbyte,
    .cb = cb,
    .ud = cb_ud,
  };
}

typedef struct {
  int error_number;
  size_t nbyte;
} CWriteAllDoneEvent;

#define _FILL_BUF(coropos, loop, f, ret, _func, _func_ud)               \
  do {                                                                  \
    assert((f)->buf_start == (f)->buf_end);                             \
    assert(sizeof((f)->buf));						\
    assert(!(f)->in_use);                                               \
                                                                        \
    (f)->buf_start = (f)->buf;                                          \
    (f)->buf_end = (f)->buf;                                            \
    (f)->in_use = true;                                                 \
    while (true) {							\
      *(ret) = read((f)->fd, (f)->buf, sizeof((f)->buf));               \
      if (*(ret) < 0 && errno == EAGAIN) {                              \
        CRYIELD(coropos,                                                \
                fdevent_add_watch(loop, (f)->fd,                        \
                                  create_stream_events(true, false),    \
                                  _func, _func_ud, NULL));              \
        continue;                                                       \
      }                                                                 \
      if (*(ret) > 0) {                                                 \
        (f)->buf_end = (f)->buf_start + *(ret);                         \
      }                                                                 \
      break;								\
    }                                                                   \
    (f)->in_use = false;                                                \
  }                                                                     \
  while (false)

#define _C_FBPEEK(coropos, loop, f, out, _func, _func_ud, peek)		\
  do {                                                                  \
    ssize_t ret;                                                        \
                                                                        \
    assert((peek) || !(f)->in_use);                                     \
                                                                        \
    if ((f)->buf_start < (f)->buf_end) {                                \
      *(out) = (unsigned char) *(f)->buf_start;				\
      (f)->buf_start += (peek) ? 0 : 1;					\
      break;                                                            \
    }                                                                   \
                                                                        \
    _FILL_BUF(coropos, loop, f, &ret, _func, _func_ud);                 \
    if (ret <= 0) {                                                     \
      *(out) = EOF;							\
      break;                                                            \
    }                                                                   \
  }                                                                     \
  while (true)

#define C_FBPEEK(coropos, loop, f, out, _func, _func_ud)	\
  _C_FBPEEK(coropos, loop, f, out, _func, _func_ud, 1)
#define C_FBGETC(coropos, loop, f, out, _func, _func_ud)	\
  _C_FBPEEK(coropos, loop, f, out, _func, _func_ud, 0)

#define _FBPEEK(f, out, peek)                                           \
  do {                                                                  \
    assert((peek) || !(f)->in_use);                                     \
    if ((f)->buf_start < (f)->buf_end) {                                \
      *(out) = (unsigned char) *(f)->buf_start;				\
      (f)->buf_start += (peek) ? 0 : 1;					\
    }                                                                   \
    else {                                                              \
      *(out) = -1;                                                      \
    }                                                                   \
  }                                                                     \
  while (false)

#define FBPEEK(f, out) _FBPEEK(f, out, 1)
#define FBGETC(f, out) _FBPEEK(f, out, 0)

void
c_fbpeek(event_type_t ev_type, void *ev, void *ud);
void
c_fbgetc(event_type_t ev_type, void *ev, void *ud);
int
fbgetc(FDBuffer *f);
int
fbpeek(FDBuffer *f);
void
c_getwhile(event_type_t ev_type, void *ev, void *ud);
void
c_write_all(event_type_t ev_type, void *ev, void *ud);
void
c_read(event_type_t ev_type, void *ev, void *ud);

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
