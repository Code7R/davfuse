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
#include <stdlib.h>
#include <string.h>

#include "c_util.h"
#include "coroutine.h"
#include "events.h"
#include "fdevent.h"
#include "uthread.h"

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
  UTHR_CTX_BASE;
  /* args */
  event_handler_t cb;
  void *ud;
  FDEventLoop *loop;
  FDBuffer *f;
  int *out;
} GetCState;

typedef GetCState PeekState;

typedef bool (*match_function_t)(char);

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  event_handler_t cb;
  void *ud;
  FDEventLoop *loop;
  FDBuffer *f;
  char *buf;
  size_t buf_size;
  match_function_t match_fn;
  size_t *out;
  /* state */
  char *buf_end;
  int peeked_char;
} GetWhileState;

typedef struct {
  UTHR_CTX_BASE;
  size_t amt_read;
  /* args */
  FDEventLoop *loop;
  FDBuffer *f;
  size_t nbyte;
  void *buf;
  event_handler_t cb;
  void *ud;
} CReadState;

typedef struct {
  int error_number;
  size_t nbyte;
} CReadDoneEvent;

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  FDEventLoop *loop;
  int fd;
  const void *buf;
  size_t count;
  ssize_t *ret;
  event_handler_t cb;
  void *ud;
  /* state */
  const void *buf_loc;
  size_t count_left;
} WriteAllState;

typedef struct {
  int error_number;
  size_t nbyte;
} CWriteAllDoneEvent;

#define _FILL_BUF(ctx, loop, f, ret, _func, _func_ud)                   \
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
        bool __ret = fdevent_add_watch(loop, (f)->fd,                     \
                                       create_stream_events(true, false), \
                                       _func, _func_ud, NULL);          \
        if (!__ret) { abort(); };                                       \
        UTHR_YIELD(ctx, 0);                                             \
        assert(UTHR_EVENT_TYPE() == FD_EVENT);                          \
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

#define _C_FBPEEK(ctx, loop, f, out, _func, _func_ud, peek)		\
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
    _FILL_BUF(ctx, loop, f, &ret, _func, _func_ud);                     \
    if (ret <= 0) {                                                     \
      *(out) = EOF;							\
      break;                                                            \
    }                                                                   \
  }                                                                     \
  while (true)

#define C_FBPEEK(ctx, loop, f, out, _func, _func_ud)	\
  _C_FBPEEK(ctx, loop, f, out, _func, _func_ud, 1)
#define C_FBGETC(ctx, loop, f, out, _func, _func_ud)	\
  _C_FBPEEK(ctx, loop, f, out, _func, _func_ud, 0)

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
c_fbpeek(FDEventLoop *loop, FDBuffer *f, int *out,
         event_handler_t cb, void *ud);
void
c_fbgetc(FDEventLoop *loop, FDBuffer *f, int *out,
         event_handler_t handler, void *ud);
int
fbgetc(FDBuffer *f);
int
fbpeek(FDBuffer *f);
void
c_getwhile(FDEventLoop *loop, FDBuffer *f,
           char *buf, size_t buf_size,
           match_function_t match_fn, size_t *parsed,
           event_handler_t cb, void *ud);
void
c_write_all(FDEventLoop *loop,
            int fd,
            const void *buf,
            size_t nbyte,
            event_handler_t cb,
            void *cb_ud);
void
c_read(FDEventLoop *loop, FDBuffer *f,
       void *buf, size_t nbyte,
       event_handler_t cb, void *ud);

HEADER_FUNCTION CONST_FUNCTION bool
match_separator(char c) {
  static const char separators[] = "()<>@,;:\\/[]?={} \t";

  for (size_t i = 0; i < sizeof(separators) - 1; ++i) {
    if (c == separators[i]) {
      return true;
    }
  }

  return false;
}

HEADER_FUNCTION CONST_FUNCTION bool
match_token(char c) {
  /* token          = 1*<any CHAR except CTLs or separators> */
  return (32 < c && c < 127 && !match_separator(c));
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

HEADER_FUNCTION CONST_FUNCTION bool
match_hex_digit(char c) {
  return (('0' <= c && c <= '9') ||
          ('a' <= c && c <= 'f') ||
          ('A' <= c && c <= 'F'));
}

#endif /* COROUTINE_IO_H */
