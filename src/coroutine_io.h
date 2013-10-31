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

#ifndef COROUTINE_IO_H
#define COROUTINE_IO_H

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c_util.h"
#include "coroutine.h"
#include "events.h"
#include "uthread.h"

enum {
  _FD_BUFFER_BUF_SIZE=4096,
};

typedef void *read_fn_handle_t;

typedef void (*read_fn_t)(read_fn_handle_t handle, void *buf, size_t nbyte,
                          event_handler_t cb, void *ud);

typedef int io_error_t;
enum {
  IO_ERROR_NONE,
  IO_ERROR_GENERAL,
};

typedef struct {
  io_error_t error;
  size_t nbyte;
} IODoneEvent;

typedef IODoneEvent ReadFnDoneEvent;
typedef IODoneEvent WriteFnDoneEvent;

/* used internally */
typedef int io_ret_t;
enum {
  IO_RET_MAX=INT_MAX,
};

typedef struct {
  read_fn_t read_fn;
  read_fn_handle_t handle;
  char *buf_start;
  char *buf_end;
  char buf[_FD_BUFFER_BUF_SIZE];
  bool in_use;
} ReadBuffer;

HEADER_FUNCTION size_t
read_from_fd_buffer(ReadBuffer *f, void *buf, size_t nbyte) {
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
  ReadBuffer *f;
  int *out;
} GetCState;

typedef GetCState PeekState;

typedef bool (*match_function_t)(char);

typedef struct {
  UTHR_CTX_BASE;
  size_t amt_read;
  /* args */
  ReadBuffer *f;
  size_t nbyte;
  void *buf;
  event_handler_t cb;
  void *ud;
} CReadState;

typedef struct {
  int error_number;
  size_t nbyte;
} CReadDoneEvent;

#define _FILL_BUF(ctx, f, ret, _func, _func_ud)                         \
  do {                                                                  \
    assert((f)->buf_start == (f)->buf_end);                             \
    assert(sizeof((f)->buf));						\
    assert(!(f)->in_use);                                               \
                                                                        \
    (f)->buf_start = (f)->buf;                                          \
    (f)->buf_end = (f)->buf;                                            \
    (f)->in_use = true;                                                 \
    UTHR_YIELD(ctx,                                                     \
               (f)->read_fn((f)->handle, (f)->buf, sizeof((f)->buf),    \
                            _func, _func_ud));                          \
    UTHR_RECEIVE_EVENT(READ_FN_DONE_EVENT, ReadFnDoneEvent,             \
                       read_done_ev);                                   \
    assert(read_done_ev->error || read_done_ev->nbyte < IO_RET_MAX);    \
    *(ret) = read_done_ev->error                                        \
      ? -read_done_ev->error                                            \
      : (io_ret_t) read_done_ev->nbyte;                                 \
    if (*(ret) > 0) {                                                   \
      (f)->buf_end = (f)->buf_start + *(ret);                           \
    }                                                                   \
    (f)->in_use = false;                                                \
  }                                                                     \
  while (false)

#define _C_FBPEEK(ctx, f, out, _func, _func_ud, peek)                   \
  do {                                                                  \
    io_ret_t ret;                                                       \
                                                                        \
    assert((peek) || !(f)->in_use);                                     \
                                                                        \
    if ((f)->buf_start < (f)->buf_end) {                                \
      *(out) = (unsigned char) *(f)->buf_start;				\
      (f)->buf_start += (peek) ? 0 : 1;					\
      break;                                                            \
    }                                                                   \
                                                                        \
    _FILL_BUF(ctx, f, &ret, _func, _func_ud);                           \
    if (ret <= 0) {                                                     \
      *(out) = EOF;							\
      break;                                                            \
    }                                                                   \
  }                                                                     \
  while (true)

#define C_FBPEEK(ctx, f, out, _func, _func_ud)	\
  _C_FBPEEK(ctx, f, out, _func, _func_ud, 1)
#define C_FBGETC(ctx, f, out, _func, _func_ud)	\
  _C_FBPEEK(ctx, f, out, _func, _func_ud, 0)

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
c_fbpeek(ReadBuffer *f, int *out,
         event_handler_t cb, void *ud);

void
c_fbgetc(ReadBuffer *f, int *out,
         event_handler_t handler, void *ud);

int
fbgetc(ReadBuffer *f);

int
fbpeek(ReadBuffer *f);

void
c_getwhile(ReadBuffer *f,
           char *buf, size_t buf_size,
           match_function_t match_fn, size_t *parsed,
           event_handler_t cb, void *ud);

void
c_read(ReadBuffer *f,
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
