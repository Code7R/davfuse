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

#ifndef UTHREAD_H
#define UTHREAD_H

#include <stdlib.h>

#include "coroutine.h"
#include "c_util.h"

#define UTHR_DEFINE(name) void name(event_type_t __ev_type, void *__ev, void *__tctx)
#define UTHR_DECLARE(name) UTHR_DEFINE(name)
#define UTHR_EVENT_TYPE() __ev_type
#define UTHR_EVENT() __ev
#define UTHR_USER_DATA() __tctx

#define UTHR_HEADER(type, name) \
  UNUSED(__ev_type);                                                    \
  UNUSED(__ev);                                                         \
  type *const name = __tctx;                                            \
  CRBEGIN(name->__coropos);                                             \
  assert(__ev_type == START_COROUTINE_EVENT)

#define UTHR_FOOTER() CREND()

#define UTHR_YIELD(ctx, ret) CRYIELD(ctx->__coropos, (void) (ret))
#define UTHR_RETURN(ctx, ret) \
  CRRETURN(ctx->__coropos,                                              \
           ((void) ret, free(ctx)))
#define UTHR_FREE(ctx) free(ctx)

#define UTHR_RUN(coro, ctx)                     \
  do {                                          \
    ctx->__coropos = CORO_POS_INIT;             \
    coro(START_COROUTINE_EVENT, NULL, ctx);     \
  }                                             \
  while (false)

#define UTHR_CTX_BASE coroutine_position_t __coropos

#define UTHR_CALL(fn, type, init)               \
  do {                                          \
    type *const __ctx = malloc(sizeof(*__ctx)); \
    if (!__ctx) { abort(); }                    \
    *__ctx = init;                              \
    UTHR_RUN(fn, __ctx);                        \
  }                                             \
  while (false)

#define _UTHR_CALL(fn, type, ...)               \
  do {                                          \
    type *const __ctx = malloc(sizeof(*__ctx)); \
    if (!__ctx) { abort(); }                    \
    *__ctx = (type) {__VA_ARGS__};              \
    UTHR_RUN(fn, __ctx);                        \
  }                                             \
  while (false)

#define UTHR_CALL1(...) _UTHR_CALL(__VA_ARGS__)
#define UTHR_CALL2(...) _UTHR_CALL(__VA_ARGS__)
#define UTHR_CALL3(...) _UTHR_CALL(__VA_ARGS__)
#define UTHR_CALL4(...) _UTHR_CALL(__VA_ARGS__)
#define UTHR_CALL5(...) _UTHR_CALL(__VA_ARGS__)
#define UTHR_CALL6(...) _UTHR_CALL(__VA_ARGS__)
#define UTHR_CALL7(...) _UTHR_CALL(__VA_ARGS__)
#define UTHR_CALL8(...) _UTHR_CALL(__VA_ARGS__)
#define UTHR_CALL9(...) _UTHR_CALL(__VA_ARGS__)
#define UTHR_CALLA(...) _UTHR_CALL(__VA_ARGS__)

#define UTHR_RECEIVE_EVENT(ev_type, type, name) type *name = (assert(ev_type == UTHR_EVENT_TYPE()), UTHR_EVENT())

#define UTHR_SUBCALL(ctx, fn, ev_type, type, name) \
  UTHR_YIELD(ctx, fn);                             \
  UTHR_RECEIVE_EVENT(ev_type, type, name)


#endif /* UTHREAD_H */
