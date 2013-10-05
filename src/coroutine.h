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

#ifndef COROUTINE_H
#define COROUTINE_H

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

#ifdef __GNUC__

/* use gcc label values to jump to our position,
   avoids the switch bounds check */
typedef void *coroutine_position_t;
#define CORO_POS_INIT NULL
#define CRBEGIN(pos) if (pos) goto *pos
/* we have the inline "goto CORO_END" to suppress compiler warnings */
#define CREND() do {goto CORO_END; CORO_END: abort();} while (false)
#define CRRETURN(pos, ret) do {pos = &&CORO_END; return ret;} while (false)
#define LINEHA2(x, y) x ## y
#define LINEHA(x, y) LINEHA2(x, y)
#define CRYIELDA(pos, ret)						\
  do {									\
    pos = &&LINEHA(CORO_, __LINE__);					\
    /* the return is signficant, otherwise gcc won't do tail-call */    \
    return ret;                                                         \
  LINEHA(CORO_, __LINE__):						\
    if (false) {}							\
  } while (false)

#else

typedef int coroutine_position_t;
enum {
  CORO_POS_INIT=0,
};
#define CRBEGIN(pos) switch (pos) { case 0:
#define CREND() case -1: abort();}
#define CRHALT(pos) do { pos = -1; return; } while (false)
#define CRYIELDA(pos, ret) do { pos = __LINE__; return (void) (ret); case __LINE__:; } while (false)
#define CRRETURN(pos, ret) do {pos = -1; (void) ret; return; } while (false)

#endif

#define CRYIELD CRYIELDA

#endif
