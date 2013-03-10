#ifndef COROUTINE_H
#define COROUTINE_H

#include <assert.h>
#include <stddef.h>

#ifdef __GNUC__

/* use gcc label values to jump to our position,
   avoids the switch bounds check */
typedef void *coroutine_position_t;
#define CORO_POS_INIT NULL
#define CRBEGIN(pos) if (pos) goto *pos
/* we have the inline "goto CORO_END" to suppress compiler warnings */
#define CREND() do {goto CORO_END; CORO_END: assert(false); return;} while (false)
#define CRRETURN(pos, ret) do {pos = &&CORO_END; (void) ret; return;} while (false)
#define LINEHA2(x, y) x ## y
#define LINEHA(x, y) LINEHA2(x, y)
#define CRYIELDA(pos, ret)						\
  do {									\
    pos = &&LINEHA(CORO_, __LINE__);					\
    (void) ret;								\
    return;								\
  LINEHA(CORO_, __LINE__):						\
    if (false) {}							\
  } while (false)

#else

typedef int coroutine_position_t;
#define CORO_POS_INIT 0
#define CRBEGIN(pos) switch (pos) { case 0:
#define CREND() case -1:;} return
#define CRHALT(pos) do { pos = -1; return;} while(false)
#define CRYIELDA(pos, ret) do { pos = __LINE__; (void) ret; return; case __LINE__:;} while(false)
#define CRRETURN(pos, ret) do {pos = -1; (void) ret; return;} while (false)

#endif

#define CRYIELD CRYIELDA

typedef void (*coroutine_t)(void *);

#endif
