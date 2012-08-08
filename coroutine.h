#ifndef COROUTINE_H
#define COROUTINE_H

#ifdef __GNUC__

/* use gcc label values to jump to our position,
   avoids the switch bounds check */
typedef void *coroutine_position_t;
#define CORO_POS_INIT NULL
#define CRBEGIN(pos) if (pos) goto *pos
/* we have the inline goto CORO_END to suppress compiler warnings */
#define CREND() do {goto CORO_END; CORO_END: return true;} while (0)
#define CRHALT(pos) do {pos = &&CORO_END; return false;} while (0)
#define LINEHA2(x,y) x ## y
#define LINEHA(x,y) LINEHA2(x,y)
#define CRYIELDA(pos) do { pos = &&LINEHA(CORO_,__LINE__); return true; LINEHA(CORO_,__LINE__): if (0) {}} while (0)

#else

typedef int coroutine_position_t;
#define CORO_POS_INIT 0
#define CRBEGIN(pos) switch (pos) { case 0:
#define CREND() case -1:;} return false
#define CRHALT(pos) do { pos = -1; return false;} while(0)
#define CRYIELDA(pos) do { pos = __LINE__; return true; case __LINE__:;} while(0)

#endif

#define CRYIELD CRYIELDA

#endif
