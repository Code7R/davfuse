#ifndef COROUTINE_H
#define COROUTINE_H

#ifdef __GNUC__

/* use gcc label values to jump to our position,
   avoids the switch bounds check */
typedef void * CoroutinePosition;
#define CORO_POS_INIT NULL
#define CRBEGIN(pos) if (likely(pos != NULL)) goto *pos
#define CREND() CORO_END: return false
#define CRHALT(pos) do { pos = &&CORO_END; return false; } while (0)
#define LINEHA2(x,y) x ## y
#define LINEHA(x,y) LINEHA2(x,y)
#define CRYIELDA(pos) do {pos = &&LINEHA(CORO_,__LINE__); return true; LINEHA(CORO_,__LINE__): do { } while(0); } while (0)

#else

typedef int CoroutinePosition;
#define CORO_POS_INIT 0
#define CRBEGIN(pos) switch (pos) { case 0:
#define CREND() case -1:;} return false
#define CRHALT(pos) do { pos = -1; return false;} while(0)
#define CRYIELDA(pos) do { pos = __LINE__; return true; case __LINE__:;} while(0)

#endif

#endif
