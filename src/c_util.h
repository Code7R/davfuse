#ifndef C_UTIL_H
#define C_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#define UNUSED(x) ((void)(x))
#define NELEMS(arr) (sizeof(arr) / sizeof(arr[0]))

#ifdef __GNUC__

#define UNUSED_FUNCTION_ATTR __attribute__ ((unused))
#define UNUSED_CONST_ATTR __attribute__ ((unused))

#define CONST_FUNCTION __attribute__ ((const))
#define PURE_FUNCTION __attribute__ ((pure))

#define NON_NULL_ARGS0() __attribute__ ((nonnull))
#define NON_NULL_ARGS1(a) __attribute__ ((nonnull (a)))
#define NON_NULL_ARGS2(a, b) __attribute__ ((nonnull (a, b)))
#define NON_NULL_ARGS3(a, b, c) __attribute__ ((nonnull (a, b, c)))
#define NON_NULL_ARGS4(a, b, c, d) __attribute__ ((nonnull (a, b, c, d)))

#else /* __GNUC__ */

#define UNUSED_FUNCTION_ATTR
#define UNUSED_CONST_ATTR

#define CONST_FUNCTION
#define PURE_FUNCTION

#define NON_NULL_ARGS0()
#define NON_NULL_ARGS1(a)
#define NON_NULL_ARGS2(a, b)
#define NON_NULL_ARGS3(a, b, c)
#define NON_NULL_ARGS4(a, b, c, d)

#endif /* __GNUC__ */

#define HEADER_FUNCTION static UNUSED_FUNCTION_ATTR
#define HEADER_CONST static UNUSED_CONST_ATTR

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

/* just used for readability */
#define OUT_VAR

#define ASSERT_CONCAT_(a, b) a##b
#define ASSERT_CONCAT(a, b) ASSERT_CONCAT_(a, b)
  /* These can't be used after statements in c89. */
#ifdef __COUNTER__
#define STATIC_ASSERT(e, m)                                             \
  enum { ASSERT_CONCAT(static_assert_, __COUNTER__) = 1/(!!(e)) }
#else
/* This can't be used twice on the same line so ensure if using in headers
 * that the headers are not included twice (by wrapping in #ifndef...#endif)
 * Note it doesn't cause an issue when used on same line of separate modules
 * compiled with gcc -combine -fwhole-program.  */
#define STATIC_ASSERT(e, m)                                             \
  enum { ASSERT_CONCAT(assert_line_, __LINE__) = 1/(!!(e)) }
#endif

#ifdef __cplusplus
}
#endif

/* C_UTIL_H */
#endif
