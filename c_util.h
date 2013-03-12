#ifndef C_UTIL_H
#define C_UTIL_H

#define UNUSED(x) ((void)(x))
#define NELEMS(arr) (sizeof(arr) / sizeof(arr[0]))

#define UNUSED_FUNCTION_ATTR __attribute__ ((unused))

#define HEADER_FUNCTION static UNUSED_FUNCTION_ATTR
#define CONST_FUNCTION __attribute__ ((const))
#define PURE_FUNCTION __attribute__ ((pure))

#define NON_NULL_ARGS0() __attribute__ ((nonnull))
#define NON_NULL_ARGS2(a, b) __attribute__ ((nonnull (a, b)))
#define NON_NULL_ARGS3(a, b, c) __attribute__ ((nonnull (a, b, c)))

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

/* C_UTIL_H */
#endif
