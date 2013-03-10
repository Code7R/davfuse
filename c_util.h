#ifndef C_UTIL_H
#define C_UTIL_H

#define UNUSED(x) (void)(x)
#define NELEMS(arr) (sizeof(arr) / sizeof(arr[0]))

#define UNUSED_FUNCTION_ATTR __attribute__ ((unused))

#define HEADER_FUNCTION static UNUSED_FUNCTION_ATTR
#define CONST_FUNCTION __attribute__ ((const))

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

/* C_UTIL_H */
#endif
