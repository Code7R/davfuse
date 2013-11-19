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

#define NON_NULL_ARGS() __attribute__ ((nonnull))
#define NON_NULL_ARGS1(a) __attribute__ ((nonnull (a)))
#define NON_NULL_ARGS2(a, b) __attribute__ ((nonnull (a, b)))
#define NON_NULL_ARGS3(a, b, c) __attribute__ ((nonnull (a, b, c)))
#define NON_NULL_ARGS4(a, b, c, d) __attribute__ ((nonnull (a, b, c, d)))

#define PRINTF(FMT,X) __attribute__ ((format (printf, FMT, X)))

#else /* __GNUC__ */

#define UNUSED_FUNCTION_ATTR
#define UNUSED_CONST_ATTR

#define CONST_FUNCTION
#define PURE_FUNCTION

#define NON_NULL_ARGS()
#define NON_NULL_ARGS1(a)
#define NON_NULL_ARGS2(a, b)
#define NON_NULL_ARGS3(a, b, c)
#define NON_NULL_ARGS4(a, b, c, d)

#define PRINTF(FMT,X)

#endif /* __GNUC__ */

#ifdef _WIN32
#define DYNAMICALLY_LINKED_FUNCTION_ATTR __declspec(dllexport)
#elif __GNUC__
#define DYNAMICALLY_LINKED_FUNCTION_ATTR __attribute__ ((visibility("default")))
#else
#warning "DYNAMICALLY_LINKED_FUNCTION_ATTR will be empty on unknown platform"
#define DYNAMICALLY_LINKED_FUNCTION_ATTR
#endif

#define HEADER_FUNCTION static UNUSED_FUNCTION_ATTR
#define HEADER_CONST static UNUSED_CONST_ATTR

/* use gcc style single-eval macros if possible */
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/* just used for readability */
#define OUT_VAR

#define ASSERT_CONCAT_(a, b) a##b
#define ASSERT_CONCAT(a, b) ASSERT_CONCAT_(a, b)

/* These should only be used before local variable declarations in c89. */
#ifdef __COUNTER__
#define STATIC_ASSERT(e, m)                                             \
  enum { ASSERT_CONCAT(__static_assert_, __COUNTER__) = 1/(!!(e)) }
#else
/* This can't be used twice on the same line so ensure if using in headers
 * that the headers are not included twice (by wrapping in #ifndef...#endif)
 * Note it doesn't cause an issue when used on same line of separate modules.
 */
#define STATIC_ASSERT(e, m)                                             \
  enum { ASSERT_CONCAT(__assert_line_, __LINE__) = 1/(!!(e)) }
#endif

#ifdef __cplusplus
}
#endif

/* C_UTIL_H */
#endif
