#ifndef _IFACE_UTIL_H
#define _IFACE_UTIL_H

#include <string.h>

#include "c_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __COUNTER__
#define ASSERT_SAME_IMPL(s1, s2) STATIC_ASSERT(s1 == s2, #s1 " != " #s2)
#define CREATE_IMPL_TAG(m) enum{m=__COUNTER__}
#else
#define ASSERT_SAME_IMPL(s1, s2) STATIC_ASSERT(!strcmp(s1, s2), #s1 " != " #s2)
#define CREATE_IMPL_TAG(m) static const char *const m = #m
#endif

#ifdef __cplusplus
}
#endif

#endif
