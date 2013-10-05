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
