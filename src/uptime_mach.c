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

#define _ISOC99_SOURCE

#include "uptime_mach.h"

#include "c_util.h"
#include "util.h"

#include <stdbool.h>
#include <stdint.h>

#include <mach/mach_time.h>

static bool _g_set_info;
static mach_timebase_info_data_t _g_info;

enum {
  NANOSECONDS_PER_SECOND = 1000000000,
};

static
bool
_ensure_timebase_info(void) {
  if (_g_set_info) return true;
  kern_return_t ret = mach_timebase_info(&_g_info);
  if (ret) return false;
  _g_set_info = true;
  return true;
}

bool
uptime_mach_time(UptimeMachTimespec *out) {
  if (!_ensure_timebase_info()) return false;
  uint64_t t = mach_absolute_time();
  uint64_t nanos = t * _g_info.numer / _g_info.denom;
  out->seconds = nanos / NANOSECONDS_PER_SECOND;
  out->nanoseconds = nanos % NANOSECONDS_PER_SECOND;
  return true;
}
