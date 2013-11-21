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

#include "uptime_get_tick_count.h"

#include <stdbool.h>
#include <stdint.h>

#include <windows.h>

enum {
  MILLISECONDS_PER_SECOND = 1000,
  NANOSECONDS_PER_MILLISECOND = 1000000,
};

bool
uptime_get_tick_count_time(UptimeGetTickCountTimespec *out) {
  DWORD tick_count = GetTickCount();
  out->seconds = tick_count / MILLISECONDS_PER_SECOND;
  out->nanoseconds = ((tick_count % MILLISECONDS_PER_SECOND) *
                      NANOSECONDS_PER_MILLISECOND);
  return true;
}
