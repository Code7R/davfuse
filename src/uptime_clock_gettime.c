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
#define _POSIX_C_SOURCE 199309L

#include "uptime_clock_gettime.h"

#include "c_util.h"
#include "util.h"

#include <stdbool.h>
#include <stdint.h>

#include <time.h>

bool
uptime_clock_gettime_time(UptimeClockGettimeTimespec *out) {
  struct timespec uptime;
  /* CLOCK_BOOTTIME requires linux >=2.6.39,
     TODO: on EINVAL we can use /proc
   */
  int ret_gettime = clock_gettime(CLOCK_BOOTTIME, &uptime);
  if (ret_gettime) return false;
  out->seconds = uptime.tv_sec;
  out->nanoseconds = uptime.tv_nsec;
  return true;
}
