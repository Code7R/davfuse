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

#ifndef _UPTIME_MACH_H
#define _UPTIME_MACH_H

#include <stdbool.h>
#include <stdint.h>

typedef uint64_t uptime_mach_time_t;

bool
uptime_mach_timebase(uptime_mach_time_t *numer, uptime_mach_time_t *denom);

bool
uptime_mach_time(uptime_mach_time_t *out);

#endif
