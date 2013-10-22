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

#ifndef _LOG_PRINTER_STDIO_H
#define _LOG_PRINTER_STDIO_H

#include <stdbool.h>
#include <stdio.h>

#include "c_util.h"
#include "logging_types.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
log_printer_outputdebugstring_default_init(void);

void
log_printer_outputdebugstring_shutdown(void);

PRINTF(4, 5) void
log_printer_outputdebugstring_print(const char *filename, int lineno,
                                    log_level_t level,
                                    const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif
