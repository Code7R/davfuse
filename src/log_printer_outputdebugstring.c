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

#define _WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef _WIN32_LEAN_AND_MEAN

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "c_util.h"
#include "log_printer_outputdebugstring.h"

bool
log_printer_outputdebugstring_default_init(void) {
  return true;
}

void
log_printer_outputdebugstring_shutdown(void) {
}

void
log_printer_outputdebugstring_print(const char *filename, int lineno,
                                    log_level_t level,
                                    const char *format, ...) {
  /* figure out how many chacters are needed */
  va_list ap;

  va_start(ap, format);
  const int chars_needed =
    _vscprintf(format, ap);
  va_end(ap);

  if (chars_needed < 0) {
    /* TODO: convert string using utf8_to_mb in fs_win32.c,
       and use OutputDebugStringW */
    OutputDebugStringA("Error while getting necessary length for log");
    return;
  }

  char *const buf = malloc(chars_needed + 1);
  if (!buf) {
    OutputDebugStringA("Error while malloc'ing buf for log");
    return;
  }

  UNUSED(filename);
  UNUSED(lineno);
  UNUSED(level);

  va_start(ap, format);
  const int chars_printed =
    vsnprintf(buf, chars_needed + 1, format, ap);
  va_end(ap);

  if (chars_printed >= 0) {
    assert(chars_printed == chars_needed);
    OutputDebugStringA(buf);
  }
  else {
    OutputDebugStringA("Couldn't print string");
  }

  free(buf);
}
