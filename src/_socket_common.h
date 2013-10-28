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

#ifndef _INCLUDE_SOCKET_COMMON_H
#error "DON'T INCLUDE THIS UNLESS YOU KNOW WHAT YOU ARE DOING"
#endif

#ifndef __SOCKET_COMMON_H
#define __SOCKET_COMMON_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool
init_socket_subsystem(void);

bool
shutdown_socket_subsystem(void);

bool
set_socket_non_blocking(socket_t sock);

bool
ignore_sigpipe();

#ifdef __cplusplus
}
#endif

#endif
