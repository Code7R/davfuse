# davfuse: FUSE file systems as WebDAV servers
# Copyright (C) 2012, 2013 Rian Hunter <rian@alum.mit.edu>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

# Customize below to fit your system
# This example is made for nt/msvcrt/mingw
SOCKETS_IMPL = winsock
LOG_PRINTER_IMPL = outputdebugstring
UPTIME_IMPL = get_tick_count

FS_IMPL = win32
FS_IMPL_EXTRA_SOURCES = fs_helpers.c

EVENT_LOOP_IMPL = select
EVENT_LOOP_IMPL_EXTRA_SOURCES = uptime_${UPTIME_IMPL}.c
EVENT_LOOP_IMPL_EXTRA_GEN_HEADERS = sockets.h uptime.h
EVENT_LOOP_IMPL_EXTRA_IFACE_DEFS = SOCKETS_DEF=${SOCKETS_IMPL} UPTIME_DEF=${UPTIME_IMPL}

SOCKETS_LIBS = -lws2_32
WEBDAV_SERVER_CLINKFLAGS = -static

# flags
# http://utf8everywhere.org/#how
CPPFLAGS += -D_UNICODE -DUNICODE

CFLAGS ?= $(if $(RELEASE),-O3,-g)
CFLAGS += -std=c99 -Wall -Wextra -Werror

CXXFLAGS ?= $(if $(RELEASE),-O3,-g)
CXXFLAGS += -std=c++11 -Wall -Wextra -Werror

# compiler and linker
CC ?= gcc
CXX ?= g++
LINK_COMMAND ?= ld -shared
LINK_FLAG_NAME ?= -soname
LINK_FLAG_VERSION_SCRIPT ?= --version-script
CXX_LIBS ?= -lstdc++
