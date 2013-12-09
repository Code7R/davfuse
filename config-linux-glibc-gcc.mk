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
# This example is made for glibc/gcc
SOCKETS_IMPL = posix
LOG_PRINTER_IMPL = stdio
UPTIME_IMPL = clock_gettime

FS_IMPL = posix
FS_IMPL_EXTRA_SOURCES = fstatat_native.c fd_utils.c fs_helpers.c
FS_IMPL_EXTRA_GEN_HEADERS = fstatat.h
FS_IMPL_EXTRA_IFACE_DEFS = FSTATAT_DEF=native

EVENT_LOOP_IMPL = select
EVENT_LOOP_IMPL_EXTRA_SOURCES = uptime_${UPTIME_IMPL}.c
EVENT_LOOP_IMPL_EXTRA_GEN_HEADERS = sockets.h uptime.h
EVENT_LOOP_IMPL_EXTRA_IFACE_DEFS = SOCKETS_DEF=${SOCKETS_IMPL} UPTIME_DEF=${UPTIME_IMPL}

# flags
# this is used on linux for seamless 64-bit filesystem usage
# on 32-bit systems
CPPFLAGS ?= $(if $(RELEASE),-DNDEBUG,-D_FORTIFY_SOURCE=2)
CPPFLAGS += -D_FILE_OFFSET_BITS=64

CFLAGS ?= $(if $(RELEASE),-O3,-g)
CFLAGS += -std=c99 -Wall -Wextra -Werror

CXXFLAGS ?= $(if $(RELEASE),-O3,-g)
CXXFLAGS += -std=c++11 -Wall -Wextra -Werror

CFLAGS_DYN = -fPIC
CXXFLAGS_DYN = -fPIC

CXX_LIBS = -lstdc++

# compiler and linker
CC = gcc
CXX = g++
LINK_COMMAND = gcc -shared
LINK_FLAG_NAME = -Xlinker -soname -Xlinker
LINK_FLAG_VERSION_SCRIPT = -Xlinker --version-script -Xlinker

# libfuse file name
LIBDAVFUSE_FILE_NAME = libfuse.so.2
