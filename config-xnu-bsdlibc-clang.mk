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
# This example is made for xnu/bsdlibc/clang
SOCKETS_IMPL = posix
LOG_PRINTER_IMPL = stdio
UPTIME_IMPL = mach

FS_IMPL = posix
FS_IMPL_EXTRA_SOURCES = fstatat_emu.c fd_utils.c fs_helpers.c
FS_IMPL_EXTRA_GEN_HEADERS = fstatat.h
FS_IMPL_EXTRA_IFACE_DEFS = FSTATAT_DEF=emu

EVENT_LOOP_IMPL = select
EVENT_LOOP_IMPL_EXTRA_SOURCES = uptime_${UPTIME_IMPL}.c
EVENT_LOOP_IMPL_EXTRA_GEN_HEADERS = sockets.h uptime.h
EVENT_LOOP_IMPL_EXTRA_IFACE_DEFS = SOCKETS_DEF=${SOCKETS_IMPL} UPTIME_DEF=${UPTIME_IMPL}

# flags
CFLAGS ?= $(if $(RELEASE),-O3,-g -ftrapv -fcatch-undefined-behavior)
CFLAGS += -std=c99 -Wall -Wextra -Werror

CXXFLAGS ?= $(if $(RELEASE),-O3,-g -ftrapv) -stdlib=libc++
CXXFLAGS += -std=c++11 -Wall -Wextra -Werror

CFLAGS_DYN ?= -fPIC -fvisibility=hidden
CXXFLAGS_DYN ?= -fPIC -fvisibility=hidden

# compiler and linker
CC ?= clang
CXX ?= clang++
LINK_COMMAND ?= $(CC) -dynamiclib
LINK_FLAG_NAME ?= -dylinker_install_name
LINK_FLAG_VERSION_SCRIPT ?=
CXX_LIBS ?= -lc++

# libdavfuse file name
LIBDAVFUSE_FILE_NAME = libfuse.2.dylib
LIBDAVFUSE_EXTRA_LINK_ARGS = -compatibility_version 11.0.0 -current_version 11.7.0
