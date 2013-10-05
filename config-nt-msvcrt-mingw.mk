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

FS_IMPL = win32
FS_IMPL_EXTRA_SOURCES = fs_win32.c

FDEVENT_IMPL = select
FDEVENT_IMPL_EXTRA_SOURCES =
FDEVENT_IMPL_EXTRA_GEN_HEADERS = fdevent_select_sockets.h
FDEVENT_IMPL_EXTRA_IFACE_DEFS = FDEVENT_SELECT_SOCKETS_DEF=fdevent_select/sockets/${SOCKETS_IMPL}

SOCKETS_LIBS = -lws2_32
WEBDAV_SERVER_CLINKFLAGS = -static

# flags
CPPFLAGS_RELEASE = -DNDEBUG

# http://utf8everywhere.org/#how
CPPFLAGS += -D_UNICODE -DUNICODE

CFLAGS += -std=c99 -Wall -Wextra -Werror
CFLAGS_DEBUG = -g
CFLAGS_RELEASE = -O3 -flto

CXXFLAGS += -std=c++11 -Wall -Wextra -Werror
CXXFLAGS_DEBUG = -g
CXXFLAGS_RELEASE = -O3 -flto

# compiler and linker
CC = gcc
CXX = g++
LINK_COMMAND = ld -shared
LINK_FLAG_NAME = -soname
LINK_FLAG_VERSION_SCRIPT = --version-script
CXX_LIBS = -lstdc++
