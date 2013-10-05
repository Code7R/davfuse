# davfuse: FUSE file systems as WebDAV servers
# Copyright (C) 2012, 2013 Rian Hunter <rian@alum.mit.edu>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lessage General Public License as published by
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

FS_IMPL = posix
FS_IMPL_EXTRA_SOURCES = fs_posix.c fstatat_emu.c fd_utils.c
FS_IMPL_EXTRA_GEN_HEADERS = fs_posix_fstatat.h
FS_IMPL_EXTRA_IFACE_DEFS = FS_POSIX_FSTATAT_DEF=fs_posix/fstatat/emu

FDEVENT_IMPL = select
FDEVENT_IMPL_EXTRA_SOURCES =
FDEVENT_IMPL_EXTRA_GEN_HEADERS = fdevent_select_sockets.h
FDEVENT_IMPL_EXTRA_IFACE_DEFS = FDEVENT_SELECT_SOCKETS_DEF=fdevent_select/sockets/${SOCKETS_IMPL}

# flags
CPPFLAGS_RELEASE ?= -DNDEBUG

CFLAGS += -std=c99 -Wall -Wextra -Werror
# we can't use -fcatch-undefined-behavior because it catches false positives
# i.e. readdir() http://clang-developers.42468.n3.nabble.com/fcatch-undefined-behavior-false-positive-with-readdir-td4026941.html
CFLAGS_DEBUG ?= -g -ftrapv
CFLAGS_RELEASE ?= -O4

CXXFLAGS += -std=c++11 -Wall -Wextra -Werror -stdlib=libc++
CXXFLAGS_DEBUG ?= -g -ftrapv
CXXFLAGS_RELEASE ?= -O4

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
