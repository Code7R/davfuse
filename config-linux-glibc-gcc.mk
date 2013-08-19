# Customize below to fit your system
# This example is made for glibc/gcc
FDEVENT_IMPL = select
FSTATAT_IMPL = native
SOCKETS_IMPL = posix
LOG_PRINTER_IMPL = stdio
FS_IMPL = posix
FS_IMPL_EXTRA_SOURCES = fstatat_native.c fd_utils.c
FS_IMPL_EXTRA_INTERFACES = fstatat

# flags
# this is used on linux for seamless 64-bit filesystem usage
# on 32-bit systems
CPPFLAGS += -D_FILE_OFFSET_BITS=64
CPPFLAGS_RELEASE = -DNDEBUG
CPPFLAGS_DEBUG = -D_FORTIFY_SOURCE=2

CFLAGS += -std=c99 -Wall -Wextra -Werror -fPIC
CFLAGS_DEBUG = -g
CFLAGS_RELEASE = -O3

CXXFLAGS += -std=c++11 -Wall -Wextra -Werror -fPIC
CXXFLAGS_DEBUG = -g
CXXFLAGS_RELEASE = -O3

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
