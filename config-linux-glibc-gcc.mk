# Customize below to fit your system
# This example is made for glibc/gcc
FDEVENT_IMPL = select
FSTATAT_IMPL = native
HTTP_BACKEND_IMPL = fdevent
HTTP_BACKEND_SOURCES = http_backend_fdevent.c fdevent_select.c

# flags
# this is used on linux for seamless 64-bit filesystem usage
# on 32-bit systems
CPPFLAGS += -D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64
CPPFLAGS_RELEASE = -DNDEBUG

CFLAGS += -std=c99 -Wall -Wextra -Werror -fPIC
CFLAGS_DEBUG = -g
CFLAGS_RELEASE = -O3

CXXFLAGS += -std=c++11 -Wall -Wextra -Werror -fPIC
CXXFLAGS_DEBUG = -g
CXXFLAGS_RELEASE = -O3

# compiler and linker
CC = gcc
CXX = g++
LINK_COMMAND = ld -shared
LINK_FLAG_NAME = -soname
LINK_FLAG_VERSION_SCRIPT = --version-script
CXX_LDFLAGS = -lstdc++

# libfuse file name
LIBFUSE_FILE_NAME = libfuse.so.2
