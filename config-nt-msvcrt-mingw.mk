# Customize below to fit your system
# This example is made for nt/msvcrt/mingw
FDEVENT_IMPL = select
HTTP_BACKEND_IMPL = fdevent
SOCKET_IMPL = winsock
SOCKET_LDFLAGS = -lws2_32
HTTP_BACKEND_SOURCES = http_backend_fdevent.c fdevent_select.c socket_winsock.c

# flags
CPPFLAGS_RELEASE = -DNDEBUG

CFLAGS += -std=c99 -Wall -Wextra -Werror
CFLAGS_DEBUG = -g
CFLAGS_RELEASE = -O3

CXXFLAGS += -std=c++11 -Wall -Wextra -Werror
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
