# Customize below to fit your system
# This example is made for nt/msvcrt/mingw
LOG_PRINTER_IMPL = outputdebugstring
FDEVENT_IMPL = select
SOCKETS_IMPL = winsock
FS_IMPL = win32
SOCKETS_LIBS = -lws2_32
WEBDAV_SERVER_CLINKFLAGS = -static

# flags
CPPFLAGS_RELEASE = -DNDEBUG

# http://utf8everywhere.org/#how
CPPFLAGS += -D_UNICODE -DUNICODE

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
CXX_LIBS = -lstdc++

# libfuse file name
LIBFUSE_FILE_NAME = libfuse.so.2
