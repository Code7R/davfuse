# Customize below to fit your system
# This example is made for nt/msvcrt/mingw
SOCKETS_IMPL = winsock
LOG_PRINTER_IMPL = outputdebugstring
FS_IMPL = win32

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
