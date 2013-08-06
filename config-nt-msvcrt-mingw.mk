# Customize below to fit your system
# This example is made for nt/msvcrt/mingw
FDEVENT_IMPL = select
FSTATAT_IMPL = none
SOCKETS_IMPL = winsock
FS_IMPL = win32
WEBDAV_BACKEND_IMPL = fs
HTTP_BACKEND_IMPL = sockets_fdevent
HTTP_BACKEND_SOURCES = http_backend_sockets_fdevent.c fdevent_select.c sockets_winsock.c util_sockets.c
WEBDAV_BACKEND_SOURCES = webdav_backend_fs.c fs_win32.c dfs.c util_fs.c

SOCKETS_LDFLAGS = -lws2_32

# flags
CPPFLAGS_RELEASE = -DNDEBUG

# http://utf8everywhere.org/#how
CPPFLAGS += -D_UNICODE

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
