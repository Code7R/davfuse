# Customize below to fit your system
# This example is made for xnu/bsdlibc/clang
FDEVENT_IMPL = select
FSTATAT_IMPL = emu
SOCKETS_IMPL = posix
FS_IMPL = posix
WEBDAV_BACKEND_IMPL = fs
HTTP_BACKEND_IMPL = sockets_fdevent
HTTP_BACKEND_SOURCES = http_backend_sockets_fdevent.c fdevent_select.c sockets_posix.c util_sockets.c
WEBDAV_BACKEND_SOURCES = webdav_backend_fs.c fs_posix.c dfs.c util_fs.c fstatat_emu.c fd_utils.c

# flags
CPPFLAGS_RELEASE = -DNDEBUG

CFLAGS += -std=c99 -Wall -Wextra -Werror
CFLAGS_DEBUG = -g
CFLAGS_RELEASE = -O3

CXXFLAGS += -std=c++11 -Wall -Wextra -Werror
CXXFLAGS_DEBUG = -g
CXXFLAGS_RELEASE = -O3

# compiler and linker
CC = clang
CXX = clang++
LINK_COMMAND = gcc -dynamiclib
LINK_FLAG_NAME = -dylinker_install_name
LINK_FLAG_VERSION_SCRIPT =
CXX_LDFLAGS = -lc++

# libfuse file name
LIBFUSE_FILE_NAME = libfuse.2.dylib
