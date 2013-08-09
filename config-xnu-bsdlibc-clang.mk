# Customize below to fit your system
# This example is made for xnu/bsdlibc/clang
FDEVENT_IMPL = select
FSTATAT_IMPL = emu
SOCKETS_IMPL = posix
FS_IMPL = posix
FS_IMPL_EXTRA_SOURCES = fstatat_emu.c fd_utils.c
FS_IMPL_EXTRA_INTERFACES = fstatat

# flags
CPPFLAGS_RELEASE = -DNDEBUG

CFLAGS += -std=c99 -Wall -Wextra -Werror
CFLAGS_DEBUG = -g
CFLAGS_RELEASE = -O3

CXXFLAGS += -std=c++11 -Wall -Wextra -Werror
CXXFLAGS_DEBUG = -g
CXXFLAGS_RELEASE = -O3

CFLAGS_DYN = -fPIC
CXXFLAGS_DYN = -fPIC

# compiler and linker
CC = clang
CXX = clang++
LINK_COMMAND = gcc -dynamiclib
LINK_FLAG_NAME = -dylinker_install_name
LINK_FLAG_VERSION_SCRIPT =
CXX_LDFLAGS = -lc++

# libdavfuse file name
LIBDAVFUSE_FILE_NAME = libfuse.2.dylib
