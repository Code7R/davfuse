# Customize below to fit your system
# This example is made for xnu/bsdlibc/clang
SOCKETS_IMPL = posix
LOG_PRINTER_IMPL = stdio

FS_IMPL = posix
FS_IMPL_EXTRA_SOURCES = fstatat_emu.c fd_utils.c
FS_IMPL_EXTRA_GEN_HEADERS = fs_posix_fstatat.h
FS_IMPL_EXTRA_IFACE_DEFS = FS_POSIX_FSTATAT_DEF=fs_posix/fstatat/emu

FDEVENT_IMPL = select
FDEVENT_IMPL_EXTRA_SOURCES =
FDEVENT_IMPL_EXTRA_GEN_HEADERS = fdevent_select_sockets.h
FDEVENT_IMPL_EXTRA_IFACE_DEFS = FDEVENT_SELECT_SOCKETS_DEF=fdevent_select/sockets/${SOCKETS_IMPL}

# flags
CPPFLAGS_RELEASE = -DNDEBUG

CFLAGS += -std=c99 -Wall -Wextra -Werror
# we can't use -fcatch-undefined-behavior because it catches false positives
# i.e. readdir() http://clang-developers.42468.n3.nabble.com/fcatch-undefined-behavior-false-positive-with-readdir-td4026941.html
CFLAGS_DEBUG = -g -ftrapv
CFLAGS_RELEASE = -O4

CXXFLAGS += -std=c++11 -Wall -Wextra -Werror -stdlib=libc++
CXXFLAGS_DEBUG = -g
CXXFLAGS_RELEASE = -O4

CFLAGS_DYN = -fPIC -fvisibility=hidden
CXXFLAGS_DYN = -fPIC -fvisibility=hidden

# compiler and linker
CC = clang
CXX = clang++
LINK_COMMAND = gcc -dynamiclib
LINK_FLAG_NAME = -dylinker_install_name
LINK_FLAG_VERSION_SCRIPT =
CXX_LIBS = -lc++

# libdavfuse file name
LIBDAVFUSE_FILE_NAME = libfuse.2.dylib
LIBDAVFUSE_EXTRA_LINK_ARGS = -compatibility_version 11.0.0 -current_version 11.7.0
