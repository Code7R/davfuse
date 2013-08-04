# Customize below to fit your system
# This example is made for bsdlibc/clang
FDEVENT_SOURCE = select
FSTATAT_SOURCE = emu

# flags
# this is used on linux for seamless 64-bit filesystem usage
# on 32-bit systems
CPPFLAGS +=
CFLAGS += -std=c99 -Wall -Wextra -Werror

# compiler and linker
CC ?= clang
CFLAGS_DEBUG = -g
CFLAGS_RELEASE = -O3
CPPFLAGS_RELEASE = -DNDEBUG

LIBFUSE_FILE_NAME = libfuse.2.dylib
LINK_COMMAND = gcc -dynamiclib
LINK_FLAG_NAME = -dylinker_install_name
LINK_FLAG_VERSION_SCRIPT =
