# Customize below to fit your system
# This example is made for glibc/gcc
FDEVENT_SOURCE = select
FSTATAT_SOURCE = native

# flags
# this is used on linux for seamless 64-bit filesystem usage
# on 32-bit systems
CPPFLAGS += -D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64
CFLAGS += -std=c99 -Wall -Wextra -Werror

# compiler and linker
CC ?= gcc
CFLAGS_DEBUG = -g
CFLAGS_RELEASE = -O3
CPPFLAGS_RELEASE = -DNDEBUG

LIBFUSE_FILE_NAME = libfuse.so.2
LINK_COMMAND = ld -shared
LINK_FLAG_NAME = -soname
LINK_FLAG_VERSION_SCRIPT = --version-script
