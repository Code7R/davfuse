# Customize below to fit your system
# This example is made for posix/gcc
FDEVENT_SOURCE = select

# paths
PREFIX = /usr/local
MANPREFIX = ${PREFIX}/share/man
LIBDIR = ${PREFIX}/lib

# non-standard includes and libs
INCS =
LIBS =

# flags
CPPFLAGS += $(patsubst %,-I%,${INCS}) 
# these flags are used by gcc
CFLAGS += -std=c99 -Wall -Wextra -Werror
# this is used for debugging on linux, no effect on other systems
CFLAGS += -D_FORTIFY_SOURCE=2
# this is used on linux for seamless 64-bit filesystem usage
# on 32-bit systems
CFLAGS += -D_FILE_OFFSET_BITS=64
LDFLAGS += $(patsubst %,-L%,${LIBS})

# compiler and linker
CC ?= cc
LD ?= ld