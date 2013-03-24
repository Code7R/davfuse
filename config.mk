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
CFLAGS += -std=c99 -Wall -Wextra -Werror
LDFLAGS += $(patsubst %,-L%,${LIBS})

# compiler and linker
CC ?= cc
LD ?= ld