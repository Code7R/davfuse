# libdavfuse.so version
MAJOR_VERSION = 0
MINOR_VERSION = 1
VERSION = ${MAJOR_VERSION}.${MINOR_VERSION}

# Customize below to fit your system

# paths
PREFIX = /usr/local
MANPREFIX = ${PREFIX}/share/man
LIBDIR = ${PREFIX}/lib

# includes and libs
INCS = -I. -I/usr/include
LIBS = -L/usr/lib -lc

# flags
CPPFLAGS = -DVERSION=\"${VERSION}\"
CFLAGS += -std=c99 -pedantic -Wall -Werror -Os ${INCS} ${CPPFLAGS}
LDFLAGS += -s ${LIBS}

# compiler and linker
CC ?= cc
LD ?= ld