MAJOR_VERSION = 0
MINOR_VERSION = 1
VERSION = ${MAJOR_VERSION}.${MINOR_VERSION}

# Customize below to fit your system
#FDEVENT_SOURCE = epoll
FDEVENT_SOURCE = select

# paths
PREFIX = /usr/local
MANPREFIX = ${PREFIX}/share/man
LIBDIR = ${PREFIX}/lib

# includes and libs
INCS = -I. -I/usr/include
LIBS = -L/usr/lib -lc

# flags
CPPFLAGS = -DVERSION=\"${VERSION}\"
CFLAGS += -std=c99 -Wall -Wextra -Werror -DNDEBUG -O3 ${INCS} ${CPPFLAGS}
#CFLAGS += -std=c99 -Wall -Wextra -Werror -g ${INCS} ${CPPFLAGS}
LDFLAGS += -s ${LIBS}

# compiler and linker
CC ?= cc
LD ?= ld