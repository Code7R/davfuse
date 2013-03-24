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
#CFLAGS += -std=c99 -Wall -Wextra -Werror -DNDEBUG -O3 ${INCS} ${CPPFLAGS}
CFLAGS += -std=c99 -Wall -Wextra -Werror -g ${INCS} ${CPPFLAGS}
LDFLAGS += ${LIBS}

# compiler and linker
CC ?= cc
LD ?= ld