# davfuse - run fuse file systems as webdav servers
# See LICENSE file for copyright and license details.

include config.mk

SRC = libdavfuse.c
OBJ = ${SRC:.c=.o}
LIB=libdavfuse.so.${MAJOR_VERSION}

all: options davfuse ${LIB}

options:
	@echo "davfuse build options:"
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "LDFLAGS  = ${LDFLAGS}"
	@echo "CC       = ${CC}"

config.h:
	@cp config.def.h config.h

generate-davfuse.sh: config.mk

davfuse: generate-davfuse.sh
	@LIBDIR=${LIBDIR} sh generate-davfuse.sh > davfuse
	@chmod a+x davfuse

libdavfuse.c: config.h config.mk

libdavfuse.o: libdavfuse.c
	@${CC} -c ${CFLAGS} -fPIC $<

${LIB}: libdavfuse.o
	${LD} -shared -soname $@ -o $@ $<

