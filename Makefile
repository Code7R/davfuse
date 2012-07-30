# davfuse - run fuse file systems as webdav servers
# See LICENSE file for copyright and license details.

include config.mk

SRC = libdavfuse.c fdevent_${FDEVENT_SOURCE}.c
OBJ = ${SRC:.c=.o}
LIB = libfuse.so.2

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
	@PRIVATE_LIBDIR=. sh generate-davfuse.sh > davfuse
	@chmod a+x davfuse

${SRC}: config.h config.mk

fdevent.h: fdevent_${FDEVENT_SOURCE}.h
	@cp $< fdevent.h

libdavfuse.c: fdevent.h fuse.h

.c.o:
	@echo CC -fPIC $<
	@${CC} ${CFLAGS} -c -fPIC $<

${OBJ}: ${SRC}

${LIB}: ${OBJ}
	@echo LD -shared --version-script fuse_versionscript -soname $@ $^
	@${LD} -shared --version-script fuse_versionscript -soname $@ -o $@ $^
