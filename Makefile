# davfuse - run fuse file systems as webdav servers
# See LICENSE file for copyright and license details.

include config.mk

SRC = fdevent_${FDEVENT_SOURCE}.c http_server.c libdavfuse.c logging.c
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

fdevent.h: fdevent_${FDEVENT_SOURCE}.h
	@cp $< fdevent.h

.c.o:
	@echo CC $<
	@${CC} ${CFLAGS} -c -fPIC $<

${OBJ}: config.h config.mk

fdevent_epoll.o: fdevent_epoll.h logging.h

fdevent_select.o: fdevent_select.h

libdavfuse.o: fdevent.h fuse.h logging.h coroutine.h

http_server.o: c_util.h coroutine.h coroutine_io.h fdevent.h fd_utils.h http_server.h logging.h

test_http_server.o: events.h fdevent.h fd_utils.h http_server.h logging.h

fd_utils.o: c_util.h fd_utils.h logging.h

test_http_server: test_http_server.o http_server.o \
	fdevent_${FDEVENT_SOURCE}.o logging.o fd_utils.o coroutine_io.o
	@${CC} -o $@ $^

${LIB}: ${OBJ}
	@echo LD -shared --version-script fuse_versionscript -soname $@ $^
	@${LD} -shared --version-script fuse_versionscript -soname $@ -o $@ $^
