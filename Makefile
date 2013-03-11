# davfuse - run fuse file systems as webdav servers
# See LICENSE file for copyright and license details.

include config.mk

FDEVENT_MODULE = fdevent_${FDEVENT_SOURCE}
MAKEFILES = config.mk Makefile
HTTP_SERVER_SRC = ${FDEVENT_MODULE}.c http_server.c logging.c fd_utils.c coroutine_io.c
HTTP_SERVER_OBJ = ${HTTP_SERVER_SRC:.c=.o}
ALL_SRC = test_http_server.c libdavfuse.c ${HTTP_SERVER_SRC}
ALL_OBJ = ${ALL_SRC:.c=.o}
TEST_HTTP_SERVER_OBJ = test_http_server.o ${HTTP_SERVER_OBJ}
LIBFUSE_OBJ = libdavfuse.o ${HTTP_SERVER_OBJ}

all: options davfuse libfuse.so.2 test_http_server

options:
	@echo "davfuse build options:"
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "LDFLAGS  = ${LDFLAGS}"
	@echo "CC       = ${CC}"

config.h: config.def.h ${MAKEFILES}
	@echo -n Generating config.h...
	@cp config.def.h config.h
	@echo ' Done!'

fdevent.h: ${FDEVENT_MODULE}.h ${MAKEFILES}
	@echo -n Generating fdevent.h...
	@cp ${FDEVENT_MODULE}.h fdevent.h
	@echo ' Done!'

davfuse: generate-davfuse.sh ${MAKEFILES}
	@echo Running generate-davfuse.sh...
	@PRIVATE_LIBDIR=. sh generate-davfuse.sh > davfuse
	@chmod a+x davfuse
	@echo ' Done!'

# always copy over config.h and fdevent.h before doing makedepends
.c.o:
	@[ -e config.h ] || cp config.def.h config.h
	@[ -e fdevent.h ] || cp ${FDEVENT_MODULE}.h fdevent.h
	@${MAKEDEPEND}; \
		cp ${df}.d ${df}.P; \
		sed -e 's/#.*//' -e 's/^[^:]*: *//' -e 's/ *\\$$//' \
			-e '/^$$/ d' -e 's/$$/ :/' < ${df}.d >> ${df}.P; \
		rm -f ${df}.d
	@echo CC $<
	@${CC} ${CFLAGS} -c -fPIC $<

${ALL_OBJ}: ${MAKEFILES}

test_http_server: ${TEST_HTTP_SERVER_OBJ}
	@echo LD -o $@ $^
	@${CC} -o $@ $^

libfuse.so.2: ${LIBFUSE_OBJ}
	@echo LD -shared --version-script fuse_versionscript -soname $@ $^
	@${LD} -shared --version-script fuse_versionscript -soname $@ -o $@ $^

# for dependency auto generateion
DEPDIR = .deps
df = ${DEPDIR}/${*F}
MAKEDEPEND = mkdir -p ${DEPDIR}; gcc -M ${CPPFLAGS} -o ${df}.d $<

-include $(ALL_SRC:%.c=$(DEPDIR)/%.P)

clean:
	-rm -f config.h fdevent.h davfuse ${ALL_OBJ} test_http_server libfuse.so.2
	-rm -rf ${DEPDIR}

