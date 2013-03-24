# davfuse - run fuse file systems as webdav servers
# See LICENSE file for copyright and license details.

# Platform dependent configuation
include config.mk

OUTROOT := out
TARGETROOT := ${OUTROOT}
OBJROOT := ${OUTROOT}/obj
GENHROOT := ${OUTROOT}/headers
SRCROOT := src

MAJOR_VERSION := 0
MINOR_VERSION := 1
VERSION := ${MAJOR_VERSION}.${MINOR_VERSION}

# TODO: configure this with a flag
CFLAGS += -g
#CFLAGS += -O3
#CPPFLAGS += -DNDEBUG

# Cross-platform essential build flags
CPPFLAGS += -DVERSION=\"${VERSION}\" -I${GENHROOT} -I${SRCROOT}
CFLAGS += $(shell xml2-config --cflags) ${CPPFLAGS}
LDFLAGS += $(shell xml2-config --libs)

FDEVENT_MODULE := fdevent_${FDEVENT_SOURCE}
MAKEFILES := config.mk Makefile

# Files in $SRCROOT
HTTP_SERVER_SRC_ := ${FDEVENT_MODULE}.c http_server.c logging.c fd_utils.c coroutine_io.c util.c
TARGET_SRC_ := posix_fs_webdav_server.c test_http_server.c libdavfuse.c
ALL_SRC_ := ${TARGET_SRC_} ${HTTP_SERVER_SRC_}

# Object files that should be in $OBJROOT
HTTP_SERVER_OBJ_ := $(patsubst %.c,%.o,${HTTP_SERVER_SRC_})
POSIX_FS_WEBDAV_SERVER_OBJ_ := posix_fs_webdav_server.o ${HTTP_SERVER_OBJ_}
TEST_HTTP_SERVER_OBJ_ := test_http_server.o ${HTTP_SERVER_OBJ_}
LIBFUSE_OBJ_ := libdavfuse.o ${HTTP_SERVER_OBJ_}
ALL_OBJ_ := $(patsubst %.c,%.o,${ALL_SRC_})

# Absolute locations of the sources
ALL_SRC := $(patsubst %,${SRCROOT}/%,${ALL_SRC_})

# Absolute locations of the object files
POSIX_FS_WEBDAV_SERVER_OBJ := $(patsubst %,${OBJROOT}/%,${POSIX_FS_WEBDAV_SERVER_OBJ_})
TEST_HTTP_SERVER_OBJ := $(patsubst %,${OBJROOT}/%,${TEST_HTTP_SERVER_OBJ_})
LIBFUSE_OBJ := $(patsubst %,${OBJROOT}/%,${LIBFUSE_OBJ_})
ALL_OBJ := $(patsubst %,${OBJROOT}/%,${ALL_OBJ_})

TEST_HTTP_SERVER_TARGET := ${TARGETROOT}/test_http_server
POSIX_FS_WEBDAV_SERVER_TARGET := ${TARGETROOT}/posix_fs_webdav_server
LIBFUSE_TARGET := ${TARGETROOT}/libfuse.so.2
DAVFUSE_TARGET := ${TARGETROOT}/davfuse 

ALL_TARGETS := ${TEST_HTTP_SERVER_TARGET} ${POSIX_FS_WEBDAV_SERVER_TARGET} \
	${LIBFUSE_TARGET} ${DAVFUSE_TARGET}

all: options ${ALL_TARGETS}

options:
	@echo "build options:"
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "LDFLAGS  = ${LDFLAGS}"
	@echo "CC       = ${CC}"
	@echo "LD       = ${LD}"

posix_fs_webdav_server: options ${POSIX_FS_WEBDAV_SERVER_TARGET}

${GENHROOT}/config.h: config.def.h ${MAKEFILES}
	@mkdir -p $(dir $@)
	@echo -n Generating config.h...
	@cp config.def.h $@
	@echo ' Done!'

${GENHROOT}/fdevent.h: ${SRCROOT}/${FDEVENT_MODULE}.h ${MAKEFILES}
	@mkdir -p $(dir $@)
	@echo -n Generating fdevent.h...
	@cp ${SRCROOT}/${FDEVENT_MODULE}.h $@
	@echo ' Done!'

${DAVFUSE_TARGET}: generate-davfuse.sh ${MAKEFILES}
	@mkdir -p $(dir $@)
	@echo Running generate-davfuse.sh...
	@PRIVATE_LIBDIR=. sh generate-davfuse.sh > $@
	@chmod a+x $@
	@echo ' Done!'

# always copy over config.h and fdevent.h before doing makedepends
${OBJROOT}/%.o: ${SRCROOT}/%.c
	@mkdir -p $(dir $@)
	@mkdir -p ${GENHROOT}
	@[ -e ${GENHROOT}/config.h ] || cp config.def.h ${GENHROOT}/config.h
	@[ -e ${GENHROOT}/fdevent.h ] || cp ${SRCROOT}/${FDEVENT_MODULE}.h ${GENHROOT}/fdevent.h
	@${MAKEDEPEND}; \
		cp ${df}.d ${df}.P; \
		sed -e 's/#.*//' -e 's/^[^:]*: *//' -e 's/ *\\$$//' \
			-e '/^$$/ d' -e 's/$$/ :/' < ${df}.d >> ${df}.P; \
		rm -f ${df}.d
	@echo CC $(notdir $<)
	@${CC} ${CFLAGS} -c -o $@ -fPIC $<

${ALL_OBJ}: ${MAKEFILES}

${TEST_HTTP_SERVER_TARGET}: ${TEST_HTTP_SERVER_OBJ}
	@mkdir -p $(dir $@)
	@echo Linking $(notdir $@)
	@${CC} -o $@ $^ ${LDFLAGS}

${POSIX_FS_WEBDAV_SERVER_TARGET}: ${POSIX_FS_WEBDAV_SERVER_OBJ}
	@mkdir -p $(dir $@)
	@echo Linking $(notdir $@)
	@${CC} -o $@ $^ ${LDFLAGS} 

${LIBFUSE_TARGET}: ${LIBFUSE_OBJ}
	@mkdir -p $(dir $@)
	@echo Linking $(notdir $@)
	@${LD} -shared --version-script fuse_versionscript -soname $@ -o $@ $^

# for dependency auto generateion
DEPDIR := .deps
df = ${DEPDIR}/${*F}
MAKEDEPEND = mkdir -p ${DEPDIR}; gcc -M ${CFLAGS} -o ${df}.d $<

-include $(ALL_SRC:%.c=$(DEPDIR)/%.P)

clean:
	-rm -rf ${DEPDIR} ${OUTROOT}

.PHONY: all options clean posix_fs_webdav_server