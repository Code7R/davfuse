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
CPPFLAGS += -DVERSION=\"${VERSION}\" -I${GENHROOT} -I${SRCROOT}

# TODO: configure this with a flag
CFLAGS += ${CFLAGS_DEBUG}
#CFLAGS += ${CFLAGS_RELEASE}
#CPPFLAGS += ${CPPFLAGS_RELEASE}
# Cross-platform essential build flags

CXXFLAGS += ${CXXFLAGS_DEBUG}

FDEVENT_MODULE := fdevent_${FDEVENT_IMPL}
FSTATAT_MODULE := fstatat_${FSTATAT_IMPL}
HTTP_BACKEND_MODULE := http_backend_${HTTP_BACKEND_IMPL}
SOCKET_MODULE := socket_${SOCKET_IMPL}

# Different xml backends for the webdav server
WEBDAV_SERVER_XML_IMPL := webdav_server_xml_tinyxml2.cpp tinyxml2.cpp
WEBDAV_LDFLAGS := ${CXX_LDFLAGS}

#WEBDAV_SERVER_XML_IMPL := webdav_server_xml_libxml2.c
#CFLAGS += $(shell xml2-config --cflags)
#WEBDAV_LDFLAGS += $(shell xml2-config --libs)

MAKEFILES := config.mk Makefile

# Files in $SRCROOT
HTTP_SERVER_SRC_ := http_server.c coroutine_io.c logging.c util.c http_helpers.c ${HTTP_BACKEND_SOURCES}
TEST_HTTP_UNIQUE_SRC_ := test_http_server.c socket_utils.c

WEBDAV_SERVER_SRC_ := ${HTTP_SERVER_SRC_} webdav_server.c ${WEBDAV_SERVER_XML_IMPL} webdav_server_common.c
POSIX_FS_WEBDAV_SERVER_UNIQUE_SRC_ = posix_fs_webdav_server.c ${FSTATAT_MODULE}.c
LIBFUSE_UNIQUE_SRC_ = libdavfuse.c async_fuse_fs.c async_fuse_fs_helpers.c async_rdwr_lock.c async_tree.c

ALL_SRC_ := ${WEBDAV_SERVER_SRC_} ${POSIX_FS_WEBDAV_SERVER_UNIQUE_SRC_} ${LIBFUSE_UNIQUE_SRC_} ${TEST_HTTP_UNIQUE_SRC_}

# Object files that should be in $OBJROOT
HTTP_SERVER_OBJ_ := $(patsubst %,%.o,${HTTP_SERVER_SRC_})
TEST_HTTP_SERVER_OBJ_ := $(patsubst %,%.o,${TEST_HTTP_UNIQUE_SRC_}) ${HTTP_SERVER_OBJ_}

WEBDAV_SERVER_OBJ_ := $(patsubst %,%.o,${WEBDAV_SERVER_SRC_})
POSIX_FS_WEBDAV_SERVER_OBJ_ := $(patsubst %,%.o,${POSIX_FS_WEBDAV_SERVER_UNIQUE_SRC_}) ${WEBDAV_SERVER_OBJ_}
LIBFUSE_OBJ_ := $(patsubst %,%.o,${LIBFUSE_UNIQUE_SRC_}) ${WEBDAV_SERVER_OBJ_}

ALL_OBJ_ := $(patsubst %,%.o,${ALL_SRC_})

# Absolute locations of the sources
ALL_SRC := $(patsubst %,${SRCROOT}/%,${ALL_SRC_})

# Absolute locations of the object files
POSIX_FS_WEBDAV_SERVER_OBJ := $(patsubst %,${OBJROOT}/%,${POSIX_FS_WEBDAV_SERVER_OBJ_})
TEST_HTTP_SERVER_OBJ := $(patsubst %,${OBJROOT}/%,${TEST_HTTP_SERVER_OBJ_})
LIBFUSE_OBJ := $(patsubst %,${OBJROOT}/%,${LIBFUSE_OBJ_})
ALL_OBJ := $(patsubst %,${OBJROOT}/%,${ALL_OBJ_})

TEST_HTTP_SERVER_TARGET := ${TARGETROOT}/test_http_server
POSIX_FS_WEBDAV_SERVER_TARGET := ${TARGETROOT}/posix_fs_webdav_server
LIBFUSE_TARGET := ${TARGETROOT}/${LIBFUSE_FILE_NAME}
DAVFUSE_TARGET := ${TARGETROOT}/davfuse

ALL_TARGETS := ${TEST_HTTP_SERVER_TARGET} ${POSIX_FS_WEBDAV_SERVER_TARGET} \
	${LIBFUSE_TARGET} ${DAVFUSE_TARGET}

GEN_HEADERS_ := fdevent.h fstatat.h socket.h http_backend.h
GEN_HEADERS := $(patsubst %,${GENHROOT}/%,${GEN_HEADERS_})

all: options ${ALL_TARGETS}

options:
	@echo "build options:"
	@echo "CFLAGS          = ${CFLAGS}"
	@echo "CXXFLAGS        = ${CXXFLAGS}"
	@echo "LDFLAGS         = ${LDFLAGS}"
	@echo "SOCKET_LDFLAGS  = ${SOCKET_LDFLAGS}"
	@echo "WEBDAV_LDFLAGS  = ${WEBDAV_LDFLAGS}"
	@echo "CC              = ${CC}"
	@echo "CXX             = ${CXX}"
	@echo "LINK_COMMAND    = ${LINK_COMMAND}"

test_http_server: options ${TEST_HTTP_SERVER_TARGET}
posix_fs_webdav_server: options ${POSIX_FS_WEBDAV_SERVER_TARGET}
libdavfuse: options ${LIBFUSE_TARGET}
davfuse: options ${DAVFUSE_TARGET}

${GENHROOT}/%.h: ${SRCROOT}/%.idef
	@mkdir -p $(dir $@)
	@echo -n Generating $(notdir $@)
	@FDEVENT_IMPL=${FDEVENT_IMPL} FSTATAT_IMPL=${FSTATAT_IMPL} HTTP_BACKEND_IMPL=${HTTP_BACKEND_IMPL} SOCKET_IMPL=${SOCKET_IMPL} sh generate-interface-implementation.sh $^ > $@
	@echo ' Done!'

${DAVFUSE_TARGET}: generate-davfuse.sh ${MAKEFILES} ${LIBFUSE_TARGET}
	@mkdir -p $(dir $@)
	@echo Running generate-davfuse.sh...
	@PRIVATE_LIBDIR=. sh generate-davfuse.sh > $@
	@chmod a+x $@
	@echo ' Done!'

${OBJROOT}/%.c.o: ${SRCROOT}/%.c
	@mkdir -p ${OBJROOT}
	@${MAKEDEPEND_CC}; \
		cp ${df}.d ${Df}.c.P; \
		sed -e 's/#.*//' -e 's/^[^:]*: *//' -e 's/ *\\$$//' \
			-e '/^$$/ d' -e 's/$$/ :/' < ${df}.d >> ${df}.c.P; \
		rm -f ${df}.d
	@echo CC $(notdir $<)
	@${CC} ${CPPFLAGS} ${CFLAGS} -c -o $@ $<

${OBJROOT}/%.cpp.o: ${SRCROOT}/%.cpp
	@mkdir -p ${OBJROOT}
	@${MAKEDEPEND_CXX}; \
		cp ${df}.d ${df}.cpp.P; \
		sed -e 's/#.*//' -e 's/^[^:]*: *//' -e 's/ *\\$$//' \
			-e '/^$$/ d' -e 's/$$/ :/' < ${df}.d >> ${df}.cpp.P; \
		rm -f ${df}.d
	@echo CXX $(notdir $<)
	@${CXX} ${CPPFLAGS} ${CXXFLAGS} -c -o $@ $<

${ALL_OBJ}: ${MAKEFILES} ${GEN_HEADERS}

${TEST_HTTP_SERVER_TARGET}: ${TEST_HTTP_SERVER_OBJ}
	@mkdir -p $(dir $@)
	@echo Linking $(notdir $@)
	@${CC} -o $@ $^ ${LDFLAGS} ${SOCKET_LDFLAGS}

${POSIX_FS_WEBDAV_SERVER_TARGET}: ${POSIX_FS_WEBDAV_SERVER_OBJ}
	@mkdir -p $(dir $@)
	@echo Linking $(notdir $@)
	@${CC} -o $@ $^ ${LDFLAGS} ${WEBDAV_LDFLAGS} ${SOCKET_LDFLAGS}

${LIBFUSE_TARGET}: ${LIBFUSE_OBJ}
	@mkdir -p $(dir $@)
	@echo Linking $(notdir $@)
	@${LINK_COMMAND} ${LINK_FLAG_NAME} $(notdir $@) $(if ${LINK_FLAG_VERSION_SCRIPT}, ${LINK_FLAG_VERSION_SCRIPT} fuse_versionscript) -o $@ $^ ${LDFLAGS} ${WEBDAV_LDFLAGS} ${SOCKET_LDFLAGS}

# for dependency auto generateion
DEPDIR := .deps
df = ${DEPDIR}/${*F}
MAKEDEPEND_CC = mkdir -p ${DEPDIR}; gcc -M -MT $@ ${CPPFLAGS} ${CFLAGS} -o ${df}.d $<
MAKEDEPEND_CXX = mkdir -p ${DEPDIR}; gcc -M -MT $@ ${CPPFLAGS} ${CXXFLAGS} -o ${df}.d $<

-include $(ALL_SRC:${SRCROOT}/%=$(DEPDIR)/%.P)

clean:
	-rm -rf ${DEPDIR} ${OUTROOT}

.PHONY: all options clean posix_fs_webdav_server libdavfuse test_http_server
