# davfuse - run fuse file systems as webdav servers
# See LICENSE file for copyright and license details.

# Platform dependent configuation
include config.mk

OUTROOT := out
TARGETROOT := ${OUTROOT}/targets
SRCROOT := src

MAJOR_VERSION := 0
MINOR_VERSION := 1
VERSION := ${MAJOR_VERSION}.${MINOR_VERSION}
CPPFLAGS += -DVERSION=\"${VERSION}\" -I${SRCROOT}
CPPFLAGS_HTTP_SERVER_TEST_MAIN = 

# TODO: configure this with a flag
CFLAGS += ${CFLAGS_DEBUG}
#CFLAGS += ${CFLAGS_RELEASE}
#CPPFLAGS += ${CPPFLAGS_RELEASE}
# Cross-platform essential build flags

CXXFLAGS += ${CXXFLAGS_DEBUG}

# Different xml backends for the webdav server
WEBDAV_SERVER_XML_IMPL := webdav_server_xml_tinyxml2.cpp tinyxml2.cpp
WEBDAV_LDFLAGS := ${CXX_LDFLAGS}

#WEBDAV_SERVER_XML_IMPL := webdav_server_xml_libxml2.c
#CFLAGS += $(shell xml2-config --cflags)
#WEBDAV_LDFLAGS += $(shell xml2-config --libs)

MAKEFILES := config.mk Makefile

HTTP_SERVER_SRC := http_server.c coroutine_io.c logging.c util.c http_helpers.c
WEBDAV_SERVER_SRC := webdav_server.c webdav_server_common.c \
    ${WEBDAV_SERVER_XML_IMPL}

# http_server_test_main vars

HTTP_SERVER_TEST_MAIN_SRC := http_server_test_main.c \
    ${HTTP_SERVER_SRC} http_backend_sockets_fdevent.c \
    fdevent_${FDEVENT_IMPL}.c sockets_${SOCKETS_IMPL}.c util_sockets.c
GEN_HEADERS_HTTP_SERVER_TEST_MAIN_ := fdevent.h sockets.h http_backend.h

GEN_HEADERS_HTTP_SERVER_TEST_MAIN := $(patsubst %,${OUTROOT}/http_server_test_main/headers/%,${GEN_HEADERS_HTTP_SERVER_TEST_MAIN_})
HTTP_SERVER_TEST_MAIN_OBJ := $(patsubst %,${OUTROOT}/http_server_test_main/obj/%.o,${HTTP_SERVER_TEST_MAIN_SRC})

HTTP_SERVER_TEST_MAIN_TARGET := ${TARGETROOT}/http_server_test_main

# webdav_server_sockets_fs_main vars

WEBDAV_SERVER_SOCKETS_FS_MAIN_SRC = \
    webdav_server_sockets_fs_main.c \
    ${HTTP_SERVER_SRC} http_backend_sockets_fdevent.c \
    fdevent_${FDEVENT_IMPL}.c sockets_${SOCKETS_IMPL}.c util_sockets.c \
    ${WEBDAV_SERVER_SRC} \
    webdav_backend_fs.c fs_${FS_IMPL}.c util_fs.c dfs.c \
    ${FS_IMPL_EXTRA_SOURCES}
GEN_HEADERS_WEBDAV_SERVER_SOCKETS_FS_MAIN_ := \
    fdevent.h sockets.h http_backend.h fs.h webdav_backend.h \
    $(patsubst %,%.h,${FS_IMPL_EXTRA_INTERFACES})

GEN_HEADERS_WEBDAV_SERVER_SOCKETS_FS_MAIN = $(patsubst %,${OUTROOT}/webdav_server_sockets_fs_main/headers/%,${GEN_HEADERS_WEBDAV_SERVER_SOCKETS_FS_MAIN_})
WEBDAV_SERVER_SOCKETS_FS_MAIN_OBJ := $(patsubst %,${OUTROOT}/webdav_server_sockets_fs_main/obj/%.o,${WEBDAV_SERVER_SOCKETS_FS_MAIN_SRC})

WEBDAV_SERVER_SOCKETS_FS_MAIN_TARGET := ${TARGETROOT}/webdav_server_sockets_fs_main

# libdavfuse vars

LIBDAVFUSE_SRC = \
    libdavfuse.c async_fuse_fs.c \
    async_fuse_fs_helpers.c async_rdwr_lock.c async_tree.c \
    fd_utils.c \
    ${HTTP_SERVER_SRC} http_backend_sockets_fdevent.c \
    fdevent_${FDEVENT_IMPL}.c sockets_${SOCKETS_IMPL}.c util_sockets.c \
    ${WEBDAV_SERVER_SRC} webdav_backend_async_fuse.c
GEN_HEADERS_LIBDAVFUSE_ = \
    fdevent.h sockets.h http_backend.h fs.h webdav_backend.h

GEN_HEADERS_LIBDAVFUSE = $(patsubst %,${OUTROOT}/libdavfuse/headers/%,${GEN_HEADERS_LIBDAVFUSE_})
LIBDAVFUSE_OBJ := $(patsubst %,${OUTROOT}/libdavfuse/obj/%.o,${LIBDAVFUSE_SRC})

LIBDAVFUSE_TARGET := ${TARGETROOT}/${LIBDAVFUSE_FILE_NAME}

# davfuse vars

DAVFUSE_TARGET := ${TARGETROOT}/davfuse

all: options \
    ${HTTP_SERVER_TEST_MAIN_TARGET} \
    ${WEBDAV_SERVER_SOCKETS_FS_MAIN_TARGET} \
    ${LIBDAVFUSE_TARGET} ${DAVFUSE_TARGET}

options:
	@echo "build options:"
	@echo "CFLAGS          = ${CFLAGS}"
	@echo "CFLAGS_DYN      = ${CFLAGS_DYN}"
	@echo "CXXFLAGS        = ${CXXFLAGS}"
	@echo "CXXFLAGS_DYN    = ${CXXFLAGS_DYN}"
	@echo "CPPFLAGS        = ${CPPFLAGS}"
	@echo "LDFLAGS         = ${LDFLAGS}"
	@echo "SOCKETS_LDFLAGS = ${SOCKETS_LDFLAGS}"
	@echo "WEBDAV_LDFLAGS  = ${WEBDAV_LDFLAGS}"
	@echo "CC              = ${CC}"
	@echo "CXX             = ${CXX}"
	@echo "LINK_COMMAND    = ${LINK_COMMAND}"

http_server_test_main: options ${HTTP_SERVER_TEST_MAIN_TARGET}
webdav_server_sockets_fs_main: options ${WEBDAV_SERVER_SOCKETS_FS_MAIN_TARGET}
libdavfuse: options ${LIBDAVFUSE_TARGET}
davfuse: options ${DAVFUSE_TARGET}

# general rules

# http_server_test_main rules

${OUTROOT}/http_server_test_main/obj/%.c.o: ${SRCROOT}/%.c ${MAKEFILES} 
	@mkdir -p $(dir $@)
	@${MAKEDEPEND_CC}
	@echo CC $(notdir $<)
	@${CC} -I$(dir $@)../headers ${CPPFLAGS} ${CFLAGS} -c -o $@ $<

${OUTROOT}/http_server_test_main/headers/%.h: ${SRCROOT}/%.idef generate-interface-implementation.sh ${MAKEFILES}
	@mkdir -p $(dir $@)
	@echo -n Generating $(notdir $@)
	@HTTP_BACKEND_IMPL=sockets_fdevent FSTATAT_IMPL=${FSTATAT_IMPL} FS_IMPL=${FS_IMPL} FDEVENT_IMPL=${FDEVENT_IMPL} SOCKETS_IMPL=${SOCKETS_IMPL} sh generate-interface-implementation.sh $^ > $@
	@echo ' Done!'

${HTTP_SERVER_TEST_MAIN_OBJ}: ${GEN_HEADERS_HTTP_SERVER_TEST_MAIN}

${HTTP_SERVER_TEST_MAIN_TARGET}: ${HTTP_SERVER_TEST_MAIN_OBJ}
	@mkdir -p $(dir $@)
	@echo Linking $(notdir $@)
	@${CC} -o $@ $^ ${LDFLAGS} ${SOCKETS_LDFLAGS}

# webdav_server_sockets_fs_main rules

${OUTROOT}/webdav_server_sockets_fs_main/headers/%.h: ${SRCROOT}/%.idef generate-interface-implementation.sh ${MAKEFILES}
	@mkdir -p $(dir $@)
	@echo -n Generating $(notdir $@)
	@WEBDAV_BACKEND_IMPL=fs HTTP_BACKEND_IMPL=sockets_fdevent FSTATAT_IMPL=${FSTATAT_IMPL} FS_IMPL=${FS_IMPL} FDEVENT_IMPL=${FDEVENT_IMPL} SOCKETS_IMPL=${SOCKETS_IMPL} sh generate-interface-implementation.sh $^ > $@
	@echo ' Done!'

${OUTROOT}/webdav_server_sockets_fs_main/obj/%.c.o: ${SRCROOT}/%.c ${MAKEFILES}
	@mkdir -p $(dir $@)
	@${MAKEDEPEND_CC}
	@echo CC $(notdir $<)
	@${CC} -I$(dir $@)../headers ${CPPFLAGS} ${CFLAGS} -c -o $@ $<

${OUTROOT}/webdav_server_sockets_fs_main/obj/%.cpp.o: ${SRCROOT}/%.cpp ${MAKEFILES}
	@mkdir -p $(dir $@)
	@${MAKEDEPEND_CXX}
	@echo CXX $(notdir $<)
	@${CXX} -I$(dir $@)../headers ${CPPFLAGS} ${CXXFLAGS} -c -o $@ $<

${WEBDAV_SERVER_SOCKETS_FS_MAIN_OBJ}: ${GEN_HEADERS_WEBDAV_SERVER_SOCKETS_FS_MAIN}

${WEBDAV_SERVER_SOCKETS_FS_MAIN_TARGET}: ${WEBDAV_SERVER_SOCKETS_FS_MAIN_OBJ}
	@mkdir -p $(dir $@)
	@echo Linking $(notdir $@)
	@${CC} -o $@ $^ ${LDFLAGS} ${WEBDAV_LDFLAGS} ${SOCKETS_LDFLAGS}

# libdavfuse rules

${OUTROOT}/libdavfuse/headers/%.h: ${SRCROOT}/%.idef generate-interface-implementation.sh ${MAKEFILES}
	@mkdir -p $(dir $@)
	@echo -n Generating $(notdir $@)
	@WEBDAV_BACKEND_IMPL=async_fuse HTTP_BACKEND_IMPL=sockets_fdevent FSTATAT_IMPL=${FSTATAT_IMPL} FS_IMPL=${FS_IMPL} FDEVENT_IMPL=${FDEVENT_IMPL} SOCKETS_IMPL=${SOCKETS_IMPL} sh generate-interface-implementation.sh $^ > $@
	@echo ' Done!'

${OUTROOT}/libdavfuse/obj/%.c.o: ${SRCROOT}/%.c ${MAKEFILES}
	@mkdir -p $(dir $@)
	@${MAKEDEPEND_CC}
	@echo CC $(notdir $<)
	@${CC} -I$(dir $@)../headers ${CPPFLAGS} ${CFLAGS} ${CFLAGS_DYN} -c -o $@ $<

${OUTROOT}/libdavfuse/obj/%.cpp.o: ${SRCROOT}/%.cpp ${MAKEFILES}
	@mkdir -p $(dir $@)
	@${MAKEDEPEND_CXX}
	@echo CXX $(notdir $<)
	@${CXX} -I$(dir $@)../headers ${CPPFLAGS} ${CXXFLAGS} ${CXXFLAGS_DYN} -c -o $@ $<

${LIBDAVFUSE_OBJ}: ${GEN_HEADERS_LIBDAVFUSE}

${LIBDAVFUSE_TARGET}: ${LIBDAVFUSE_OBJ}
	@mkdir -p $(dir $@)
	@echo Linking $(notdir $@)
	@${LINK_COMMAND} ${LINK_FLAG_NAME} $(notdir $@) $(if ${LINK_FLAG_VERSION_SCRIPT}, ${LINK_FLAG_VERSION_SCRIPT} fuse_versionscript) -o $@ $^ ${LDFLAGS} ${WEBDAV_LDFLAGS} ${SOCKETS_LDFLAGS}

# davfuse rules

${DAVFUSE_TARGET}: generate-davfuse.sh ${MAKEFILES} ${LIBDAVFUSE_TARGET}
	@mkdir -p $(dir $@)
	@echo -n Running generate-davfuse.sh...
	@PRIVATE_LIBDIR=. sh generate-davfuse.sh > $@
	@chmod a+x $@
	@echo ' Done!'

# for dependency auto generateion
DEPDIR = $(dir $@)../deps
df = ${DEPDIR}/${*F}
MAKEDEPEND_CC = \
    mkdir -p ${DEPDIR}; \
    ${CC} -M -MT $@ -I$(dir $@)../headers ${CPPFLAGS} ${CFLAGS} -o ${df}.d $<; \
    CMD=`printf ':a\n s;/\./;/;g \n s;//;/;g \n s;/[^/][^/]*/\.\./;/;g \n s;/[^/][^/]*/\.\.$$;/;g \n ta'`; \
    sed -e "$$CMD" < ${df}.d > ${df}.c.P; \
    rm -f ${df}.d

MAKEDEPEND_CXX = \
    mkdir -p ${DEPDIR}; \
    ${CXX} -M -MT $@ -I$(dir $@)../headers ${CPPFLAGS} ${CXXFLAGS} -o ${df}.d $<; \
    CMD=`printf ':a\n s;/\./;/;g \n s;//;/;g \n s;/[^/][^/]*/\.\./;/;g \n s;/[^/][^/]*/\.\.$$;/;g \n ta'`; \
    sed -e "$$CMD" < ${df}.d > ${df}.cpp.P; \
    rm -f ${df}.d

-include $(HTTP_SERVER_TEST_MAIN_SRC:%=${OUTROOT}/http_server_test_main/deps/%.P)
-include $(WEBDAV_SERVER_SOCKETS_FS_MAIN_SRC:%=${OUTROOT}/webdav_server_sockets_fs_main/deps/%.P)
-include $(LIBDAVFUSE_SRC:%=${OUTROOT}/libdavfuse/deps/%.P)

clean:
	-rm -rf ${OUTROOT}

.PHONY: all options clean webdav_server_sockets_fs_main libdavfuse http_server_test_main
