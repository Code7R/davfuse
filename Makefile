# davfuse: FUSE file systems as WebDAV servers
# Copyright (C) 2012, 2013 Rian Hunter <rian@alum.mit.edu>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

# Platform dependent configuation
include config.mk

# default
WEBDAV_SERVER_SOCKETS_FS_FS_IMPL ?= $(FS_IMPL)
WEBDAV_SERVER_SOCKETS_FS_FS_IMPL_EXTRA_SOURCES ?= $(FS_IMPL_EXTRA_SOURCES)
WEBDAV_SERVER_SOCKETS_FS_FS_IMPL_EXTRA_GEN_HEADERS ?= $(FS_IMPL_EXTRA_GEN_HEADERS)
WEBDAV_SERVER_SOCKETS_FS_FS_IMPL_EXTRA_IFACE_DEFS ?= $(FS_IMPL_EXTRA_IFACE_DEFS)

OUTROOT := $(if ${RELEASE}, out-release, out)
TARGETROOT := ${OUTROOT}/targets
SRCROOT := src

CPPFLAGS += -I${SRCROOT}

CFLAGS += $(if ${RELEASE}, ${CFLAGS_RELEASE}, ${CFLAGS_DEBUG})
CXXFLAGS += $(if ${RELEASE}, ${CXXFLAGS_RELEASE}, ${CXXFLAGS_DEBUG})
CPPFLAGS += $(if ${RELEASE}, ${CPPFLAGS_RELEASE}, ${CPPFLAGS_DEBUG})

# Different xml backends for the webdav server
WEBDAV_SERVER_XML_IMPL := webdav_server_xml_tinyxml2.cpp tinyxml2.cpp
WEBDAV_LIBS := ${CXX_LIBS}

MAKEFILES := config.mk Makefile

HTTP_SERVER_SRC := http_server.c coroutine_io.c logging.c util.c http_helpers.c
WEBDAV_SERVER_SRC := webdav_server.c ${WEBDAV_SERVER_XML_IMPL}

# http_server_test_main vars

HTTP_SERVER_TEST_MAIN_SRC := http_server_test_main.c \
    ${HTTP_SERVER_SRC} http_backend_sockets_fdevent.c \
    fdevent_${FDEVENT_IMPL}.c sockets_${SOCKETS_IMPL}.c util_sockets.c \
    log_printer_${LOG_PRINTER_IMPL}.c
GEN_HEADERS_HTTP_SERVER_TEST_MAIN_ := \
    http_backend_sockets_fdevent_fdevent.h \
    http_backend_sockets_fdevent_sockets.h \
    http_server_http_backend.h \
    logging_log_printer.h \
    util_sockets_sockets.h \
    ${FDEVENT_IMPL_EXTRA_GEN_HEADERS}
HTTP_SERVER_TEST_MAIN_IFACE_DEFS := \
    HTTP_BACKEND_SOCKETS_FDEVENT_FDEVENT_DEF=http_backend_sockets_fdevent/fdevent/${FDEVENT_IMPL} \
    HTTP_BACKEND_SOCKETS_FDEVENT_SOCKETS_DEF=http_backend_sockets_fdevent/sockets/${SOCKETS_IMPL} \
    HTTP_SERVER_HTTP_BACKEND_DEF=http_server/http_backend/sockets_fdevent \
    LOGGING_LOG_PRINTER_DEF=logging/log_printer/${LOG_PRINTER_IMPL} \
    UTIL_SOCKETS_SOCKETS_DEF=util_sockets/sockets/${SOCKETS_IMPL} \
    ${FDEVENT_IMPL_EXTRA_IFACE_DEFS}

GEN_HEADERS_HTTP_SERVER_TEST_MAIN := $(patsubst %,${OUTROOT}/http_server_test_main/headers/%,${GEN_HEADERS_HTTP_SERVER_TEST_MAIN_})
HTTP_SERVER_TEST_MAIN_OBJ := $(patsubst %,${OUTROOT}/http_server_test_main/obj/%.o,${HTTP_SERVER_TEST_MAIN_SRC})

HTTP_SERVER_TEST_MAIN_TARGET := ${TARGETROOT}/http_server_test_main

# libwebdav_server_sockets_fs.a vars

LIBWEBDAV_SERVER_SOCKETS_FS_SRC = \
    ${HTTP_SERVER_SRC} \
    ${WEBDAV_SERVER_SRC} \
    http_backend_sockets_fdevent.c \
    fdevent_${FDEVENT_IMPL}.c \
    sockets_${SOCKETS_IMPL}.c \
    util_sockets.c \
    webdav_backend_fs.c \
    util_fs.c \
    dfs.c \
    ${FDEVENT_IMPL_EXTRA_SOURCES}
GEN_HEADERS_LIBWEBDAV_SERVER_SOCKETS_FS_ := \
    http_backend_sockets_fdevent_fdevent.h \
    http_backend_sockets_fdevent_sockets.h \
    http_server_http_backend.h \
    logging_log_printer.h \
    webdav_server_webdav_backend.h \
    webdav_backend_fs_fs.h \
    util_sockets_sockets.h \
    util_fs_fs.h \
    ${FDEVENT_IMPL_EXTRA_GEN_HEADERS}
LIBWEBDAV_SERVER_SOCKETS_FS_IFACE_DEFS := \
    HTTP_BACKEND_SOCKETS_FDEVENT_FDEVENT_DEF=http_backend_sockets_fdevent/fdevent/${FDEVENT_IMPL} \
    HTTP_BACKEND_SOCKETS_FDEVENT_SOCKETS_DEF=http_backend_sockets_fdevent/sockets/${SOCKETS_IMPL} \
    HTTP_SERVER_HTTP_BACKEND_DEF=http_server/http_backend/sockets_fdevent \
    LOGGING_LOG_PRINTER_DEF=logging/log_printer/${LOG_PRINTER_IMPL} \
    WEBDAV_SERVER_WEBDAV_BACKEND_DEF=webdav_server/webdav_backend/fs \
    WEBDAV_BACKEND_FS_FS_DEF=webdav_backend_fs/fs/${WEBDAV_SERVER_SOCKETS_FS_FS_IMPL} \
    UTIL_FS_FS_DEF=util_fs/fs/${WEBDAV_SERVER_SOCKETS_FS_FS_IMPL} \
    UTIL_SOCKETS_SOCKETS_DEF=util_sockets/sockets/${SOCKETS_IMPL} \
    ${FDEVENT_IMPL_EXTRA_IFACE_DEFS}

GEN_HEADERS_LIBWEBDAV_SERVER_SOCKETS_FS = $(patsubst %,${OUTROOT}/libwebdav_server_sockets_fs/headers/%,${GEN_HEADERS_LIBWEBDAV_SERVER_SOCKETS_FS_})
LIBWEBDAV_SERVER_SOCKETS_FS_OBJ := $(patsubst %,${OUTROOT}/libwebdav_server_sockets_fs/obj/%.o,${LIBWEBDAV_SERVER_SOCKETS_FS_SRC})

LIBWEBDAV_SERVER_SOCKETS_FS_TARGET := ${TARGETROOT}/libwebdav_server_sockets_fs.a

# webdav_server_sockets_fs_main vars

WEBDAV_SERVER_SOCKETS_FS_MAIN_SRC := \
    ${LIBWEBDAV_SERVER_SOCKETS_FS_SRC} \
    webdav_server_sockets_fs_main.c \
    log_printer_${LOG_PRINTER_IMPL}.c \
    ${WEBDAV_SERVER_SOCKETS_FS_FS_IMPL_EXTRA_SOURCES}
GEN_HEADERS_WEBDAV_SERVER_SOCKETS_FS_MAIN_ := \
    ${GEN_HEADERS_LIBWEBDAV_SERVER_SOCKETS_FS_} \
    ${WEBDAV_SERVER_SOCKETS_FS_FS_IMPL_EXTRA_GEN_HEADERS}
WEBDAV_SERVER_SOCKETS_FS_MAIN_IFACE_DEFS := \
    ${LIBWEBDAV_SERVER_SOCKETS_FS_IFACE_DEFS} \
    ${WEBDAV_SERVER_SOCKETS_FS_FS_IMPL_EXTRA_IFACE_DEFS}

GEN_HEADERS_WEBDAV_SERVER_SOCKETS_FS_MAIN = $(patsubst %,${OUTROOT}/webdav_server_sockets_fs_main/headers/%,${GEN_HEADERS_WEBDAV_SERVER_SOCKETS_FS_MAIN_})
WEBDAV_SERVER_SOCKETS_FS_MAIN_OBJ := $(patsubst %,${OUTROOT}/webdav_server_sockets_fs_main/obj/%.o,${WEBDAV_SERVER_SOCKETS_FS_MAIN_SRC})

WEBDAV_SERVER_SOCKETS_FS_MAIN_TARGET := ${TARGETROOT}/webdav_server_sockets_fs_main

# libdavfuse vars

LIBDAVFUSE_SRC := \
    libdavfuse.c async_fuse_fs.c \
    async_fuse_fs_helpers.c async_rdwr_lock.c async_tree.c \
    fd_utils.c \
    ${HTTP_SERVER_SRC} http_backend_sockets_fdevent.c \
    fdevent_${FDEVENT_IMPL}.c sockets_${SOCKETS_IMPL}.c util_sockets.c \
    log_printer_${LOG_PRINTER_IMPL}.c \
    ${WEBDAV_SERVER_SRC} webdav_backend_async_fuse.c
GEN_HEADERS_LIBDAVFUSE_ := \
    async_fuse_fs_fdevent.h \
    http_backend_sockets_fdevent_fdevent.h \
    http_backend_sockets_fdevent_sockets.h \
    http_server_http_backend.h \
    logging_log_printer.h \
    webdav_server_webdav_backend.h \
    util_sockets_sockets.h \
    ${FDEVENT_IMPL_EXTRA_GEN_HEADERS}
LIBDAVFUSE_IFACE_DEFS := \
    ASYNC_FUSE_FS_FDEVENT_DEF=async_fuse_fs/fdevent/${FDEVENT_IMPL} \
    HTTP_BACKEND_SOCKETS_FDEVENT_FDEVENT_DEF=http_backend_sockets_fdevent/fdevent/${FDEVENT_IMPL} \
    HTTP_BACKEND_SOCKETS_FDEVENT_SOCKETS_DEF=http_backend_sockets_fdevent/sockets/${SOCKETS_IMPL} \
    HTTP_SERVER_HTTP_BACKEND_DEF=http_server/http_backend/sockets_fdevent \
    LOGGING_LOG_PRINTER_DEF=logging/log_printer/${LOG_PRINTER_IMPL} \
    WEBDAV_SERVER_WEBDAV_BACKEND_DEF=webdav_server/webdav_backend/async_fuse \
    UTIL_SOCKETS_SOCKETS_DEF=util_sockets/sockets/${SOCKETS_IMPL} \
    ${FDEVENT_IMPL_EXTRA_IFACE_DEFS}

GEN_HEADERS_LIBDAVFUSE = $(patsubst %,${OUTROOT}/libdavfuse/headers/%,${GEN_HEADERS_LIBDAVFUSE_})
LIBDAVFUSE_OBJ := $(patsubst %,${OUTROOT}/libdavfuse/obj/%.o,${LIBDAVFUSE_SRC})

LIBDAVFUSE_TARGET := ${TARGETROOT}/${LIBDAVFUSE_FILE_NAME}

# davfuse vars

DAVFUSE_TARGET := ${TARGETROOT}/davfuse

STATIC_OBJS = \
	${LIBWEBDAV_SERVER_SOCKETS_FS_OBJ} \
        ${WEBDAV_SERVER_SOCKETS_FS_MAIN_OBJ} \
	${HTTP_SERVER_TEST_MAIN_OBJ}
DYNAMIC_OBJS = ${LIBDAVFUSE_OBJ}

all: options \
    ${HTTP_SERVER_TEST_MAIN_TARGET} \
    ${LIBWEBDAV_SERVER_SOCKETS_FS_TARGET} \
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
	@echo "SOCKETS_LIBS    = ${SOCKETS_LIBS}"
	@echo "WEBDAV_LIBS     = ${WEBDAV_LIBS}"
	@echo "CC              = ${CC}"
	@echo "CXX             = ${CXX}"
	@echo "LINK_COMMAND    = ${LINK_COMMAND}"
	@echo "WEBDAV_SERVER_CLINKFLAGS = ${WEBDAV_SERVER_CLINKFLAGS}"

http_server_test_main: options ${HTTP_SERVER_TEST_MAIN_TARGET}
libwebdav_server_sockets_fs: options ${LIBWEBDAV_SERVER_SOCKETS_FS_TARGET}
webdav_server_sockets_fs_main: options ${WEBDAV_SERVER_SOCKETS_FS_MAIN_TARGET}
libdavfuse: options ${LIBDAVFUSE_TARGET}
davfuse: options ${DAVFUSE_TARGET}

# dependencies

${OUTROOT}/*/headers/*_fdevent.h: ${SRCROOT}/fdevent.idef
${OUTROOT}/*/headers/*_fs.h: ${SRCROOT}/fs.idef
${OUTROOT}/*/headers/*_fstatat.h: ${SRCROOT}/fstatat.idef
${OUTROOT}/*/headers/*_http_backend.h: ${SRCROOT}/http_backend.idef
${OUTROOT}/*/headers/*_log_printer.h: ${SRCROOT}/log_printer.idef
${OUTROOT}/*/headers/*_sockets.h: ${SRCROOT}/sockets.idef
${OUTROOT}/*/headers/*_webdav_backend.h: ${SRCROOT}/webdav_backend.idef

${GEN_HEADERS_HTTP_SERVER_TEST_MAIN} \
    ${GEN_HEADERS_LIBWEBDAV_SERVER_SOCKETS_FS} \
    ${GEN_HEADERS_WEBDAV_SERVER_SOCKETS_FS_MAIN} \
    ${GEN_HEADERS_LIBDAVFUSE}: generate-interface-implementation.sh ${MAKEFILES}

${HTTP_SERVER_TEST_MAIN_OBJ}: \
    ${OUTROOT}/http_server_test_main/obj/%.c.o: ${SRCROOT}/%.c
${HTTP_SERVER_TEST_MAIN_OBJ}: \
    ${GEN_HEADERS_HTTP_SERVER_TEST_MAIN} \
    ${MAKEFILES}
${HTTP_SERVER_TEST_MAIN_TARGET}: ${HTTP_SERVER_TEST_MAIN_OBJ} ${MAKEFILES}

$(filter %.c.o,${LIBWEBDAV_SERVER_SOCKETS_FS_OBJ}): \
    ${OUTROOT}/libwebdav_server_sockets_fs/obj/%.c.o: ${SRCROOT}/%.c
$(filter %.cpp.o,${LIBWEBDAV_SERVER_SOCKETS_FS_OBJ}): \
    ${OUTROOT}/libwebdav_server_sockets_fs/obj/%.cpp.o: ${SRCROOT}/%.cpp
${LIBWEBDAV_SERVER_SOCKETS_FS_OBJ}: \
    ${GEN_HEADERS_LIBWEBDAV_SERVER_SOCKETS_FS} \
    ${MAKEFILES}
${LIBWEBDAV_SERVER_SOCKETS_FS_TARGET}: ${LIBWEBDAV_SERVER_SOCKETS_FS_OBJ} ${MAKEFILES}

$(filter %.c.o,${WEBDAV_SERVER_SOCKETS_FS_MAIN_OBJ}): \
    ${OUTROOT}/webdav_server_sockets_fs_main/obj/%.c.o: ${SRCROOT}/%.c
$(filter %.cpp.o,${WEBDAV_SERVER_SOCKETS_FS_MAIN_OBJ}): \
    ${OUTROOT}/webdav_server_sockets_fs_main/obj/%.cpp.o: ${SRCROOT}/%.cpp
${WEBDAV_SERVER_SOCKETS_FS_MAIN_OBJ}: \
    ${GEN_HEADERS_WEBDAV_SERVER_SOCKETS_FS_MAIN} \
    ${MAKEFILES}
${WEBDAV_SERVER_SOCKETS_FS_MAIN_TARGET}: \
	${WEBDAV_SERVER_SOCKETS_FS_MAIN_OBJ} \
	${MAKEFILES}

$(filter %.c.o,${LIBDAVFUSE_OBJ}): \
    ${OUTROOT}/libdavfuse/obj/%.c.o: ${SRCROOT}/%.c
$(filter %.cpp.o,${LIBDAVFUSE_OBJ}): \
    ${OUTROOT}/libdavfuse/obj/%.cpp.o: ${SRCROOT}/%.cpp
${LIBDAVFUSE_OBJ}: ${GEN_HEADERS_LIBDAVFUSE} ${MAKEFILES}
${LIBDAVFUSE_TARGET}: ${LIBDAVFUSE_OBJ} ${MAKEFILES}

# basic compilation rules

$(filter %.c.o,${STATIC_OBJS}):
	@mkdir -p $(dir $@)
	@${MAKEDEPEND_CC}
	@echo CC $(patsubst %.o,%,$(notdir $@))
	@${CC} -I$(dir $@)../headers ${CPPFLAGS} ${CFLAGS} -c -o $@ ${SRCROOT}/$(patsubst %.o,%,$(notdir $@))

$(filter %.cpp.o,${STATIC_OBJS}):
	@mkdir -p $(dir $@)
	@${MAKEDEPEND_CXX}
	@echo CXX $(patsubst %.o,%,$(notdir $@))
	@${CXX} -I$(dir $@)../headers ${CPPFLAGS} ${CXXFLAGS} -c -o $@ ${SRCROOT}/$(patsubst %.o,%,$(notdir $@))

$(filter %.c.o,${DYNAMIC_OBJS}):
	@mkdir -p $(dir $@)
	@${MAKEDEPEND_CC}
	@echo CC $(patsubst %.o,%,$(notdir $@))
	@${CC} -I$(dir $@)../headers ${CPPFLAGS} ${CFLAGS} ${CFLAGS_DYN} -c -o $@ ${SRCROOT}/$(patsubst %.o,%,$(notdir $@))

$(filter %.cpp.o,${DYNAMIC_OBJS}):
	@mkdir -p $(dir $@)
	@${MAKEDEPEND_CXX}
	@echo CXX $(patsubst %.o,%,$(notdir $@))
	@${CXX} -I$(dir $@)../headers ${CPPFLAGS} ${CXXFLAGS} ${CFLAGS_DYN} -c -o $@ ${SRCROOT}/$(patsubst %.o,%,$(notdir $@))

# http_server_test_main rules

${GEN_HEADERS_HTTP_SERVER_TEST_MAIN}:
	@mkdir -p $(dir $@)
	@echo Generating $(notdir $@)
	@${HTTP_SERVER_TEST_MAIN_IFACE_DEFS} sh generate-interface-implementation.sh $(patsubst %.h,%,$(notdir $@)) > $@

${HTTP_SERVER_TEST_MAIN_TARGET}:
	@mkdir -p $(dir $@)
	@echo Linking $(notdir $@)
	@${CC} -o $@ ${HTTP_SERVER_TEST_MAIN_OBJ} ${LDFLAGS} ${SOCKETS_LIBS}

# libwedav_server_sockets_fs.a rules

${GEN_HEADERS_LIBWEBDAV_SERVER_SOCKETS_FS}:
	@mkdir -p $(dir $@)
	@echo Generating $(notdir $@)
	@${LIBWEBDAV_SERVER_SOCKETS_FS_IFACE_DEFS} sh generate-interface-implementation.sh $(patsubst %.h,%,$(notdir $@)) > $@

${LIBWEBDAV_SERVER_SOCKETS_FS_TARGET}:
	@mkdir -p $(dir $@)
	@echo Linking $(notdir $@)
	@${AR} rcs $@ ${LIBWEBDAV_SERVER_SOCKETS_FS_OBJ}

# webdav_server_sockets_fs_main rules

${GEN_HEADERS_WEBDAV_SERVER_SOCKETS_FS_MAIN}:
	@mkdir -p $(dir $@)
	@echo Generating $(notdir $@)
	@${WEBDAV_SERVER_SOCKETS_FS_MAIN_IFACE_DEFS} sh generate-interface-implementation.sh $(patsubst %.h,%,$(notdir $@)) > $@

${WEBDAV_SERVER_SOCKETS_FS_MAIN_TARGET}:
	@mkdir -p $(dir $@)
	@echo Linking $(notdir $@)
	@${CC} ${WEBDAV_SERVER_CLINKFLAGS} ${CFLAGS} -o $@ ${WEBDAV_SERVER_SOCKETS_FS_MAIN_OBJ} ${WEBDAV_LIBS} ${SOCKETS_LIBS}

# libdavfuse rules

${GEN_HEADERS_LIBDAVFUSE}:
	@mkdir -p $(dir $@)
	@echo Generating $(notdir $@)
	@${LIBDAVFUSE_IFACE_DEFS} sh generate-interface-implementation.sh $(patsubst %.h,%,$(notdir $@)) > $@

${LIBDAVFUSE_TARGET}:
	@mkdir -p $(dir $@)
	@echo Linking $(notdir $@)
	@${LINK_COMMAND} ${LINK_FLAG_NAME} $(notdir $@) $(if ${LINK_FLAG_VERSION_SCRIPT}, ${LINK_FLAG_VERSION_SCRIPT} fuse_versionscript) ${LIBDAVFUSE_EXTRA_LINK_ARGS} -o $@ ${LIBDAVFUSE_OBJ} ${LDFLAGS} ${WEBDAV_LIBS} ${SOCKETS_LIBS}

# davfuse rules

${DAVFUSE_TARGET}: ${LIBDAVFUSE_TARGET} generate-davfuse.sh ${MAKEFILES} 
	@mkdir -p $(dir $@)
	@echo Running generate-davfuse.sh...
	@PRIVATE_LIBDIR=. sh generate-davfuse.sh > $@
	@chmod a+x $@

# for dependency auto generateion
DEPDIR = $(dir $@)../deps
df = ${DEPDIR}/${*F}
MAKEDEPEND_CC = \
    mkdir -p ${DEPDIR}; \
    ${CC} -M -MT $@ -I$(dir $@)../headers ${CPPFLAGS} ${CFLAGS} -o ${df}.d $<; \
    CMD=`printf ':a\n s;/\./;/; \n s;//;/; \n s;/[^/][^/]*/\.\./;/; \n s;/[^/][^/]*/\.\.$$;/; \n ta'`; \
    sed -e "$$CMD" < ${df}.d > ${df}.c.P; \
    rm -f ${df}.d

MAKEDEPEND_CC_WDM = \
    mkdir -p ${DEPDIR}; \
    ${CC} -M -MT $@ -I$(OUTROOT)/libwebdav_server_sockets_fs/headers -I$(dir $@)../headers ${CPPFLAGS} ${CFLAGS} -o ${df}.d $<; \
    CMD=`printf ':a\n s;/\./;/; \n s;//;/; \n s;/[^/][^/]*/\.\./;/; \n s;/[^/][^/]*/\.\.$$;/; \n ta'`; \
    sed -e "$$CMD" < ${df}.d > ${df}.c.P; \
    rm -f ${df}.d

MAKEDEPEND_CXX = \
    mkdir -p ${DEPDIR}; \
    ${CXX} -M -MT $@ -I$(dir $@)../headers ${CPPFLAGS} ${CXXFLAGS} -o ${df}.d $<; \
    CMD=`printf ':a\n s;/\./;/; \n s;//;/; \n s;/[^/][^/]*/\.\./;/; \n s;/[^/][^/]*/\.\.$$;/; \n ta'`; \
    sed -e "$$CMD" < ${df}.d > ${df}.cpp.P; \
    rm -f ${df}.d

-include $(HTTP_SERVER_TEST_MAIN_SRC:%=${OUTROOT}/http_server_test_main/deps/%.P)
-include $(WEBDAV_SERVER_SOCKETS_FS_MAIN_SRC:%=${OUTROOT}/webdav_server_sockets_fs_main/deps/%.P)
-include $(LIBDAVFUSE_SRC:%=${OUTROOT}/libdavfuse/deps/%.P)

.PHONY: all options webdav_server_sockets_fs_main libdavfuse http_server_test_main
