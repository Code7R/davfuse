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

unique_fn = $(shell echo $(1) | tr ' ' '\n' | sort | uniq | tr '\n' ' ')

ifdef USE_DYNAMIC_FS
MAIN_FS_IMPL := dynamic
else
MAIN_FS_IMPL := $(FS_IMPL)
endif

OUTROOT := $(if ${RELEASE}, out-release, out)
TARGETROOT := ${OUTROOT}/targets
SRCROOT := src

CPPFLAGS += -I${SRCROOT}

# Different xml backends for the webdav server
WEBDAV_SERVER_XML_IMPL := webdav_server_xml_tinyxml2.cpp tinyxml2.cpp
WEBDAV_LIBS := ${CXX_LIBS}

MAKEFILES := config.mk GNUmakefile

HTTP_SERVER_SRC := http_server.c coroutine_io.c logging.c util.c \
	http_helpers.c util_event_loop.c \
	util_sockets.c uptime_${UPTIME_IMPL}.c \
	event_loop_${EVENT_LOOP_IMPL}.c sockets_${SOCKETS_IMPL}.c \
	log_printer_${LOG_PRINTER_IMPL}.c
GEN_HEADERS_HTTP_SERVER := \
    event_loop.h \
    sockets.h \
    log_printer.h \
    uptime.h \
    ${EVENT_LOOP_IMPL_EXTRA_GEN_HEADERS}
HTTP_SERVER_IFACE_DEFS := \
    EVENT_LOOP_DEF=${EVENT_LOOP_IMPL} \
    SOCKETS_DEF=${SOCKETS_IMPL} \
    LOG_PRINTER_DEF=${LOG_PRINTER_IMPL} \
    UPTIME_DEF=${UPTIME_IMPL} \
    ${EVENT_LOOP_IMPL_EXTRA_IFACE_DEFS}

WEBDAV_SERVER_SRC := webdav_server.c ${WEBDAV_SERVER_XML_IMPL}

# http_server_test_main vars

HTTP_SERVER_TEST_MAIN_SRC := http_server_test_main.c ${HTTP_SERVER_SRC}
GEN_HEADERS_HTTP_SERVER_TEST_MAIN_ := ${GEN_HEADERS_HTTP_SERVER}
HTTP_SERVER_TEST_MAIN_IFACE_DEFS := ${HTTP_SERVER_IFACE_DEFS}

GEN_HEADERS_HTTP_SERVER_TEST_MAIN := $(call unique_fn,$(patsubst %,${OUTROOT}/http_server_test_main/headers/%,${GEN_HEADERS_HTTP_SERVER_TEST_MAIN_}))
HTTP_SERVER_TEST_MAIN_OBJ := $(patsubst %,${OUTROOT}/http_server_test_main/obj/%.o,${HTTP_SERVER_TEST_MAIN_SRC})

HTTP_SERVER_TEST_MAIN_TARGET := ${TARGETROOT}/http_server_test_main

# libwebdav_server_fs.a vars

LIBWEBDAV_SERVER_FS_SRC_ = \
    ${HTTP_SERVER_SRC} \
    ${WEBDAV_SERVER_SRC} \
    webdav_backend_fs.c \
    util_fs.c \
    dfs.c \
    fs_${FS_IMPL}.c \
    fs_${MAIN_FS_IMPL}.c \
    ${FS_IMPL_EXTRA_SOURCES}
GEN_HEADERS_LIBWEBDAV_SERVER_FS_ := \
    webdav_backend.h \
    fs.h \
    fs_native.h \
    ${EVENT_LOOP_IMPL_EXTRA_GEN_HEADERS} \
    ${FS_IMPL_EXTRA_GEN_HEADERS} \
    ${GEN_HEADERS_HTTP_SERVER}
LIBWEBDAV_SERVER_FS_IFACE_DEFS := \
    WEBDAV_BACKEND_DEF=fs \
    FS_DEF=${MAIN_FS_IMPL} \
    FS_NATIVE_DEF=${FS_IMPL}/fs \
    ${FS_IMPL_EXTRA_IFACE_DEFS} \
    ${HTTP_SERVER_IFACE_DEFS}

LIBWEBDAV_SERVER_FS_SRC = $(call unique_fn,$(LIBWEBDAV_SERVER_FS_SRC_))
GEN_HEADERS_LIBWEBDAV_SERVER_FS = $(call unique_fn,$(patsubst %,${OUTROOT}/libwebdav_server_fs/headers/%,${GEN_HEADERS_LIBWEBDAV_SERVER_FS_}))
LIBWEBDAV_SERVER_FS_OBJ := $(patsubst %,${OUTROOT}/libwebdav_server_fs/obj/%.o,${LIBWEBDAV_SERVER_FS_SRC})

LIBWEBDAV_SERVER_FS_TARGET := ${TARGETROOT}/libwebdav_server_fs.a

# webdav_server_fs_main vars

WEBDAV_SERVER_FS_MAIN_SRC := \
    ${LIBWEBDAV_SERVER_FS_SRC} \
    webdav_server_fs_main.c
GEN_HEADERS_WEBDAV_SERVER_FS_MAIN_ := \
    ${GEN_HEADERS_LIBWEBDAV_SERVER_FS_}
WEBDAV_SERVER_FS_MAIN_IFACE_DEFS := \
    ${LIBWEBDAV_SERVER_FS_IFACE_DEFS}

GEN_HEADERS_WEBDAV_SERVER_FS_MAIN = $(call unique_fn,$(patsubst %,${OUTROOT}/webdav_server_fs_main/headers/%,${GEN_HEADERS_WEBDAV_SERVER_FS_MAIN_}))
WEBDAV_SERVER_FS_MAIN_OBJ := $(patsubst %,${OUTROOT}/webdav_server_fs_main/obj/%.o,${WEBDAV_SERVER_FS_MAIN_SRC})

WEBDAV_SERVER_FS_MAIN_TARGET := ${TARGETROOT}/webdav_server_fs_main

# libdavfuse vars

LIBDAVFUSE_SRC := \
    libdavfuse.c async_fuse_fs.c \
    async_fuse_fs_helpers.c async_rdwr_lock.c async_tree.c \
    fd_utils.c \
    ${HTTP_SERVER_SRC} \
    ${WEBDAV_SERVER_SRC} webdav_backend_async_fuse.c
GEN_HEADERS_LIBDAVFUSE_ := \
    webdav_backend.h \
    ${GEN_HEADERS_HTTP_SERVER}
LIBDAVFUSE_IFACE_DEFS := \
    WEBDAV_BACKEND_DEF=async_fuse \
    ${HTTP_SERVER_IFACE_DEFS}

GEN_HEADERS_LIBDAVFUSE = $(call unique_fn,$(patsubst %,${OUTROOT}/libdavfuse/headers/%,${GEN_HEADERS_LIBDAVFUSE_}))
LIBDAVFUSE_OBJ := $(patsubst %,${OUTROOT}/libdavfuse/obj/%.o,${LIBDAVFUSE_SRC})

LIBDAVFUSE_TARGET := ${TARGETROOT}/${LIBDAVFUSE_FILE_NAME}

# davfuse vars

DAVFUSE_TARGET := ${TARGETROOT}/davfuse

STATIC_OBJS = \
	${LIBWEBDAV_SERVER_FS_OBJ} \
        ${WEBDAV_SERVER_FS_MAIN_OBJ} \
	${HTTP_SERVER_TEST_MAIN_OBJ}
DYNAMIC_OBJS = ${LIBDAVFUSE_OBJ}

all: options \
    ${HTTP_SERVER_TEST_MAIN_TARGET} \
    ${LIBWEBDAV_SERVER_FS_TARGET} \
    ${WEBDAV_SERVER_FS_MAIN_TARGET} \
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
libwebdav_server_fs.a: options ${LIBWEBDAV_SERVER_FS_TARGET}
webdav_server_fs_main: options ${WEBDAV_SERVER_FS_MAIN_TARGET}
libdavfuse: options ${LIBDAVFUSE_TARGET}
davfuse: options ${DAVFUSE_TARGET}

# dependencies

${OUTROOT}/*/headers/event_loop.h: ${SRCROOT}/event_loop.idef
${OUTROOT}/*/headers/fs.h: ${SRCROOT}/fs.idef
${OUTROOT}/*/headers/fstatat.h: ${SRCROOT}/fstatat.idef
${OUTROOT}/*/headers/log_printer.h: ${SRCROOT}/log_printer.idef
${OUTROOT}/*/headers/sockets.h: ${SRCROOT}/sockets.idef
${OUTROOT}/*/headers/webdav_backend.h: ${SRCROOT}/webdav_backend.idef
${OUTROOT}/*/headers/uptime.h: ${SRCROOT}/uptime.idef

${OUTROOT}/libwebdav_server_fs/headers/fs_native.h: ${SRCROOT}/fs.idef

${GEN_HEADERS_HTTP_SERVER_TEST_MAIN} \
    ${GEN_HEADERS_LIBWEBDAV_SERVER_FS} \
    ${GEN_HEADERS_WEBDAV_SERVER_FS_MAIN} \
    ${GEN_HEADERS_LIBDAVFUSE}: generate-interface-implementation.sh ${MAKEFILES}

${HTTP_SERVER_TEST_MAIN_OBJ}: \
    ${OUTROOT}/http_server_test_main/obj/%.c.o: ${SRCROOT}/%.c
${HTTP_SERVER_TEST_MAIN_OBJ}: \
    ${GEN_HEADERS_HTTP_SERVER_TEST_MAIN} \
    ${MAKEFILES}
${HTTP_SERVER_TEST_MAIN_TARGET}: ${HTTP_SERVER_TEST_MAIN_OBJ} ${MAKEFILES}

$(filter %.c.o,${LIBWEBDAV_SERVER_FS_OBJ}): \
    ${OUTROOT}/libwebdav_server_fs/obj/%.c.o: ${SRCROOT}/%.c
$(filter %.cpp.o,${LIBWEBDAV_SERVER_FS_OBJ}): \
    ${OUTROOT}/libwebdav_server_fs/obj/%.cpp.o: ${SRCROOT}/%.cpp
${LIBWEBDAV_SERVER_FS_OBJ}: \
    ${GEN_HEADERS_LIBWEBDAV_SERVER_FS} \
    ${MAKEFILES}
${LIBWEBDAV_SERVER_FS_TARGET}: ${LIBWEBDAV_SERVER_FS_OBJ} ${MAKEFILES}

$(filter %.c.o,${WEBDAV_SERVER_FS_MAIN_OBJ}): \
    ${OUTROOT}/webdav_server_fs_main/obj/%.c.o: ${SRCROOT}/%.c
$(filter %.cpp.o,${WEBDAV_SERVER_FS_MAIN_OBJ}): \
    ${OUTROOT}/webdav_server_fs_main/obj/%.cpp.o: ${SRCROOT}/%.cpp
${WEBDAV_SERVER_FS_MAIN_OBJ}: \
    ${GEN_HEADERS_WEBDAV_SERVER_FS_MAIN} \
    ${MAKEFILES}
${WEBDAV_SERVER_FS_MAIN_TARGET}: \
	${WEBDAV_SERVER_FS_MAIN_OBJ} \
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

${GEN_HEADERS_LIBWEBDAV_SERVER_FS}:
	@mkdir -p $(dir $@)
	@echo Generating $(notdir $@)
	@${LIBWEBDAV_SERVER_FS_IFACE_DEFS} sh generate-interface-implementation.sh $(patsubst %.h,%,$(notdir $@)) > $@

${LIBWEBDAV_SERVER_FS_TARGET}:
	@mkdir -p $(dir $@)
	@echo Linking $(notdir $@)
	@${AR} rcs $@ ${LIBWEBDAV_SERVER_FS_OBJ}

# webdav_server_fs_main rules

${GEN_HEADERS_WEBDAV_SERVER_FS_MAIN}:
	@mkdir -p $(dir $@)
	@echo Generating $(notdir $@)
	@${WEBDAV_SERVER_FS_MAIN_IFACE_DEFS} sh generate-interface-implementation.sh $(patsubst %.h,%,$(notdir $@)) > $@

${WEBDAV_SERVER_FS_MAIN_TARGET}:
	@mkdir -p $(dir $@)
	@echo Linking $(notdir $@)
	@${CC} ${WEBDAV_SERVER_CLINKFLAGS} ${CFLAGS} -o $@ ${WEBDAV_SERVER_FS_MAIN_OBJ} ${WEBDAV_LIBS} ${SOCKETS_LIBS}

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
    ${CC} -M -MT $@ -I$(OUTROOT)/libwebdav_server_fs/headers -I$(dir $@)../headers ${CPPFLAGS} ${CFLAGS} -o ${df}.d $<; \
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
-include $(WEBDAV_SERVER_FS_MAIN_SRC:%=${OUTROOT}/webdav_server_fs_main/deps/%.P)
-include $(LIBDAVFUSE_SRC:%=${OUTROOT}/libdavfuse/deps/%.P)

.PHONY: all options webdav_server_fs_main libdavfuse http_server_test_main libwebdav_server_fs.a
