#!/bin/sh
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

LOOKUP=$(echo "$1" | tr '[a-z]' '[A-Z]')
eval "TRIPLE=\${${LOOKUP}_DEF}"

if [ -z "$TRIPLE" ]; then
    echo "Interface file \"${LOOKUP}_DEF\" was not defined"  > /dev/stderr
    exit 255
fi

USER=$(echo "$TRIPLE" | sed 's|\([^/]*\)/\([^/]*\)/\([^/]*\)|\1|')
IFACE=$(echo "$TRIPLE" | sed 's|\([^/]*\)/\([^/]*\)/\([^/]*\)|\2|')
IMPL=$(echo "$TRIPLE" | sed 's|\([^/]*\)/\([^/]*\)/\([^/]*\)|\3|')

if [ -z "$2" ]; then
    IDEF_PATH="src/${IFACE}.idef"
else
    IDEF_PATH="$2"
fi


if ! (echo "$USER" | grep "^[a-z]\([a-z_0-9]*[a-z0-9]\)\{0,1\}$" > /dev/null); then
    echo "Bad user name: $USER" > /dev/stderr
    exit 255
fi

if ! (echo "$IFACE" | grep "^[a-z]\([a-z_0-9]*[a-z0-9]\)\{0,1\}$" > /dev/null); then
    echo "Bad interface name: $IFACE" > /dev/stderr
    exit 255
fi

if ! (echo "$IMPL" | grep "^[a-z]\([a-z_0-9]*[a-z0-9]\)\{0,1\}$" > /dev/null); then
    echo "Bad implementation name: $IMPL" > /dev/stderr
    exit 255
fi

USER_UPPER=$(echo "$USER" | tr '[a-z]' '[A-Z]')
IFACE_UPPER=$(echo "$IFACE" | tr '[a-z]' '[A-Z]')
IMPL_UPPER=$(echo "$IMPL" | tr '[a-z]' '[A-Z]')

USER_TITLE=$(echo "$USER" | perl -pe 's/^([a-z])/\U$1/' | perl -pe 's/_([a-z])/\U$1/g')
IFACE_TITLE=$(echo "$IFACE" | perl -pe 's/^([a-z])/\U$1/' | perl -pe 's/_([a-z])/\U$1/g')
IMPL_TITLE=$(echo "$IMPL" | perl -pe 's/^([a-z])/\U$1/' | perl -pe 's/_([a-z])/\U$1/g')

HEADER_FILE="${USER}_${IFACE}"

if which md5sum > /dev/null; then
    IMPL_HASH=0x$(echo "$IMPL" | md5sum | cut -b 1-8)
elif which md5 > /dev/null; then
    IMPL_HASH=0x$(echo "$IMPL" | md5 | cut -b 1-8)
else
    echo "No MD5 program available!" > /dev/stderr
    exit 255
fi

cat <<EOF
/* AUTOMATICALLY GENERATED from "$IDEF_PATH" on $(date),
   DO NOT EDIT MANUALLY */
#ifndef __${USER}_${IFACE}_h
#define __${USER}_${IFACE}_h

#include "${IFACE}_${IMPL}.h"

#ifdef __${IFACE}_HEADER

#if __${IFACE}_HEADER != ${IMPL_HASH}
#error "Multiple implementations of the '${IFACE}' interface included. This one is '${IMPL}'."
#endif

#else

#define __${IFACE}_HEADER ${IMPL_HASH}

EOF

export PARENT_PID=$$
cat "$IDEF_PATH" | (
    REGEX='^ *\([a-zA-Z]\([0-9a-zA-Z_]*[0-9a-zA-Z]\)\{0,1\}\)\{0,1\} *\(# *\(.*\) *\)\{0,1\}$'
    while read LINE; do
        if ! ( echo "$LINE" | grep "$REGEX" > /dev/null ); then
            # bad file
            echo "Bad line syntax: $LINE" > /dev/stderr
            kill "$PARENT_PID";
        fi
        COMMENT=$(echo "$LINE" | sed "s/${REGEX}/\4/g")
        if [ ! -z "$COMMENT" ]; then
            echo "/* $COMMENT */"
        fi

        SYMBOL=$(echo "$LINE" | sed "s/${REGEX}/\1/g")
        if [ -z "$SYMBOL" ]; then
            if [ -z "$COMMENT" ]; then
                echo
            fi
            continue
        fi

        if echo "$SYMBOL" | grep "^[A-Z_]\{1,\}$" > /dev/null; then
            # it's all uppercase, generate an uppercase SYMBOL
            echo "#define ${IFACE_UPPER}_${SYMBOL} ${IFACE_UPPER}_${IMPL_UPPER}_${SYMBOL}"
        elif echo "$SYMBOL" | grep "^[A-Z][a-z]" > /dev/null; then
            echo "#define ${IFACE_TITLE}${SYMBOL} ${IFACE_TITLE}${IMPL_TITLE}${SYMBOL}"
        else
            echo "#define ${IFACE}_${SYMBOL} ${IFACE}_${IMPL}_${SYMBOL}"
        fi
    done;
    )

cat <<EOF

#endif

#define ${USER_UPPER}_${IFACE_UPPER}_IMPL ${IFACE_UPPER}_${IMPL_UPPER}_IMPL

#endif
EOF

