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

IFACE_SYNONYM="$1"
IFACE_SYNONYM_UPPER=$(echo "$IFACE_SYNONYM" | tr '[a-z]' '[A-Z]')

if [ -z "$IFACE_SYNONYM" ]; then
    echo "Interface not found: $1"  > /dev/stderr
fi

eval "IFACE_CFG=\${${IFACE_SYNONYM_UPPER}_DEF}"

if echo "$IFACE_CFG" | grep "/" > /dev/null; then
    IMPL=$(echo "$IFACE_CFG" | sed 's|^\([a-z_0-9]\{1,\}\)/\([a-z_0-9]\{1,\}\)$|\1|')
    IFACE=$(echo "$IFACE_CFG" | sed 's|^\([a-z_0-9]\{1,\}\)/\([a-z_0-9]\{1,\}\)$|\2|')
else
    IMPL="$IFACE_CFG"
    IFACE="$IFACE_SYNONYM"
fi

if [ -z "$IMPL" ]; then
    echo "Implementation not found for interface: ${IFACE_CFG}" > /dev/stderr
    echo > /dev/stderr
    env | grep "_DEF=" > /dev/stderr
    exit 255
fi

if [ -z "$2" ]; then
    IDEF_PATH="src/${IFACE}.idef"
else
    IDEF_PATH="$2"
fi

IFACE_UPPER=$(echo "$IFACE" | tr '[a-z]' '[A-Z]')
IMPL_UPPER=$(echo "$IMPL" | tr '[a-z]' '[A-Z]')

IFACE_SYNONYM_TITLE=$(echo "$IFACE_SYNONYM" | perl -pe 's/^([a-z])/\U$1/' | perl -pe 's/_([a-z])/\U$1/g')
IFACE_TITLE=$(echo "$IFACE" | perl -pe 's/^([a-z])/\U$1/' | perl -pe 's/_([a-z])/\U$1/g')
IMPL_TITLE=$(echo "$IMPL" | perl -pe 's/^([a-z])/\U$1/' | perl -pe 's/_([a-z])/\U$1/g')

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
#ifndef __${IFACE_SYNONYM}_h
#define __${IFACE_SYNONYM}_h

#include "${IFACE}_${IMPL}.h"

#ifdef __${IFACE_SYNONYM}_HEADER

#if __${IFACE_SYNONYM}_HEADER != ${IMPL_HASH}
#error "Multiple implementations of the '${IFACE_SYNONYM}' interface included. This one is '${IMPL}'."
#endif

#else

#define __${IFACE_SYNONYM}_HEADER ${IMPL_HASH}

EOF

# first do a C++ style header
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
            # this is a constant
            echo "#ifdef __cplusplus"
            echo "const auto ${IFACE_SYNONYM_UPPER}_${SYMBOL} = ${IFACE_UPPER}_${IMPL_UPPER}_${SYMBOL};"
            echo "#else"
            echo "#define ${IFACE_SYNONYM_UPPER}_${SYMBOL} ${IFACE_UPPER}_${IMPL_UPPER}_${SYMBOL}"
            echo "#endif"
        elif echo "$SYMBOL" | grep "^[A-Z][a-z]" > /dev/null; then
            # this is a struct
            echo "typedef ${IFACE_TITLE}${IMPL_TITLE}${SYMBOL} ${IFACE_SYNONYM_TITLE}${SYMBOL};"
        elif echo "$SYMBOL" | grep "\\(^\\|_\\)t$" > /dev/null; then
            # this is a integral type
            echo "typedef ${IFACE}_${IMPL}_${SYMBOL} ${IFACE_SYNONYM}_${SYMBOL};"
        else
            # this is a function
            echo "#ifdef __cplusplus"
            echo "const auto ${IFACE_SYNONYM}_${SYMBOL} = ${IFACE}_${IMPL}_${SYMBOL};"
            echo "#else"
            echo "#define ${IFACE_SYNONYM}_${SYMBOL} ${IFACE}_${IMPL}_${SYMBOL}"
            echo "#endif"
        fi
    done;
    )

cat <<EOF

#endif

#define ${IFACE_SYNONYM_UPPER}_IMPL ${IFACE_UPPER}_${IMPL_UPPER}_IMPL

#endif
EOF

