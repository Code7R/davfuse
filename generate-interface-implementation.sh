#!/bin/sh

INTERFACE_DEF="$1"
INTERFACE=$(basename "$1" | sed 's/\..\{1,\}//')
INTERFACE_UPPER=$(echo "$INTERFACE" | tr '[a-z]' '[A-Z]')
eval "IMPLEMENTATION=\${${INTERFACE_UPPER}_IMPL}"

if ! (echo "$INTERFACE" | grep "^[a-z]\([a-z_]*[a-z]\)\{0,1\}$" > /dev/null); then
    echo "Bad interface name: $INTERFACE" > /dev/stderr
    exit -1
fi

if ! (echo "$IMPLEMENTATION" | grep "^[a-z]\([a-z_]*[a-z]\)\{0,1\}$" > /dev/null); then
    echo "Bad implementation name: $IMPLEMENTATION" > /dev/stderr
    exit -1
fi

IMPLEMENTATION_UPPER=$(echo "$IMPLEMENTATION" | tr '[a-z]' '[A-Z]')

INTERFACE_TITLE=$(echo "$INTERFACE" | perl -pe 's/^([a-z])/\U$1/' | perl -pe 's/_([a-z])/\U$1/')
IMPLEMENTATION_TITLE=$(echo "$IMPLEMENTATION" | perl -pe 's/^([a-z])/\U$1/' | perl -pe 's/_([a-z])/\U$1/')

cat <<EOF
/* AUTOMATICALLY GENERATED from "$INTERFACE_DEF" on $(date),
   DO NOT EDIT MANUALLY */
#ifndef __${INTERFACE}_h
#define __${INTERFACE}_h

#include "${INTERFACE}_${IMPLEMENTATION}.h"

EOF

export PARENT_PID=$$
cat "$INTERFACE_DEF" | (
    REGEX='^ *\([a-zA-Z]\([0-9a-zA-Z_]*[0-9a-zA-Z]\)\{0,1\}\)\{0,1\} *\(# *\(.*\) *\)\{0,1\}$'
    while read LINE; do
        if ! ( echo "$LINE" | grep "$REGEX" > /dev/null ); then
            # bad file
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

        if echo "$SYMBOL" | grep "^[A-Z_]*$" > /dev/null; then
            # it's all uppercase, generate an uppercase SYMBOL
            echo "#define ${INTERFACE_UPPER}_${SYMBOL} ${INTERFACE_UPPER}_${IMPLEMENTATION_UPPER}_${SYMBOL}"
        elif echo "$SYMBOL" | grep "^[A-Z][a-z]" > /dev/null; then
            echo "#define ${INTERFACE_TITLE}${SYMBOL} ${INTERFACE_TITLE}${IMPLEMENTATION_TITLE}${SYMBOL}"
        else
            echo "#define ${INTERFACE}_${SYMBOL} ${INTERFACE}_${IMPLEMENTATION}_${SYMBOL}"
        fi
        PRINTED_SYMBOL=1
    done;
    )

cat <<EOF

#endif
EOF

