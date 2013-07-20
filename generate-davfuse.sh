#!/bin/sh

# The headers
cat <<EOF
#!/bin/sh

# A simple script to wrap FUSE programs and run them as WebDAV Servers
# Usage:
#	davfuse <command> <command options and arguments>

EOF

UNAME=`uname`
if [ "${UNAME}x" = "Darwinx" ]; then
    cat <<EOF
DYLD_LIBRARY_PATH=${PRIVATE_LIBDIR}\${DYLD_LIBRARY_PATH:+:\$DYLD_LIBRARY_PATH} exec "\$@"
EOF
elif [ "${UNAME}x" = "Linuxx" ]; then
    cat <<EOF
LD_LIBRARY_PATH=${PRIVATE_LIBDIR}\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH} exec "\$@"
EOF
fi
