#!/bin/sh

cat <<EOF
#!/bin/sh

# A simple script to wrap FUSE programs and run them as WebDAV Servers
# Usage:
#	davfuse <command> <command options and arguments>

LD_LIBRARY_PATH=${PRIVATE_LIBDIR}\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH} exec "\$@"
EOF
