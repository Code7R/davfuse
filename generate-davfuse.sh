#!/bin/sh

cat <<EOF
#!/bin/sh

# A simple script to wrap FUSE programs and run them as WebDAV Servers
# Usage:
#	davfuse <command> <command options and arguments>

LD_PRELOAD=${LIBDIR}/libdavfuse.so\${LD_PRELOAD:+:\$LD_PRELOAD} exec "\$@"
EOF
