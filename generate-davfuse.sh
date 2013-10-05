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
