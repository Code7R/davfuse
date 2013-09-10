davfuse: FUSE file systems as WebDAV servers
============================================

davfuse is a utility that allows you to transparently turn FUSE file systems
into WebDAV servers. On systems that natively support mounting WebDAV servers,
like Mac OS X, it conveniently serves as an alternative to using the FUSE
kernel driver (via mounting "localhost").

It provides a library `libdavfuse` that emulates the necessary components
of the native FUSE library, `libfuse`. It also provides a wrapper script,
`davfuse`, that configures the system runtime linker to link against
`libdavfuse` instead of `libfuse` when running a FUSE file system.

When distributing applications based on FUSE file systems, you can link
directly against the library, or statically compile in each source file.
The advantage here is that you can drop a kernel module dependency for your
application if your system native supports mounting WebDAV servers.

Usage
-----

Using davfuse via the command line is simple and fun! Here we use it
with the wonderful encfs program.

    $ davfuse encfs ~/.private ~/private

Test with `curl` (store a file called foo on your FUSE file system):

    $ cat <<EOF | curl -T - 'http://localhost/foo.txt'
    fizz buzz
    EOF

Compiling
---------

Compiling davfuse is simple and fun!

    $ cp config-linux-glibc-gcc.mk config.mk # customize for your system :)
    $ make RELEASE=1 davfuse

Copyright
---------

davfuse: FUSE file systems as WebDAV servers
Copyright (C) 2012, 2013 Rian Hunter <rian@alum.mit.edu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lessage General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
