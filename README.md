davfuse
=======

davfuse is a utility that allows you to transparently turn
[FUSE](http://fuse.sf.net/) file systems
into [WebDAV](http://webdav.org/) servers. On systems that
natively support mounting WebDAV servers,
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
with the wonderful [encfs](http://www.arg0.net/encfs) program.

    $ davfuse encfs ~/.private ~/private

Test with `curl` (store a file called foo on your FUSE file system):

    $ cat <<EOF | curl -T - 'http://localhost:8080/foo.txt'
    fizz buzz
    EOF

Platform Support
----------------

davfuse has been compiled and tested on Mac OS X 10.8 and Debian Wheezy
GNU/Linux. The author has no reason to believe that it should not
compile and run on other versions of Mac OS X and GNU/Linux but YMMV.
Additionally, The pure WebDAV component has been compiled and run
on Windows XP and Windows 7 using [MinGW](http://mingw.org/).

Compiling
---------

Compiling davfuse is simple and fun!

    $ cp config-linux-glibc-gcc.mk config.mk # customize for your system :)
    $ make RELEASE=1 davfuse

Binaries will be places in `out/targets`.

Also included is a test WebDAV server, it'll build on Windows (using MinGW) :)

    $ make RELEASE=1 webdav_server_fs_main

Copyright
---------

All files except those excluded below are copyrighted under the following notice:

    davfuse: FUSE file systems as WebDAV servers
    Copyright (C) 2012, 2013 Rian Hunter <rian@alum.mit.edu>
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.
    
    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>

Regarding inclusion of `fuse.h`, `fuse_common.h`, `fuse_opt.h` and `fuse_versionscript`:

    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.
    
    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>

Regarding inclusion of `tinyxml2.cpp` and `tinyxml2.h`:

    Original code by Lee Thomason (www.grinninglizard.com)
    
    This software is provided 'as-is', without any express or implied
    warranty. In no event will the authors be held liable for any
    damages arising from the use of this software.

    Permission is granted to anyone to use this software for any
    purpose, including commercial applications, and to alter it and
    redistribute it freely, subject to the following restrictions:

    1. The origin of this software must not be misrepresented; you must
    not claim that you wrote the original software. If you use this
    software in a product, an acknowledgment in the product documentation
    would be appreciated but is not required.
    
    
    2. Altered source versions must be plainly marked as such, and
    must not be misrepresented as being the original software.
    
    3. This notice may not be removed or altered from any source
    distribution.
