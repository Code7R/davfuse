/*
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
 */

#ifndef _INCLUDE_EVENT_LOOP_COMMON_H
#error "DON'T INCLUDE THIS UNLESS YOU KNOW WHAT YOU'RE DOING"
#endif

typedef struct {
  bool read : 1;
  bool write : 1;
} StreamEvents;

/* Make this is a macro if too slow */
HEADER_FUNCTION CONST_FUNCTION StreamEvents
create_stream_events(bool read, bool write) {
  return (StreamEvents) {.read = read, .write = write};
}

HEADER_FUNCTION CONST_FUNCTION bool
stream_events_are_equal(StreamEvents a, StreamEvents b) {
  return a.read == b.read && a.write == b.write;
}
