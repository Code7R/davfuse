#ifndef FDEVENT_COMMON_H
#define FDEVENT_COMMON_H

#ifndef FDEVENT_LOOP
#error "must define FDEVENT_LOOP before including this file!"
#endif

#include <stdbool.h>

#include "c_util.h"

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

typedef struct {
  FDEVENT_LOOP *loop;
  int fd;
  StreamEvents events;
} FDEvent;

#endif /* FDEVENT_COMMON_H */
