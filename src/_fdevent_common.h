#ifndef _INCLUDE_FDEVENT_COMMON_H
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
