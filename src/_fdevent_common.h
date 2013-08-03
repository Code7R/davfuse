#ifndef FDEVENT_COMMON_H
#define FDEVENT_COMMON_H

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

typedef struct {
  fdevent_loop_t loop;
  fd_t fd;
  StreamEvents events;
} FDEvent;

fdevent_loop_t
fdevent_new();

bool
fdevent_add_watch(fdevent_loop_t loop,
                  fd_t fd,
                  StreamEvents events,
                  event_handler_t handler,
                  void *ud,
                  fd_event_watch_key_t *key);

bool
fdevent_remove_watch(fdevent_loop_t wt,
                     fd_event_watch_key_t key);

bool
fdevent_main_loop(fdevent_loop_t loop);

void
fdevent_destroy(fdevent_loop_t loop);

#endif /* FDEVENT_COMMON_H */
