#ifndef EVENTS_H
#define EVENTS_H

/* all events types go here,
   the benefits of writing all your own code */
   
typedef enum {
  HTTP_NEW_REQUEST_EVENT,
  HTTP_REQUEST_READ_HEADERS_DONE_EVENT,
  HTTP_REQUEST_READ_DONE_EVENT,
  HTTP_REQUEST_WRITE_HEADERS_DONE_EVENT,
  HTTP_REQUEST_WRITE_DONE_EVENT,
  HTTP_END_REQUEST_EVENT,
  START_COROUTINE_EVENT,
  C_FBGETC_DONE_EVENT,
  C_FBPEEK_DONE_EVENT,
  C_GETWHILE_DONE_EVENT,
  FD_EVENT,
  C_WRITEALL_DONE_EVENT,
  C_READ_DONE_EVENT,
} event_type_t;

typedef void (*event_handler_t)(event_type_t, void *, void *);

#endif /* EVENTS_H */
