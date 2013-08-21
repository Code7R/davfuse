#ifndef FDEVENT_SELECT_H
#define FDEVENT_SELECT_H

#include <stdbool.h>

#include "c_util.h"
#include "events.h"
#include "fdevent_select_sockets.h"
#include "iface_util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* event subsystem */

/* forward decl */
struct _fd_event_loop;
struct _fdevent_link;

typedef struct _fd_event_loop *fdevent_select_loop_t;
typedef struct _fdevent_link *fdevent_select_watch_key_t;

#define _INCLUDE_FDEVENT_COMMON_H
#include "_fdevent_common.h"
#undef _INCLUDE_FDEVENT_COMMON_H

typedef struct {
  fdevent_select_loop_t loop;
  fd_t fd;
  StreamEvents events;
} FdeventSelectEvent;

#define FDEVENT_SELECT_INVALID_WATCH_KEY NULL

fdevent_select_loop_t
fdevent_select_default_new();

bool
fdevent_select_add_watch(fdevent_select_loop_t loop,
                         fd_t fd,
                         StreamEvents events,
                         event_handler_t handler,
                         void *ud,
                         fdevent_select_watch_key_t *key);

bool
fdevent_select_remove_watch(fdevent_select_loop_t wt,
                            fdevent_select_watch_key_t key);

bool
fdevent_select_main_loop(fdevent_select_loop_t loop);

bool
fdevent_select_destroy(fdevent_select_loop_t loop);

CREATE_IMPL_TAG(FDEVENT_SELECT_IMPL);

#ifdef __cplusplus
}
#endif

#endif
