#ifndef FDEVENT_SELECT_H
#define FDEVENT_SELECT_H

#include <stdbool.h>

#include "c_util.h"
#include "events.h"
#include "socket.h"

/* event subsystem */

/* forward decl */
struct _fd_event_loop;
struct _fdevent_link;

typedef struct _fd_event_loop *fdevent_loop_t;
typedef struct _fdevent_link *fd_event_watch_key_t;

#define FD_EVENT_INVALID_WATCH_KEY NULL

#define _INCLUDE_FDEVENT_COMMON_H
#include "_fdevent_common.h"
#undef _INCLUDE_FDEVENT_COMMON_H


#endif
