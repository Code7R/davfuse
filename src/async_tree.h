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

#ifndef ASYNC_TREE_H
#define ASYNC_TREE_H

#include "util.h"

typedef void (*async_tree_apply_fn_t)(void *user_data,
                                      void *elt,
                                      event_handler_t cb, void *ud);

typedef void (*async_tree_expand_fn_t)(void *user_data,
                                       linked_list_t stack,
                                       void *elt,
                                       event_handler_t cb, void *ud);

typedef struct {
  bool error;
  linked_list_t new_stack;
} AsyncTreeExpandFnDoneEvent;

typedef struct {
  bool error;
} AsyncTreeApplyFnDoneEvent;


void
async_tree_apply(void *op_ud,
                 async_tree_apply_fn_t apply_fn,
                 async_tree_expand_fn_t expand_fn,
                 void *root,
                 bool is_postorder,
                 event_handler_t cb, void *cb_ud);

#endif
