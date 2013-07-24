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
