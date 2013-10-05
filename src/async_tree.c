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

#include <inttypes.h>
#include <stdbool.h>

#include "uthread.h"
#include "util.h"

#include "async_tree.h"

typedef struct {
  UTHR_CTX_BASE;
  /* args */
  void *op_ud;
  async_tree_apply_fn_t apply_fn;
  async_tree_expand_fn_t expand_fn;
  void *root;
  bool is_postorder : 1;
  bool is_preorder_node : 1;
  event_handler_t cb;
  void *cb_ud;
  /* ctx */
  linked_list_t stack;
  linked_list_t old_stack;
  void *curnode;
  void *next;
} AsyncTreeApplyCtx;

static bool
pointer_is_preorder(void *p) {
  return !(((intptr_t) p) & 0x1);
}

static void *
make_pointer_postorder(void *p) {
  return (void *)(((intptr_t) p) | 0x1);
}

static void *
clear_pointer_postorder(void *p) {
  return (void *)(((intptr_t) p) & ~0x1);
}

UTHR_DEFINE(_async_tree_apply_uthr) {
  UTHR_HEADER(AsyncTreeApplyCtx, ctx);

  ctx->stack = linked_list_prepend(LINKED_LIST_INITIALIZER, ctx->root);

  while (ctx->stack) {
    ctx->stack = linked_list_popleft(ctx->stack, &ctx->curnode);

    /* first yield this node */
    ctx->is_preorder_node = pointer_is_preorder(ctx->curnode);
    ctx->next = clear_pointer_postorder(ctx->curnode);

    /* if this is pre-order then populate the stack with
       the post-order node and its child entries */
    if (ctx->is_preorder_node) {
      if (ctx->is_postorder) {
        ctx->stack = linked_list_prepend(ctx->stack,
                                         make_pointer_postorder(ctx->curnode));
      }

      /* XXX: it would be good to assert that each one of these nodes
         don't have their 0th bit set */
      /* XXX: also that none of them are NULL */
      ctx->old_stack = ctx->stack;
      UTHR_YIELD(ctx,
                 ctx->expand_fn(ctx->op_ud, ctx->stack, ctx->curnode,
                                _async_tree_apply_uthr, ctx));
      UTHR_RECEIVE_EVENT(ASYNC_TREE_EXPAND_FN_DONE_EVENT,
                         AsyncTreeExpandFnDoneEvent, expand_fn_done_ev);
      ASSERT_TRUE(!expand_fn_done_ev->error);
      ctx->stack = expand_fn_done_ev->new_stack;

      if (ctx->old_stack == ctx->stack) {
        /* this entry didn't extend, it's just a leaf */
        ctx->is_preorder_node = false;
        if (ctx->is_postorder) {
          ctx->stack = linked_list_popleft(ctx->stack, NULL);
        }
      }
    }

    if (!(ctx->is_preorder_node && ctx->is_postorder)) {
      UTHR_YIELD(ctx,
                 ctx->apply_fn(ctx->op_ud, ctx->next,
                               _async_tree_apply_uthr, ctx));
      UTHR_RECEIVE_EVENT(ASYNC_TREE_APPLY_FN_DONE_EVENT,
                         AsyncTreeApplyFnDoneEvent, apply_fn_done_ev);
      /* TODO: don't do anything with the result,
         maybe in the future we can terminate early
      */
      UNUSED(apply_fn_done_ev);
    }
  }

  UTHR_RETURN(ctx,
              ctx->cb(ASYNC_TREE_APPLY_DONE_EVENT, NULL, ctx->cb_ud));

  UTHR_FOOTER();
}

void
async_tree_apply(void *op_ud,
                 async_tree_apply_fn_t apply_fn,
                 async_tree_expand_fn_t expand_fn,
                 void *root,
                 bool is_postorder,
                 event_handler_t cb, void *cb_ud) {
  UTHR_CALL7(_async_tree_apply_uthr, AsyncTreeApplyCtx,
             .op_ud = op_ud,
             .apply_fn = apply_fn,
             .expand_fn = expand_fn,
             .root = root,
             .is_postorder = is_postorder,
             .cb = cb,
             .cb_ud = cb_ud);
}
