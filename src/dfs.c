#include <stdint.h>
#include <stdlib.h>

#include "coroutine.h"
#include "util.h"

#include "dfs.h"

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

NON_NULL_ARGS3(1, 3, 4) depth_first_t
dfs_create(void *init,
           bool is_postorder,
           expand_fn expand_,
           free_fn free_,
           void *user_data) {
  EASY_ALLOC(struct depth_first, df);

  /* we use tagged pointers, so the initial pointer
     should not have it's low bit set */
  assert(pointer_is_preorder(init));

  *df = (struct depth_first) {
    .coropos = CORO_POS_INIT,
    .stack = linked_list_prepend(LINKED_LIST_INITIALIZER, init),
    .curnode = NULL,
    .expand_ = expand_,
    .free_ = free_,
    .is_postorder = is_postorder,
    .user_data = user_data,
  };

  return df;
}

NON_NULL_ARGS0() void *
dfs_next(depth_first_t ctx) {
  CRBEGIN(ctx->coropos);

  while (true) {
    while (ctx->stack) {
      ctx->stack = linked_list_popleft(ctx->stack, &ctx->curnode);

      /* first yield this node */
      bool is_preorder_node = pointer_is_preorder(ctx->curnode);
      void *next = clear_pointer_postorder(ctx->curnode);

      /* if this is pre-order then populate the stack with
         the post-order node and its child entries */
      if (is_preorder_node) {
        if (ctx->is_postorder) {
          ctx->stack = linked_list_prepend(ctx->stack,
                                           make_pointer_postorder(ctx->curnode));
        }

        /* XXX: it would be good to assert that each one of these nodes
           don't have their 0th bit set */
        /* XXX: also that none of them are NULL */
        linked_list_t old_stack = ctx->stack;
        ctx->stack = ctx->expand_(ctx->user_data, ctx->curnode, ctx->stack);

        if (old_stack == ctx->stack) {
          /* this entry didn't extend, it's just a leaf */
          is_preorder_node = false;
          if (ctx->is_postorder) {
            ctx->stack = linked_list_popleft(ctx->stack, NULL);
          }
        }
      }

      if (!(is_preorder_node && ctx->is_postorder)) {
        CRYIELD(ctx->coropos, next);
      }
    }

    CRYIELD(ctx->coropos, NULL);
  }

  /* not reached */
  CRRETURN(ctx->coropos, 0);

  CREND();
}

static void
my_free(void *p, void *ud) {
  struct depth_first *ctx = ud;
  ctx->free_(ctx->user_data, clear_pointer_postorder(p));
}

NON_NULL_ARGS0() void
dfs_destroy(depth_first_t ctx) {
  linked_list_free_ud(ctx->stack, my_free, ctx);
  free(ctx);
}


void
dfs_ignore_user_data_free(void *ctx, void *ptr) {
  UNUSED(ctx);
  free(ptr);
}
