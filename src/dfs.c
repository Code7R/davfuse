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

NON_NULL_ARGS2(2, 3) depth_first_t
dfs_create(void *init,
           expand_fn expand_,
           free_fn free_) {
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
  };

  return df;
}

NON_NULL_ARGS0() void
dfs_next(depth_first_t ctx, bool *pre_order, void **next) {
  CRBEGIN(ctx->coropos);

  while (true) {
    while (ctx->stack) {
      ctx->stack = linked_list_popleft(ctx->stack, &ctx->curnode);

      /* first yield this node */
      *pre_order = pointer_is_preorder(ctx->curnode);
      *next = clear_pointer_postorder(ctx->curnode);

      /* if this is pre-order then populate the stack with
         the post-order node and its child entries */
      if (*pre_order) {
        ctx->stack = linked_list_prepend(ctx->stack,
                                         make_pointer_postorder(ctx->curnode));

        /* XXX: it would be good to assert that each one of these nodes
           don't have their 0th bit set */
        linked_list_t old_stack = ctx->stack;
        ctx->stack = ctx->expand_(ctx->curnode, ctx->stack);

        if (old_stack == ctx->stack) {
          /* this entry didn't extend, treat this like a post-order entry */
          *pre_order = false;
          ctx->stack = linked_list_popleft(ctx->stack, NULL);
        }
      }

      CRYIELD(ctx->coropos, 0);
    }

    *next = NULL;
    CRYIELD(ctx->coropos, 0);
  }

  /* not reached */
  CRRETURN(ctx->coropos, 0);

  CREND();
}

static void
my_free(void *p, void *ud) {
  struct depth_first *ctx = ud;
  ctx->free_(clear_pointer_postorder(p));
}

NON_NULL_ARGS0() void
dfs_destroy(depth_first_t ctx) {
  linked_list_free_ud(ctx->stack, my_free, ctx);
}
