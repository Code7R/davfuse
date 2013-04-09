#ifndef DFS_H
#define DFS_H

#include <stdbool.h>

#include "coroutine.h"
#include "util.h"

typedef void (*free_fn)(void *);
typedef linked_list_t (*expand_fn)(void *, linked_list_t);

struct depth_first {
  coroutine_position_t coropos;
  linked_list_t stack;
  void *curnode;
  expand_fn expand_;
  free_fn free_;
};

typedef struct depth_first *depth_first_t;

NON_NULL_ARGS2(2, 3) depth_first_t
dfs_create(void *init,
           expand_fn expand_,
           free_fn free_);

NON_NULL_ARGS0() void
dfs_next(depth_first_t t, bool *pre_order, void **next);

NON_NULL_ARGS0() void
dfs_destroy(depth_first_t t);

#endif /* DFS_H */
