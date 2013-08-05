#ifndef DFS_H
#define DFS_H

#include <stdbool.h>

#include "coroutine.h"
#include "util.h"

typedef void (*free_fn)(void *user_data, void *);
typedef linked_list_t (*expand_fn)(void *user_data, void *, linked_list_t);

struct depth_first {
  coroutine_position_t coropos;
  linked_list_t stack;
  void *curnode;
  expand_fn expand_;
  free_fn free_;
  bool is_postorder;
  void *user_data;
};

typedef struct depth_first *depth_first_t;

NON_NULL_ARGS3(1, 3, 4) depth_first_t
dfs_create(void *init,
           bool is_postorder,
           expand_fn expand_,
           free_fn free_,
           void *user_data);

NON_NULL_ARGS0() void *
dfs_next(depth_first_t t);

NON_NULL_ARGS0() void
dfs_destroy(depth_first_t t);

void
dfs_ignore_user_data_free(void *, void *);

#endif /* DFS_H */
