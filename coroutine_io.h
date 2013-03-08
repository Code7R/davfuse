#define BUF_SIZE 4096

typedef struct {
  coroutine_position_t coropos;
} GetCState;

typedef GetCState PeekState;

typedef struct {
  coroutine_position_t coropos;
  char *buf_end;
} GetWhileState;

typedef struct {
  coroutine_position_t coropos;
  const void *buf_loc;
  size_t count_left;
} WriteAllState;

typedef struct {
  int fd;
  char *buf_start;
  char *buf_end;
  char buf[BUF_SIZE];
} FDBuffer;
