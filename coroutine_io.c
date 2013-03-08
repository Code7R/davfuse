#define _C_FBPEEK(coropos, f, out, peek)                       \
  do {                                                         \
    ssize_t ret;                                               \
                                                               \
    if (f->buf_start < f->buf_end) {                           \
      out = (unsigned char) *f->buf_start;                     \
      f->buf_start += peek ? 1 : 0;                            \
      break;                                                   \
    }                                                          \
                                                               \
    assert(f->buf_start == f->buf_end);                        \
    assert(sizeof(f->buf));                                    \
                                                               \
    ret = read(f->fd, f->buf, sizeof(f->buf));                 \
    if (ret < 0 && errno == EAGAIN) {                          \
      /* TODO: register for read events */                     \
      CRYIELD(coropos);                                        \
      continue;                                                \
    }                                                          \
    else if (ret <= 0) {                                       \
      out = EOF;                                               \
      break;                                                   \
    }                                                          \
                                                               \
    f->buf_start = f->buf;                                     \
    f->buf_end = f->buf + ret;                                 \
  }                                                            \
  while (true)

#define C_FBPEEK(coropos, f, out) _C_FBPEEK(coropos, f, out, 0)
#define C_FBGETC(coropos, f, out) _C_FBPEEK(coropos, f, out, 1)

static bool
c_fbgetc(GetCState *state, FDBuffer *f, int *out) {
  CRBEGIN(state->coropos);
  C_FBGETC(state->coropos, f, *out);
  CREND();
}

static bool
c_fbpeek(PeekState *state, FDBuffer *f, int *out) {
  CRBEGIN(state->coropos);
  C_FBPEEK(state->coropos, f, *out);
  CREND();
}

static void
fbungetc(FDBuffer *f, int c) {
  f->buf_start -= 1;
  *f->buf_start = c;
}

static bool
c_getwhile(GetWhileState *state, FDBuffer *f,
           char *buf, size_t buf_size,
           bool (*fn)(char),
           size_t *out) {
  /* always do these asserts first */
  assert(buf);
  assert(buf_size);
  assert(!state->buf_end ||
         (state->buf_end >= buf && state->buf_end < buf + buf_size));

  CRBEGIN(state->coropos);

  state->buf_end = buf;

  /* find terminator in existing buffer */
  do {
    int c;

    /* we only call fbgetc in one place here, so we force an inline */
    C_FBGETC(state->coropos, f, c);

    if (c == EOF) {
      log_error("Error while expecting a character: %s", strerror(errno));
      break;
    }

    /* pain! we make an indirect function call here to accomodate multiple uses
       it definitely slows done this loop,
       maybe we can optimized this in the future */
    if (!(*fn)(c)) {
      fbungetc(f, c);
      break;
    }

    *state->buf_end++ = c;
  }
  while (state->buf_end < buf + buf_size);

  *out = state->buf_end - buf;
  CREND();
}

static bool
c_write_all(WriteAllState *state, int fd,
            const void *buf, size_t count, ssize_t *ret) {
  CRBEGIN(state->coropos);

  state->buf_loc = buf;
  state->count_left = count;

  while (state->count_left) {
    ssize_t ret2;
    ret2 = write(fd, state->buf_loc, state->count_left);
    if (ret2 < 0) {
      if (errno == EAGAIN) {
        CRYIELD(state->coropos);
        continue;
      }
      else {
        assert(count >= state->count_left);
        *ret = count - state->count_left;
      }
    }

    assert(state->count_left >= (size_t) ret2);
    state->count_left -= ret2;
    state->buf_loc += ret2;
  }

  *ret = 0;

  CREND();
}

static bool
__attribute__((const))
match_seperator(char c) {
#define N(l) l == c ||
  /* these are lots of independent checks but the CPU should plow through
     this since it's not a loop and doesn't access memory */
  return (N('(') N(')') N('<') N('>') N('@') N(',') N(';') N(':')
          N('\\') N('/') N('[') N(']') N('?') N('=') N('{') N('}')
          N(' ') '\t' == c);
#undef N
}

static bool
__attribute__((const))
match_token(char c) {
  /* token          = 1*<any CHAR except CTLs or separators> */
  return (32 < c && c < 127 && !match_seperator(c));
}

static bool
__attribute__((const))
match_non_null_or_space(char c) {
  return c && c != ' ';
}

static bool
__attribute__((const))
match_non_null_or_colon(char c) {
  return c && c != ':';
}

static bool
__attribute__((const))
match_non_null_or_carriage_return(char c) {
  return c && c != '\r';
}

static bool
__attribute__((const))
match_digit(char c) {
  return '0' <= c && c <= '9';
}
