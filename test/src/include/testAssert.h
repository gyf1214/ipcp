#pragma once

#include <stdio.h>
#include <stdlib.h>

static inline void testAssertTrue(int cond, const char *msg) {
  if (!cond) {
    fprintf(stderr, "FAIL: %s\n", msg);
    exit(1);
  }
}
