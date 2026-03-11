#pragma once

#include <stdio.h>
#include <stdlib.h>

static inline void testAssertTrue(int cond, const char *msg) {
  if (!cond) {
    fprintf(stderr, "FAIL: %s\n", msg);
    exit(1);
  }
}

static inline void testLogExpectedErrorMarker(const char *label, const char *phase) {
  fprintf(stderr, "[TEST][EXPECTED-ERROR][%s] %s\n", label, phase);
  fflush(stderr);
}
