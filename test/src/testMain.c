#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ioTest.h"
#include "protocolTest.h"
#include "sessionTest.h"

typedef struct {
  const char *name;
  void (*run)(void);
} suiteEntry_t;

static const suiteEntry_t suites[] = {
    {"protocol", runProtocolTests},
    {"io", runIoTests},
    {"session", runSessionTests},
};

static int runNamedSuite(const char *name) {
  size_t i;
  for (i = 0; i < sizeof(suites) / sizeof(suites[0]); i++) {
    if (strcmp(suites[i].name, name) == 0) {
      suites[i].run();
      fprintf(stderr, "PASS %s tests\n", suites[i].name);
      return 0;
    }
  }

  fprintf(stderr, "unknown test suite: %s\n", name);
  return 1;
}

int main(int argc, char **argv) {
  size_t i;
  int status = 0;

  if (argc == 1) {
    for (i = 0; i < sizeof(suites) / sizeof(suites[0]); i++) {
      suites[i].run();
      fprintf(stderr, "PASS %s tests\n", suites[i].name);
    }
    return EXIT_SUCCESS;
  }

  for (i = 1; i < (size_t)argc; i++) {
    if (runNamedSuite(argv[i]) != 0) {
      status = 1;
    }
  }

  if (status != 0) {
    fprintf(stderr, "usage: %s [protocol] [io] [session]\n", argv[0]);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
