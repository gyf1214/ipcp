#include "logTest.h"

#include "log.h"
#include "testAssert.h"

static void testGenericLoggingAvailable() {
  const char *ts = logTimeStr();
  testAssertTrue(ts != NULL, "logTimeStr should return a string");
  testAssertTrue(ts[0] != '\0', "logTimeStr should not be empty");
  logf("generic logging smoke test");
}

static void testDbgAssertfPassesOnTrueCondition(void) {
  dbgAssertf(1);
}

void runLogTests(void) {
  testGenericLoggingAvailable();
  testDbgAssertfPassesOnTrueCondition();
}
