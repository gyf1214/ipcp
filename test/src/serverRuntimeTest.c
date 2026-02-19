#include "serverRuntimeTest.h"

#include <string.h>

#include "serverRuntime.h"
#include "testAssert.h"

static const sessionHeartbeatConfig_t testHeartbeatCfg = {
    .intervalMs = 5000,
    .timeoutMs = 15000,
};

static void testServerRuntimeAddRemoveAndReuseSlots(void) {
  serverRuntime_t runtime;
  int slot0;
  int slot1;
  int reusedSlot;

  testAssertTrue(serverRuntimeInit(&runtime, 10, 11, 2, &testHeartbeatCfg), "runtime init should succeed");

  slot0 = serverRuntimeAddClient(&runtime, 100);
  slot1 = serverRuntimeAddClient(&runtime, 101);
  testAssertTrue(slot0 == 0, "first client should use slot 0");
  testAssertTrue(slot1 == 1, "second client should use slot 1");
  testAssertTrue(serverRuntimeClientCount(&runtime) == 2, "client count should track active clients");

  testAssertTrue(serverRuntimeRemoveClient(&runtime, slot0), "remove should succeed for active slot");
  testAssertTrue(serverRuntimeClientCount(&runtime) == 1, "client count should decrement after remove");

  reusedSlot = serverRuntimeAddClient(&runtime, 102);
  testAssertTrue(reusedSlot == 0, "runtime should reuse first free slot");
  testAssertTrue(serverRuntimeClientCount(&runtime) == 2, "client count should return to cap");

  serverRuntimeDeinit(&runtime);
}

static void testServerRuntimeRejectsBeyondMaxSessions(void) {
  serverRuntime_t runtime;

  testAssertTrue(serverRuntimeInit(&runtime, 20, 21, 1, &testHeartbeatCfg), "runtime init should succeed");
  testAssertTrue(serverRuntimeAddClient(&runtime, 200) == 0, "first slot should be accepted");
  testAssertTrue(serverRuntimeAddClient(&runtime, 201) < 0, "runtime should reject client when max reached");

  serverRuntimeDeinit(&runtime);
}

static void testServerRuntimeFindSlotByFdAndPickEgress(void) {
  serverRuntime_t runtime;
  int slot0;
  int slot1;

  testAssertTrue(serverRuntimeInit(&runtime, 30, 31, 3, &testHeartbeatCfg), "runtime init should succeed");
  slot0 = serverRuntimeAddClient(&runtime, 300);
  slot1 = serverRuntimeAddClient(&runtime, 301);
  testAssertTrue(slot0 == 0 && slot1 == 1, "runtime should allocate first two slots");

  testAssertTrue(serverRuntimeFindSlotByFd(&runtime, 300) == slot0, "fd should map to slot 0");
  testAssertTrue(serverRuntimeFindSlotByFd(&runtime, 301) == slot1, "fd should map to slot 1");
  testAssertTrue(serverRuntimeFindSlotByFd(&runtime, 999) < 0, "unknown fd should not map to slot");

  testAssertTrue(serverRuntimePickEgressClient(&runtime) == 300, "egress pick should choose first active client");

  testAssertTrue(serverRuntimeRemoveClient(&runtime, slot0), "slot 0 removal should succeed");
  testAssertTrue(serverRuntimePickEgressClient(&runtime) == 301, "egress pick should move to next active client");

  serverRuntimeDeinit(&runtime);
}

void runServerRuntimeTests(void) {
  testServerRuntimeAddRemoveAndReuseSlots();
  testServerRuntimeRejectsBeyondMaxSessions();
  testServerRuntimeFindSlotByFdAndPickEgress();
}
