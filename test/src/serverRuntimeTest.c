#include "serverRuntimeTest.h"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string.h>

#include "serverRuntime.h"
#include "testAssert.h"

static const sessionHeartbeatConfig_t testHeartbeatCfg = {
    .intervalMs = 5000,
    .timeoutMs = 15000,
};
static const unsigned char testKey[ProtocolPskSize] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10,
    0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98,
    0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f, 0x1e,
};

static void testServerRuntimeAddRemoveAndReuseSlots(void) {
  serverRuntime_t runtime;
  int slot0;
  int slot1;
  int reusedSlot;

  testAssertTrue(serverRuntimeInit(&runtime, 10, 11, 2, &testHeartbeatCfg), "runtime init should succeed");

  slot0 = serverRuntimeAddClient(&runtime, 100, testKey, "10.0.0.2");
  slot1 = serverRuntimeAddClient(&runtime, 101, testKey, "10.0.0.3");
  testAssertTrue(slot0 == 0, "first client should use slot 0");
  testAssertTrue(slot1 == 1, "second client should use slot 1");
  testAssertTrue(serverRuntimeClientCount(&runtime) == 2, "client count should track active clients");

  testAssertTrue(serverRuntimeRemoveClient(&runtime, slot0), "remove should succeed for active slot");
  testAssertTrue(serverRuntimeClientCount(&runtime) == 1, "client count should decrement after remove");

  reusedSlot = serverRuntimeAddClient(&runtime, 102, testKey, "10.0.0.4");
  testAssertTrue(reusedSlot == 0, "runtime should reuse first free slot");
  testAssertTrue(serverRuntimeClientCount(&runtime) == 2, "client count should return to cap");

  serverRuntimeDeinit(&runtime);
}

static void testServerRuntimeRejectsBeyondMaxSessions(void) {
  serverRuntime_t runtime;

  testAssertTrue(serverRuntimeInit(&runtime, 20, 21, 1, &testHeartbeatCfg), "runtime init should succeed");
  testAssertTrue(serverRuntimeAddClient(&runtime, 200, testKey, "10.0.0.2") == 0, "first slot should be accepted");
  testAssertTrue(serverRuntimeAddClient(&runtime, 201, testKey, "10.0.0.3") < 0, "runtime should reject client when max reached");

  serverRuntimeDeinit(&runtime);
}

static void testServerRuntimeFindSlotByFdAndPickEgress(void) {
  serverRuntime_t runtime;
  int slot0;
  int slot1;

  testAssertTrue(serverRuntimeInit(&runtime, 30, 31, 3, &testHeartbeatCfg), "runtime init should succeed");
  slot0 = serverRuntimeAddClient(&runtime, 300, testKey, "10.0.0.2");
  slot1 = serverRuntimeAddClient(&runtime, 301, testKey, "10.0.0.3");
  testAssertTrue(slot0 == 0 && slot1 == 1, "runtime should allocate first two slots");

  testAssertTrue(serverRuntimeFindSlotByFd(&runtime, 300) == slot0, "fd should map to slot 0");
  testAssertTrue(serverRuntimeFindSlotByFd(&runtime, 301) == slot1, "fd should map to slot 1");
  testAssertTrue(serverRuntimeFindSlotByFd(&runtime, 999) < 0, "unknown fd should not map to slot");

  testAssertTrue(serverRuntimePickEgressClient(&runtime) == 300, "egress pick should choose first active client");

  testAssertTrue(serverRuntimeRemoveClient(&runtime, slot0), "slot 0 removal should succeed");
  testAssertTrue(serverRuntimePickEgressClient(&runtime) == 301, "egress pick should move to next active client");

  serverRuntimeDeinit(&runtime);
}

static void testServerRuntimeSharedTunInterestTracksGlobalQueue(void) {
  serverRuntime_t runtime;
  int tunPair[2];
  int epollFd;
  char payloadA[16];
  char payloadB[16];

  memset(payloadA, 'a', sizeof(payloadA));
  memset(payloadB, 'b', sizeof(payloadB));
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should be created");
  testAssertTrue(serverRuntimeInit(&runtime, tunPair[0], 40, 2, &testHeartbeatCfg), "runtime init should succeed");

  epollFd = epoll_create1(0);
  testAssertTrue(epollFd >= 0, "epoll_create1 should succeed");
  runtime.epollFd = epollFd;
  testAssertTrue(epoll_ctl(epollFd, EPOLL_CTL_ADD, runtime.tunFd, &(struct epoll_event){.events = runtime.tunEvents, .data.fd = runtime.tunFd}) == 0, "add tun fd should succeed");

  testAssertTrue(serverRuntimeQueueTunWrite(&runtime, payloadA, sizeof(payloadA)), "first shared tun queue write should succeed");
  testAssertTrue(serverRuntimeQueueTunWrite(&runtime, payloadB, sizeof(payloadB)), "second shared tun queue write should succeed");
  testAssertTrue((runtime.tunEvents & EPOLLOUT) != 0, "shared tun epollout should stay enabled while queue has bytes");
  testAssertTrue(serverRuntimeSyncTunWriteInterest(&runtime), "sync should keep epollout enabled while queue is not empty");
  testAssertTrue((runtime.tunEvents & EPOLLOUT) != 0, "sync should preserve epollout while backlog remains");

  runtime.tunOutOffset = 0;
  runtime.tunOutNbytes = 0;
  testAssertTrue(serverRuntimeSyncTunWriteInterest(&runtime), "sync should disable epollout when queue drains");
  testAssertTrue((runtime.tunEvents & EPOLLOUT) == 0, "shared tun epollout should disable after global queue drains");

  close(epollFd);
  serverRuntimeDeinit(&runtime);
  close(tunPair[0]);
  close(tunPair[1]);
}

static void testServerRuntimeRoundRobinRetryCursorRotates(void) {
  serverRuntime_t runtime;

  testAssertTrue(serverRuntimeInit(&runtime, 50, 51, 4, &testHeartbeatCfg), "runtime init should succeed");
  testAssertTrue(runtime.retryCursor == 0, "retry cursor should start at zero");
  testAssertTrue(serverRuntimeAddClient(&runtime, 500, testKey, "10.0.0.2") == 0, "first client should be added");
  testAssertTrue(serverRuntimeAddClient(&runtime, 501, testKey, "10.0.0.3") == 1, "second client should be added");
  testAssertTrue(serverRuntimeAddClient(&runtime, 502, testKey, "10.0.0.4") == 2, "third client should be added");

  runtime.retryCursor = 1;
  testAssertTrue(serverRuntimeRetryBlockedTunRoundRobin(&runtime) == 2, "retry pass should advance cursor to next slot");
  testAssertTrue(runtime.retryCursor == 2, "retry cursor should rotate after retry pass");

  testAssertTrue(serverRuntimeRetryBlockedTunRoundRobin(&runtime) == 0, "retry pass should wrap cursor");
  testAssertTrue(runtime.retryCursor == 0, "retry cursor should wrap to zero");

  serverRuntimeDeinit(&runtime);
}

void runServerRuntimeTests(void) {
  testServerRuntimeAddRemoveAndReuseSlots();
  testServerRuntimeRejectsBeyondMaxSessions();
  testServerRuntimeFindSlotByFdAndPickEgress();
  testServerRuntimeSharedTunInterestTracksGlobalQueue();
  testServerRuntimeRoundRobinRetryCursorRotates();
}
