#include "serverTest.h"

#include <fcntl.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string.h>

#include "packet.h"
#include "server.h"
#include "sessionInternal.h"
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
static const unsigned char claim2[] = {10, 0, 0, 2};
static const unsigned char claim3[] = {10, 0, 0, 3};
static const unsigned char claim4[] = {10, 0, 0, 4};
static long long fakeNowMs = 0;

typedef struct {
  int epollFd;
  ioTunPoller_t tunPoller;
  ioTcpPoller_t tcpPoller;
} splitPollersFixture_t;

static int setupSplitPollers(splitPollersFixture_t *poller, int tunFd, int tcpFd) {
  if (poller == NULL) {
    return -1;
  }
  poller->epollFd = epoll_create1(0);
  if (poller->epollFd < 0) {
    return -1;
  }
  if (ioTunPollerInit(&poller->tunPoller, poller->epollFd, tunFd) < 0
      || ioTcpPollerInit(&poller->tcpPoller, poller->epollFd, tcpFd) < 0) {
    close(poller->epollFd);
    poller->epollFd = -1;
    return -1;
  }
  return 0;
}

static void teardownSplitPollers(splitPollersFixture_t *poller) {
  if (poller != NULL && poller->epollFd >= 0) {
    close(poller->epollFd);
    poller->epollFd = -1;
  }
}

static long long fakeNow(void *ctx) {
  (void)ctx;
  return fakeNowMs;
}

static sessionStepResult_t runSessionStepSplit(
    session_t *session,
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    ioEvent_t event,
    const unsigned char key[ProtocolPskSize]) {
  return sessionStep(session, tcpPoller, tunPoller, event, key);
}

static sessionStepResult_t runSessionStepWithSuppressedStderr(
    session_t *session,
    splitPollersFixture_t *poller,
    ioEvent_t event,
    const unsigned char key[ProtocolPskSize]) {
  int savedStderr = dup(STDERR_FILENO);
  int nullFd = -1;
  sessionStepResult_t result;
  testAssertTrue(savedStderr >= 0, "dup stderr should succeed");

  fflush(stderr);
  nullFd = open("/dev/null", O_WRONLY);
  testAssertTrue(nullFd >= 0, "open /dev/null should succeed");
  testAssertTrue(dup2(nullFd, STDERR_FILENO) >= 0, "redirect stderr should succeed");
  close(nullFd);

  result = sessionStep(session, &poller->tcpPoller, &poller->tunPoller, event, key);

  fflush(stderr);
  testAssertTrue(dup2(savedStderr, STDERR_FILENO) >= 0, "restore stderr should succeed");
  close(savedStderr);
  return result;
}

static void wireServerSessionRuntime(session_t *session, server_t *runtime, splitPollersFixture_t *poller) {
  memset(runtime, 0, sizeof(*runtime));
  testAssertTrue(
      serverInit(runtime, poller->tunPoller.tunFd, poller->tcpPoller.tcpFd, 1, 1, &testHeartbeatCfg, NULL, NULL),
      "server runtime init should succeed");
  runtime->tunPoller.epollFd = poller->tunPoller.epollFd;
  runtime->tunPoller.events = poller->tunPoller.events;
  sessionSetServer(session, runtime);
}

static int fakeLookup(
    void *ctx,
    const unsigned char *claim,
    long claimNbytes,
    unsigned char key[ProtocolPskSize],
    int *outActiveSlot) {
  (void)ctx;
  (void)claim;
  (void)claimNbytes;
  (void)key;
  (void)outActiveSlot;
  return 0;
}

static void testServerServeMultiClientRejectsInvalidArgs(void) {
  testAssertTrue(
      serverServeMultiClient(-1, -1, fakeLookup, NULL, "tun", NULL, 5000, &testHeartbeatCfg, 2, 2) < 0,
      "server runtime should reject invalid fds");
  testAssertTrue(
      serverServeMultiClient(1, 2, NULL, NULL, "tun", NULL, 5000, &testHeartbeatCfg, 2, 2) < 0,
      "server runtime should reject null lookup callback");
  testAssertTrue(
      serverServeMultiClient(1, 2, fakeLookup, NULL, "tun", NULL, 5000, NULL, 2, 2) < 0,
      "server runtime should reject null heartbeat config");
  testAssertTrue(
      serverServeMultiClient(1, 2, fakeLookup, NULL, "tun", NULL, 5000, &testHeartbeatCfg, 0, 2) < 0,
      "server runtime should reject non-positive max session count");
  testAssertTrue(
      serverServeMultiClient(1, 2, fakeLookup, NULL, "tun", NULL, 5000, &testHeartbeatCfg, 2, 0) < 0,
      "server runtime should reject non-positive max pre-auth session count");
}

static void testServerAddRemoveAndReuseSlots(void) {
  server_t runtime;
  int slot0;
  int slot1;
  int reusedSlot;

  testAssertTrue(
      serverInit(&runtime, 10, 11, 2, 2, &testHeartbeatCfg, NULL, NULL),
      "runtime init should succeed");

  slot0 = serverAddClient(&runtime, 0, 100, testKey, claim2, sizeof(claim2));
  slot1 = serverAddClient(&runtime, 1, 101, testKey, claim3, sizeof(claim3));
  testAssertTrue(slot0 == 0, "first client should use slot 0");
  testAssertTrue(slot1 == 1, "second client should use slot 1");
  testAssertTrue(serverClientCount(&runtime) == 2, "client count should track active clients");

  testAssertTrue(serverRemoveClient(&runtime, slot0), "remove should succeed for active slot");
  testAssertTrue(serverClientCount(&runtime) == 1, "client count should decrement after remove");

  reusedSlot = serverAddClient(&runtime, 0, 102, testKey, claim4, sizeof(claim4));
  testAssertTrue(reusedSlot == 0, "runtime should reuse first free slot");
  testAssertTrue(serverClientCount(&runtime) == 2, "client count should return to cap");

  serverDeinit(&runtime);
}

static void testServerRejectsBeyondMaxSessions(void) {
  server_t runtime;

  testAssertTrue(
      serverInit(&runtime, 20, 21, 1, 1, &testHeartbeatCfg, NULL, NULL),
      "runtime init should succeed");
  testAssertTrue(
      serverAddClient(&runtime, 0, 200, testKey, claim2, sizeof(claim2)) == 0,
      "first slot should be accepted");
  testAssertTrue(
      serverAddClient(&runtime, 0, 201, testKey, claim3, sizeof(claim3)) < 0,
      "runtime should reject client when max reached");

  serverDeinit(&runtime);
}

static void testServerFindSlotByFdAndPickEgress(void) {
  server_t runtime;
  int slot0;
  int slot1;

  testAssertTrue(
      serverInit(&runtime, 30, 31, 3, 3, &testHeartbeatCfg, NULL, NULL),
      "runtime init should succeed");
  slot0 = serverAddClient(&runtime, 0, 300, testKey, claim2, sizeof(claim2));
  slot1 = serverAddClient(&runtime, 1, 301, testKey, claim3, sizeof(claim3));
  testAssertTrue(slot0 == 0 && slot1 == 1, "runtime should allocate first two slots");

  testAssertTrue(serverFindSlotByFd(&runtime, 300) == slot0, "fd should map to slot 0");
  testAssertTrue(serverFindSlotByFd(&runtime, 301) == slot1, "fd should map to slot 1");
  testAssertTrue(serverFindSlotByFd(&runtime, 999) < 0, "unknown fd should not map to slot");

  testAssertTrue(serverPickEgressClient(&runtime) == 300, "egress pick should choose first active client");

  testAssertTrue(serverRemoveClient(&runtime, slot0), "slot 0 removal should succeed");
  testAssertTrue(serverPickEgressClient(&runtime) == 301, "egress pick should move to next active client");

  serverDeinit(&runtime);
}

static void testServerFindSlotByClaim(void) {
  server_t runtime;
  int slot0;
  int slot1;
  unsigned char mismatchLenClaim[] = {10, 0, 0};
  unsigned char unknownClaim[] = {10, 0, 0, 99};

  testAssertTrue(
      serverInit(&runtime, 35, 36, 3, 3, &testHeartbeatCfg, NULL, NULL),
      "runtime init should succeed");
  slot0 = serverAddClient(&runtime, 0, 350, testKey, claim2, sizeof(claim2));
  slot1 = serverAddClient(&runtime, 1, 351, testKey, claim3, sizeof(claim3));
  testAssertTrue(slot0 == 0 && slot1 == 1, "runtime should allocate slots for claim tests");

  testAssertTrue(
      serverFindSlotByClaim(&runtime, claim2, sizeof(claim2)) == slot0,
      "claim lookup should return exact matching slot");
  testAssertTrue(
      serverFindSlotByClaim(&runtime, claim3, sizeof(claim3)) == slot1,
      "claim lookup should return second matching slot");
  testAssertTrue(
      serverFindSlotByClaim(&runtime, unknownClaim, sizeof(unknownClaim)) < 0,
      "unknown claim should not match");
  testAssertTrue(
      serverFindSlotByClaim(&runtime, mismatchLenClaim, sizeof(mismatchLenClaim)) < 0,
      "claim length mismatch should not match");

  testAssertTrue(serverRemoveClient(&runtime, slot0), "remove slot 0 should succeed");
  testAssertTrue(
      serverFindSlotByClaim(&runtime, claim2, sizeof(claim2)) < 0,
      "inactive slot should be ignored for claim lookup");

  serverDeinit(&runtime);
}

static void testServerSharedTunInterestTracksGlobalQueue(void) {
  server_t runtime;
  int tunPair[2];
  int epollFd;
  char payloadA[16];
  char payloadB[16];

  memset(payloadA, 'a', sizeof(payloadA));
  memset(payloadB, 'b', sizeof(payloadB));
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should be created");
  testAssertTrue(
      serverInit(&runtime, tunPair[0], 40, 2, 2, &testHeartbeatCfg, NULL, NULL),
      "runtime init should succeed");

  epollFd = epoll_create1(0);
  testAssertTrue(epollFd >= 0, "epoll_create1 should succeed");
  runtime.epollFd = epollFd;
  testAssertTrue(
      epoll_ctl(
          epollFd,
          EPOLL_CTL_ADD,
          runtime.tunPoller.tunFd,
          &(struct epoll_event){.events = runtime.tunPoller.events, .data.fd = runtime.tunPoller.tunFd})
      == 0,
      "add tun fd should succeed");

  testAssertTrue(serverQueueTunWrite(&runtime, payloadA, sizeof(payloadA)), "first shared tun queue write should succeed");
  testAssertTrue(serverQueueTunWrite(&runtime, payloadB, sizeof(payloadB)), "second shared tun queue write should succeed");
  testAssertTrue(
      (runtime.tunPoller.events & EPOLLOUT) != 0, "shared tun epollout should stay enabled while queue has bytes");
  testAssertTrue(serverSyncTunWriteInterest(&runtime), "sync should keep epollout enabled while queue is not empty");
  testAssertTrue(
      (runtime.tunPoller.events & EPOLLOUT) != 0, "sync should preserve epollout while backlog remains");

  testAssertTrue(serverServiceTunWriteEvent(&runtime), "shared tun write event should flush queued frames");
  testAssertTrue(serverSyncTunWriteInterest(&runtime), "sync should disable epollout when queue drains");
  testAssertTrue((runtime.tunPoller.events & EPOLLOUT) == 0, "shared tun epollout should disable after global queue drains");

  close(epollFd);
  serverDeinit(&runtime);
  close(tunPair[0]);
  close(tunPair[1]);
}

static void testServerRoundRobinRetryCursorRotates(void) {
  server_t runtime;

  testAssertTrue(
      serverInit(&runtime, 50, 51, 4, 4, &testHeartbeatCfg, NULL, NULL),
      "runtime init should succeed");
  testAssertTrue(runtime.retryCursor == 0, "retry cursor should start at zero");
  testAssertTrue(
      serverAddClient(&runtime, 0, 500, testKey, claim2, sizeof(claim2)) == 0,
      "first client should be added");
  testAssertTrue(
      serverAddClient(&runtime, 1, 501, testKey, claim3, sizeof(claim3)) == 1,
      "second client should be added");
  testAssertTrue(
      serverAddClient(&runtime, 2, 502, testKey, claim4, sizeof(claim4)) == 2,
      "third client should be added");

  runtime.retryCursor = 1;
  testAssertTrue(serverRetryBlockedTunRoundRobin(&runtime) == 2, "retry pass should advance cursor to next slot");
  testAssertTrue(runtime.retryCursor == 2, "retry cursor should rotate after retry pass");

  testAssertTrue(serverRetryBlockedTunRoundRobin(&runtime) == 0, "retry pass should wrap cursor");
  testAssertTrue(runtime.retryCursor == 0, "retry cursor should wrap to zero");

  serverDeinit(&runtime);
}

static void testServerPendingTunToTcpOwnerControlsRetryAndReadInterest(void) {
  server_t runtime;
  int tunPair[2];
  int tcpPair[2];
  unsigned char payload[] = "pending-owner-payload";
  serverPendingRetry_t retry;

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "tcp socketpair should be created");
  testAssertTrue(serverInit(&runtime, tunPair[0], 52, 1, 1, &testHeartbeatCfg, NULL, NULL), "runtime init should succeed");
  testAssertTrue(serverAddClient(&runtime, 0, tcpPair[0], testKey, claim2, sizeof(claim2)) == 0, "slot should be added");

  runtime.activeConns[0].tcpPoller.outOffset = 0;
  runtime.activeConns[0].tcpPoller.outNbytes = IoPollerQueueCapacity;

  testAssertTrue(
      serverStorePendingTunToTcp(&runtime, 0, payload, (long)sizeof(payload)),
      "storing pending tun-to-tcp payload should succeed");
  testAssertTrue(serverHasPendingTunToTcp(&runtime), "runtime should report pending tun-to-tcp payload");
  testAssertTrue(serverPendingTunToTcpOwner(&runtime) == 0, "runtime should record pending owner slot");
  testAssertTrue((runtime.tunPoller.events & EPOLLIN) == 0, "runtime should disable tun epollin while pending is active");

  retry = serverRetryPendingTunToTcp(&runtime, 1, &runtime.activeConns[0].tcpPoller);
  testAssertTrue(retry == serverPendingRetryBlocked, "non-owner retry should be blocked");
  testAssertTrue(serverHasPendingTunToTcp(&runtime), "non-owner retry should not consume pending payload");

  runtime.activeConns[0].tcpPoller.outOffset = 0;
  runtime.activeConns[0].tcpPoller.outNbytes = 0;
  retry = serverRetryPendingTunToTcp(&runtime, 0, &runtime.activeConns[0].tcpPoller);
  testAssertTrue(retry == serverPendingRetryQueued, "owner retry should queue pending payload");
  testAssertTrue(!serverHasPendingTunToTcp(&runtime), "owner retry should clear pending payload");

  testAssertTrue(
      serverSetTunReadEnabled(&runtime, true),
      "read interest should be re-enabled after pending payload clears");
  testAssertTrue((runtime.tunPoller.events & EPOLLIN) != 0, "runtime should enable tun epollin when requested");

  serverDeinit(&runtime);
  close(tcpPair[0]);
  close(tcpPair[1]);
  close(tunPair[0]);
  close(tunPair[1]);
}

static void testServerRoutesTunIngressByClaimMatch(void) {
  server_t runtime;
  int tunPair[2];
  int tcpPairA[2];
  int tcpPairB[2];
  unsigned char payload[] = {
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 0, 0, 1,
      10, 0, 0, 3,
  };
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPairA) == 0, "tcp A socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPairB) == 0, "tcp B socketpair should be created");
  testAssertTrue(serverInit(&runtime, tunPair[0], 60, 3, 3, &testHeartbeatCfg, NULL, NULL), "server init should succeed");
  testAssertTrue(
      serverAddClient(&runtime, 0, tcpPairA[0], testKey, claim2, sizeof(claim2)) == 0,
      "slot A should be added");
  testAssertTrue(
      serverAddClient(&runtime, 1, tcpPairB[0], testKey, claim3, sizeof(claim3)) == 1,
      "slot B should be added");

  testAssertTrue(
      serverRouteTunIngressPacket(&runtime, "tun", payload, sizeof(payload)),
      "tun ingress routing should succeed for matching claim");
  testAssertTrue(
      runtime.activeConns[0].tcpPoller.outNbytes == 0,
      "non-matching client should have no queued tcp bytes");
  testAssertTrue(
      runtime.activeConns[1].tcpPoller.outNbytes > 0,
      "matching client should have queued encrypted frame bytes");

  serverDeinit(&runtime);
  close(tcpPairA[0]);
  close(tcpPairA[1]);
  close(tcpPairB[0]);
  close(tcpPairB[1]);
  close(tunPair[0]);
  close(tunPair[1]);
}

static void testServerDropsTunIngressOnUnmatchedBroadcastMulticastAndMalformed(void) {
  server_t runtime;
  int tunPair[2];
  int tcpPairA[2];
  unsigned char unmatched[] = {
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 0, 0, 1,
      10, 0, 0, 99,
  };
  unsigned char multicast[] = {
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 0, 0, 1,
      224, 1, 2, 3,
  };
  unsigned char malformed[] = {0x45, 0x00, 0x00, 0x14};
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPairA) == 0, "tcp socketpair should be created");
  testAssertTrue(serverInit(&runtime, tunPair[0], 61, 2, 2, &testHeartbeatCfg, NULL, NULL), "server init should succeed");
  testAssertTrue(
      serverAddClient(&runtime, 0, tcpPairA[0], testKey, claim2, sizeof(claim2)) == 0,
      "slot A should be added");

  testAssertTrue(serverRouteTunIngressPacket(&runtime, "tun", unmatched, sizeof(unmatched)), "unmatched route should not fail");
  testAssertTrue(serverRouteTunIngressPacket(&runtime, "tun", multicast, sizeof(multicast)), "multicast drop should not fail");
  testAssertTrue(serverRouteTunIngressPacket(&runtime, "tun", malformed, sizeof(malformed)), "malformed drop should not fail");
  testAssertTrue(runtime.activeConns[0].tcpPoller.outNbytes == 0, "drop cases should not queue to any client");

  serverDeinit(&runtime);
  close(tcpPairA[0]);
  close(tcpPairA[1]);
  close(tunPair[0]);
  close(tunPair[1]);
}

static void testServerFanoutTapBroadcastToAllClients(void) {
  server_t runtime;
  int tunPair[2];
  int tcpPairA[2];
  int tcpPairB[2];
  unsigned char tapBroadcast[] = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0x02, 0x00, 0x5e, 0x00, 0x00, 0x01,
      0x08, 0x00,
  };

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPairA) == 0, "tcp A socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPairB) == 0, "tcp B socketpair should be created");
  testAssertTrue(serverInit(&runtime, tunPair[0], 62, 3, 3, &testHeartbeatCfg, NULL, NULL), "server init should succeed");
  testAssertTrue(serverAddClient(&runtime, 0, tcpPairA[0], testKey, claim2, sizeof(claim2)) == 0, "slot A should be added");
  testAssertTrue(serverAddClient(&runtime, 1, tcpPairB[0], testKey, claim3, sizeof(claim3)) == 1, "slot B should be added");

  testAssertTrue(
      serverRouteTunIngressPacket(&runtime, "tap", tapBroadcast, sizeof(tapBroadcast)),
      "tap broadcast fanout should not fail");
  testAssertTrue(runtime.activeConns[0].tcpPoller.outNbytes > 0, "client A should receive tap broadcast");
  testAssertTrue(runtime.activeConns[1].tcpPoller.outNbytes > 0, "client B should receive tap broadcast");

  serverDeinit(&runtime);
  close(tcpPairA[0]);
  close(tcpPairA[1]);
  close(tcpPairB[0]);
  close(tcpPairB[1]);
  close(tunPair[0]);
  close(tunPair[1]);
}

static void testServerFanoutTunBroadcastsBySubnetPolicy(void) {
  server_t runtime;
  int tunPair[2];
  int tcpPairA[2];
  int tcpPairB[2];
  unsigned char directedBroadcast[] = {
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 250, 0, 1,
      10, 250, 0, 255,
  };
  unsigned char limitedBroadcast[] = {
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 250, 0, 1,
      255, 255, 255, 255,
  };
  unsigned char nonMatchingDirected[] = {
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 250, 0, 1,
      10, 251, 0, 255,
  };
  unsigned char multicast[] = {
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 250, 0, 1,
      224, 1, 2, 3,
  };

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPairA) == 0, "tcp A socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPairB) == 0, "tcp B socketpair should be created");
  testAssertTrue(serverInit(&runtime, tunPair[0], 63, 3, 3, &testHeartbeatCfg, NULL, NULL), "server init should succeed");
  runtime.tunSubnet.enabled = true;
  runtime.tunSubnet.prefix = 24;
  runtime.tunSubnet.broadcast[0] = 10;
  runtime.tunSubnet.broadcast[1] = 250;
  runtime.tunSubnet.broadcast[2] = 0;
  runtime.tunSubnet.broadcast[3] = 255;
  testAssertTrue(serverAddClient(&runtime, 0, tcpPairA[0], testKey, claim2, sizeof(claim2)) == 0, "slot A should be added");
  testAssertTrue(serverAddClient(&runtime, 1, tcpPairB[0], testKey, claim3, sizeof(claim3)) == 1, "slot B should be added");

  testAssertTrue(
      serverRouteTunIngressPacket(&runtime, "tun", directedBroadcast, sizeof(directedBroadcast)),
      "directed broadcast fanout should not fail");
  testAssertTrue(runtime.activeConns[0].tcpPoller.outNbytes > 0, "client A should receive directed broadcast");
  testAssertTrue(runtime.activeConns[1].tcpPoller.outNbytes > 0, "client B should receive directed broadcast");

  runtime.activeConns[0].tcpPoller.outNbytes = 0;
  runtime.activeConns[1].tcpPoller.outNbytes = 0;
  testAssertTrue(
      serverRouteTunIngressPacket(&runtime, "tun", limitedBroadcast, sizeof(limitedBroadcast)),
      "limited broadcast fanout should not fail");
  testAssertTrue(runtime.activeConns[0].tcpPoller.outNbytes > 0, "client A should receive limited broadcast");
  testAssertTrue(runtime.activeConns[1].tcpPoller.outNbytes > 0, "client B should receive limited broadcast");

  runtime.activeConns[0].tcpPoller.outNbytes = 0;
  runtime.activeConns[1].tcpPoller.outNbytes = 0;
  testAssertTrue(
      serverRouteTunIngressPacket(&runtime, "tun", nonMatchingDirected, sizeof(nonMatchingDirected)),
      "non-matching directed broadcast should not fail");
  testAssertTrue(runtime.activeConns[0].tcpPoller.outNbytes == 0, "non-matching directed broadcast should drop");
  testAssertTrue(runtime.activeConns[1].tcpPoller.outNbytes == 0, "non-matching directed broadcast should drop");

  testAssertTrue(serverRouteTunIngressPacket(&runtime, "tun", multicast, sizeof(multicast)), "multicast drop should not fail");
  testAssertTrue(runtime.activeConns[0].tcpPoller.outNbytes == 0, "multicast should not queue client A");
  testAssertTrue(runtime.activeConns[1].tcpPoller.outNbytes == 0, "multicast should not queue client B");

  serverDeinit(&runtime);
  close(tcpPairA[0]);
  close(tcpPairA[1]);
  close(tcpPairB[0]);
  close(tcpPairB[1]);
  close(tunPair[0]);
  close(tunPair[1]);
}

static void testServerBroadcastFanoutSkipsSaturatedClient(void) {
  server_t runtime;
  int tunPair[2];
  int tcpPairA[2];
  int tcpPairB[2];
  unsigned char limitedBroadcast[] = {
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 250, 0, 1,
      255, 255, 255, 255,
  };

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPairA) == 0, "tcp A socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPairB) == 0, "tcp B socketpair should be created");
  testAssertTrue(serverInit(&runtime, tunPair[0], 64, 3, 3, &testHeartbeatCfg, NULL, NULL), "server init should succeed");
  runtime.tunSubnet.enabled = true;
  runtime.tunSubnet.prefix = 24;
  runtime.tunSubnet.broadcast[0] = 10;
  runtime.tunSubnet.broadcast[1] = 250;
  runtime.tunSubnet.broadcast[2] = 0;
  runtime.tunSubnet.broadcast[3] = 255;
  testAssertTrue(serverAddClient(&runtime, 0, tcpPairA[0], testKey, claim2, sizeof(claim2)) == 0, "slot A should be added");
  testAssertTrue(serverAddClient(&runtime, 1, tcpPairB[0], testKey, claim3, sizeof(claim3)) == 1, "slot B should be added");

  runtime.activeConns[0].tcpPoller.outOffset = 0;
  runtime.activeConns[0].tcpPoller.outNbytes = IoPollerQueueCapacity;

  testAssertTrue(
      serverRouteTunIngressPacket(&runtime, "tun", limitedBroadcast, sizeof(limitedBroadcast)),
      "broadcast fanout with saturation should not fail");
  testAssertTrue(
      runtime.activeConns[0].tcpPoller.outNbytes == IoPollerQueueCapacity,
      "saturated client queue should remain unchanged");
  testAssertTrue(runtime.activeConns[1].tcpPoller.outNbytes > 0, "non-saturated client should still receive broadcast");
  testAssertTrue(!serverHasPendingTunToTcp(&runtime), "broadcast best-effort skip should not set shared pending packet");

  serverDeinit(&runtime);
  close(tcpPairA[0]);
  close(tcpPairA[1]);
  close(tcpPairB[0]);
  close(tcpPairB[1]);
  close(tunPair[0]);
  close(tunPair[1]);
}

static void setupServerForSessionTest(
    server_t *runtime,
    int maxSessions,
    int *epollFd,
    int tunPair[2],
    int tcpPairA[2],
    int tcpPairB[2],
    int *slotA,
    int *slotB) {
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPairA) == 0, "tcp pair A should be created");
  testAssertTrue(
      serverInit(runtime, tunPair[0], 72, maxSessions, maxSessions, &testHeartbeatCfg, NULL, NULL),
      "runtime init should succeed");

  *epollFd = epoll_create1(0);
  testAssertTrue(*epollFd >= 0, "epoll_create1 should succeed");
  runtime->epollFd = *epollFd;
  testAssertTrue(
      epoll_ctl(
          *epollFd,
          EPOLL_CTL_ADD,
          runtime->tunPoller.tunFd,
          &(struct epoll_event){.events = runtime->tunPoller.events, .data.fd = runtime->tunPoller.tunFd})
          == 0,
      "add tun fd should succeed");

  *slotA = serverAddClient(runtime, 0, tcpPairA[0], testKey, claim2, sizeof(claim2));
  testAssertTrue(*slotA == 0, "first client should be added");
  testAssertTrue(
      epoll_ctl(
          *epollFd,
          EPOLL_CTL_ADD,
          tcpPairA[0],
          &(struct epoll_event){.events = runtime->activeConns[*slotA].tcpPoller.events, .data.fd = tcpPairA[0]})
          == 0,
      "add tcp A fd should succeed");

  *slotB = -1;
  if (maxSessions > 1) {
    testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPairB) == 0, "tcp pair B should be created");
    *slotB = serverAddClient(runtime, 1, tcpPairB[0], testKey, claim3, sizeof(claim3));
    testAssertTrue(*slotB == 1, "second client should be added");
    testAssertTrue(
        epoll_ctl(
            *epollFd,
            EPOLL_CTL_ADD,
            tcpPairB[0],
            &(struct epoll_event){.events = runtime->activeConns[*slotB].tcpPoller.events, .data.fd = tcpPairB[0]})
            == 0,
        "add tcp B fd should succeed");
  }
}

static void teardownServerForSessionTest(
    server_t *runtime,
    int epollFd,
    int tunPair[2],
    int tcpPairA[2],
    int tcpPairB[2],
    int slotA,
    int slotB) {
  if (slotA >= 0) {
    (void)serverRemoveClient(runtime, slotA);
  }
  if (slotB >= 0) {
    (void)serverRemoveClient(runtime, slotB);
  }
  close(epollFd);
  serverDeinit(runtime);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPairA[0]);
  close(tcpPairA[1]);
  if (tcpPairB[0] >= 0) {
    close(tcpPairB[0]);
  }
  if (tcpPairB[1] >= 0) {
    close(tcpPairB[1]);
  }
}

static void testServerHeartbeatTimeoutStopsSession(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  server_t serverRuntime;
  int tunPair[2];
  int tcpPair[2];

  memset(key, 0x11, sizeof(key));
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "tcp socketpair should be created");
  testAssertTrue(setupSplitPollers(&poller, tunPair[0], tcpPair[0]) == 0, "setup split pollers should succeed");
  fakeNowMs = 0;
  session_t *session = sessionCreate(true, &testHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireServerSessionRuntime(session, &serverRuntime, &poller);

  fakeNowMs = 15000;
  testAssertTrue(
      runSessionStepWithSuppressedStderr(session, &poller, ioEventTimeout, key) == sessionStepStop,
      "server should stop after heartbeat timeout");

  sessionDestroy(session);
  serverDeinit(&serverRuntime);
  teardownSplitPollers(&poller);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testServerHeartbeatTimeoutUsesConfiguredTimeout(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  server_t serverRuntime;
  int tunPair[2];
  int tcpPair[2];
  sessionHeartbeatConfig_t heartbeatCfg = {
      .intervalMs = 3000,
      .timeoutMs = 9000,
  };

  memset(key, 0x33, sizeof(key));
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "tcp socketpair should be created");
  testAssertTrue(setupSplitPollers(&poller, tunPair[0], tcpPair[0]) == 0, "setup split pollers should succeed");
  fakeNowMs = 0;
  session_t *session = sessionCreate(true, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireServerSessionRuntime(session, &serverRuntime, &poller);

  fakeNowMs = 8999;
  testAssertTrue(
      sessionStep(session, &poller.tcpPoller, &poller.tunPoller, ioEventTimeout, key) == sessionStepContinue,
      "server should continue before configured timeout");
  fakeNowMs = 9000;
  testAssertTrue(
      runSessionStepWithSuppressedStderr(session, &poller, ioEventTimeout, key) == sessionStepStop,
      "server should stop at configured timeout");

  sessionDestroy(session);
  serverDeinit(&serverRuntime);
  teardownSplitPollers(&poller);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testServerTunOverflowDisablesTunEpollinGlobally(void) {
  unsigned char key[ProtocolPskSize];
  server_t runtime;
  int epollFd;
  int tunPair[2];
  int tcpPairA[2];
  int tcpPairB[2] = {-1, -1};
  int slotA;
  int slotB;
  char fill[IoPollerQueueCapacity];
  char tunPayload[128];
  session_t *session;
  ioTcpPoller_t *poller;

  memset(key, 0x51, sizeof(key));
  memset(fill, 'p', sizeof(fill));
  memset(tunPayload, 'q', sizeof(tunPayload));
  setupServerForSessionTest(&runtime, 1, &epollFd, tunPair, tcpPairA, tcpPairB, &slotA, &slotB);
  session = serverSessionAt(&runtime, slotA);
  testAssertTrue(session != NULL, "server session should exist");
  poller = &runtime.activeConns[slotA].tcpPoller;

  testAssertTrue(
      ioTcpWrite(poller, fill, IoPollerQueueCapacity - 16),
      "prefill tcp queue should succeed");
  testAssertTrue(write(tunPair[1], tunPayload, sizeof(tunPayload)) == (long)sizeof(tunPayload), "tun write should succeed");
  testAssertTrue(
      runSessionStepSplit(session, poller, &runtime.tunPoller, ioEventTunRead, key) == sessionStepContinue,
      "session should continue on overflow");
  testAssertTrue(serverHasPendingTunToTcp(&runtime), "server overflow should retain pending data in runtime");
  testAssertTrue((runtime.tunPoller.events & EPOLLIN) == 0, "runtime should disable tun epollin while pending exists");

  teardownServerForSessionTest(&runtime, epollFd, tunPair, tcpPairA, tcpPairB, slotA, slotB);
}

static void testServerPendingRetriesOnOwnerAndResumesTunEpollinAtLowWatermark(void) {
  unsigned char key[ProtocolPskSize];
  server_t runtime;
  int epollFd;
  int tunPair[2];
  int tcpPairA[2];
  int tcpPairB[2];
  int slotA;
  int slotB;
  char fill[IoPollerQueueCapacity];
  char tunPayload[128];
  session_t *ownerSession;
  session_t *otherSession;
  ioTcpPoller_t *ownerPoller;
  ioTcpPoller_t *otherPoller;
  long queued;

  memset(key, 0x52, sizeof(key));
  memset(fill, 'r', sizeof(fill));
  memset(tunPayload, 's', sizeof(tunPayload));
  setupServerForSessionTest(&runtime, 2, &epollFd, tunPair, tcpPairA, tcpPairB, &slotA, &slotB);
  ownerSession = serverSessionAt(&runtime, slotA);
  otherSession = serverSessionAt(&runtime, slotB);
  ownerPoller = &runtime.activeConns[slotA].tcpPoller;
  otherPoller = &runtime.activeConns[slotB].tcpPoller;
  testAssertTrue(ownerSession != NULL, "owner session should exist");
  testAssertTrue(otherSession != NULL, "other session should exist");

  testAssertTrue(
      ioTcpWrite(ownerPoller, fill, IoPollerQueueCapacity - 16),
      "prefill owner tcp queue should succeed");
  testAssertTrue(write(tunPair[1], tunPayload, sizeof(tunPayload)) == (long)sizeof(tunPayload), "tun write should succeed");
  testAssertTrue(
      runSessionStepSplit(ownerSession, ownerPoller, &runtime.tunPoller, ioEventTunRead, key) == sessionStepContinue,
      "overflow on owner should continue");
  testAssertTrue(serverHasPendingTunToTcp(&runtime), "owner overflow should store runtime pending bytes");
  testAssertTrue((runtime.tunPoller.events & EPOLLIN) == 0, "tun epollin should be disabled while runtime pending exists");

  testAssertTrue(
      runSessionStepSplit(otherSession, otherPoller, &runtime.tunPoller, ioEventTcpWrite, key) == sessionStepContinue,
      "non-owner tcp write path should continue");
  testAssertTrue((runtime.tunPoller.events & EPOLLIN) == 0, "non-owner should not consume runtime pending");

  ownerPoller->outOffset = 0;
  ownerPoller->outNbytes = IoPollerLowWatermark + 100;
  testAssertTrue(
      runSessionStepSplit(ownerSession, ownerPoller, &runtime.tunPoller, ioEventTcpWrite, key) == sessionStepContinue,
      "owner tcp write path should continue after first drain");
  queued = ioTcpQueuedBytes(ownerPoller);
  testAssertTrue(queued > IoPollerLowWatermark, "owner queue should remain above low watermark");
  testAssertTrue((runtime.tunPoller.events & EPOLLIN) == 0, "tun epollin should stay disabled above low watermark");

  ownerPoller->outOffset = 0;
  ownerPoller->outNbytes = IoPollerLowWatermark;
  testAssertTrue(
      runSessionStepSplit(ownerSession, ownerPoller, &runtime.tunPoller, ioEventTcpWrite, key) == sessionStepContinue,
      "owner tcp write path should continue after second drain");
  queued = ioTcpQueuedBytes(ownerPoller);
  testAssertTrue(queued <= IoPollerLowWatermark, "owner queue should drain to low watermark");
  testAssertTrue((runtime.tunPoller.events & EPOLLIN) != 0, "tun epollin should resume at low watermark");

  teardownServerForSessionTest(&runtime, epollFd, tunPair, tcpPairA, tcpPairB, slotA, slotB);
}

static void testServerOwnerDisconnectDropsRuntimePendingAndResumesTunEpollin(void) {
  unsigned char key[ProtocolPskSize];
  server_t runtime;
  int epollFd;
  int tunPair[2];
  int tcpPairA[2];
  int tcpPairB[2] = {-1, -1};
  int slotA;
  int slotB;
  char fill[IoPollerQueueCapacity];
  char tunPayload[128];
  session_t *session;
  ioTcpPoller_t *poller;

  memset(key, 0x53, sizeof(key));
  memset(fill, 'u', sizeof(fill));
  memset(tunPayload, 'v', sizeof(tunPayload));
  setupServerForSessionTest(&runtime, 1, &epollFd, tunPair, tcpPairA, tcpPairB, &slotA, &slotB);
  session = serverSessionAt(&runtime, slotA);
  testAssertTrue(session != NULL, "server session should exist");
  poller = &runtime.activeConns[slotA].tcpPoller;

  testAssertTrue(
      ioTcpWrite(poller, fill, IoPollerQueueCapacity - 16),
      "prefill tcp queue should succeed");
  testAssertTrue(write(tunPair[1], tunPayload, sizeof(tunPayload)) == (long)sizeof(tunPayload), "tun write should succeed");
  testAssertTrue(
      runSessionStepSplit(session, poller, &runtime.tunPoller, ioEventTunRead, key) == sessionStepContinue,
      "overflow path should continue");
  testAssertTrue((runtime.tunPoller.events & EPOLLIN) == 0, "tun epollin should be disabled while pending is active");

  testAssertTrue(serverRemoveClient(&runtime, slotA), "owner removal should succeed");
  slotA = -1;
  testAssertTrue((runtime.tunPoller.events & EPOLLIN) != 0, "tun epollin should re-enable after owner disconnect drop");

  teardownServerForSessionTest(&runtime, epollFd, tunPair, tcpPairA, tcpPairB, slotA, slotB);
}

static void testServerQueueBackpressureBlocksAndStoresRuntimePendingPayload(void) {
  server_t runtime;
  int tunPair[2];
  int tcpPair[2];
  char fill[IoPollerQueueCapacity];
  char payload[128];
  sessionQueueResult_t result;

  memset(fill, 'w', sizeof(fill));
  memset(payload, 'z', sizeof(payload));
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "server tun pair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "server tcp pair should be created");
  testAssertTrue(
      serverInit(&runtime, tunPair[0], 80, 1, 1, &testHeartbeatCfg, NULL, NULL),
      "server runtime init should succeed");
  testAssertTrue(serverAddClient(&runtime, 0, tcpPair[0], testKey, claim2, sizeof(claim2)) == 0, "server client should be added");
  testAssertTrue(
      ioTcpWrite(&runtime.activeConns[0].tcpPoller, fill, IoPollerQueueCapacity - 16),
      "prefill server tcp queue should succeed");
  result = serverQueueTcpWithBackpressure(
      &runtime, &runtime.activeConns[0].tcpPoller, payload, sizeof(payload));
  testAssertTrue(result == sessionQueueResultBlocked, "server queue api should block on overflow");
  testAssertTrue(serverHasPendingTunToTcp(&runtime), "server queue api should store runtime pending payload");
  testAssertTrue(serverPendingTunToTcpOwner(&runtime) == 0, "server pending payload owner should match slot");

  serverDeinit(&runtime);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testServerInboundHeartbeatHandlerQueuesAckAndRefreshesTimestamp(void) {
  server_t runtime;
  int tunPair[2];
  int tcpPair[2];
  bool heartbeatPending = false;
  long long lastValidInboundMs = 17;
  protocolMessage_t req = {.type = protocolMsgHeartbeatReq, .nbytes = 0, .buf = NULL};
  sessionQueueResult_t result;

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "server tun pair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "server tcp pair should be created");
  testAssertTrue(
      serverInit(&runtime, tunPair[0], 81, 1, 1, &testHeartbeatCfg, NULL, NULL),
      "server runtime init should succeed");
  testAssertTrue(serverAddClient(&runtime, 0, tcpPair[0], testKey, claim2, sizeof(claim2)) == 0, "server client should be added");

  result = serverHandleInboundMessage(
      &runtime,
      &runtime.activeConns[0].tcpPoller,
      testKey,
      &heartbeatPending,
      &lastValidInboundMs,
      &req);
  testAssertTrue(result == sessionQueueResultQueued, "server inbound heartbeat request should route through server handler");
  testAssertTrue(lastValidInboundMs > 0, "server handler should refresh last valid inbound timestamp");

  serverDeinit(&runtime);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testServerHeartbeatTickTimeoutBoundary(void) {
  testAssertTrue(serverHeartbeatTick(NULL, 8999, 0, 9000), "server heartbeat should allow pre-timeout interval");
  testAssertTrue(!serverHeartbeatTick(NULL, 9000, 0, 9000), "server heartbeat should stop at timeout boundary");
}

static void testServerBackpressureServiceSucceedsWithoutPendingBytes(void) {
  server_t runtime;
  int tunPair[2];
  int tcpPair[2];

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "server tun pair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "server tcp pair should be created");
  testAssertTrue(
      serverInit(&runtime, tunPair[0], 82, 1, 1, &testHeartbeatCfg, NULL, NULL),
      "server runtime init should succeed");
  testAssertTrue(serverAddClient(&runtime, 0, tcpPair[0], testKey, claim2, sizeof(claim2)) == 0, "server client should be added");
  testAssertTrue(
      serverServiceBackpressure(
          &runtime,
          &runtime.activeConns[0].tcpPoller,
          ioEventTimeout),
      "server backpressure service should succeed without pending bytes");

  serverDeinit(&runtime);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

void runServerTests(void) {
  testServerServeMultiClientRejectsInvalidArgs();
  testServerAddRemoveAndReuseSlots();
  testServerRejectsBeyondMaxSessions();
  testServerFindSlotByFdAndPickEgress();
  testServerFindSlotByClaim();
  testServerSharedTunInterestTracksGlobalQueue();
  testServerRoundRobinRetryCursorRotates();
  testServerPendingTunToTcpOwnerControlsRetryAndReadInterest();
  testServerRoutesTunIngressByClaimMatch();
  testServerDropsTunIngressOnUnmatchedBroadcastMulticastAndMalformed();
  testServerFanoutTapBroadcastToAllClients();
  testServerFanoutTunBroadcastsBySubnetPolicy();
  testServerBroadcastFanoutSkipsSaturatedClient();
  testServerQueueBackpressureBlocksAndStoresRuntimePendingPayload();
  testServerInboundHeartbeatHandlerQueuesAckAndRefreshesTimestamp();
  testServerHeartbeatTickTimeoutBoundary();
  testServerBackpressureServiceSucceedsWithoutPendingBytes();
  testServerHeartbeatTimeoutStopsSession();
  testServerHeartbeatTimeoutUsesConfiguredTimeout();
  testServerTunOverflowDisablesTunEpollinGlobally();
  testServerPendingRetriesOnOwnerAndResumesTunEpollinAtLowWatermark();
  testServerOwnerDisconnectDropsRuntimePendingAndResumesTunEpollin();
}
