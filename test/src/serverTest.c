#include "serverTest.h"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string.h>

#include "packet.h"
#include "server.h"
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

void runServerTests(void) {
  testServerServeMultiClientRejectsInvalidArgs();
  testServerAddRemoveAndReuseSlots();
  testServerRejectsBeyondMaxSessions();
  testServerFindSlotByFdAndPickEgress();
  testServerFindSlotByClaim();
  testServerSharedTunInterestTracksGlobalQueue();
  testServerRoundRobinRetryCursorRotates();
  testServerRoutesTunIngressByClaimMatch();
  testServerDropsTunIngressOnUnmatchedBroadcastMulticastAndMalformed();
  testServerFanoutTapBroadcastToAllClients();
  testServerFanoutTunBroadcastsBySubnetPolicy();
  testServerBroadcastFanoutSkipsSaturatedClient();
}
