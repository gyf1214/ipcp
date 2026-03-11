#include "sessionTest.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
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
static const sessionServerIdentity_t testServerIdentity = {
    .claim = {10, 0, 0, 1},
    .claimNbytes = 4,
    .directedBroadcastEnabled = false,
    .directedBroadcast = {0, 0, 0, 0},
};
static long long fakeNowMs = 0;

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
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
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

  result = sessionStep(session, tcpPoller, tunPoller, event, key);

  fflush(stderr);
  testAssertTrue(dup2(savedStderr, STDERR_FILENO) >= 0, "restore stderr should succeed");
  close(savedStderr);
  return result;
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

static bool serverInitFixture(
    server_t *server,
    int tunFd,
    int listenFd,
    int maxActiveSessions,
    int maxPreAuthSessions,
    const sessionHeartbeatConfig_t *heartbeatCfg,
    sessionNowMsFn_t nowMsFn,
    void *nowCtx) {
  if (!serverInit(server, maxActiveSessions, maxPreAuthSessions, heartbeatCfg, nowMsFn, nowCtx)) {
    return false;
  }
  server->tunPoller.poller.fd = tunFd;
  server->listenPoller.poller.fd = listenFd;
  return true;
}

#define serverInit(...) serverInitFixture(__VA_ARGS__)

typedef struct {
  server_t server;
  int tunPair[2];
  int tcpPair[2];
} serverFixture_t;

static void serverFixtureSetup(
    serverFixture_t *fixture,
    int listenFd,
    int maxActiveSessions,
    int maxPreAuthSessions,
    const sessionHeartbeatConfig_t *heartbeatCfg,
    sessionNowMsFn_t nowMsFn,
    void *nowCtx);
static int serverFixtureAddClient(
    serverFixture_t *fixture,
    int keySlot,
    const unsigned char key[ProtocolPskSize],
    const unsigned char *claim,
    long claimNbytes);
static void serverFixtureTeardown(serverFixture_t *fixture);

static void testServerServeMultiClientRejectsInvalidArgs(void) {
  server_t server;
  memset(&server, 0, sizeof(server));
  testAssertTrue(
      serverServeMultiClient(NULL) < 0,
      "server server should reject null server");
  testAssertTrue(
      serverServeMultiClient(&server) < 0,
      "server server should reject uninitialized server");
  testAssertTrue(
      serverInit(&server, -1, -1, 2, 2, &testHeartbeatCfg, NULL, NULL),
      "fixture init should succeed");
  server.resolveClaimFn = fakeLookup;
  server.mode = sessionIfModeTun;
  server.authTimeoutMs = 5000;
  testAssertTrue(
      serverServeMultiClient(&server) < 0,
      "server server should reject missing poller fds");
  serverDeinit(&server);
}

static void testSessionRunEntrypointsRejectInvalidConfigs(void) {
  sessionServerConfig_t serverCfg = {
      .ifName = "tun0",
      .ifMode = ioIfModeTun,
      .listenIP = "127.0.0.1",
      .port = 5001,
      .resolveClaimFn = fakeLookup,
      .resolveClaimCtx = NULL,
      .serverIdentity = &testServerIdentity,
      .authTimeoutMs = 5000,
      .heartbeat = testHeartbeatCfg,
      .maxActiveSessions = 2,
      .maxPreAuthSessions = 2,
  };

  testAssertTrue(sessionRunServer(NULL) < 0, "sessionRunServer should reject null config pointer");

  serverCfg.ifName = NULL;
  testAssertTrue(sessionRunServer(&serverCfg) < 0, "sessionRunServer should reject null interface name");
  serverCfg.ifName = "tun0";
  serverCfg.ifName = "";
  testAssertTrue(sessionRunServer(&serverCfg) < 0, "sessionRunServer should reject empty interface name");
  serverCfg.ifName = "tun0";
  serverCfg.ifMode = (ioIfMode_t)99;
  testAssertTrue(sessionRunServer(&serverCfg) < 0, "sessionRunServer should reject invalid interface mode");
  serverCfg.ifMode = ioIfModeTun;
  serverCfg.listenIP = NULL;
  testAssertTrue(sessionRunServer(&serverCfg) < 0, "sessionRunServer should reject null listen ip");
  serverCfg.listenIP = "127.0.0.1";
  serverCfg.port = 0;
  testAssertTrue(sessionRunServer(&serverCfg) < 0, "sessionRunServer should reject non-positive listen port");
  serverCfg.port = 5001;
  serverCfg.resolveClaimFn = NULL;
  testAssertTrue(sessionRunServer(&serverCfg) < 0, "sessionRunServer should reject null resolve callback");
  serverCfg.resolveClaimFn = fakeLookup;
  serverCfg.authTimeoutMs = 0;
  testAssertTrue(sessionRunServer(&serverCfg) < 0, "sessionRunServer should reject non-positive auth timeout");
  serverCfg.authTimeoutMs = 5000;
  serverCfg.maxActiveSessions = 0;
  testAssertTrue(sessionRunServer(&serverCfg) < 0, "sessionRunServer should reject non-positive max active sessions");
  serverCfg.maxActiveSessions = 2;
  serverCfg.maxPreAuthSessions = 0;
  testAssertTrue(sessionRunServer(&serverCfg) < 0, "sessionRunServer should reject non-positive max pre-auth sessions");
  serverCfg.maxPreAuthSessions = 2;
  serverCfg.heartbeat.intervalMs = 0;
  testAssertTrue(sessionRunServer(&serverCfg) < 0, "sessionRunServer should reject non-positive heartbeat interval");
  serverCfg.heartbeat.intervalMs = testHeartbeatCfg.intervalMs;
  serverCfg.heartbeat.timeoutMs = testHeartbeatCfg.intervalMs;
  testAssertTrue(sessionRunServer(&serverCfg) < 0, "sessionRunServer should reject heartbeat timeout <= interval");
}

static void testServerAddRemoveAndReuseSlots(void) {
  server_t server;
  int slot0;
  int slot1;
  int reusedSlot;

  testAssertTrue(
      serverInit(&server, 10, 11, 2, 2, &testHeartbeatCfg, NULL, NULL),
      "server init should succeed");

  slot0 = serverAddClient(&server, 0, 100, testKey, claim2, sizeof(claim2));
  slot1 = serverAddClient(&server, 1, 101, testKey, claim3, sizeof(claim3));
  testAssertTrue(slot0 == 0, "first client should use slot 0");
  testAssertTrue(slot1 == 1, "second client should use slot 1");
  testAssertTrue(serverClientCount(&server) == 2, "client count should track active clients");

  testAssertTrue(serverRemoveClient(&server, slot0), "remove should succeed for active slot");
  testAssertTrue(serverClientCount(&server) == 1, "client count should decrement after remove");

  reusedSlot = serverAddClient(&server, 0, 102, testKey, claim4, sizeof(claim4));
  testAssertTrue(reusedSlot == 0, "server should reuse first free slot");
  testAssertTrue(serverClientCount(&server) == 2, "client count should return to cap");

  serverDeinit(&server);
}

static void testServerActiveKeyBorrowUsesAuthoritativeStorage(void) {
  server_t server;
  unsigned char zeroKey[ProtocolPskSize];
  const unsigned char *borrowed;
  const unsigned char *authoritative;

  memset(zeroKey, 0, sizeof(zeroKey));
  testAssertTrue(
      serverInit(&server, 14, 15, 2, 2, &testHeartbeatCfg, NULL, NULL),
      "server init should succeed");
  testAssertTrue(
      serverAddClient(&server, 0, 140, testKey, claim2, sizeof(claim2)) == 0,
      "server should add active client");

  borrowed = serverKeyAt(&server, 0);
  authoritative = serverAuthoritativeKeyAt(&server, 0);
  testAssertTrue(borrowed != NULL, "borrowed key should be available for active slot");
  testAssertTrue(authoritative != NULL, "authoritative key should be available for slot");
  testAssertTrue(borrowed == authoritative, "active key should borrow authoritative storage");
  testAssertTrue(memcmp(authoritative, testKey, ProtocolPskSize) == 0, "authoritative slot should store resolved key");

  testAssertTrue(serverRemoveClient(&server, 0), "remove should succeed");
  authoritative = serverAuthoritativeKeyAt(&server, 0);
  testAssertTrue(memcmp(authoritative, zeroKey, ProtocolPskSize) == 0, "authoritative key bytes should zeroize on remove");
  testAssertTrue(server.activeConns[0].keyRef == NULL, "active slot should clear borrowed key reference on remove");
  testAssertTrue(server.activeConns[0].keySlot == -1, "active slot should clear borrowed key slot index on remove");

  serverDeinit(&server);
}

static void testServerRemoveClientClearsBorrowedPollerState(void) {
  server_t server;

  testAssertTrue(
      serverInit(&server, 16, 17, 2, 2, &testHeartbeatCfg, NULL, NULL),
      "server init should succeed");
  testAssertTrue(
      serverAddClient(&server, 0, 160, testKey, claim2, sizeof(claim2)) == 0,
      "server should add active client");
  testAssertTrue(server.activeConns[0].tcpPoller.poller.fd == 160, "active poller should borrow active connection fd");
  testAssertTrue(
      server.activeConns[0].tcpPoller.poller.ctx == &server.activeConns[0],
      "active poller should carry active-conn callback ctx");

  testAssertTrue(serverRemoveClient(&server, 0), "remove should succeed");
  testAssertTrue(server.activeConns[0].tcpPoller.poller.fd == -1, "remove should clear borrowed poller fd");
  testAssertTrue(server.activeConns[0].tcpPoller.poller.reactor == NULL, "remove should clear borrowed poller reactor");
  testAssertTrue(server.activeConns[0].tcpPoller.poller.events == 0, "remove should clear borrowed poller events");
  testAssertTrue(server.activeConns[0].tcpPoller.poller.ctx == NULL, "remove should clear borrowed poller callback ctx");
  testAssertTrue(server.activeConns[0].session == NULL, "remove should clear borrowed session reference");

  serverDeinit(&server);
}

static void testServerRejectsBeyondMaxSessions(void) {
  server_t server;

  testAssertTrue(
      serverInit(&server, 20, 21, 1, 1, &testHeartbeatCfg, NULL, NULL),
      "server init should succeed");
  testAssertTrue(
      serverAddClient(&server, 0, 200, testKey, claim2, sizeof(claim2)) == 0,
      "first slot should be accepted");
  testAssertTrue(
      serverAddClient(&server, 0, 201, testKey, claim3, sizeof(claim3)) < 0,
      "server should reject client when max reached");

  serverDeinit(&server);
}

static void testServerFindSlotByClaim(void) {
  server_t server;
  int slot0;
  int slot1;
  unsigned char mismatchLenClaim[] = {10, 0, 0};
  unsigned char unknownClaim[] = {10, 0, 0, 99};

  testAssertTrue(
      serverInit(&server, 35, 36, 3, 3, &testHeartbeatCfg, NULL, NULL),
      "server init should succeed");
  slot0 = serverAddClient(&server, 0, 350, testKey, claim2, sizeof(claim2));
  slot1 = serverAddClient(&server, 1, 351, testKey, claim3, sizeof(claim3));
  testAssertTrue(slot0 == 0 && slot1 == 1, "server should allocate slots for claim tests");

  testAssertTrue(
      serverFindSlotByClaim(&server, claim2, sizeof(claim2)) == slot0,
      "claim lookup should return exact matching slot");
  testAssertTrue(
      serverFindSlotByClaim(&server, claim3, sizeof(claim3)) == slot1,
      "claim lookup should return second matching slot");
  testAssertTrue(
      serverFindSlotByClaim(&server, unknownClaim, sizeof(unknownClaim)) < 0,
      "unknown claim should not match");
  testAssertTrue(
      serverFindSlotByClaim(&server, mismatchLenClaim, sizeof(mismatchLenClaim)) < 0,
      "claim length mismatch should not match");

  testAssertTrue(serverRemoveClient(&server, slot0), "remove slot 0 should succeed");
  testAssertTrue(
      serverFindSlotByClaim(&server, claim2, sizeof(claim2)) < 0,
      "inactive slot should be ignored for claim lookup");

  serverDeinit(&server);
}

static void testServerRoundRobinRetryCursorRotates(void) {
  server_t server;

  testAssertTrue(
      serverInit(&server, 50, 51, 4, 4, &testHeartbeatCfg, NULL, NULL),
      "server init should succeed");
  testAssertTrue(server.retryCursor == 0, "retry cursor should start at zero");
  testAssertTrue(
      serverAddClient(&server, 0, 500, testKey, claim2, sizeof(claim2)) == 0,
      "first client should be added");
  testAssertTrue(
      serverAddClient(&server, 1, 501, testKey, claim3, sizeof(claim3)) == 1,
      "second client should be added");
  testAssertTrue(
      serverAddClient(&server, 2, 502, testKey, claim4, sizeof(claim4)) == 2,
      "third client should be added");

  server.retryCursor = 1;
  testAssertTrue(serverRetryBlockedTunRoundRobin(&server) == 2, "retry pass should advance cursor to next slot");
  testAssertTrue(server.retryCursor == 2, "retry cursor should rotate after retry pass");

  testAssertTrue(serverRetryBlockedTunRoundRobin(&server) == 0, "retry pass should wrap cursor");
  testAssertTrue(server.retryCursor == 0, "retry cursor should wrap to zero");

  serverDeinit(&server);
}

static void testServerPendingTunToTcpOwnerControlsRetryAndReadInterest(void) {
  serverFixture_t fixture;
  unsigned char payload[] = "pending-owner-payload";
  serverPendingRetry_t retry;
  int slot;

  serverFixtureSetup(&fixture, 52, 1, 1, &testHeartbeatCfg, NULL, NULL);
  slot = serverFixtureAddClient(&fixture, 0, testKey, claim2, sizeof(claim2));
  testAssertTrue(slot == 0, "slot should be added");

  fixture.server.activeConns[0].tcpPoller.outOffset = 0;
  fixture.server.activeConns[0].tcpPoller.outNbytes = IoPollerQueueCapacity;

  testAssertTrue(
      serverStorePendingTunToTcp(&fixture.server, 0, payload, (long)sizeof(payload)),
      "storing pending tun-to-tcp payload should succeed");
  testAssertTrue(serverHasPendingTunToTcp(&fixture.server), "server should report pending tun-to-tcp payload");
  testAssertTrue(serverPendingTunToTcpOwner(&fixture.server) == 0, "server should record pending owner slot");
  testAssertTrue((fixture.server.tunPoller.poller.events & EPOLLIN) == 0, "server should disable tun epollin while pending is active");

  retry = serverRetryPendingTunToTcp(&fixture.server, 1, &fixture.server.activeConns[0].tcpPoller);
  testAssertTrue(retry == serverPendingRetryBlocked, "non-owner retry should be blocked");
  testAssertTrue(serverHasPendingTunToTcp(&fixture.server), "non-owner retry should not consume pending payload");

  fixture.server.activeConns[0].tcpPoller.outOffset = 0;
  fixture.server.activeConns[0].tcpPoller.outNbytes = 0;
  retry = serverRetryPendingTunToTcp(&fixture.server, 0, &fixture.server.activeConns[0].tcpPoller);
  testAssertTrue(retry == serverPendingRetryQueued, "owner retry should queue pending payload");
  testAssertTrue(!serverHasPendingTunToTcp(&fixture.server), "owner retry should clear pending payload");

  testAssertTrue(
      serverSetTunReadEnabled(&fixture.server, true),
      "read interest should be re-enabled after pending payload clears");
  testAssertTrue((fixture.server.tunPoller.poller.events & EPOLLIN) != 0, "server should enable tun epollin when requested");
  serverFixtureTeardown(&fixture);
}

static void testServerRoutesTunIngressByClaimMatch(void) {
  server_t server;
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
  testAssertTrue(serverInit(&server, tunPair[0], 60, 3, 3, &testHeartbeatCfg, NULL, NULL), "server init should succeed");
  testAssertTrue(
      serverAddClient(&server, 0, tcpPairA[0], testKey, claim2, sizeof(claim2)) == 0,
      "slot A should be added");
  testAssertTrue(
      serverAddClient(&server, 1, tcpPairB[0], testKey, claim3, sizeof(claim3)) == 1,
      "slot B should be added");

  testAssertTrue(
      serverRouteTunIngressPacket(&server, payload, sizeof(payload)),
      "tun ingress routing should succeed for matching claim");
  testAssertTrue(
      server.activeConns[0].tcpPoller.outNbytes == 0,
      "non-matching client should have no queued tcp bytes");
  testAssertTrue(
      server.activeConns[1].tcpPoller.outNbytes > 0,
      "matching client should have queued encrypted frame bytes");

  serverDeinit(&server);
  close(tcpPairA[0]);
  close(tcpPairA[1]);
  close(tcpPairB[0]);
  close(tcpPairB[1]);
  close(tunPair[0]);
  close(tunPair[1]);
}

static void testServerDropsTunIngressOnUnmatchedBroadcastMulticastAndMalformed(void) {
  server_t server;
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
  testAssertTrue(serverInit(&server, tunPair[0], 61, 2, 2, &testHeartbeatCfg, NULL, NULL), "server init should succeed");
  testAssertTrue(
      serverAddClient(&server, 0, tcpPairA[0], testKey, claim2, sizeof(claim2)) == 0,
      "slot A should be added");

  testAssertTrue(serverRouteTunIngressPacket(&server, unmatched, sizeof(unmatched)), "unmatched route should not fail");
  testAssertTrue(serverRouteTunIngressPacket(&server, multicast, sizeof(multicast)), "multicast drop should not fail");
  testAssertTrue(serverRouteTunIngressPacket(&server, malformed, sizeof(malformed)), "malformed drop should not fail");
  testAssertTrue(server.activeConns[0].tcpPoller.outNbytes == 0, "drop cases should not queue to any client");

  serverDeinit(&server);
  close(tcpPairA[0]);
  close(tcpPairA[1]);
  close(tunPair[0]);
  close(tunPair[1]);
}

static void testServerFanoutTapBroadcastToAllClients(void) {
  server_t server;
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
  testAssertTrue(serverInit(&server, tunPair[0], 62, 3, 3, &testHeartbeatCfg, NULL, NULL), "server init should succeed");
  server.mode = sessionIfModeTap;
  testAssertTrue(serverAddClient(&server, 0, tcpPairA[0], testKey, claim2, sizeof(claim2)) == 0, "slot A should be added");
  testAssertTrue(serverAddClient(&server, 1, tcpPairB[0], testKey, claim3, sizeof(claim3)) == 1, "slot B should be added");

  testAssertTrue(
      serverRouteTunIngressPacket(&server, tapBroadcast, sizeof(tapBroadcast)),
      "tap broadcast fanout should not fail");
  testAssertTrue(server.activeConns[0].tcpPoller.outNbytes > 0, "client A should receive tap broadcast");
  testAssertTrue(server.activeConns[1].tcpPoller.outNbytes > 0, "client B should receive tap broadcast");

  serverDeinit(&server);
  close(tcpPairA[0]);
  close(tcpPairA[1]);
  close(tcpPairB[0]);
  close(tcpPairB[1]);
  close(tunPair[0]);
  close(tunPair[1]);
}

static void testServerFanoutTunBroadcastsBySubnetPolicy(void) {
  server_t server;
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
  testAssertTrue(serverInit(&server, tunPair[0], 63, 3, 3, &testHeartbeatCfg, NULL, NULL), "server init should succeed");
  server.serverIdentity.directedBroadcastEnabled = true;
  server.serverIdentity.directedBroadcast[0] = 10;
  server.serverIdentity.directedBroadcast[1] = 250;
  server.serverIdentity.directedBroadcast[2] = 0;
  server.serverIdentity.directedBroadcast[3] = 255;
  testAssertTrue(serverAddClient(&server, 0, tcpPairA[0], testKey, claim2, sizeof(claim2)) == 0, "slot A should be added");
  testAssertTrue(serverAddClient(&server, 1, tcpPairB[0], testKey, claim3, sizeof(claim3)) == 1, "slot B should be added");

  testAssertTrue(
      serverRouteTunIngressPacket(&server, directedBroadcast, sizeof(directedBroadcast)),
      "directed broadcast fanout should not fail");
  testAssertTrue(server.activeConns[0].tcpPoller.outNbytes > 0, "client A should receive directed broadcast");
  testAssertTrue(server.activeConns[1].tcpPoller.outNbytes > 0, "client B should receive directed broadcast");

  server.activeConns[0].tcpPoller.outNbytes = 0;
  server.activeConns[1].tcpPoller.outNbytes = 0;
  testAssertTrue(
      serverRouteTunIngressPacket(&server, limitedBroadcast, sizeof(limitedBroadcast)),
      "limited broadcast fanout should not fail");
  testAssertTrue(server.activeConns[0].tcpPoller.outNbytes > 0, "client A should receive limited broadcast");
  testAssertTrue(server.activeConns[1].tcpPoller.outNbytes > 0, "client B should receive limited broadcast");

  server.activeConns[0].tcpPoller.outNbytes = 0;
  server.activeConns[1].tcpPoller.outNbytes = 0;
  testAssertTrue(
      serverRouteTunIngressPacket(&server, nonMatchingDirected, sizeof(nonMatchingDirected)),
      "non-matching directed broadcast should not fail");
  testAssertTrue(server.activeConns[0].tcpPoller.outNbytes == 0, "non-matching directed broadcast should drop");
  testAssertTrue(server.activeConns[1].tcpPoller.outNbytes == 0, "non-matching directed broadcast should drop");

  testAssertTrue(serverRouteTunIngressPacket(&server, multicast, sizeof(multicast)), "multicast drop should not fail");
  testAssertTrue(server.activeConns[0].tcpPoller.outNbytes == 0, "multicast should not queue client A");
  testAssertTrue(server.activeConns[1].tcpPoller.outNbytes == 0, "multicast should not queue client B");

  serverDeinit(&server);
  close(tcpPairA[0]);
  close(tcpPairA[1]);
  close(tcpPairB[0]);
  close(tcpPairB[1]);
  close(tunPair[0]);
  close(tunPair[1]);
}

static void testServerBroadcastFanoutSkipsSaturatedClient(void) {
  server_t server;
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
  testAssertTrue(serverInit(&server, tunPair[0], 64, 3, 3, &testHeartbeatCfg, NULL, NULL), "server init should succeed");
  server.serverIdentity.directedBroadcastEnabled = true;
  server.serverIdentity.directedBroadcast[0] = 10;
  server.serverIdentity.directedBroadcast[1] = 250;
  server.serverIdentity.directedBroadcast[2] = 0;
  server.serverIdentity.directedBroadcast[3] = 255;
  testAssertTrue(serverAddClient(&server, 0, tcpPairA[0], testKey, claim2, sizeof(claim2)) == 0, "slot A should be added");
  testAssertTrue(serverAddClient(&server, 1, tcpPairB[0], testKey, claim3, sizeof(claim3)) == 1, "slot B should be added");

  server.activeConns[0].tcpPoller.outOffset = 0;
  server.activeConns[0].tcpPoller.outNbytes = IoPollerQueueCapacity;

  testAssertTrue(
      serverRouteTunIngressPacket(&server, limitedBroadcast, sizeof(limitedBroadcast)),
      "broadcast fanout with saturation should not fail");
  testAssertTrue(
      server.activeConns[0].tcpPoller.outNbytes == IoPollerQueueCapacity,
      "saturated client queue should remain unchanged");
  testAssertTrue(server.activeConns[1].tcpPoller.outNbytes > 0, "non-saturated client should still receive broadcast");
  testAssertTrue(!serverHasPendingTunToTcp(&server), "broadcast best-effort skip should not set shared pending packet");

  serverDeinit(&server);
  close(tcpPairA[0]);
  close(tcpPairA[1]);
  close(tcpPairB[0]);
  close(tcpPairB[1]);
  close(tunPair[0]);
  close(tunPair[1]);
}

static void testServerQueueWithDropSkipsOverflowWithoutPendingState(void) {
  serverFixture_t fixture;
  const char payload[] = "drop-me";
  sessionQueueResult_t result;
  int slot;

  serverFixtureSetup(&fixture, 78, 1, 1, &testHeartbeatCfg, NULL, NULL);
  slot = serverFixtureAddClient(&fixture, 0, testKey, claim2, sizeof(claim2));
  testAssertTrue(slot == 0, "server client should be added");

  fixture.server.activeConns[0].tcpPoller.outOffset = 0;
  fixture.server.activeConns[0].tcpPoller.outNbytes = IoPollerQueueCapacity - 2;

  result = serverQueueTcpWithDrop(
      &fixture.server.activeConns[0].tcpPoller,
      payload,
      (long)sizeof(payload) - 1);
  testAssertTrue(result == sessionQueueResultBlocked, "queue-with-drop should report dropped on overflow");
  testAssertTrue(
      fixture.server.activeConns[0].tcpPoller.outNbytes == IoPollerQueueCapacity - 2,
      "queue-with-drop should leave queue unchanged when dropping");
  testAssertTrue(!serverHasPendingTunToTcp(&fixture.server), "queue-with-drop should not use shared pending state");
  serverFixtureTeardown(&fixture);
}

static void testServerRoutesTcpIngressAcrossClientsAndTun(void) {
  server_t server;
  int tunPair[2];
  int tcpPairA[2];
  int tcpPairB[2];
  unsigned char toPeer[] = {
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 0, 0, 2,
      10, 0, 0, 3,
  };
  unsigned char toServer[] = {
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 0, 0, 2,
      10, 0, 0, 1,
  };
  unsigned char broadcast[] = {
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 0, 0, 2,
      255, 255, 255, 255,
  };
  unsigned char selfDest[] = {
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 0, 0, 2,
      10, 0, 0, 2,
  };
  unsigned char unknownDest[] = {
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 0, 0, 2,
      10, 0, 0, 99,
  };
  unsigned char multicast[] = {
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 0, 0, 2,
      224, 1, 2, 3,
  };
  unsigned char malformed[] = {0x45, 0x00, 0x00, 0x14};
  unsigned char tapBroadcast[] = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0x02, 0x00, 0x5e, 0x00, 0x00, 0x01,
      0x08, 0x00,
  };

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun pair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPairA) == 0, "tcp A pair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPairB) == 0, "tcp B pair should be created");
  testAssertTrue(serverInit(&server, tunPair[0], 83, 3, 3, &testHeartbeatCfg, NULL, NULL), "server init should succeed");
  server.mode = sessionIfModeTun;
  testAssertTrue(serverAddClient(&server, 0, tcpPairA[0], testKey, claim2, sizeof(claim2)) == 0, "slot A should be active");
  testAssertTrue(serverAddClient(&server, 1, tcpPairB[0], testKey, claim3, sizeof(claim3)) == 1, "slot B should be active");
  server.serverIdentity.claim[0] = 10;
  server.serverIdentity.claim[1] = 0;
  server.serverIdentity.claim[2] = 0;
  server.serverIdentity.claim[3] = 1;
  server.serverIdentity.claimNbytes = 4;
  server.serverIdentity.directedBroadcastEnabled = true;
  server.serverIdentity.directedBroadcast[0] = 10;
  server.serverIdentity.directedBroadcast[1] = 0;
  server.serverIdentity.directedBroadcast[2] = 0;
  server.serverIdentity.directedBroadcast[3] = 255;
  server.activeConns[0].session->lastValidInboundMs = 0;

  testAssertTrue(
      serverRouteTcpIngressPacket(&server, &server.activeConns[0], toPeer, sizeof(toPeer)),
      "unicast to other client should route");
  testAssertTrue(
      server.activeConns[0].session->lastValidInboundMs > 0,
      "valid tcp ingress should refresh source session inbound timestamp");
  testAssertTrue(server.activeConns[0].tcpPoller.outNbytes == 0, "source client should not receive self echo");
  testAssertTrue(server.activeConns[1].tcpPoller.outNbytes > 0, "destination client should receive routed frame");

  server.activeConns[0].tcpPoller.outNbytes = 0;
  server.activeConns[1].tcpPoller.outNbytes = 0;
  testAssertTrue(
      serverRouteTcpIngressPacket(&server, &server.activeConns[0], toServer, sizeof(toServer)),
      "unicast to server identity should route to tun");
  testAssertTrue(server.activeConns[0].tcpPoller.outNbytes == 0, "server-local route should not enqueue source tcp");
  testAssertTrue(server.activeConns[1].tcpPoller.outNbytes == 0, "server-local route should not enqueue peer tcp");
  testAssertTrue(ioTunQueuedBytes(&server.tunPoller) > 0, "server-local route should enqueue tun payload");

  server.tunPoller.queuedBytes = 0;
  server.tunPoller.frameCount = 0;
  server.activeConns[0].tcpPoller.outNbytes = 0;
  server.activeConns[1].tcpPoller.outNbytes = 0;
  testAssertTrue(
      serverRouteTcpIngressPacket(&server, &server.activeConns[0], broadcast, sizeof(broadcast)),
      "broadcast should fanout to peers and tun");
  testAssertTrue(server.activeConns[0].tcpPoller.outNbytes == 0, "broadcast should exclude source tcp");
  testAssertTrue(server.activeConns[1].tcpPoller.outNbytes > 0, "broadcast should fanout to peer tcp");
  testAssertTrue(ioTunQueuedBytes(&server.tunPoller) > 0, "broadcast should enqueue tun payload");

  server.tunPoller.queuedBytes = 0;
  server.tunPoller.frameCount = 0;
  server.activeConns[0].tcpPoller.outNbytes = 0;
  server.activeConns[1].tcpPoller.outNbytes = 0;
  testAssertTrue(
      serverRouteTcpIngressPacket(&server, &server.activeConns[0], selfDest, sizeof(selfDest)),
      "self destination should drop");
  testAssertTrue(
      serverRouteTcpIngressPacket(&server, &server.activeConns[0], unknownDest, sizeof(unknownDest)),
      "unknown destination should drop");
  testAssertTrue(
      serverRouteTcpIngressPacket(&server, &server.activeConns[0], multicast, sizeof(multicast)),
      "multicast should drop");
  testAssertTrue(
      serverRouteTcpIngressPacket(&server, &server.activeConns[0], malformed, sizeof(malformed)),
      "malformed should drop");
  testAssertTrue(server.activeConns[0].tcpPoller.outNbytes == 0, "drop cases should not queue source tcp");
  testAssertTrue(server.activeConns[1].tcpPoller.outNbytes == 0, "drop cases should not queue peer tcp");
  testAssertTrue(ioTunQueuedBytes(&server.tunPoller) == 0, "drop cases should not queue tun payload");

  server.mode = sessionIfModeTap;
  server.tunPoller.queuedBytes = 0;
  server.tunPoller.frameCount = 0;
  server.activeConns[0].tcpPoller.outNbytes = 0;
  server.activeConns[1].tcpPoller.outNbytes = 0;
  testAssertTrue(
      serverRouteTcpIngressPacket(&server, &server.activeConns[0], tapBroadcast, sizeof(tapBroadcast)),
      "tap broadcast should fanout to peers and tun");
  testAssertTrue(server.activeConns[0].tcpPoller.outNbytes == 0, "tap broadcast should exclude source tcp");
  testAssertTrue(server.activeConns[1].tcpPoller.outNbytes > 0, "tap broadcast should fanout to peer tcp");
  testAssertTrue(ioTunQueuedBytes(&server.tunPoller) > 0, "tap broadcast should enqueue tun payload");

  serverDeinit(&server);
  close(tcpPairA[0]);
  close(tcpPairA[1]);
  close(tcpPairB[0]);
  close(tcpPairB[1]);
  close(tunPair[0]);
  close(tunPair[1]);
}

static void testServerTcpIngressToTunRequiresWriteServiceProgress(void) {
  serverFixture_t fixture;
  unsigned char toServer[] = {
      0x00, 0x00, 0x08, 0x00,
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 0, 0, 2,
      10, 0, 0, 1,
  };
  char peerBuf[64];
  ssize_t nread;
  int flags;
  int attempts;
  int slot;

  serverFixtureSetup(&fixture, 91, 1, 1, &testHeartbeatCfg, NULL, NULL);
  slot = serverFixtureAddClient(&fixture, 0, testKey, claim2, sizeof(claim2));
  testAssertTrue(slot == 0, "slot should be active");
  testAssertTrue(ioReactorInit(&fixture.server.reactor), "reactor init should succeed");
  fixture.server.tunPoller.poller.reactor = &fixture.server.reactor;
  testAssertTrue(
      ioReactorAddPoller(&fixture.server.reactor, &fixture.server.tunPoller.poller, &sessionEventFixtureCallbacks, NULL, true),
      "tun poller should be attached to reactor");

  fixture.server.mode = sessionIfModeTun;
  fixture.server.serverIdentity.claim[0] = 10;
  fixture.server.serverIdentity.claim[1] = 0;
  fixture.server.serverIdentity.claim[2] = 0;
  fixture.server.serverIdentity.claim[3] = 1;
  fixture.server.serverIdentity.claimNbytes = 4;

  testAssertTrue(
      serverRouteTcpIngressPacket(&fixture.server, &fixture.server.activeConns[0], toServer, sizeof(toServer)),
      "tcp ingress to server identity should queue tun payload");
  testAssertTrue(ioTunQueuedBytes(&fixture.server.tunPoller) > 0, "tun payload should be queued");

  flags = fcntl(fixture.tunPair[1], F_GETFL, 0);
  testAssertTrue(flags >= 0, "peer flags fetch should succeed");
  testAssertTrue(fcntl(fixture.tunPair[1], F_SETFL, flags | O_NONBLOCK) == 0, "peer should become nonblocking");
  nread = read(fixture.tunPair[1], peerBuf, sizeof(peerBuf));
  testAssertTrue(nread < 0, "without explicit write service, queued tun bytes should not flush");

  for (attempts = 0; attempts < 8 && ioTunQueuedBytes(&fixture.server.tunPoller) > 0; attempts++) {
    ioReactorStepResult_t step = ioReactorStep(&fixture.server.reactor, 50);
    testAssertTrue(step == ioReactorStepReady || step == ioReactorStepTimeout, "reactor write drive should remain healthy");
  }
  testAssertTrue(ioTunQueuedBytes(&fixture.server.tunPoller) == 0, "reactor should flush queued tun payload");
  nread = read(fixture.tunPair[1], peerBuf, sizeof(peerBuf));
  testAssertTrue(nread == (ssize_t)sizeof(toServer), "reactor write drive should flush queued payload");

  ioReactorDispose(&fixture.server.reactor);
  serverFixtureTeardown(&fixture);
}

static void serverFixtureSetup(
    serverFixture_t *fixture,
    int listenFd,
    int maxActiveSessions,
    int maxPreAuthSessions,
    const sessionHeartbeatConfig_t *heartbeatCfg,
    sessionNowMsFn_t nowMsFn,
    void *nowCtx) {
  testAssertTrue(fixture != NULL, "fixture should not be null");
  memset(&fixture->server, 0, sizeof(fixture->server));
  fixture->tunPair[0] = -1;
  fixture->tunPair[1] = -1;
  fixture->tcpPair[0] = -1;
  fixture->tcpPair[1] = -1;
  testAssertTrue(sessionTestTunPairOpen(fixture->tunPair), "tun socketpair should be created");
  testAssertTrue(sessionTestTcpPairOpen(fixture->tcpPair), "tcp socketpair should be created");
  testAssertTrue(
      serverInit(
          &fixture->server,
          fixture->tunPair[0],
          listenFd,
          maxActiveSessions,
          maxPreAuthSessions,
          heartbeatCfg,
          nowMsFn,
          nowCtx),
      "server init should succeed");
}

static int serverFixtureAddClient(
    serverFixture_t *fixture,
    int keySlot,
    const unsigned char key[ProtocolPskSize],
    const unsigned char *claim,
    long claimNbytes) {
  if (fixture == NULL || key == NULL || claim == NULL || claimNbytes <= 0) {
    return -1;
  }
  return serverAddClient(&fixture->server, keySlot, fixture->tcpPair[0], key, claim, claimNbytes);
}

static void serverFixtureTeardown(serverFixture_t *fixture) {
  testAssertTrue(fixture != NULL, "fixture should not be null");
  serverDeinit(&fixture->server);
  sessionTestTunPairClose(fixture->tunPair);
  sessionTestTcpPairClose(fixture->tcpPair);
}

static void testServerHeartbeatTimeoutStopsSession(void) {
  unsigned char key[ProtocolPskSize];
  serverFixture_t fixture;
  int slot;
  session_t *session;
  ioTcpPoller_t *tcpPoller;

  memset(key, 0x11, sizeof(key));
  fakeNowMs = 0;
  serverFixtureSetup(&fixture, 84, 1, 1, &testHeartbeatCfg, fakeNow, NULL);
  slot = serverFixtureAddClient(&fixture, 0, testKey, claim2, sizeof(claim2));
  testAssertTrue(slot == 0, "server should add active client");
  session = serverSessionAt(&fixture.server, slot);
  tcpPoller = &fixture.server.activeConns[slot].tcpPoller;
  testAssertTrue(session != NULL, "session should be retrievable from server active slot");

  fakeNowMs = 15000;
  testAssertTrue(
      runSessionStepWithSuppressedStderr(session, tcpPoller, &fixture.server.tunPoller, ioEventTimeout, key) == sessionStepStop,
      "server should stop after heartbeat timeout");

  serverFixtureTeardown(&fixture);
}

static void testServerCreateAndRemovePreAuthConnResetsState(void) {
  serverFixture_t fixture;
  int slot;
  preAuthConn_t *conn;

  serverFixtureSetup(&fixture, 84, 2, 2, &testHeartbeatCfg, NULL, NULL);

  testAssertTrue(
      sessionTestInitTcpPollerFromFd(&fixture.server.preAuthConns[0].tcpPoller, fixture.tcpPair[0]),
      "pre-auth tcp poller init should succeed");
  fixture.server.preAuthConns[0].tcpPoller.poller.events = EPOLLIN | EPOLLRDHUP;
  fixture.server.preAuthConns[0].tcpPoller.poller.readEnabled = true;
  slot = serverCreatePreAuthConn(&fixture.server, 0, 12345);
  testAssertTrue(slot >= 0, "pre-auth slot should be allocated");
  conn = serverPreAuthAt(&fixture.server, slot);
  testAssertTrue(conn != NULL, "pre-auth connection should be retrievable");
  testAssertTrue(conn->tcpPoller.poller.fd == fixture.tcpPair[0], "pre-auth create should initialize embedded tcp poller fd");
  testAssertTrue(conn->tcpPoller.poller.kind == ioPollerKindTcp, "pre-auth create should mark embedded poller as tcp");
  testAssertTrue(conn->tcpPoller.poller.ctx == conn, "pre-auth create should attach pre-auth callback ctx");
  conn->decoder.frame.nbytes = 99;
  conn->decoder.offset = 11;
  conn->decoder.hasFrame = 1;
  memcpy(conn->resolvedKey, testKey, sizeof(conn->resolvedKey));
  memcpy(conn->serverNonce, testKey, sizeof(conn->serverNonce));
  memcpy(conn->claim, claim2, sizeof(claim2));
  conn->claimNbytes = (long)sizeof(claim2);
  memset(conn->tcpReadCarryBuf, 'a', 8);
  conn->tcpReadCarryNbytes = 8;
  memset(conn->authWriteBuf, 'b', 6);
  conn->authWriteOffset = 3;
  conn->authWriteNbytes = 6;
  conn->authState = 2;

  testAssertTrue(serverRemovePreAuthConn(&fixture.server, slot), "pre-auth remove should succeed");
  testAssertTrue(serverPreAuthAt(&fixture.server, slot) == NULL, "removed pre-auth slot should be inactive");
  testAssertTrue(fixture.server.preAuthCount == 0, "pre-auth count should decrement after remove");
  testAssertTrue(fixture.server.preAuthConns[slot].tcpPoller.poller.fd == -1, "removed slot should reset poller fd");
  testAssertTrue(fixture.server.preAuthConns[slot].claimNbytes == 0, "removed slot should clear claim length");
  testAssertTrue(fixture.server.preAuthConns[slot].tcpReadCarryNbytes == 0, "removed slot should clear carry length");
  testAssertTrue(fixture.server.preAuthConns[slot].authWriteOffset == 0, "removed slot should reset auth write offset");
  testAssertTrue(fixture.server.preAuthConns[slot].authWriteNbytes == 0, "removed slot should reset auth write length");
  testAssertTrue(fixture.server.preAuthConns[slot].authState == 0, "removed slot should reset auth state");
  testAssertTrue(fixture.server.preAuthConns[slot].decoder.hasFrame == 0, "removed slot should clear decoder state");
  testAssertTrue(fixture.server.preAuthConns[slot].decoder.offset == 0, "removed slot should clear decoder offset");
  testAssertTrue(fixture.server.preAuthConns[slot].decoder.frame.nbytes == 0, "removed slot should clear decoder frame length");
  serverFixtureTeardown(&fixture);
}

static void testServerPromoteToActiveSlotAndApplyCarryState(void) {
  serverFixture_t fixture;
  int slot;
  preAuthConn_t *conn;
  protocolDecoder_t helloDecoder;
  char helloCarryBuf[ProtocolFrameSize];
  long helloCarryNbytes = 5;
  session_t *activeSession;

  serverFixtureSetup(&fixture, 85, 2, 2, &testHeartbeatCfg, NULL, NULL);

  testAssertTrue(
      sessionTestInitTcpPollerFromFd(&fixture.server.preAuthConns[0].tcpPoller, fixture.tcpPair[0]),
      "pre-auth tcp poller init should succeed");
  fixture.server.preAuthConns[0].tcpPoller.poller.events = EPOLLIN | EPOLLRDHUP;
  fixture.server.preAuthConns[0].tcpPoller.poller.readEnabled = true;
  slot = serverCreatePreAuthConn(&fixture.server, 0, 23456);
  testAssertTrue(slot >= 0, "pre-auth slot should be allocated");
  conn = serverPreAuthAt(&fixture.server, slot);
  testAssertTrue(conn != NULL, "pre-auth connection should be retrievable");
  conn->resolvedActiveSlot = 0;
  memcpy(conn->resolvedKey, testKey, sizeof(conn->resolvedKey));
  memcpy(conn->claim, claim2, sizeof(claim2));
  conn->claimNbytes = (long)sizeof(claim2);
  protocolDecoderInit(&conn->decoder);
  conn->decoder.hasFrame = 1;
  conn->decoder.offset = 7;
  conn->decoder.frame.nbytes = 19;
  memcpy(conn->decoder.frame.buf, "decoder-carry", 12);
  memset(conn->tcpReadCarryBuf, 0, sizeof(conn->tcpReadCarryBuf));
  memcpy(conn->tcpReadCarryBuf, "hello", (size_t)helloCarryNbytes);
  conn->tcpReadCarryNbytes = helloCarryNbytes;
  testAssertTrue(ioReactorInit(&fixture.server.reactor), "reactor init should succeed");
  conn->tcpPoller.poller.reactor = &fixture.server.reactor;
  testAssertTrue(
      ioReactorAddPoller(&fixture.server.reactor, &conn->tcpPoller.poller, &sessionEventFixtureCallbacks, NULL, true),
      "pre-auth poller should be attached");

  helloDecoder = conn->decoder;
  memcpy(helloCarryBuf, conn->tcpReadCarryBuf, (size_t)helloCarryNbytes);
  testAssertTrue(conn->tcpPoller.poller.fd == fixture.tcpPair[0], "pre-auth poller should own connection fd before promote");
  testAssertTrue(serverPromoteToActiveSlot(&fixture.server, slot), "promote should create active session");
  testAssertTrue(fixture.server.preAuthCount == 1, "promote should keep pre-auth slot until handoff");
  testAssertTrue(fixture.server.activeCount == 1, "promote should increment active count");
  testAssertTrue(fixture.server.activeConns[0].tcpPoller.poller.fd == -1, "active poller should be detached before handoff");
  testAssertTrue(
      ioTcpPollerHandoff(
          &fixture.server.activeConns[0].tcpPoller,
          &conn->tcpPoller,
          &sessionEventFixtureCallbacks,
          NULL,
          true),
      "promote handoff should retarget to active poller");
  testAssertTrue(serverRemovePreAuthConn(&fixture.server, slot), "promote handoff should clear pre-auth slot");
  testAssertTrue(fixture.server.preAuthCount == 0, "promote handoff should remove pre-auth slot");
  testAssertTrue(
      fixture.server.activeConns[0].tcpPoller.poller.fd == fixture.tcpPair[0],
      "promote should bind active poller to pre-auth-owned connection fd");

  activeSession = serverSessionAt(&fixture.server, 0);
  testAssertTrue(activeSession != NULL, "promoted active session should exist");
  testAssertTrue(
      sessionPromoteFromPreAuth(activeSession, &helloDecoder, helloCarryBuf, helloCarryNbytes),
      "session should accept transferred decoder/carry state");
  testAssertTrue(activeSession->tcpDecoder.hasFrame == helloDecoder.hasFrame, "session decoder hasFrame should match");
  testAssertTrue(activeSession->tcpDecoder.offset == helloDecoder.offset, "session decoder offset should match");
  testAssertTrue(
      activeSession->tcpDecoder.frame.nbytes == helloDecoder.frame.nbytes,
      "session decoder frame length should match");
  testAssertTrue(activeSession->tcpReadCarryNbytes == helloCarryNbytes, "session carry length should match");
  testAssertTrue(
      memcmp(activeSession->tcpReadCarryBuf, helloCarryBuf, (size_t)helloCarryNbytes) == 0,
      "session carry bytes should match");

  ioReactorDispose(&fixture.server.reactor);
  serverFixtureTeardown(&fixture);
}

static void testServerHeartbeatTimeoutUsesConfiguredTimeout(void) {
  unsigned char key[ProtocolPskSize];
  serverFixture_t fixture;
  int slot;
  session_t *session;
  ioTcpPoller_t *tcpPoller;
  sessionHeartbeatConfig_t heartbeatCfg = {
      .intervalMs = 3000,
      .timeoutMs = 9000,
  };

  memset(key, 0x33, sizeof(key));
  fakeNowMs = 0;
  serverFixtureSetup(&fixture, 85, 1, 1, &heartbeatCfg, fakeNow, NULL);
  slot = serverFixtureAddClient(&fixture, 0, testKey, claim2, sizeof(claim2));
  testAssertTrue(slot == 0, "server should add active client");
  session = serverSessionAt(&fixture.server, slot);
  tcpPoller = &fixture.server.activeConns[slot].tcpPoller;
  testAssertTrue(session != NULL, "session should be retrievable from server active slot");

  fakeNowMs = 8999;
  testAssertTrue(
      sessionStep(session, tcpPoller, &fixture.server.tunPoller, ioEventTimeout, key) == sessionStepContinue,
      "server should continue before configured timeout");
  fakeNowMs = 9000;
  testAssertTrue(
      runSessionStepWithSuppressedStderr(session, tcpPoller, &fixture.server.tunPoller, ioEventTimeout, key) == sessionStepStop,
      "server should stop at configured timeout");

  serverFixtureTeardown(&fixture);
}

static void testServerTunOverflowDisablesTunEpollinGlobally(void) {
  unsigned char key[ProtocolPskSize];
  serverFixture_t fixture;
  int slotA;
  char fill[IoPollerQueueCapacity];
  char tunPayload[128];
  session_t *session;
  ioTcpPoller_t *poller;

  memset(key, 0x51, sizeof(key));
  memset(fill, 'p', sizeof(fill));
  memset(tunPayload, 'q', sizeof(tunPayload));
  serverFixtureSetup(&fixture, 72, 1, 1, &testHeartbeatCfg, NULL, NULL);
  slotA = serverFixtureAddClient(&fixture, 0, testKey, claim2, sizeof(claim2));
  testAssertTrue(slotA == 0, "first client should be added");
  session = serverSessionAt(&fixture.server, slotA);
  testAssertTrue(session != NULL, "server session should exist");
  poller = &fixture.server.activeConns[slotA].tcpPoller;

  testAssertTrue(
      ioTcpWrite(poller, fill, IoPollerQueueCapacity - 16),
      "prefill tcp queue should succeed");
  testAssertTrue(
      write(fixture.tunPair[1], tunPayload, sizeof(tunPayload)) == (long)sizeof(tunPayload),
      "tun write should succeed");
  testAssertTrue(
      runSessionStepSplit(session, poller, &fixture.server.tunPoller, ioEventTunRead, key) == sessionStepContinue,
      "session should continue on overflow");
  testAssertTrue(serverHasPendingTunToTcp(&fixture.server), "server overflow should retain pending data in server");
  testAssertTrue(fixture.server.tunReadPaused, "server server should mark tun read paused while pending exists");
  testAssertTrue((fixture.server.tunPoller.poller.events & EPOLLIN) == 0, "server should disable tun epollin while pending exists");

  serverFixtureTeardown(&fixture);
}

static void testServerPendingRetriesOnOwnerAndResumesTunEpollinAtLowWatermark(void) {
  unsigned char key[ProtocolPskSize];
  serverFixture_t fixture;
  int slotA;
  int slotB;
  int tcpPairB[2];
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
  serverFixtureSetup(&fixture, 72, 2, 2, &testHeartbeatCfg, NULL, NULL);
  slotA = serverFixtureAddClient(&fixture, 0, testKey, claim2, sizeof(claim2));
  testAssertTrue(slotA == 0, "first client should be added");
  testAssertTrue(sessionTestTcpPairOpen(tcpPairB), "tcp pair B should be created");
  slotB = serverAddClient(&fixture.server, 1, tcpPairB[0], testKey, claim3, sizeof(claim3));
  testAssertTrue(slotB == 1, "second client should be added");
  ownerSession = serverSessionAt(&fixture.server, slotA);
  otherSession = serverSessionAt(&fixture.server, slotB);
  ownerPoller = &fixture.server.activeConns[slotA].tcpPoller;
  otherPoller = &fixture.server.activeConns[slotB].tcpPoller;
  testAssertTrue(ownerSession != NULL, "owner session should exist");
  testAssertTrue(otherSession != NULL, "other session should exist");

  testAssertTrue(
      ioTcpWrite(ownerPoller, fill, IoPollerQueueCapacity - 16),
      "prefill owner tcp queue should succeed");
  testAssertTrue(
      write(fixture.tunPair[1], tunPayload, sizeof(tunPayload)) == (long)sizeof(tunPayload),
      "tun write should succeed");
  testAssertTrue(
      runSessionStepSplit(ownerSession, ownerPoller, &fixture.server.tunPoller, ioEventTunRead, key) == sessionStepContinue,
      "overflow on owner should continue");
  testAssertTrue(serverHasPendingTunToTcp(&fixture.server), "owner overflow should store server pending bytes");
  testAssertTrue(fixture.server.tunReadPaused, "server server should mark tun read paused while pending exists");
  testAssertTrue((fixture.server.tunPoller.poller.events & EPOLLIN) == 0, "tun epollin should be disabled while server pending exists");

  testAssertTrue(
      runSessionStepSplit(otherSession, otherPoller, &fixture.server.tunPoller, ioEventTcpWrite, key) == sessionStepContinue,
      "non-owner tcp write path should continue");
  testAssertTrue(
      serverServiceBackpressure(&fixture.server, slotB, ioEventTcpWrite),
      "non-owner backpressure service should continue");
  testAssertTrue((fixture.server.tunPoller.poller.events & EPOLLIN) == 0, "non-owner should not consume server pending");

  ownerPoller->outOffset = 0;
  ownerPoller->outNbytes = IoPollerLowWatermark + 100;
  testAssertTrue(
      runSessionStepSplit(ownerSession, ownerPoller, &fixture.server.tunPoller, ioEventTcpWrite, key) == sessionStepContinue,
      "owner tcp write path should continue after first drain");
  testAssertTrue(
      serverServiceBackpressure(&fixture.server, slotA, ioEventTcpWrite),
      "owner backpressure service should continue above low watermark");
  queued = ioTcpQueuedBytes(ownerPoller);
  testAssertTrue(queued > IoPollerLowWatermark, "owner queue should remain above low watermark");
  testAssertTrue(serverHasPendingTunToTcp(&fixture.server), "owner pending payload should remain while queue is above low watermark");
  testAssertTrue((fixture.server.tunPoller.poller.events & EPOLLIN) == 0, "tun epollin should stay disabled above low watermark");

  ownerPoller->outOffset = 0;
  ownerPoller->outNbytes = IoPollerLowWatermark;
  testAssertTrue(
      runSessionStepSplit(ownerSession, ownerPoller, &fixture.server.tunPoller, ioEventTcpWrite, key) == sessionStepContinue,
      "owner tcp write path should continue after second drain");
  queued = ioTcpQueuedBytes(ownerPoller);
  testAssertTrue(queued <= IoPollerLowWatermark, "owner queue should drain to low watermark before retry");
  testAssertTrue(
      serverServiceBackpressure(&fixture.server, slotA, ioEventTcpWrite),
      "owner backpressure service should continue at low watermark");
  testAssertTrue(!serverHasPendingTunToTcp(&fixture.server), "owner pending payload should clear once queue drains to low watermark");
  testAssertTrue(!fixture.server.tunReadPaused, "server server should clear tun read paused at low watermark");
  testAssertTrue((fixture.server.tunPoller.poller.events & EPOLLIN) != 0, "tun epollin should resume at low watermark");

  serverFixtureTeardown(&fixture);
  sessionTestTcpPairClose(tcpPairB);
}

static void testServerOwnerDisconnectDropsRuntimePendingAndResumesTunEpollin(void) {
  unsigned char key[ProtocolPskSize];
  serverFixture_t fixture;
  int slotA;
  char fill[IoPollerQueueCapacity];
  char tunPayload[128];
  session_t *session;
  ioTcpPoller_t *poller;

  memset(key, 0x53, sizeof(key));
  memset(fill, 'u', sizeof(fill));
  memset(tunPayload, 'v', sizeof(tunPayload));
  serverFixtureSetup(&fixture, 72, 1, 1, &testHeartbeatCfg, NULL, NULL);
  slotA = serverFixtureAddClient(&fixture, 0, testKey, claim2, sizeof(claim2));
  testAssertTrue(slotA == 0, "first client should be added");
  session = serverSessionAt(&fixture.server, slotA);
  testAssertTrue(session != NULL, "server session should exist");
  poller = &fixture.server.activeConns[slotA].tcpPoller;

  testAssertTrue(
      ioTcpWrite(poller, fill, IoPollerQueueCapacity - 16),
      "prefill tcp queue should succeed");
  testAssertTrue(
      write(fixture.tunPair[1], tunPayload, sizeof(tunPayload)) == (long)sizeof(tunPayload),
      "tun write should succeed");
  testAssertTrue(
      runSessionStepSplit(session, poller, &fixture.server.tunPoller, ioEventTunRead, key) == sessionStepContinue,
      "overflow path should continue");
  testAssertTrue(fixture.server.tunReadPaused, "server server should mark tun read paused while pending is active");
  testAssertTrue((fixture.server.tunPoller.poller.events & EPOLLIN) == 0, "tun epollin should be disabled while pending is active");

  testAssertTrue(serverRemoveClient(&fixture.server, slotA), "owner removal should succeed");
  testAssertTrue(!fixture.server.tunReadPaused, "server server should clear tun read paused after owner drop");
  testAssertTrue((fixture.server.tunPoller.poller.events & EPOLLIN) != 0, "tun epollin should re-enable after owner disconnect drop");

  serverFixtureTeardown(&fixture);
}

static void testServerQueueBackpressureBlocksAndStoresRuntimePendingPayload(void) {
  serverFixture_t fixture;
  char fill[IoPollerQueueCapacity];
  char payload[128];
  sessionQueueResult_t result;
  int slot;

  memset(fill, 'w', sizeof(fill));
  memset(payload, 'z', sizeof(payload));
  serverFixtureSetup(&fixture, 80, 1, 1, &testHeartbeatCfg, NULL, NULL);
  slot = serverFixtureAddClient(&fixture, 0, testKey, claim2, sizeof(claim2));
  testAssertTrue(slot == 0, "server client should be added");
  testAssertTrue(
      ioTcpWrite(&fixture.server.activeConns[0].tcpPoller, fill, IoPollerQueueCapacity - 16),
      "prefill server tcp queue should succeed");
  result = serverQueueTcpWithBackpressure(
      &fixture.server, &fixture.server.activeConns[0], payload, sizeof(payload));
  testAssertTrue(result == sessionQueueResultBlocked, "server queue api should block on overflow");
  testAssertTrue(serverHasPendingTunToTcp(&fixture.server), "server queue api should store server pending payload");
  testAssertTrue(serverPendingTunToTcpOwner(&fixture.server) == 0, "server pending payload owner should match slot");
  serverFixtureTeardown(&fixture);
}

static void testServerInboundHeartbeatHandlerQueuesAckAndRefreshesTimestamp(void) {
  serverFixture_t fixture;
  long long lastValidInboundMs = 17;
  protocolMessage_t req = {.type = protocolMsgHeartbeatReq, .nbytes = 0, .buf = NULL};
  sessionQueueResult_t result;
  int slot;

  serverFixtureSetup(&fixture, 81, 1, 1, &testHeartbeatCfg, NULL, NULL);
  slot = serverFixtureAddClient(&fixture, 0, testKey, claim2, sizeof(claim2));
  testAssertTrue(slot == 0, "server client should be added");

  result = serverHandleInboundMessage(
      &fixture.server,
      &fixture.server.activeConns[0],
      testKey,
      &lastValidInboundMs,
      &req);
  testAssertTrue(result == sessionQueueResultQueued, "server inbound heartbeat request should route through server handler");
  testAssertTrue(lastValidInboundMs > 0, "server handler should refresh last valid inbound timestamp");

  serverFixtureTeardown(&fixture);
}

static void testServerBackpressurePrioritizesHeartbeatAckBeforeRuntimePendingRetry(void) {
  serverFixture_t fixture;
  long long lastValidInboundMs = 0;
  char fill[IoPollerQueueCapacity];
  unsigned char pendingPayload[128];
  protocolMessage_t req = {.type = protocolMsgHeartbeatReq, .nbytes = 0, .buf = NULL};
  sessionQueueResult_t result;
  int slot;

  memset(fill, 'j', sizeof(fill));
  memset(pendingPayload, 'k', sizeof(pendingPayload));
  serverFixtureSetup(&fixture, 82, 1, 1, &testHeartbeatCfg, NULL, NULL);
  slot = serverFixtureAddClient(&fixture, 0, testKey, claim2, sizeof(claim2));
  testAssertTrue(slot == 0, "server client should be added");
  testAssertTrue(
      serverStorePendingTunToTcp(&fixture.server, 0, pendingPayload, sizeof(pendingPayload)),
      "server should accept existing runtime pending payload");
  testAssertTrue(
      ioTcpWrite(&fixture.server.activeConns[0].tcpPoller, fill, IoPollerQueueCapacity),
      "prefill server tcp queue should succeed");

  result = serverHandleInboundMessage(
      &fixture.server,
      &fixture.server.activeConns[0],
      testKey,
      &lastValidInboundMs,
      &req);
  testAssertTrue(result == sessionQueueResultBlocked, "server heartbeat ack should block while runtime pending exists");
  testAssertTrue(serverHasPendingTunToTcp(&fixture.server), "runtime pending should still be present before retry cycle");

  fixture.server.activeConns[0].tcpPoller.outOffset = 0;
  fixture.server.activeConns[0].tcpPoller.outNbytes = IoPollerLowWatermark;
  testAssertTrue(
      serverServiceBackpressure(&fixture.server, 0, ioEventTcpWrite),
      "server backpressure service should continue on owner write event");
  testAssertTrue(
      serverHasPendingTunToTcp(&fixture.server),
      "server should preserve runtime pending payload while prioritizing heartbeat ack retry");

  serverFixtureTeardown(&fixture);
}

static void testServerHeartbeatTickTimeoutBoundary(void) {
  testAssertTrue(serverHeartbeatTick(8999, 0, 9000), "server heartbeat should allow pre-timeout interval");
  testAssertTrue(!serverHeartbeatTick(9000, 0, 9000), "server heartbeat should stop at timeout boundary");
}

static void testServerRuntimeHasNoRawIoCalls(void) {
  static const char *forbidden[] = {"epoll_", "read(", "write(", "close("};
  const char *candidatePaths[] = {"session/src/server.c", "../session/src/server.c"};
  FILE *fp = NULL;
  char line[4096];
  int lineNo = 0;
  size_t pathIdx;
  size_t i;

  for (pathIdx = 0; pathIdx < sizeof(candidatePaths) / sizeof(candidatePaths[0]); pathIdx++) {
    fp = fopen(candidatePaths[pathIdx], "r");
    if (fp != NULL) {
      break;
    }
  }
  testAssertTrue(fp != NULL, "guardrail should open server runtime source");
  while (fgets(line, sizeof(line), fp) != NULL) {
    lineNo++;
    for (i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
      testAssertTrue(
          strstr(line, forbidden[i]) == NULL,
          "server runtime should avoid raw io calls in source");
    }
  }
  (void)lineNo;
  fclose(fp);
}

void runServerTests(void) {
  testServerServeMultiClientRejectsInvalidArgs();
  testSessionRunEntrypointsRejectInvalidConfigs();
  testServerAddRemoveAndReuseSlots();
  testServerActiveKeyBorrowUsesAuthoritativeStorage();
  testServerRemoveClientClearsBorrowedPollerState();
  testServerRejectsBeyondMaxSessions();
  testServerFindSlotByClaim();
  testServerRoundRobinRetryCursorRotates();
  testServerPendingTunToTcpOwnerControlsRetryAndReadInterest();
  testServerRoutesTunIngressByClaimMatch();
  testServerDropsTunIngressOnUnmatchedBroadcastMulticastAndMalformed();
  testServerFanoutTapBroadcastToAllClients();
  testServerFanoutTunBroadcastsBySubnetPolicy();
  testServerBroadcastFanoutSkipsSaturatedClient();
  testServerQueueWithDropSkipsOverflowWithoutPendingState();
  testServerRoutesTcpIngressAcrossClientsAndTun();
  testServerTcpIngressToTunRequiresWriteServiceProgress();
  testServerQueueBackpressureBlocksAndStoresRuntimePendingPayload();
  testServerInboundHeartbeatHandlerQueuesAckAndRefreshesTimestamp();
  testServerBackpressurePrioritizesHeartbeatAckBeforeRuntimePendingRetry();
  testServerHeartbeatTickTimeoutBoundary();
  testServerRuntimeHasNoRawIoCalls();
  testServerHeartbeatTimeoutStopsSession();
  testServerHeartbeatTimeoutUsesConfiguredTimeout();
  testServerCreateAndRemovePreAuthConnResetsState();
  testServerPromoteToActiveSlotAndApplyCarryState();
  testServerTunOverflowDisablesTunEpollinGlobally();
  testServerPendingRetriesOnOwnerAndResumesTunEpollinAtLowWatermark();
  testServerOwnerDisconnectDropsRuntimePendingAndResumesTunEpollin();
}
