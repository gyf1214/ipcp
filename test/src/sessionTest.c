#include "sessionTest.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "io.h"
#include "protocol.h"
#include "sessionInternal.h"
#include "testAssert.h"

#define TestAssertServerRunSig(fnExpr) \
  _Static_assert(_Generic((fnExpr), int (*)(const sessionServerConfig_t *): 1, default: 0), "sessionRunServer signature drift")
#define TestAssertClientRunSig(fnExpr) \
  _Static_assert(_Generic((fnExpr), int (*)(const sessionClientConfig_t *): 1, default: 0), "sessionRunClient signature drift")

TestAssertServerRunSig(sessionRunServer);
TestAssertClientRunSig(sessionRunClient);

typedef struct {
  ioReactor_t reactor;
  ioTunPoller_t tunPoller;
  ioTcpPoller_t tcpPoller;
  ioEvent_t capturedEvents[32];
  int capturedHead;
  int capturedTail;
  int capturedCount;
} splitPollersFixture_t;

static long long fakeNowMs = 0;
static const sessionHeartbeatConfig_t defaultHeartbeatCfg = {
    .intervalMs = 5000,
    .timeoutMs = 15000,
};

static void splitPollersCaptureEvent(splitPollersFixture_t *poller, ioEvent_t event) {
  if (poller == NULL || poller->capturedCount >= (int)(sizeof(poller->capturedEvents) / sizeof(poller->capturedEvents[0]))) {
    return;
  }
  poller->capturedEvents[poller->capturedTail] = event;
  poller->capturedTail = (poller->capturedTail + 1) % (int)(sizeof(poller->capturedEvents) / sizeof(poller->capturedEvents[0]));
  poller->capturedCount++;
}

static ioPollerAction_t splitPollerCaptureReadable(void *ctx, ioReactor_t *reactor, ioPoller_t *poller) {
  splitPollersFixture_t *fixture = (splitPollersFixture_t *)ctx;
  (void)reactor;
  if (fixture == NULL || poller == NULL) {
    return ioPollerContinue;
  }
  if (poller->kind == ioPollerTun) {
    splitPollersCaptureEvent(fixture, ioEventTunRead);
  } else if (poller->kind == ioPollerTcp) {
    splitPollersCaptureEvent(fixture, ioEventTcpRead);
  }
  return ioPollerContinue;
}

static ioPollerAction_t splitPollerCaptureLowWatermark(void *ctx, ioPoller_t *poller, long queuedBytes) {
  splitPollersFixture_t *fixture = (splitPollersFixture_t *)ctx;
  (void)queuedBytes;
  if (fixture == NULL || poller == NULL) {
    return ioPollerContinue;
  }
  if (poller->kind == ioPollerTun) {
    splitPollersCaptureEvent(fixture, ioEventTunWrite);
  } else if (poller->kind == ioPollerTcp) {
    splitPollersCaptureEvent(fixture, ioEventTcpWrite);
  }
  return ioPollerContinue;
}

static const ioPollerCallbacks_t splitPollerCallbacks = {
    .onClosed = NULL,
    .onLowWatermark = splitPollerCaptureLowWatermark,
    .onReadable = splitPollerCaptureReadable,
};

static int setupSplitPollers(splitPollersFixture_t *poller, int tunFd, int tcpFd) {
  if (poller == NULL) {
    return -1;
  }
  if (!ioReactorInit(&poller->reactor)) {
    return -1;
  }
  poller->capturedHead = 0;
  poller->capturedTail = 0;
  poller->capturedCount = 0;

  memset(&poller->tunPoller, 0, sizeof(poller->tunPoller));
  poller->tunPoller.poller.reactor = NULL;
  poller->tunPoller.poller.fd = tunFd;
  poller->tunPoller.poller.events = EPOLLRDHUP;
  poller->tunPoller.poller.kind = ioPollerTun;
  if (!ioReactorAddPoller(&poller->reactor, &poller->tunPoller.poller, &splitPollerCallbacks, poller, true)) {
    ioReactorDispose(&poller->reactor);
    return -1;
  }

  memset(&poller->tcpPoller, 0, sizeof(poller->tcpPoller));
  poller->tcpPoller.poller.reactor = NULL;
  poller->tcpPoller.poller.fd = tcpFd;
  poller->tcpPoller.poller.events = EPOLLRDHUP;
  poller->tcpPoller.poller.kind = ioPollerTcp;
  if (!ioReactorAddPoller(&poller->reactor, &poller->tcpPoller.poller, &splitPollerCallbacks, poller, true)) {
    ioReactorDispose(&poller->reactor);
    return -1;
  }
  return 0;
}

static void teardownSplitPollers(splitPollersFixture_t *poller) {
  if (poller != NULL) {
    ioReactorDispose(&poller->reactor);
  }
}

static long long fakeNow(void *ctx) {
  (void)ctx;
  return fakeNowMs;
}

static void setupSplitPollersFixture(splitPollersFixture_t *poller, int tunPair[2], int tcpPair[2]) {
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "tcp socketpair should be created");
  testAssertTrue(setupSplitPollers(poller, tunPair[0], tcpPair[0]) == 0, "setupSplitPollers should succeed");
}

static void teardownSplitPollersFixture(splitPollersFixture_t *poller, int tunPair[2], int tcpPair[2]) {
  teardownSplitPollers(poller);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static sessionStepResult_t runSessionStep(session_t *session, splitPollersFixture_t *poller, ioEvent_t event, const unsigned char key[ProtocolPskSize]) {
  return sessionStep(session, &poller->tcpPoller, &poller->tunPoller, event, key);
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

  result = runSessionStep(session, poller, event, key);

  fflush(stderr);
  testAssertTrue(dup2(savedStderr, STDERR_FILENO) >= 0, "restore stderr should succeed");
  close(savedStderr);
  return result;
}

static void assertSessionStepBehaviorWhenRuntimeMissing(bool isServer, bool expectAbort) {
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  unsigned char key[ProtocolPskSize];
  pid_t pid;
  int status = 0;

  memset(key, 0x7a, sizeof(key));
  fakeNowMs = 0;
  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  pid = fork();
  testAssertTrue(pid >= 0, "fork should succeed");
  if (pid == 0) {
    session_t *session = sessionCreate(isServer, &defaultHeartbeatCfg, fakeNow, NULL);
    testAssertTrue(session != NULL, "session create should succeed");
    (void)runSessionStepWithSuppressedStderr(session, &poller, ioEventTimeout, key);
    sessionDestroy(session);
    _exit(0);
  }

  testAssertTrue(waitpid(pid, &status, 0) == pid, "waitpid should succeed");
  if (expectAbort) {
    testAssertTrue(WIFSIGNALED(status), "child should terminate via signal");
    testAssertTrue(WTERMSIG(status) == SIGABRT, "child should abort on missing runtime");
  } else {
    testAssertTrue(WIFEXITED(status), "child should exit cleanly");
    testAssertTrue(WEXITSTATUS(status) == 0, "child should return success without runtime assertion");
  }
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testSessionApiSmoke(void) {
  const session_t *session = sessionCreate(true, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  testAssertTrue(sessionApiSmoke(), "session smoke api should return true");
  sessionDestroy((session_t *)session);
}

static void testSessionServerRoleSkipsRuntimeAssertOnTimeout(void) {
  assertSessionStepBehaviorWhenRuntimeMissing(true, false);
}

static void testSessionClientRoleAssertsOnMissingRuntime(void) {
  assertSessionStepBehaviorWhenRuntimeMissing(false, true);
}

static void testSessionInitSeedsModeAndTimestamps(void) {

  fakeNowMs = 12345;
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  testAssertTrue(!session->isServer, "session should keep client mode");
  testAssertTrue(session->lastValidInboundMs == fakeNowMs, "lastValidInboundMs should be seeded");
  testAssertTrue(session->runtime == NULL, "client runtime should be unset before runtime wiring");
  sessionDestroy(session);
}

static void testSessionResetClearsPendingAndPauseFlags(void) {
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  const char payload[] = "session-reset-overflow";
  sessionQueueResult_t result;

  fakeNowMs = 5000;

  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  poller.tunPoller.frameCount = IoTunQueueFrameCapacity;
  poller.tunPoller.queuedBytes = IoPollerQueueCapacity;
  result = sessionQueueTunWithBackpressure(
      &poller.tcpPoller, &poller.tunPoller, session, payload, (long)sizeof(payload) - 1);
  testAssertTrue(result == sessionQueueResultBlocked, "session queue should block when tun queue is saturated");
  testAssertTrue(session->overflowNbytes > 0, "session overflow bytes should be tracked");
  testAssertTrue(session->overflowKind == sessionOverflowToTun, "session overflow kind should target tun");
  testAssertTrue(session->tcpReadPaused, "session tcp read should be paused under overflow");

  sessionReset(session);
  testAssertTrue(session->overflowNbytes == 0, "reset should clear pending tun bytes");
  testAssertTrue(!session->tcpReadPaused, "reset should clear tcp pause");
  sessionDestroy(session);
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testSessionBackpressurePauseAndResumeFlow(void) {
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  const char payload[] = "session-overflow-retry";
  char out[128];
  sessionQueueResult_t result;

  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  poller.tunPoller.frameCount = IoTunQueueFrameCapacity;
  poller.tunPoller.queuedBytes = IoPollerQueueCapacity;
  result = sessionQueueTunWithBackpressure(
      &poller.tcpPoller, &poller.tunPoller, session, payload, (long)sizeof(payload) - 1);
  testAssertTrue(result == sessionQueueResultBlocked, "session queue should block when tun queue is saturated");
  testAssertTrue(session->tcpReadPaused, "session should pause tcp read after overflow");
  testAssertTrue(sessionHasOverflow(session), "session should track pending overflow");

  poller.tunPoller.frameCount = 0;
  poller.tunPoller.queuedBytes = 0;
  testAssertTrue(
      sessionRetryOverflow(session, &poller.tcpPoller, &poller.tunPoller, ioEventTunWrite),
      "session retry overflow should succeed on tun write event");
  testAssertTrue(!sessionHasOverflow(session), "session overflow should flush after retry");
  testAssertTrue(!session->tcpReadPaused, "session should resume tcp read after retry");
  testAssertTrue(ioTunServiceWriteEvent(&poller.tunPoller), "tun write service should flush retried payload");
  testAssertTrue(
      recv(tunPair[1], out, sizeof(out), MSG_DONTWAIT) == (ssize_t)(sizeof(payload) - 1),
      "tun peer should receive retried payload");
  testAssertTrue(memcmp(out, payload, sizeof(payload) - 1) == 0, "retried payload should match");

  sessionDestroy(session);
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testSessionRetryOverflowFlushesAndResumesRead(void) {
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  session_t *session;
  const char payload[] = "retry-overflow";

  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  memcpy(session->overflowBuf, payload, sizeof(payload) - 1);
  session->overflowNbytes = (long)sizeof(payload) - 1;
  session->overflowKind = sessionOverflowToTun;
  session->overflowDestSlot = -1;
  session->tcpReadPaused = true;

  testAssertTrue(sessionHasOverflow(session), "session should report pending overflow");
  testAssertTrue(
      sessionRetryOverflow(session, &poller.tcpPoller, &poller.tunPoller, ioEventTunWrite),
      "session retry overflow should succeed");
  testAssertTrue(!sessionHasOverflow(session), "session overflow should clear after retry");
  testAssertTrue(!session->tcpReadPaused, "tcp read pause should clear after retry");

  sessionDestroy(session);
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testSessionRetryOverflowKeepsPendingWhenTunQueueStillSaturated(void) {
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  session_t *session;
  const char payload[] = "retry-blocked";

  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  session = sessionCreate(true, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  poller.tunPoller.frameCount = IoTunQueueFrameCapacity;
  poller.tunPoller.queuedBytes = IoPollerQueueCapacity;

  memcpy(session->overflowBuf, payload, sizeof(payload) - 1);
  session->overflowNbytes = (long)sizeof(payload) - 1;
  session->overflowKind = sessionOverflowToTun;
  session->overflowDestSlot = -1;
  session->tcpReadPaused = true;

  testAssertTrue(
      sessionRetryOverflow(session, &poller.tcpPoller, &poller.tunPoller, ioEventTunWrite),
      "session retry overflow should stay alive when queue remains saturated");
  testAssertTrue(sessionHasOverflow(session), "session overflow should remain pending");
  testAssertTrue(session->tcpReadPaused, "tcp read should remain paused while overflow is pending");

  sessionDestroy(session);
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testSessionDestinationAwareTcpQueueAndDropApis(void) {
  splitPollersFixture_t poller;
  int tunPair[2];
  int sourcePair[2];
  int destPairA[2];
  int destPairB[2];
  ioTcpPoller_t destPollerA;
  ioTcpPoller_t destPollerB;
  session_t *session;
  char fill[IoPollerQueueCapacity];
  char payload[128];
  sessionQueueResult_t result;

  memset(fill, 'q', sizeof(fill));
  memset(payload, 'r', sizeof(payload));
  setupSplitPollersFixture(&poller, tunPair, sourcePair);
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, destPairA) == 0, "dest A pair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, destPairB) == 0, "dest B pair should be created");
  testAssertTrue(ioTcpPollerInit(&destPollerA, &poller.reactor, destPairA[0]) == 0, "dest A poller init should succeed");
  testAssertTrue(ioTcpPollerInit(&destPollerB, &poller.reactor, destPairB[0]) == 0, "dest B poller init should succeed");

  session = sessionCreate(true, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  testAssertTrue(ioTcpWrite(&destPollerA, fill, IoPollerQueueCapacity - 16), "dest A prefill should succeed");

  result = sessionQueueTcpWithBackpressure(
      &poller.tcpPoller,
      &destPollerA,
      session,
      3,
      payload,
      sizeof(payload));
  testAssertTrue(result == sessionQueueResultBlocked, "tcp backpressure queue should block on saturation");
  testAssertTrue(session->overflowNbytes == (long)sizeof(payload), "session should store pending payload bytes");
  testAssertTrue(session->overflowKind == sessionOverflowToClient, "pending kind should be to-client");
  testAssertTrue(session->overflowDestSlot == 3, "pending destination slot should be recorded");
  testAssertTrue(session->tcpReadPaused, "source tcp read should pause while pending");

  result = sessionQueueTcpWithDrop(&destPollerA, session, 3, payload, 32);
  testAssertTrue(result == sessionQueueResultBlocked, "drop queue should block same destination while pending exists");
  result = sessionQueueTcpWithDrop(&destPollerB, session, 4, payload, 32);
  testAssertTrue(result == sessionQueueResultBlocked, "drop queue should block other destination while pending exists");

  testAssertTrue(sessionDropOverflow(session, &poller.tcpPoller, 2), "drop overflow non-match should be no-op");
  testAssertTrue(session->overflowNbytes > 0, "non-match should preserve pending payload");
  testAssertTrue(sessionDropOverflow(session, &poller.tcpPoller, 3), "drop overflow matching destination should succeed");
  testAssertTrue(session->overflowNbytes == 0, "matching drop should clear pending payload");
  testAssertTrue(!session->tcpReadPaused, "matching drop should resume source tcp read");

  sessionDestroy(session);
  teardownSplitPollersFixture(&poller, tunPair, sourcePair);
  close(destPairA[0]);
  close(destPairA[1]);
  close(destPairB[0]);
  close(destPairB[1]);
}

static void testSessionQueueTunWithDropForSession(void) {
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  session_t *session;
  const char payload[] = "tun-drop";
  sessionQueueResult_t result;

  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  poller.tunPoller.frameCount = IoTunQueueFrameCapacity;
  poller.tunPoller.queuedBytes = IoPollerQueueCapacity;

  result = sessionQueueTunWithDropForSession(&poller.tunPoller, session, payload, (long)sizeof(payload) - 1);
  testAssertTrue(result == sessionQueueResultBlocked, "tun drop queue should block on saturation");
  testAssertTrue(session->overflowNbytes == 0, "tun drop queue should not store pending payload");

  session->overflowNbytes = 8;
  session->overflowKind = sessionOverflowToClient;
  session->overflowDestSlot = 3;
  result = sessionQueueTunWithDropForSession(&poller.tunPoller, session, payload, (long)sizeof(payload) - 1);
  testAssertTrue(result == sessionQueueResultBlocked, "tun drop queue should block when source overflow is pending");

  sessionDestroy(session);
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testSessionCreateRejectsNullHeartbeatConfig(void) {
  session_t *session = sessionCreate(false, NULL, fakeNow, NULL);
  testAssertTrue(session == NULL, "session create should fail with null heartbeat config");
}

static void testSessionCreateRejectsInvalidHeartbeatConfig(void) {
  sessionHeartbeatConfig_t invalid;
  session_t *session;

  invalid.intervalMs = 0;
  invalid.timeoutMs = 15000;
  session = sessionCreate(false, &invalid, fakeNow, NULL);
  testAssertTrue(session == NULL, "session create should fail when interval is not positive");

  invalid.intervalMs = 5000;
  invalid.timeoutMs = 5000;
  session = sessionCreate(false, &invalid, fakeNow, NULL);
  testAssertTrue(session == NULL, "session create should fail when timeout is not greater than interval");
}

static void testSessionTopLevelRunEntrypointsRejectNullConfig(void) {
  testAssertTrue(sessionRunServer(NULL) < 0, "sessionRunServer should reject null config");
  testAssertTrue(sessionRunClient(NULL) < 0, "sessionRunClient should reject null config");
}

static void testSessionStepRequiresBorrowedPollers(void) {
  session_t *session;
  unsigned char key[ProtocolPskSize];

  memset(key, 0x33, sizeof(key));
  session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  testAssertTrue(
      sessionStep(session, NULL, NULL, ioEventTcpRead, key) == sessionStepStop,
      "sessionStep should stop when borrowed pollers are missing");
  sessionDestroy(session);
}

void runSessionTests(void) {
  testSessionServerRoleSkipsRuntimeAssertOnTimeout();
  testSessionClientRoleAssertsOnMissingRuntime();
  testSessionCreateRejectsNullHeartbeatConfig();
  testSessionCreateRejectsInvalidHeartbeatConfig();
  testSessionTopLevelRunEntrypointsRejectNullConfig();
  testSessionStepRequiresBorrowedPollers();
  testSessionApiSmoke();
  testSessionInitSeedsModeAndTimestamps();
  testSessionResetClearsPendingAndPauseFlags();
  testSessionBackpressurePauseAndResumeFlow();
  testSessionRetryOverflowFlushesAndResumesRead();
  testSessionRetryOverflowKeepsPendingWhenTunQueueStillSaturated();
  testSessionDestinationAwareTcpQueueAndDropApis();
  testSessionQueueTunWithDropForSession();
}
