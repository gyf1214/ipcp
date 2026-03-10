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
#include "client.h"
#include "server.h"
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

static bool splitPollersPopEvent(splitPollersFixture_t *poller, ioEvent_t *outEvent) {
  if (poller == NULL || outEvent == NULL || poller->capturedCount <= 0) {
    return false;
  }
  *outEvent = poller->capturedEvents[poller->capturedHead];
  poller->capturedHead = (poller->capturedHead + 1) % (int)(sizeof(poller->capturedEvents) / sizeof(poller->capturedEvents[0]));
  poller->capturedCount--;
  return true;
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
  poller->tunPoller.poller.epollFd = -1;
  poller->tunPoller.poller.fd = tunFd;
  poller->tunPoller.poller.events = EPOLLRDHUP;
  poller->tunPoller.poller.kind = ioPollerTun;
  if (!ioReactorAddPoller(&poller->reactor, &poller->tunPoller.poller, &splitPollerCallbacks, poller, true)) {
    ioReactorDeinit(&poller->reactor);
    return -1;
  }

  memset(&poller->tcpPoller, 0, sizeof(poller->tcpPoller));
  poller->tcpPoller.poller.epollFd = -1;
  poller->tcpPoller.poller.fd = tcpFd;
  poller->tcpPoller.poller.events = EPOLLRDHUP;
  poller->tcpPoller.poller.kind = ioPollerTcp;
  if (!ioReactorAddPoller(&poller->reactor, &poller->tcpPoller.poller, &splitPollerCallbacks, poller, true)) {
    ioReactorDeinit(&poller->reactor);
    return -1;
  }
  return 0;
}

static void teardownSplitPollers(splitPollersFixture_t *poller) {
  if (poller != NULL) {
    ioReactorDeinit(&poller->reactor);
  }
}

static bool drainTcpQueueWithReactor(splitPollersFixture_t *poller, int timeoutMs) {
  int attempts;

  if (poller == NULL) {
    return false;
  }
  for (attempts = 0; attempts < 5 && ioTcpQueuedBytes(&poller->tcpPoller) > 0; attempts++) {
    ioReactorStepResult_t step = ioReactorStep(&poller->reactor, timeoutMs);
    if (step == ioReactorStepError || step == ioReactorStepStop) {
      return false;
    }
  }
  return ioTcpQueuedBytes(&poller->tcpPoller) == 0;
}

static bool waitCapturedEvent(splitPollersFixture_t *poller, int timeoutMs, ioEvent_t *outEvent) {
  int attempts;

  if (poller == NULL || outEvent == NULL) {
    return false;
  }
  for (attempts = 0; attempts < 6; attempts++) {
    ioReactorStepResult_t step;
    if (splitPollersPopEvent(poller, outEvent)) {
      return true;
    }
    step = ioReactorStep(&poller->reactor, timeoutMs);
    if (step == ioReactorStepError || step == ioReactorStepStop) {
      return false;
    }
    if (splitPollersPopEvent(poller, outEvent)) {
      return true;
    }
  }
  return false;
}

static bool waitCapturedEventOfKind(splitPollersFixture_t *poller, int timeoutMs, ioEvent_t expected) {
  int attempts;
  ioEvent_t event;

  for (attempts = 0; attempts < 8; attempts++) {
    if (!waitCapturedEvent(poller, timeoutMs, &event)) {
      return false;
    }
    if (event == expected) {
      return true;
    }
  }
  return false;
}

static long long fakeNow(void *ctx) {
  (void)ctx;
  return fakeNowMs;
}

static long writeSecureWire(
    const unsigned char key[ProtocolPskSize],
    protocolMessageType_t type,
    const char *payload,
    long payloadNbytes,
    char *outBuf) {
  protocolMessage_t msg = {
      .type = type,
      .nbytes = payloadNbytes,
      .buf = payload,
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncodeSecureMsg(&msg, key, &frame);
  testAssertTrue(status == protocolStatusOk, "secure encode should succeed");

  memcpy(outBuf, frame.buf, (size_t)frame.nbytes);
  return frame.nbytes;
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

static void wireClientSession(session_t *session, splitPollersFixture_t *poller, client_t *client) {
  memset(client, 0, sizeof(*client));
  client->tunPoller = &poller->tunPoller;
  client->tcpPoller = &poller->tcpPoller;
  sessionAttachClient(session, client);
}

static void wireServerSession(session_t *session, server_t *server, splitPollersFixture_t *poller) {
  memset(server, 0, sizeof(*server));
  testAssertTrue(
      serverInit(
          server,
          poller->tunPoller.poller.fd,
          poller->tcpPoller.poller.fd,
          1,
          1,
          &defaultHeartbeatCfg,
          NULL,
          NULL),
      "server runtime init should succeed");
  server->tunPoller.poller.epollFd = poller->tunPoller.poller.epollFd;
  server->tunPoller.poller.events = poller->tunPoller.poller.events;
  sessionAttachServer(session, server);
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
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  client_t client;
  int tunPair[2];
  int tcpPair[2];
  char fill[IoPollerQueueCapacity];
  char tunPayload[128];
  ioEvent_t event;

  memset(key, 0x55, sizeof(key));
  memset(fill, 'f', sizeof(fill));
  memset(tunPayload, 't', sizeof(tunPayload));
  fakeNowMs = 5000;

  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, &poller, &client);

  testAssertTrue(write(tunPair[1], tunPayload, sizeof(tunPayload)) == (long)sizeof(tunPayload), "tun write should succeed");
  testAssertTrue(waitCapturedEventOfKind(&poller, 100, ioEventTunRead), "reactor callback should capture tun readable event");
  event = ioEventTunRead;
  testAssertTrue(
      ioTcpWrite(&poller.tcpPoller, fill, IoPollerQueueCapacity - 32),
      "prefill tcp queue should succeed");
  testAssertTrue(
      runSessionStep(session, &poller, event, key) == sessionStepContinue,
      "session should stay alive on overflow backpressure");
  testAssertTrue(client.runtimeOverflowNbytes > 0, "pending tcp bytes should be tracked");
  testAssertTrue(client.tunReadPaused, "tun read should be paused under overflow");

  sessionReset(session);
  testAssertTrue(client.runtimeOverflowNbytes == 0, "reset should clear pending tcp bytes");
  testAssertTrue(session->overflowNbytes == 0, "reset should clear pending tun bytes");
  testAssertTrue(!client.tunReadPaused, "reset should clear tun pause");
  testAssertTrue(!session->tcpReadPaused, "reset should clear tcp pause");
  sessionDestroy(session);
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testSessionTunReadQueuesEncryptedTcpFrame(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  client_t client;
  int tunPair[2];
  int tcpPair[2];
  char payload[] = "tun-payload";
  char out[ProtocolFrameSize];
  long nbytes;
  protocolDecoder_t decoder;
  protocolMessage_t msg;
  long consumed = 0;
  ioEvent_t event;

  memset(key, 0x44, sizeof(key));
  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, &poller, &client);

  testAssertTrue(write(tunPair[1], payload, strlen(payload)) == (long)strlen(payload), "tun write should succeed");
  testAssertTrue(waitCapturedEventOfKind(&poller, 100, ioEventTunRead), "reactor callback should capture tun readable event");
  event = ioEventTunRead;
  testAssertTrue(
      runSessionStep(session, &poller, event, key) == sessionStepContinue,
      "tun read event should continue");

  testAssertTrue(drainTcpQueueWithReactor(&poller, 100), "reactor should flush queued tcp payload");
  nbytes = read(tcpPair[1], out, sizeof(out));
  testAssertTrue(nbytes > 0, "tcp peer should receive encrypted wire frame");

  protocolDecoderInit(&decoder);
  testAssertTrue(
      protocolDecodeSecureMsg(&decoder, key, out, nbytes, &consumed, &msg) == protocolStatusOk,
      "received wire frame should decode");
  testAssertTrue(msg.type == protocolMsgData, "decoded message type should be data");
  testAssertTrue(msg.nbytes == (long)strlen(payload), "decoded payload length should match");
  testAssertTrue(memcmp(msg.buf, payload, strlen(payload)) == 0, "decoded payload should match");

  sessionDestroy(session);
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testSessionTcpReadQueuesTunWrite(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  client_t client;
  int tunPair[2];
  int tcpPair[2];
  char wire[ProtocolFrameSize];
  long wireNbytes;
  char out[128];
  char payload[] = "tcp-payload";
  ioEvent_t event;

  memset(key, 0x45, sizeof(key));
  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, &poller, &client);

  wireNbytes = writeSecureWire(key, protocolMsgData, payload, (long)strlen(payload), wire);
  testAssertTrue(write(tcpPair[1], wire, (size_t)wireNbytes) == wireNbytes, "tcp write should succeed");
  testAssertTrue(waitCapturedEventOfKind(&poller, 100, ioEventTcpRead), "reactor callback should capture tcp readable event");
  event = ioEventTcpRead;
  testAssertTrue(
      runSessionStep(session, &poller, event, key) == sessionStepContinue,
      "tcp read event should continue");
  testAssertTrue(ioTunServiceWriteEvent(&poller.tunPoller), "server tun write service should flush payload");

  testAssertTrue(
      recv(tunPair[1], out, sizeof(out), MSG_DONTWAIT) == (long)strlen(payload),
      "tun peer should receive payload");
  testAssertTrue(memcmp(out, payload, strlen(payload)) == 0, "tun payload should match");

  sessionDestroy(session);
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testSessionSplitEntrypointsForTunPayloadAndConnEvents(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  const char payload[] = "split-entry";
  session_t *clientSession;
  session_t *serverSession;
  client_t client;
  server_t server;
  protocolDecoder_t decoder;
  protocolMessage_t decodedMsg;
  long consumed = 0;
  ioEvent_t event;

  memset(key, 0x60, sizeof(key));
  setupSplitPollersFixture(&poller, tunPair, tcpPair);

  clientSession = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  serverSession = sessionCreate(true, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(clientSession != NULL && serverSession != NULL, "sessions should be created");
  wireClientSession(clientSession, &poller, &client);
  wireServerSession(serverSession, &server, &poller);

  testAssertTrue(
      write(tunPair[1], payload, sizeof(payload) - 1) == (ssize_t)(sizeof(payload) - 1),
      "tun peer write should succeed");
  testAssertTrue(waitCapturedEventOfKind(&poller, 100, ioEventTunRead), "reactor callback should capture tun readable event");
  event = ioEventTunRead;
  testAssertTrue(
      sessionStep(clientSession, &poller.tcpPoller, &poller.tunPoller, event, key) == sessionStepContinue,
      "tun read event should queue encrypted tcp frame");
  testAssertTrue(drainTcpQueueWithReactor(&poller, 100), "reactor should flush queued tcp payload");
  testAssertTrue(ioTcpServiceWriteEvent(&poller.tcpPoller), "tcp write service should flush queued data");

  protocolDecoderInit(&decoder);
  testAssertTrue(
      ioTcpRead(tcpPair[1], poller.tcpPoller.outBuf, sizeof(poller.tcpPoller.outBuf), &consumed) == ioStatusOk,
      "peer tcp should read encrypted frame");
  testAssertTrue(consumed > 0, "peer tcp should receive encrypted bytes");

  {
    long frameConsumed = 0;
    protocolStatus_t status =
        protocolDecodeSecureMsg(&decoder, key, poller.tcpPoller.outBuf, consumed, &frameConsumed, &decodedMsg);
    testAssertTrue(status == protocolStatusOk, "encoded tun payload should decode as secure message");
    testAssertTrue(decodedMsg.type == protocolMsgData, "decoded message should be data");
    testAssertTrue(decodedMsg.nbytes == (long)sizeof(payload) - 1, "decoded payload length should match");
    testAssertTrue(memcmp(decodedMsg.buf, payload, sizeof(payload) - 1) == 0, "decoded payload bytes should match");
  }

  {
    char inboundWire[ProtocolFrameSize];
    long inboundNbytes = writeSecureWire(
        key, protocolMsgData, "event-path", (long)strlen("event-path"), inboundWire);
    testAssertTrue(write(tcpPair[1], inboundWire, (size_t)inboundNbytes) == inboundNbytes, "peer tcp write should succeed");
  }
  testAssertTrue(waitCapturedEventOfKind(&poller, 100, ioEventTcpRead), "reactor callback should capture tcp readable event");
  event = ioEventTcpRead;
  testAssertTrue(
      sessionStep(clientSession, &poller.tcpPoller, &poller.tunPoller, event, key) == sessionStepContinue,
      "sessionStep conn path should process tcp read");
  testAssertTrue(ioTunServiceWriteEvent(&poller.tunPoller), "tun write service should flush queued frame");
  {
    char received[128];
    ssize_t nread = recv(tunPair[1], received, sizeof(received), MSG_DONTWAIT);
    testAssertTrue(nread == (ssize_t)strlen("event-path"), "tun peer should receive decoded payload");
    testAssertTrue(memcmp(received, "event-path", strlen("event-path")) == 0, "tun peer payload should match");
  }

  sessionDestroy(serverSession);
  sessionDestroy(clientSession);
  serverDeinit(&server);
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testBackpressurePauseAndResumeFlow(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  client_t client;
  int tunPair[2];
  int tcpPair[2];
  char fill[IoPollerQueueCapacity];
  char tunPayload[64];
  char drain[IoPollerQueueCapacity];
  ioEvent_t event;

  memset(key, 0x46, sizeof(key));
  memset(fill, 'x', sizeof(fill));
  memset(tunPayload, 'y', sizeof(tunPayload));
  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, &poller, &client);

  testAssertTrue(write(tunPair[1], tunPayload, sizeof(tunPayload)) == (long)sizeof(tunPayload), "tun write should succeed");
  testAssertTrue(waitCapturedEventOfKind(&poller, 100, ioEventTunRead), "reactor callback should capture tun readable event");
  event = ioEventTunRead;
  testAssertTrue(
      ioTcpWrite(&poller.tcpPoller, fill, IoPollerQueueCapacity - 16),
      "prefill should succeed");
  testAssertTrue(
      runSessionStep(session, &poller, event, key) == sessionStepContinue,
      "overflow path should continue");
  testAssertTrue(client.tunReadPaused, "tun read should be paused");
  testAssertTrue(client.runtimeOverflowNbytes > 0, "pending tcp payload should be retained");

  testAssertTrue(drainTcpQueueWithReactor(&poller, 100), "reactor should flush queued tcp payload");
  testAssertTrue(waitCapturedEventOfKind(&poller, 100, ioEventTcpWrite), "reactor callback should capture tcp writable low-watermark event");
  event = ioEventTcpWrite;
  testAssertTrue(read(tcpPair[1], drain, sizeof(drain)) > 0, "drain should consume queued bytes");
  testAssertTrue(
      runSessionStep(session, &poller, event, key) == sessionStepContinue,
      "tcp write event should continue");
  testAssertTrue(
      clientServiceBackpressure(&client, session, event, key),
      "client backpressure service should continue");
  testAssertTrue(client.runtimeOverflowNbytes == 0, "pending tcp payload should flush");
  testAssertTrue(!client.tunReadPaused, "tun read should resume when queue drains");

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
  testAssertTrue(ioTcpPollerInit(&destPollerA, poller.reactor.epollFd, destPairA[0]) == 0, "dest A poller init should succeed");
  testAssertTrue(ioTcpPollerInit(&destPollerB, poller.reactor.epollFd, destPairB[0]) == 0, "dest B poller init should succeed");

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
  testSessionTunReadQueuesEncryptedTcpFrame();
  testSessionTcpReadQueuesTunWrite();
  testSessionSplitEntrypointsForTunPayloadAndConnEvents();
  testBackpressurePauseAndResumeFlow();
  testSessionRetryOverflowFlushesAndResumesRead();
  testSessionRetryOverflowKeepsPendingWhenTunQueueStillSaturated();
  testSessionDestinationAwareTcpQueueAndDropApis();
  testSessionQueueTunWithDropForSession();
}
