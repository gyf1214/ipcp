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

typedef struct {
  int epollFd;
  ioTunPoller_t tunPoller;
  ioTcpPoller_t tcpPoller;
} splitPollersFixture_t;

static long long fakeNowMs = 0;
static unsigned char testServerKey[ProtocolPskSize] = {
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
    0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
    0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88,
    0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x00,
};
static const unsigned char testClaim2[] = {10, 0, 0, 2};
static const unsigned char testClaim3[] = {10, 0, 0, 3};
static const sessionHeartbeatConfig_t defaultHeartbeatCfg = {
    .intervalMs = 5000,
    .timeoutMs = 15000,
};

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

static ioEvent_t waitSplitPollers(splitPollersFixture_t *poller, int timeoutMs) {
  return ioPollersWait(&poller->tunPoller, &poller->tcpPoller, timeoutMs);
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
      serverInit(server, poller->tunPoller.tunFd, poller->tcpPoller.tcpFd, 1, 1, &defaultHeartbeatCfg, NULL, NULL),
      "server runtime init should succeed");
  server->tunPoller.epollFd = poller->tunPoller.epollFd;
  server->tunPoller.events = poller->tunPoller.events;
  sessionAttachServer(session, server);
}

static void assertSessionStepAbortsWhenRuntimeMissing(bool isServer) {
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
  testAssertTrue(WIFSIGNALED(status), "child should terminate via signal");
  testAssertTrue(WTERMSIG(status) == SIGABRT, "child should abort on missing runtime");
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testSessionApiSmoke(void) {
  const session_t *session = sessionCreate(true, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  testAssertTrue(sessionApiSmoke(), "session smoke api should return true");
  sessionDestroy((session_t *)session);
}

static void testSessionServerRoleAssertsOnMissingRuntime(void) {
  assertSessionStepAbortsWhenRuntimeMissing(true);
}

static void testSessionClientRoleAssertsOnMissingRuntime(void) {
  assertSessionStepAbortsWhenRuntimeMissing(false);
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

  memset(key, 0x55, sizeof(key));
  memset(fill, 'f', sizeof(fill));
  memset(tunPayload, 't', sizeof(tunPayload));
  fakeNowMs = 5000;

  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, &poller, &client);

  testAssertTrue(
      ioTcpWrite(&poller.tcpPoller, fill, IoPollerQueueCapacity - 32),
      "prefill tcp queue should succeed");
  testAssertTrue(write(tunPair[1], tunPayload, sizeof(tunPayload)) == (long)sizeof(tunPayload), "tun write should succeed");
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTunRead, key) == sessionStepContinue,
      "session should stay alive on overflow backpressure");
  testAssertTrue(client.tcpWritePendingNbytes > 0, "pending tcp bytes should be tracked");
  testAssertTrue(client.tunReadPaused, "tun read should be paused under overflow");

  sessionReset(session);
  testAssertTrue(client.tcpWritePendingNbytes == 0, "reset should clear pending tcp bytes");
  testAssertTrue(session->tunWritePendingNbytes == 0, "reset should clear pending tun bytes");
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

  memset(key, 0x44, sizeof(key));
  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, &poller, &client);

  testAssertTrue(write(tunPair[1], payload, strlen(payload)) == (long)strlen(payload), "tun write should succeed");
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTunRead, key) == sessionStepContinue,
      "tun read event should continue");

  testAssertTrue(waitSplitPollers(&poller, 100) == ioEventTcpWrite, "tcp write event should be available");
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTcpWrite, key) == sessionStepContinue,
      "tcp write event should continue");
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
  server_t server;
  int tunPair[2];
  int tcpPair[2];
  char wire[ProtocolFrameSize];
  long wireNbytes;
  char out[128];
  char payload[] = "tcp-payload";

  memset(key, 0x45, sizeof(key));
  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  session_t *session = sessionCreate(true, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireServerSession(session, &server, &poller);

  wireNbytes = writeSecureWire(key, protocolMsgData, payload, (long)strlen(payload), wire);
  testAssertTrue(write(tcpPair[1], wire, (size_t)wireNbytes) == wireNbytes, "tcp write should succeed");
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTcpRead, key) == sessionStepContinue,
      "tcp read event should continue");
  testAssertTrue(ioTunServiceWriteEvent(&poller.tunPoller), "server tun write service should flush payload");

  testAssertTrue(
      recv(tunPair[1], out, sizeof(out), MSG_DONTWAIT) == (long)strlen(payload),
      "tun peer should receive payload");
  testAssertTrue(memcmp(out, payload, strlen(payload)) == 0, "tun payload should match");

  sessionDestroy(session);
  serverDeinit(&server);
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

  memset(key, 0x60, sizeof(key));
  setupSplitPollersFixture(&poller, tunPair, tcpPair);

  clientSession = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  serverSession = sessionCreate(true, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(clientSession != NULL && serverSession != NULL, "sessions should be created");
  wireClientSession(clientSession, &poller, &client);
  wireServerSession(serverSession, &server, &poller);

  testAssertTrue(
      sessionHandleTunIngressPayload(
          clientSession, &poller.tcpPoller, &poller.tunPoller, key, payload, (long)sizeof(payload) - 1)
      == sessionStepContinue,
      "tun payload entrypoint should queue encrypted tcp frame");
  testAssertTrue(waitSplitPollers(&poller, 100) == ioEventTcpWrite, "tcp write event should be available");
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
  testAssertTrue(
      sessionHandleConnEvent(serverSession, &poller.tcpPoller, &poller.tunPoller, ioEventTcpRead, key)
      == sessionStepContinue,
      "conn event entrypoint should process tcp read");
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

  memset(key, 0x46, sizeof(key));
  memset(fill, 'x', sizeof(fill));
  memset(tunPayload, 'y', sizeof(tunPayload));
  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, &poller, &client);

  testAssertTrue(
      ioTcpWrite(&poller.tcpPoller, fill, IoPollerQueueCapacity - 16),
      "prefill should succeed");
  testAssertTrue(write(tunPair[1], tunPayload, sizeof(tunPayload)) == (long)sizeof(tunPayload), "tun write should succeed");
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTunRead, key) == sessionStepContinue,
      "overflow path should continue");
  testAssertTrue(client.tunReadPaused, "tun read should be paused");
  testAssertTrue(client.tcpWritePendingNbytes > 0, "pending tcp payload should be retained");

  testAssertTrue(waitSplitPollers(&poller, 100) == ioEventTcpWrite, "tcp write event should arrive");
  testAssertTrue(read(tcpPair[1], drain, sizeof(drain)) > 0, "drain should consume queued bytes");
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTcpWrite, key) == sessionStepContinue,
      "service backpressure should continue");
  testAssertTrue(client.tcpWritePendingNbytes == 0, "pending tcp payload should flush");
  testAssertTrue(!client.tunReadPaused, "tun read should resume when queue drains");

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

static void testSharedTunWriteInterestIsRuntimeOwned(void) {
  server_t server;
  int tunPair[2];
  int epollFd;
  int tcpPairA[2];
  int tcpPairB[2];
  char payloadA[] = "payload-a";
  char payloadB[] = "payload-b";

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPairA) == 0, "tcp pair A should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPairB) == 0, "tcp pair B should be created");
  testAssertTrue(
      serverInit(&server, tunPair[0], 70, 2, 2, &defaultHeartbeatCfg, NULL, NULL),
      "runtime init should succeed");

  epollFd = epoll_create1(0);
  testAssertTrue(epollFd >= 0, "epoll_create1 should succeed");
  server.epollFd = epollFd;
  testAssertTrue(
      epoll_ctl(
          epollFd,
          EPOLL_CTL_ADD,
          server.tunPoller.tunFd,
          &(struct epoll_event){.events = server.tunPoller.events, .data.fd = server.tunPoller.tunFd})
          == 0,
      "add tun fd should succeed");
  testAssertTrue(serverSyncTunWriteInterest(&server), "initial tun interest sync should succeed");

  testAssertTrue(
      serverAddClient(&server, 0, tcpPairA[0], testServerKey, testClaim2, sizeof(testClaim2)) == 0,
      "first client should be added");
  testAssertTrue(
      serverAddClient(&server, 1, tcpPairB[0], testServerKey, testClaim3, sizeof(testClaim3)) == 1,
      "second client should be added");

  testAssertTrue(serverQueueTunWrite(&server, payloadA, (long)strlen(payloadA)), "queue payload A should succeed");
  testAssertTrue(serverQueueTunWrite(&server, payloadB, (long)strlen(payloadB)), "queue payload B should succeed");
  testAssertTrue((server.tunPoller.events & EPOLLOUT) != 0, "runtime should enable tun epollout with pending shared queue");
  testAssertTrue(serverSyncTunWriteInterest(&server), "sync should keep epollout while queue has pending bytes");
  testAssertTrue((server.tunPoller.events & EPOLLOUT) != 0, "runtime should keep epollout until shared queue drains");

  testAssertTrue(serverServiceTunWriteEvent(&server), "shared tun write event should flush queued frames");
  testAssertTrue(serverSyncTunWriteInterest(&server), "sync should disable epollout after queue drains");
  testAssertTrue((server.tunPoller.events & EPOLLOUT) == 0, "runtime should disable epollout when shared queue drains");

  close(epollFd);
  serverDeinit(&server);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPairA[0]);
  close(tcpPairA[1]);
  close(tcpPairB[0]);
  close(tcpPairB[1]);
}

void runSessionTests(void) {
  testSessionServerRoleAssertsOnMissingRuntime();
  testSessionClientRoleAssertsOnMissingRuntime();
  testSessionCreateRejectsNullHeartbeatConfig();
  testSessionCreateRejectsInvalidHeartbeatConfig();
  testSessionApiSmoke();
  testSessionInitSeedsModeAndTimestamps();
  testSessionResetClearsPendingAndPauseFlags();
  testSessionTunReadQueuesEncryptedTcpFrame();
  testSessionTcpReadQueuesTunWrite();
  testSessionSplitEntrypointsForTunPayloadAndConnEvents();
  testBackpressurePauseAndResumeFlow();
  testSharedTunWriteInterestIsRuntimeOwned();
}
