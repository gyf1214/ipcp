#include "sessionTest.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
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

  result = runSessionStep(session, poller, event, key);

  fflush(stderr);
  testAssertTrue(dup2(savedStderr, STDERR_FILENO) >= 0, "restore stderr should succeed");
  close(savedStderr);
  return result;
}

static void testSessionApiSmoke(void) {
  const session_t *session = sessionCreate(true, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  testAssertTrue(sessionApiSmoke(), "session smoke api should return true");
  sessionDestroy((session_t *)session);
}

static void testSessionInitSeedsModeAndTimestamps(void) {
  sessionStats_t stats;

  fakeNowMs = 12345;
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(!stats.isServer, "session should keep client mode");
  testAssertTrue(stats.lastValidInboundMs == fakeNowMs, "lastValidInboundMs should be seeded");
  testAssertTrue(stats.lastDataSentMs == fakeNowMs, "lastDataSentMs should be seeded");
  testAssertTrue(stats.lastDataRecvMs == fakeNowMs, "lastDataRecvMs should be seeded");
  testAssertTrue(stats.lastHeartbeatReqMs == fakeNowMs, "lastHeartbeatReqMs should be seeded");
  sessionDestroy(session);
}

static void testSessionResetClearsPendingAndPauseFlags(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  char fill[IoPollerQueueCapacity];
  char tunPayload[128];
  sessionStats_t stats;

  memset(key, 0x55, sizeof(key));
  memset(fill, 'f', sizeof(fill));
  memset(tunPayload, 't', sizeof(tunPayload));
  fakeNowMs = 5000;

  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  testAssertTrue(
      ioTcpWrite(&poller.tcpPoller, fill, IoPollerQueueCapacity - 32),
      "prefill tcp queue should succeed");
  testAssertTrue(write(tunPair[1], tunPayload, sizeof(tunPayload)) == (long)sizeof(tunPayload), "tun write should succeed");
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTunRead, key) == sessionStepContinue,
      "session should stay alive on overflow backpressure");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(stats.tcpWritePendingNbytes > 0, "pending tcp bytes should be tracked");
  testAssertTrue(stats.tunReadPaused, "tun read should be paused under overflow");

  sessionReset(session);
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed after reset");
  testAssertTrue(stats.tcpWritePendingNbytes == 0, "reset should clear pending tcp bytes");
  testAssertTrue(stats.tunWritePendingNbytes == 0, "reset should clear pending tun bytes");
  testAssertTrue(!stats.tunReadPaused, "reset should clear tun pause");
  testAssertTrue(!stats.tcpReadPaused, "reset should clear tcp pause");
  sessionDestroy(session);
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testServerHeartbeatTimeoutStopsSession(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];

  memset(key, 0x11, sizeof(key));
  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  fakeNowMs = 0;
  session_t *session = sessionCreate(true, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  fakeNowMs = 15000;
  testAssertTrue(
      runSessionStepWithSuppressedStderr(session, &poller, ioEventTimeout, key) == sessionStepStop,
      "server should stop after heartbeat timeout");

  sessionDestroy(session);
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testClientHeartbeatUsesConfiguredInterval(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  sessionStats_t stats;
  sessionHeartbeatConfig_t heartbeatCfg = {
      .intervalMs = 2000,
      .timeoutMs = 6000,
  };

  memset(key, 0x31, sizeof(key));
  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  fakeNowMs = 1999;
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client should continue before configured heartbeat interval");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(!stats.heartbeatPending, "heartbeat should not be pending before configured interval");

  fakeNowMs = 2000;
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client should send heartbeat at configured interval");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(stats.heartbeatPending, "heartbeat should be pending at configured interval");

  sessionDestroy(session);
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testClientHeartbeatTimeoutUsesConfiguredTimeout(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  sessionStats_t stats;
  sessionHeartbeatConfig_t heartbeatCfg = {
      .intervalMs = 2000,
      .timeoutMs = 6000,
  };

  memset(key, 0x32, sizeof(key));
  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  fakeNowMs = 2000;
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client should send heartbeat request");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(stats.heartbeatPending, "heartbeat request should be pending");

  fakeNowMs = 7999;
  testAssertTrue(
      runSessionStepWithSuppressedStderr(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client should continue before configured timeout");

  fakeNowMs = 8000;
  testAssertTrue(
      runSessionStepWithSuppressedStderr(session, &poller, ioEventTimeout, key) == sessionStepStop,
      "client should stop at configured timeout");

  sessionDestroy(session);
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testServerHeartbeatTimeoutUsesConfiguredTimeout(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  sessionHeartbeatConfig_t heartbeatCfg = {
      .intervalMs = 3000,
      .timeoutMs = 9000,
  };

  memset(key, 0x33, sizeof(key));
  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  fakeNowMs = 0;
  session_t *session = sessionCreate(true, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  fakeNowMs = 8999;
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "server should continue before configured timeout");
  fakeNowMs = 9000;
  testAssertTrue(
      runSessionStepWithSuppressedStderr(session, &poller, ioEventTimeout, key) == sessionStepStop,
      "server should stop at configured timeout");

  sessionDestroy(session);
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testClientHeartbeatRequestAndAckFlow(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  sessionStats_t stats;
  char wire[ProtocolFrameSize];
  long wireNbytes;

  memset(key, 0x22, sizeof(key));
  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  testAssertTrue(
      runSessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client should continue before heartbeat interval");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(!stats.heartbeatPending, "heartbeat should not be pending before idle interval");

  fakeNowMs = 6000;
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client should stay alive when sending heartbeat request");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(stats.heartbeatPending, "heartbeat should become pending after idle interval");

  wireNbytes = writeSecureWire(key, protocolMsgHeartbeatAck, NULL, 0, wire);
  testAssertTrue(write(tcpPair[1], wire, (size_t)wireNbytes) == wireNbytes, "tcp write should succeed");
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTcpRead, key) == sessionStepContinue,
      "client should continue after heartbeat ack");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(!stats.heartbeatPending, "heartbeat pending should clear after ack");

  sessionDestroy(session);
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testClientHeartbeatPendingSetOnlyWhenReqEnqueueSucceeds(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  sessionStats_t stats;
  char fill[IoPollerQueueCapacity];

  memset(key, 0x24, sizeof(key));
  memset(fill, 'h', sizeof(fill));
  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  testAssertTrue(ioTcpWrite(&poller.tcpPoller, fill, IoPollerQueueCapacity), "prefill tcp queue should succeed");
  fakeNowMs = 6000;
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client heartbeat tick should continue when request enqueue is blocked");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(!stats.heartbeatPending, "heartbeat should remain non-pending when req enqueue is blocked");
  testAssertTrue(stats.tcpWritePendingNbytes > 0, "blocked heartbeat request should be retained as pending tcp write");

  sessionDestroy(session);
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testClientRejectsInboundHeartbeatRequest(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  char wire[ProtocolFrameSize];
  long wireNbytes;

  memset(key, 0x23, sizeof(key));
  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireNbytes = writeSecureWire(key, protocolMsgHeartbeatReq, NULL, 0, wire);
  testAssertTrue(write(tcpPair[1], wire, (size_t)wireNbytes) == wireNbytes, "tcp write should succeed");
  testAssertTrue(
      runSessionStepWithSuppressedStderr(session, &poller, ioEventTcpRead, key) == sessionStepStop,
      "client should stop on inbound heartbeat request");

  sessionDestroy(session);
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testSessionTunReadQueuesEncryptedTcpFrame(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
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

  wireNbytes = writeSecureWire(key, protocolMsgData, payload, (long)strlen(payload), wire);
  testAssertTrue(write(tcpPair[1], wire, (size_t)wireNbytes) == wireNbytes, "tcp write should succeed");
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTcpRead, key) == sessionStepContinue,
      "tcp read event should continue");

  testAssertTrue(waitSplitPollers(&poller, 100) == ioEventTunWrite, "tun write event should be available");
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTunWrite, key) == sessionStepContinue,
      "tun write event should continue");
  testAssertTrue(read(tunPair[1], out, sizeof(out)) == (long)strlen(payload), "tun peer should receive payload");
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
  protocolDecoder_t decoder;
  protocolMessage_t decodedMsg;
  long consumed = 0;

  memset(key, 0x60, sizeof(key));
  setupSplitPollersFixture(&poller, tunPair, tcpPair);

  clientSession = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  serverSession = sessionCreate(true, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(clientSession != NULL && serverSession != NULL, "sessions should be created");

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
  testAssertTrue(waitSplitPollers(&poller, 100) == ioEventTunWrite, "tun write event should be available");
  testAssertTrue(ioTunServiceWriteEvent(&poller.tunPoller), "tun write service should flush queued frame");

  {
    char received[128];
    ssize_t nread = read(tunPair[1], received, sizeof(received));
    testAssertTrue(nread == (ssize_t)strlen("event-path"), "tun peer should receive decoded payload");
    testAssertTrue(memcmp(received, "event-path", strlen("event-path")) == 0, "tun peer payload should match");
  }

  sessionDestroy(serverSession);
  sessionDestroy(clientSession);
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);
}

static void testBackpressurePauseAndResumeFlow(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  char fill[IoPollerQueueCapacity];
  char tunPayload[64];
  char drain[IoPollerQueueCapacity];
  sessionStats_t stats;

  memset(key, 0x46, sizeof(key));
  memset(fill, 'x', sizeof(fill));
  memset(tunPayload, 'y', sizeof(tunPayload));
  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  testAssertTrue(
      ioTcpWrite(&poller.tcpPoller, fill, IoPollerQueueCapacity - 16),
      "prefill should succeed");
  testAssertTrue(write(tunPair[1], tunPayload, sizeof(tunPayload)) == (long)sizeof(tunPayload), "tun write should succeed");
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTunRead, key) == sessionStepContinue,
      "overflow path should continue");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(stats.tunReadPaused, "tun read should be paused");
  testAssertTrue(stats.tcpWritePendingNbytes > 0, "pending tcp payload should be retained");

  testAssertTrue(waitSplitPollers(&poller, 100) == ioEventTcpWrite, "tcp write event should arrive");
  testAssertTrue(read(tcpPair[1], drain, sizeof(drain)) > 0, "drain should consume queued bytes");
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTcpWrite, key) == sessionStepContinue,
      "service backpressure should continue");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(stats.tcpWritePendingNbytes == 0, "pending tcp payload should flush");
  testAssertTrue(!stats.tunReadPaused, "tun read should resume when queue drains");

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
  server_t runtime;
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
      serverInit(&runtime, tunPair[0], 70, 2, 2, &defaultHeartbeatCfg, NULL, NULL),
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
  testAssertTrue(serverSyncTunWriteInterest(&runtime), "initial tun interest sync should succeed");

  testAssertTrue(
      serverAddClient(&runtime, 0, tcpPairA[0], testServerKey, testClaim2, sizeof(testClaim2)) == 0,
      "first client should be added");
  testAssertTrue(
      serverAddClient(&runtime, 1, tcpPairB[0], testServerKey, testClaim3, sizeof(testClaim3)) == 1,
      "second client should be added");

  testAssertTrue(serverQueueTunWrite(&runtime, payloadA, (long)strlen(payloadA)), "queue payload A should succeed");
  testAssertTrue(serverQueueTunWrite(&runtime, payloadB, (long)strlen(payloadB)), "queue payload B should succeed");
  testAssertTrue((runtime.tunPoller.events & EPOLLOUT) != 0, "runtime should enable tun epollout with pending shared queue");
  testAssertTrue(serverSyncTunWriteInterest(&runtime), "sync should keep epollout while queue has pending bytes");
  testAssertTrue((runtime.tunPoller.events & EPOLLOUT) != 0, "runtime should keep epollout until shared queue drains");

  testAssertTrue(serverServiceTunWriteEvent(&runtime), "shared tun write event should flush queued frames");
  testAssertTrue(serverSyncTunWriteInterest(&runtime), "sync should disable epollout after queue drains");
  testAssertTrue((runtime.tunPoller.events & EPOLLOUT) == 0, "runtime should disable epollout when shared queue drains");

  close(epollFd);
  serverDeinit(&runtime);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPairA[0]);
  close(tcpPairA[1]);
  close(tcpPairB[0]);
  close(tcpPairB[1]);
}

static void setupServerForTest(
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
      serverInit(runtime, tunPair[0], 72, maxSessions, maxSessions, &defaultHeartbeatCfg, NULL, NULL),
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

  *slotA = serverAddClient(runtime, 0, tcpPairA[0], testServerKey, testClaim2, sizeof(testClaim2));
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
    *slotB = serverAddClient(runtime, 1, tcpPairB[0], testServerKey, testClaim3, sizeof(testClaim3));
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

static void teardownServerForTest(
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
  sessionStats_t stats;

  memset(key, 0x51, sizeof(key));
  memset(fill, 'p', sizeof(fill));
  memset(tunPayload, 'q', sizeof(tunPayload));
  setupServerForTest(&runtime, 1, &epollFd, tunPair, tcpPairA, tcpPairB, &slotA, &slotB);
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
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(stats.tcpWritePendingNbytes == 0, "server overflow should retain pending data in runtime, not session");
  testAssertTrue((runtime.tunPoller.events & EPOLLIN) == 0, "runtime should disable tun epollin while pending exists");

  teardownServerForTest(&runtime, epollFd, tunPair, tcpPairA, tcpPairB, slotA, slotB);
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
  sessionStats_t ownerStats;
  long queued;

  memset(key, 0x52, sizeof(key));
  memset(fill, 'r', sizeof(fill));
  memset(tunPayload, 's', sizeof(tunPayload));
  setupServerForTest(&runtime, 2, &epollFd, tunPair, tcpPairA, tcpPairB, &slotA, &slotB);
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
  testAssertTrue(sessionGetStats(ownerSession, &ownerStats), "sessionGetStats should succeed");
  testAssertTrue(ownerStats.tcpWritePendingNbytes == 0, "owner session should not keep runtime pending bytes locally");
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

  teardownServerForTest(&runtime, epollFd, tunPair, tcpPairA, tcpPairB, slotA, slotB);
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
  setupServerForTest(&runtime, 1, &epollFd, tunPair, tcpPairA, tcpPairB, &slotA, &slotB);
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

  teardownServerForTest(&runtime, epollFd, tunPair, tcpPairA, tcpPairB, slotA, slotB);
}

static void testRoleQueueAdaptersDispatchToServerAndClientApis(void) {
  server_t serverRuntime;
  client_t clientRuntime;
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  int serverTunPair[2];
  int serverTcpPair[2];
  char fill[IoPollerQueueCapacity];
  char payload[128];
  bool clientTunReadPaused = false;
  long clientTcpPendingNbytes = 0;
  char clientTcpPendingBuf[ProtocolFrameSize];
  sessionQueueResult_t result;
  int serverSlot;

  memset(fill, 'w', sizeof(fill));
  memset(payload, 'z', sizeof(payload));
  memset(clientTcpPendingBuf, 0, sizeof(clientTcpPendingBuf));

  setupSplitPollersFixture(&poller, tunPair, tcpPair);
  clientRuntime.tunPoller = &poller.tunPoller;
  clientRuntime.tcpPoller = &poller.tcpPoller;
  testAssertTrue(
      ioTcpWrite(&poller.tcpPoller, fill, IoPollerQueueCapacity - 16),
      "prefill client tcp queue should succeed");
  result = clientQueueTcpWithBackpressure(
      &clientRuntime,
      &poller.tcpPoller,
      &poller.tunPoller,
      &clientTunReadPaused,
      &clientTcpPendingNbytes,
      clientTcpPendingBuf,
      payload,
      sizeof(payload));
  testAssertTrue(result == sessionQueueResultBlocked, "client queue api should block on overflow");
  testAssertTrue(clientTunReadPaused, "client queue api should pause tun reads on overflow");
  testAssertTrue(clientTcpPendingNbytes > 0, "client queue api should store pending tcp payload");
  teardownSplitPollersFixture(&poller, tunPair, tcpPair);

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, serverTunPair) == 0, "server tun pair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, serverTcpPair) == 0, "server tcp pair should be created");
  testAssertTrue(
      serverInit(&serverRuntime, serverTunPair[0], 80, 1, 1, &defaultHeartbeatCfg, NULL, NULL),
      "server runtime init should succeed");
  serverSlot = serverAddClient(&serverRuntime, 0, serverTcpPair[0], testServerKey, testClaim2, sizeof(testClaim2));
  testAssertTrue(serverSlot == 0, "server client should be added");
  testAssertTrue(
      ioTcpWrite(&serverRuntime.activeConns[0].tcpPoller, fill, IoPollerQueueCapacity - 16),
      "prefill server tcp queue should succeed");
  result = serverQueueTcpWithBackpressure(
      &serverRuntime, &serverRuntime.activeConns[0].tcpPoller, payload, sizeof(payload));
  testAssertTrue(result == sessionQueueResultBlocked, "server queue api should block on overflow");
  testAssertTrue(serverHasPendingTunToTcp(&serverRuntime), "server queue api should store runtime pending payload");
  testAssertTrue(serverPendingTunToTcpOwner(&serverRuntime) == 0, "server pending payload owner should match slot");

  serverDeinit(&serverRuntime);
  close(serverTunPair[0]);
  close(serverTunPair[1]);
  close(serverTcpPair[0]);
  close(serverTcpPair[1]);
}

void runSessionTests(void) {
  testSessionCreateRejectsNullHeartbeatConfig();
  testSessionCreateRejectsInvalidHeartbeatConfig();
  testSessionApiSmoke();
  testSessionInitSeedsModeAndTimestamps();
  testSessionResetClearsPendingAndPauseFlags();
  testServerHeartbeatTimeoutStopsSession();
  testClientHeartbeatUsesConfiguredInterval();
  testClientHeartbeatTimeoutUsesConfiguredTimeout();
  testServerHeartbeatTimeoutUsesConfiguredTimeout();
  testClientHeartbeatRequestAndAckFlow();
  testClientHeartbeatPendingSetOnlyWhenReqEnqueueSucceeds();
  testClientRejectsInboundHeartbeatRequest();
  testSessionTunReadQueuesEncryptedTcpFrame();
  testSessionTcpReadQueuesTunWrite();
  testSessionSplitEntrypointsForTunPayloadAndConnEvents();
  testBackpressurePauseAndResumeFlow();
  testSharedTunWriteInterestIsRuntimeOwned();
  testServerTunOverflowDisablesTunEpollinGlobally();
  testServerPendingRetriesOnOwnerAndResumesTunEpollinAtLowWatermark();
  testServerOwnerDisconnectDropsRuntimePendingAndResumesTunEpollin();
  testRoleQueueAdaptersDispatchToServerAndClientApis();
}
