#include "sessionTest.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "io.h"
#include "protocol.h"
#include "session.h"
#include "testAssert.h"

static long long fakeNowMs = 0;
static const sessionHeartbeatConfig_t defaultHeartbeatCfg = {
    .intervalMs = 5000,
    .timeoutMs = 15000,
};

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
  protocolStatus_t status = protocolSecureEncodeMessage(&msg, key, &frame);
  testAssertTrue(status == protocolStatusOk, "secure encode should succeed");

  uint32_t wireLen = htonl((uint32_t)frame.nbytes);
  memcpy(outBuf, &wireLen, ProtocolWireLengthSize);
  memcpy(outBuf + ProtocolWireLengthSize, frame.buf, (size_t)frame.nbytes);
  return ProtocolWireLengthSize + frame.nbytes;
}

static void setupPoller(ioPoller_t *poller, int tunPair[2], int tcpPair[2]) {
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "tcp socketpair should be created");
  testAssertTrue(ioPollerInit(poller, tunPair[0], tcpPair[0]) == 0, "ioPollerInit should succeed");
}

static void teardownPoller(ioPoller_t *poller, int tunPair[2], int tcpPair[2]) {
  ioPollerClose(poller);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static sessionStepResult_t runSessionStepWithSuppressedStderr(
    session_t *session,
    ioPoller_t *poller,
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

  result = sessionStep(session, poller, event, key);

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
  ioPoller_t poller;
  int tunPair[2];
  int tcpPair[2];
  char fill[IoPollerQueueCapacity];
  char tunPayload[128];
  sessionStats_t stats;

  memset(key, 0x55, sizeof(key));
  memset(fill, 'f', sizeof(fill));
  memset(tunPayload, 't', sizeof(tunPayload));
  fakeNowMs = 5000;

  setupPoller(&poller, tunPair, tcpPair);
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  testAssertTrue(
      ioPollerQueueWrite(&poller, ioSourceTcp, fill, IoPollerQueueCapacity - 32),
      "prefill tcp queue should succeed");
  testAssertTrue(write(tunPair[1], tunPayload, sizeof(tunPayload)) == (long)sizeof(tunPayload), "tun write should succeed");
  testAssertTrue(
      sessionStep(session, &poller, ioEventTunRead, key) == sessionStepContinue,
      "session should stay alive on overflow backpressure");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(stats.pendingTcpNbytes > 0, "pending tcp bytes should be tracked");
  testAssertTrue(stats.tunReadPaused, "tun read should be paused under overflow");

  sessionReset(session);
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed after reset");
  testAssertTrue(stats.pendingTcpNbytes == 0, "reset should clear pending tcp bytes");
  testAssertTrue(stats.pendingTunNbytes == 0, "reset should clear pending tun bytes");
  testAssertTrue(!stats.tunReadPaused, "reset should clear tun pause");
  testAssertTrue(!stats.tcpReadPaused, "reset should clear tcp pause");
  sessionDestroy(session);
  teardownPoller(&poller, tunPair, tcpPair);
}

static void testServerHeartbeatTimeoutStopsSession(void) {
  unsigned char key[ProtocolPskSize];
  ioPoller_t poller;
  int tunPair[2];
  int tcpPair[2];

  memset(key, 0x11, sizeof(key));
  setupPoller(&poller, tunPair, tcpPair);
  fakeNowMs = 0;
  session_t *session = sessionCreate(true, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  fakeNowMs = 15000;
  testAssertTrue(
      runSessionStepWithSuppressedStderr(session, &poller, ioEventTimeout, key) == sessionStepStop,
      "server should stop after heartbeat timeout");

  sessionDestroy(session);
  teardownPoller(&poller, tunPair, tcpPair);
}

static void testClientHeartbeatUsesConfiguredInterval(void) {
  unsigned char key[ProtocolPskSize];
  ioPoller_t poller;
  int tunPair[2];
  int tcpPair[2];
  sessionStats_t stats;
  sessionHeartbeatConfig_t heartbeatCfg = {
      .intervalMs = 2000,
      .timeoutMs = 6000,
  };

  memset(key, 0x31, sizeof(key));
  setupPoller(&poller, tunPair, tcpPair);
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  fakeNowMs = 1999;
  testAssertTrue(
      sessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client should continue before configured heartbeat interval");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(!stats.heartbeatPending, "heartbeat should not be pending before configured interval");

  fakeNowMs = 2000;
  testAssertTrue(
      sessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client should send heartbeat at configured interval");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(stats.heartbeatPending, "heartbeat should be pending at configured interval");

  sessionDestroy(session);
  teardownPoller(&poller, tunPair, tcpPair);
}

static void testClientHeartbeatTimeoutUsesConfiguredTimeout(void) {
  unsigned char key[ProtocolPskSize];
  ioPoller_t poller;
  int tunPair[2];
  int tcpPair[2];
  sessionStats_t stats;
  sessionHeartbeatConfig_t heartbeatCfg = {
      .intervalMs = 2000,
      .timeoutMs = 6000,
  };

  memset(key, 0x32, sizeof(key));
  setupPoller(&poller, tunPair, tcpPair);
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  fakeNowMs = 2000;
  testAssertTrue(
      sessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
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
  teardownPoller(&poller, tunPair, tcpPair);
}

static void testServerHeartbeatTimeoutUsesConfiguredTimeout(void) {
  unsigned char key[ProtocolPskSize];
  ioPoller_t poller;
  int tunPair[2];
  int tcpPair[2];
  sessionHeartbeatConfig_t heartbeatCfg = {
      .intervalMs = 3000,
      .timeoutMs = 9000,
  };

  memset(key, 0x33, sizeof(key));
  setupPoller(&poller, tunPair, tcpPair);
  fakeNowMs = 0;
  session_t *session = sessionCreate(true, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  fakeNowMs = 8999;
  testAssertTrue(
      sessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "server should continue before configured timeout");
  fakeNowMs = 9000;
  testAssertTrue(
      runSessionStepWithSuppressedStderr(session, &poller, ioEventTimeout, key) == sessionStepStop,
      "server should stop at configured timeout");

  sessionDestroy(session);
  teardownPoller(&poller, tunPair, tcpPair);
}

static void testClientHeartbeatRequestAndAckFlow(void) {
  unsigned char key[ProtocolPskSize];
  ioPoller_t poller;
  int tunPair[2];
  int tcpPair[2];
  sessionStats_t stats;
  char wire[ProtocolWireLengthSize + ProtocolFrameSize];
  long wireNbytes;

  memset(key, 0x22, sizeof(key));
  setupPoller(&poller, tunPair, tcpPair);
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  testAssertTrue(
      sessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client should continue before heartbeat interval");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(!stats.heartbeatPending, "heartbeat should not be pending before idle interval");

  fakeNowMs = 6000;
  testAssertTrue(
      sessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client should stay alive when sending heartbeat request");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(stats.heartbeatPending, "heartbeat should become pending after idle interval");

  wireNbytes = writeSecureWire(key, protocolMsgHeartbeatAck, NULL, 0, wire);
  testAssertTrue(write(tcpPair[1], wire, (size_t)wireNbytes) == wireNbytes, "tcp write should succeed");
  testAssertTrue(
      sessionStep(session, &poller, ioEventTcpRead, key) == sessionStepContinue,
      "client should continue after heartbeat ack");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(!stats.heartbeatPending, "heartbeat pending should clear after ack");

  sessionDestroy(session);
  teardownPoller(&poller, tunPair, tcpPair);
}

static void testClientRejectsInboundHeartbeatRequest(void) {
  unsigned char key[ProtocolPskSize];
  ioPoller_t poller;
  int tunPair[2];
  int tcpPair[2];
  char wire[ProtocolWireLengthSize + ProtocolFrameSize];
  long wireNbytes;

  memset(key, 0x23, sizeof(key));
  setupPoller(&poller, tunPair, tcpPair);
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireNbytes = writeSecureWire(key, protocolMsgHeartbeatReq, NULL, 0, wire);
  testAssertTrue(write(tcpPair[1], wire, (size_t)wireNbytes) == wireNbytes, "tcp write should succeed");
  testAssertTrue(
      runSessionStepWithSuppressedStderr(session, &poller, ioEventTcpRead, key) == sessionStepStop,
      "client should stop on inbound heartbeat request");

  sessionDestroy(session);
  teardownPoller(&poller, tunPair, tcpPair);
}

static void testSessionTunReadQueuesEncryptedTcpFrame(void) {
  unsigned char key[ProtocolPskSize];
  ioPoller_t poller;
  int tunPair[2];
  int tcpPair[2];
  char payload[] = "tun-payload";
  char out[ProtocolWireLengthSize + ProtocolFrameSize];
  long nbytes;
  protocolDecoder_t decoder;
  protocolMessage_t msg;
  long consumed = 0;

  memset(key, 0x44, sizeof(key));
  setupPoller(&poller, tunPair, tcpPair);
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  testAssertTrue(write(tunPair[1], payload, strlen(payload)) == (long)strlen(payload), "tun write should succeed");
  testAssertTrue(
      sessionStep(session, &poller, ioEventTunRead, key) == sessionStepContinue,
      "tun read event should continue");

  testAssertTrue(ioPollerWait(&poller, 100) == ioEventTcpWrite, "tcp write event should be available");
  testAssertTrue(
      sessionStep(session, &poller, ioEventTcpWrite, key) == sessionStepContinue,
      "tcp write event should continue");
  nbytes = read(tcpPair[1], out, sizeof(out));
  testAssertTrue(nbytes > 0, "tcp peer should receive encrypted wire frame");

  protocolDecoderInit(&decoder);
  testAssertTrue(
      protocolSecureDecoderReadMessage(&decoder, key, out, nbytes, &consumed, &msg) == protocolStatusOk,
      "received wire frame should decode");
  testAssertTrue(msg.type == protocolMsgData, "decoded message type should be data");
  testAssertTrue(msg.nbytes == (long)strlen(payload), "decoded payload length should match");
  testAssertTrue(memcmp(msg.buf, payload, strlen(payload)) == 0, "decoded payload should match");

  sessionDestroy(session);
  teardownPoller(&poller, tunPair, tcpPair);
}

static void testSessionTcpReadQueuesTunWrite(void) {
  unsigned char key[ProtocolPskSize];
  ioPoller_t poller;
  int tunPair[2];
  int tcpPair[2];
  char wire[ProtocolWireLengthSize + ProtocolFrameSize];
  long wireNbytes;
  char out[128];
  char payload[] = "tcp-payload";

  memset(key, 0x45, sizeof(key));
  setupPoller(&poller, tunPair, tcpPair);
  session_t *session = sessionCreate(true, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  wireNbytes = writeSecureWire(key, protocolMsgData, payload, (long)strlen(payload), wire);
  testAssertTrue(write(tcpPair[1], wire, (size_t)wireNbytes) == wireNbytes, "tcp write should succeed");
  testAssertTrue(
      sessionStep(session, &poller, ioEventTcpRead, key) == sessionStepContinue,
      "tcp read event should continue");

  testAssertTrue(ioPollerWait(&poller, 100) == ioEventTunWrite, "tun write event should be available");
  testAssertTrue(
      sessionStep(session, &poller, ioEventTunWrite, key) == sessionStepContinue,
      "tun write event should continue");
  testAssertTrue(read(tunPair[1], out, sizeof(out)) == (long)strlen(payload), "tun peer should receive payload");
  testAssertTrue(memcmp(out, payload, strlen(payload)) == 0, "tun payload should match");

  sessionDestroy(session);
  teardownPoller(&poller, tunPair, tcpPair);
}

static void testBackpressurePauseAndResumeFlow(void) {
  unsigned char key[ProtocolPskSize];
  ioPoller_t poller;
  int tunPair[2];
  int tcpPair[2];
  char fill[IoPollerQueueCapacity];
  char tunPayload[64];
  char drain[IoPollerQueueCapacity];
  sessionStats_t stats;

  memset(key, 0x46, sizeof(key));
  memset(fill, 'x', sizeof(fill));
  memset(tunPayload, 'y', sizeof(tunPayload));
  setupPoller(&poller, tunPair, tcpPair);
  session_t *session = sessionCreate(false, &defaultHeartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");

  testAssertTrue(
      ioPollerQueueWrite(&poller, ioSourceTcp, fill, IoPollerQueueCapacity - 16),
      "prefill should succeed");
  testAssertTrue(write(tunPair[1], tunPayload, sizeof(tunPayload)) == (long)sizeof(tunPayload), "tun write should succeed");
  testAssertTrue(
      sessionStep(session, &poller, ioEventTunRead, key) == sessionStepContinue,
      "overflow path should continue");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(stats.tunReadPaused, "tun read should be paused");
  testAssertTrue(stats.pendingTcpNbytes > 0, "pending tcp payload should be retained");

  testAssertTrue(ioPollerWait(&poller, 100) == ioEventTcpWrite, "tcp write event should arrive");
  testAssertTrue(read(tcpPair[1], drain, sizeof(drain)) > 0, "drain should consume queued bytes");
  testAssertTrue(
      sessionStep(session, &poller, ioEventTcpWrite, key) == sessionStepContinue,
      "service backpressure should continue");
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(stats.pendingTcpNbytes == 0, "pending tcp payload should flush");
  testAssertTrue(!stats.tunReadPaused, "tun read should resume when queue drains");

  sessionDestroy(session);
  teardownPoller(&poller, tunPair, tcpPair);
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

static void testSessionServeMultiClientRejectsInvalidArgs(void) {
  unsigned char key[ProtocolPskSize];
  memset(key, 0x47, sizeof(key));

  testAssertTrue(
      sessionServeMultiClient(-1, -1, key, &defaultHeartbeatCfg, 2) < 0,
      "server runtime should reject invalid fds");
  testAssertTrue(
      sessionServeMultiClient(1, 2, NULL, &defaultHeartbeatCfg, 2) < 0,
      "server runtime should reject null key");
  testAssertTrue(
      sessionServeMultiClient(1, 2, key, NULL, 2) < 0,
      "server runtime should reject null heartbeat config");
  testAssertTrue(
      sessionServeMultiClient(1, 2, key, &defaultHeartbeatCfg, 0) < 0,
      "server runtime should reject non-positive max session count");
}

void runSessionTests(void) {
  testSessionCreateRejectsNullHeartbeatConfig();
  testSessionCreateRejectsInvalidHeartbeatConfig();
  testSessionServeMultiClientRejectsInvalidArgs();
  testSessionApiSmoke();
  testSessionInitSeedsModeAndTimestamps();
  testSessionResetClearsPendingAndPauseFlags();
  testServerHeartbeatTimeoutStopsSession();
  testClientHeartbeatUsesConfiguredInterval();
  testClientHeartbeatTimeoutUsesConfiguredTimeout();
  testServerHeartbeatTimeoutUsesConfiguredTimeout();
  testClientHeartbeatRequestAndAckFlow();
  testClientRejectsInboundHeartbeatRequest();
  testSessionTunReadQueuesEncryptedTcpFrame();
  testSessionTcpReadQueuesTunWrite();
  testBackpressurePauseAndResumeFlow();
}
