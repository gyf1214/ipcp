#include "sessionTest.h"

#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "io.h"
#include "protocol.h"
#include "session.h"
#include "testAssert.h"

static long long fakeNowMs = 0;

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

static void testSessionApiSmoke(void) {
  const session_t *session = sessionCreate(true, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  testAssertTrue(sessionApiSmoke(), "session smoke api should return true");
  sessionDestroy((session_t *)session);
}

static void testSessionInitSeedsModeAndTimestamps(void) {
  sessionStats_t stats;

  fakeNowMs = 12345;
  session_t *session = sessionCreate(false, fakeNow, NULL);
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
  session_t *session = sessionCreate(false, fakeNow, NULL);
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
  session_t *session = sessionCreate(true, fakeNow, NULL);

  fakeNowMs = 15000;
  testAssertTrue(
      sessionStep(session, &poller, ioEventTimeout, key) == sessionStepStop,
      "server should stop after heartbeat timeout");

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
  session_t *session = sessionCreate(false, fakeNow, NULL);

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
  session_t *session = sessionCreate(false, fakeNow, NULL);
  wireNbytes = writeSecureWire(key, protocolMsgHeartbeatReq, NULL, 0, wire);
  testAssertTrue(write(tcpPair[1], wire, (size_t)wireNbytes) == wireNbytes, "tcp write should succeed");
  testAssertTrue(
      sessionStep(session, &poller, ioEventTcpRead, key) == sessionStepStop,
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
  session_t *session = sessionCreate(false, fakeNow, NULL);

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
  session_t *session = sessionCreate(true, fakeNow, NULL);

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
  session_t *session = sessionCreate(false, fakeNow, NULL);

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

void runSessionTests(void) {
  testSessionApiSmoke();
  testSessionInitSeedsModeAndTimestamps();
  testSessionResetClearsPendingAndPauseFlags();
  testServerHeartbeatTimeoutStopsSession();
  testClientHeartbeatRequestAndAckFlow();
  testClientRejectsInboundHeartbeatRequest();
  testSessionTunReadQueuesEncryptedTcpFrame();
  testSessionTcpReadQueuesTunWrite();
  testBackpressurePauseAndResumeFlow();
}
