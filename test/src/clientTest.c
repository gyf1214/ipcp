#include "clientTest.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "io.h"
#include "protocol.h"
#include "client.h"
#include "sessionInternal.h"
#include "testAssert.h"

static unsigned char testClientKey[ProtocolPskSize] = {
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
    0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
    0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88,
    0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x00,
};
static const unsigned char testClaim[] = {10, 0, 0, 2};
static const sessionHeartbeatConfig_t heartbeatCfg = {
    .intervalMs = 5000,
    .timeoutMs = 15000,
};
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

static int writeAll(int fd, const void *buf, long nbytes) {
  long offset = 0;
  while (offset < nbytes) {
    ssize_t n = write(fd, (const char *)buf + offset, (size_t)(nbytes - offset));
    if (n < 0) {
      return -1;
    }
    if (n == 0) {
      return -1;
    }
    offset += (long)n;
  }
  return 0;
}

static int readAll(int fd, void *buf, long nbytes) {
  long offset = 0;
  while (offset < nbytes) {
    ssize_t n = read(fd, (char *)buf + offset, (size_t)(nbytes - offset));
    if (n < 0) {
      return -1;
    }
    if (n == 0) {
      return -1;
    }
    offset += (long)n;
  }
  return 0;
}

static int writeWireFrame(int fd, const protocolFrame_t *frame) {
  return writeAll(fd, frame->buf, frame->nbytes);
}

static int readWireFrame(int fd, protocolFrame_t *frame) {
  long contentNbytes = 0;
  if (readAll(fd, frame->buf, ProtocolWireLengthSize) != 0) {
    return -1;
  }
  contentNbytes = ((long)(unsigned char)frame->buf[0] << 24)
      | ((long)(unsigned char)frame->buf[1] << 16)
      | ((long)(unsigned char)frame->buf[2] << 8)
      | (long)(unsigned char)frame->buf[3];
  if (contentNbytes <= 0 || contentNbytes > (ProtocolFrameSize - ProtocolWireLengthSize)) {
    return -1;
  }
  frame->nbytes = ProtocolWireLengthSize + contentNbytes;
  return readAll(fd, frame->buf + ProtocolWireLengthSize, contentNbytes);
}

static void setupPairs(int tunPair[2], int tcpPair[2]) {
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should succeed");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "tcp socketpair should succeed");
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

static void testClientServeConnRejectsInvalidArgs(void) {
  testAssertTrue(
      clientServeConn(-1, -1, NULL, 0, NULL, &heartbeatCfg) != 0,
      "clientServeConn should reject invalid args");
}

static void testClientWriteRawMsgWritesValidWireFrame(void) {
  int tcpPair[2];
  protocolRawMsg_t rawMsg;
  protocolFrame_t frame;
  protocolRawMsg_t decoded;
  protocolDecoder_t decoder;
  long consumed = 0;

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "tcp socketpair should succeed");
  rawMsg.buf = "claim-data";
  rawMsg.nbytes = (long)strlen(rawMsg.buf);
  testAssertTrue(clientWriteRawMsg(tcpPair[0], &rawMsg) == 0, "clientWriteRawMsg should succeed");

  testAssertTrue(readWireFrame(tcpPair[1], &frame) == 0, "read wire frame should succeed");
  protocolDecoderInit(&decoder);
  consumed = 0;
  testAssertTrue(
      protocolDecodeRaw(&decoder, frame.buf, frame.nbytes, &consumed, &decoded) == protocolStatusOk,
      "raw wire should decode");
  testAssertTrue(decoded.nbytes == rawMsg.nbytes, "decoded nbytes should match");
  testAssertTrue(memcmp(decoded.buf, rawMsg.buf, (size_t)rawMsg.nbytes) == 0, "decoded payload should match");

  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientReadRawMsgSyncReadsValidWireFrame(void) {
  int tcpPair[2];
  protocolRawMsg_t rawMsg;
  protocolRawMsg_t decoded;
  protocolFrame_t frame;

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "tcp socketpair should succeed");
  rawMsg.buf = "challenge";
  rawMsg.nbytes = (long)strlen(rawMsg.buf);
  testAssertTrue(protocolEncodeRaw(&rawMsg, &frame) == protocolStatusOk, "raw encode should succeed");
  testAssertTrue(writeWireFrame(tcpPair[1], &frame) == 0, "write raw wire frame should succeed");
  testAssertTrue(clientReadRawMsg(tcpPair[0], &decoded) == 0, "clientReadRawMsg should succeed");
  testAssertTrue(decoded.nbytes == rawMsg.nbytes, "decoded nbytes should match");
  testAssertTrue(memcmp(decoded.buf, rawMsg.buf, (size_t)rawMsg.nbytes) == 0, "decoded payload should match");

  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientWriteSecureMsgWritesDecodablePayload(void) {
  int tcpPair[2];
  protocolMessage_t msg;
  protocolFrame_t frame;
  protocolMessage_t decoded;
  protocolDecoder_t decoder;
  long consumed = 0;
  const char payload[] = "hello";

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "tcp socketpair should succeed");
  msg.type = protocolMsgData;
  msg.buf = payload;
  msg.nbytes = (long)sizeof(payload);
  testAssertTrue(clientWriteSecureMsg(tcpPair[0], &msg, testClientKey) == 0, "clientWriteSecureMsg should succeed");

  testAssertTrue(readWireFrame(tcpPair[1], &frame) == 0, "read wire frame should succeed");
  protocolDecoderInit(&decoder);
  consumed = 0;
  testAssertTrue(
      protocolDecodeSecureMsg(&decoder, testClientKey, frame.buf, frame.nbytes, &consumed, &decoded)
          == protocolStatusOk,
      "secure wire should decode");
  testAssertTrue(decoded.type == msg.type, "decoded type should match");
  testAssertTrue(decoded.nbytes == msg.nbytes, "decoded nbytes should match");
  testAssertTrue(memcmp(decoded.buf, msg.buf, (size_t)msg.nbytes) == 0, "decoded payload should match");

  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientReadSecureMsgSyncReadsValidWireFrame(void) {
  int tcpPair[2];
  protocolMessage_t msg;
  protocolMessage_t decoded;
  protocolFrame_t frame;
  const char payload[] = "hello-secure";

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "tcp socketpair should succeed");
  msg.type = protocolMsgData;
  msg.buf = payload;
  msg.nbytes = (long)strlen(payload);
  testAssertTrue(protocolEncodeSecureMsg(&msg, testClientKey, &frame) == protocolStatusOk, "secure encode should succeed");
  testAssertTrue(writeWireFrame(tcpPair[1], &frame) == 0, "write secure wire frame should succeed");
  testAssertTrue(clientReadSecureMsg(tcpPair[0], testClientKey, &decoded) == 0, "clientReadSecureMsg should succeed");
  testAssertTrue(decoded.type == msg.type, "decoded type should match");
  testAssertTrue(decoded.nbytes == msg.nbytes, "decoded nbytes should match");
  testAssertTrue(memcmp(decoded.buf, msg.buf, (size_t)msg.nbytes) == 0, "decoded payload should match");

  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientServeConnFailsOnInvalidChallengeLength(void) {
  int tunPair[2];
  int tcpPair[2];
  pid_t pid;
  protocolFrame_t claimFrame;
  protocolRawMsg_t rawChallenge;
  protocolFrame_t challengeFrame;
  int status = 0;

  setupPairs(tunPair, tcpPair);
  pid = fork();
  testAssertTrue(pid >= 0, "fork should succeed");
  if (pid == 0) {
    close(tunPair[1]);
    close(tcpPair[1]);
    _exit(clientServeConn(tunPair[0], tcpPair[0], testClaim, sizeof(testClaim), testClientKey, &heartbeatCfg) == 0 ? 0 : 1);
  }

  close(tunPair[0]);
  close(tcpPair[0]);
  testAssertTrue(readWireFrame(tcpPair[1], &claimFrame) == 0, "server should receive claim wire frame");

  rawChallenge.buf = "bad";
  rawChallenge.nbytes = 3;
  testAssertTrue(protocolEncodeRaw(&rawChallenge, &challengeFrame) == protocolStatusOk, "encode raw challenge should succeed");
  testAssertTrue(writeWireFrame(tcpPair[1], &challengeFrame) == 0, "write invalid challenge should succeed");

  close(tcpPair[1]);
  close(tunPair[1]);
  testAssertTrue(waitpid(pid, &status, 0) == pid, "waitpid should succeed");
  testAssertTrue(WIFEXITED(status), "child should exit normally");
  testAssertTrue(WEXITSTATUS(status) == 1, "client should fail on invalid challenge length");
}

static void testClientServeConnHandshakeAndStopOnPeerClose(void) {
  int tunPair[2];
  int tcpPair[2];
  pid_t pid;
  protocolFrame_t claimFrame;
  protocolRawMsg_t claimMsg;
  protocolRawMsg_t rawChallenge;
  protocolFrame_t challengeFrame;
  protocolFrame_t helloFrame;
  protocolDecoder_t decoder;
  long consumed = 0;
  protocolMessage_t helloMsg;
  int status = 0;
  unsigned char challengeNonce[ProtocolNonceSize];

  memset(challengeNonce, 0x55, sizeof(challengeNonce));
  setupPairs(tunPair, tcpPair);
  pid = fork();
  testAssertTrue(pid >= 0, "fork should succeed");
  if (pid == 0) {
    close(tunPair[1]);
    close(tcpPair[1]);
    _exit(clientServeConn(tunPair[0], tcpPair[0], testClaim, sizeof(testClaim), testClientKey, &heartbeatCfg) == 0 ? 0 : 1);
  }

  close(tunPair[0]);
  close(tcpPair[0]);

  testAssertTrue(readWireFrame(tcpPair[1], &claimFrame) == 0, "server should receive claim");
  {
    protocolDecoderInit(&decoder);
    consumed = 0;
    testAssertTrue(
        protocolDecodeRaw(&decoder, claimFrame.buf, claimFrame.nbytes, &consumed, &claimMsg)
            == protocolStatusOk,
        "server should decode claim");
  }
  testAssertTrue(
      claimMsg.nbytes == (long)sizeof(testClaim) && memcmp(claimMsg.buf, testClaim, sizeof(testClaim)) == 0,
      "claim should match input");

  rawChallenge.buf = (const char *)challengeNonce;
  rawChallenge.nbytes = ProtocolNonceSize;
  testAssertTrue(protocolEncodeRaw(&rawChallenge, &challengeFrame) == protocolStatusOk, "encode challenge should succeed");
  testAssertTrue(writeWireFrame(tcpPair[1], &challengeFrame) == 0, "write challenge should succeed");

  testAssertTrue(readWireFrame(tcpPair[1], &helloFrame) == 0, "server should receive hello");
  {
    protocolDecoderInit(&decoder);
    consumed = 0;
    testAssertTrue(
        protocolDecodeSecureMsg(&decoder, testClientKey, helloFrame.buf, helloFrame.nbytes, &consumed, &helloMsg)
            == protocolStatusOk,
        "server should decode hello");
  }
  testAssertTrue(helloMsg.type == protocolMsgClientHello, "hello type should be client hello");
  testAssertTrue(helloMsg.nbytes == ProtocolNonceSize * 2, "hello payload size should include echoed and client nonce");
  testAssertTrue(memcmp(helloMsg.buf, challengeNonce, ProtocolNonceSize) == 0, "hello should echo server nonce");

  close(tcpPair[1]);
  close(tunPair[1]);
  testAssertTrue(waitpid(pid, &status, 0) == pid, "waitpid should succeed");
  testAssertTrue(WIFEXITED(status), "child should exit normally");
  testAssertTrue(WEXITSTATUS(status) == 0, "client should return success when peer closes after handshake");
}

static void testClientSessionRuntimeWiringAcceptsClientContext(void) {
  session_t *session = sessionCreate(false, &heartbeatCfg, NULL, NULL);
  client_t client = {0};

  testAssertTrue(session != NULL, "session create should succeed");
  sessionAttachClient(session, &client);
  testAssertTrue(!session->isServer, "session should remain in client mode after client wiring");

  sessionDestroy(session);
}

static void testClientQueueBackpressureBlocksAndStoresPendingPayload(void) {
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  client_t client;
  char fill[IoPollerQueueCapacity];
  char payload[128];
  sessionQueueResult_t result;

  memset(fill, 'w', sizeof(fill));
  memset(payload, 'z', sizeof(payload));
  setupPairs(tunPair, tcpPair);
  testAssertTrue(setupSplitPollers(&poller, tunPair[0], tcpPair[0]) == 0, "setup split pollers should succeed");
  memset(&client, 0, sizeof(client));
  client.tunPoller = &poller.tunPoller;
  client.tcpPoller = &poller.tcpPoller;

  testAssertTrue(
      ioTcpWrite(&poller.tcpPoller, fill, IoPollerQueueCapacity - 16),
      "prefill client tcp queue should succeed");
  result = clientQueueTcpWithBackpressure(
      &client,
      payload,
      sizeof(payload));
  testAssertTrue(result == sessionQueueResultBlocked, "client queue api should block on overflow");
  testAssertTrue(client.tunReadPaused, "client queue api should pause tun reads on overflow");
  testAssertTrue(client.runtimeOverflowNbytes > 0, "client queue api should store pending tcp payload");

  teardownSplitPollers(&poller);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientInboundHandlerAcceptsHeartbeatAckAndRefreshesTimestamp(void) {
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  client_t client;
  long long lastValidInboundMs = 17;
  protocolMessage_t ack = {.type = protocolMsgHeartbeatAck, .nbytes = 0, .buf = NULL};
  sessionQueueResult_t result;

  setupPairs(tunPair, tcpPair);
  testAssertTrue(setupSplitPollers(&poller, tunPair[0], tcpPair[0]) == 0, "setup split pollers should succeed");
  memset(&client, 0, sizeof(client));
  client.tunPoller = &poller.tunPoller;
  client.tcpPoller = &poller.tcpPoller;
  clientResetHeartbeatState(&client, heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs, 0);
  client.heartbeatAckPending = true;

  result = clientHandleInboundMessage(
      &client,
      1000,
      &lastValidInboundMs,
      &ack);
  testAssertTrue(result == sessionQueueResultQueued, "client inbound ack should route through client handler");
  testAssertTrue(lastValidInboundMs == 1000, "client handler should refresh last valid inbound timestamp");
  testAssertTrue(!client.heartbeatAckPending, "client handler should clear heartbeat pending on ack");

  teardownSplitPollers(&poller);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientHeartbeatTickSetsPendingAndTimestamps(void) {
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  client_t client;
  bool ok;

  setupPairs(tunPair, tcpPair);
  testAssertTrue(setupSplitPollers(&poller, tunPair[0], tcpPair[0]) == 0, "setup split pollers should succeed");
  memset(&client, 0, sizeof(client));
  client.tunPoller = &poller.tunPoller;
  client.tcpPoller = &poller.tcpPoller;
  clientResetHeartbeatState(&client, heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs, 0);

  ok = clientHeartbeatTick(&client, 6000, testClientKey);
  testAssertTrue(ok, "client heartbeat tick should continue");
  testAssertTrue(client.heartbeatAckPending, "client heartbeat handler should set pending when request queues");
  testAssertTrue(client.heartbeatSentMs == 6000, "client heartbeat handler should capture send timestamp");
  testAssertTrue(client.lastHeartbeatReqMs == 6000, "client heartbeat handler should capture last request timestamp");

  teardownSplitPollers(&poller);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientBackpressureServiceSucceedsWithoutPendingBytes(void) {
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  client_t client;
  session_t *session;

  setupPairs(tunPair, tcpPair);
  testAssertTrue(setupSplitPollers(&poller, tunPair[0], tcpPair[0]) == 0, "setup split pollers should succeed");
  session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  memset(&client, 0, sizeof(client));
  client.tunPoller = &poller.tunPoller;
  client.tcpPoller = &poller.tcpPoller;
  sessionAttachClient(session, &client);

  testAssertTrue(
      clientServiceBackpressure(
          &client,
          session,
          ioEventTimeout,
          testClientKey),
      "client backpressure service should succeed without pending bytes");

  sessionDestroy(session);
  teardownSplitPollers(&poller);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientBackpressureServiceSkipsRetryOnTimeoutEvent(void) {
  splitPollersFixture_t poller;
  int tunPair[2];
  int tcpPair[2];
  client_t client;
  session_t *session;
  const char tunPayload[] = "pending-tun";
  const char tcpPayload[] = "pending-tcp";

  setupPairs(tunPair, tcpPair);
  testAssertTrue(setupSplitPollers(&poller, tunPair[0], tcpPair[0]) == 0, "setup split pollers should succeed");
  session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  memset(&client, 0, sizeof(client));
  client.tunPoller = &poller.tunPoller;
  client.tcpPoller = &poller.tcpPoller;
  sessionAttachClient(session, &client);

  memcpy(session->overflowBuf, tunPayload, sizeof(tunPayload));
  session->overflowNbytes = sizeof(tunPayload);
  session->tcpReadPaused = true;
  memcpy(client.runtimeOverflowBuf, tcpPayload, sizeof(tcpPayload));
  client.runtimeOverflowNbytes = sizeof(tcpPayload);
  client.tunReadPaused = true;

  testAssertTrue(
      clientServiceBackpressure(
          &client,
          session,
          ioEventTimeout,
          testClientKey),
      "client backpressure service should continue on timeout event");
  testAssertTrue(session->overflowNbytes == (long)sizeof(tunPayload), "timeout event should not retry pending tun overflow");
  testAssertTrue(client.runtimeOverflowNbytes == (long)sizeof(tcpPayload), "timeout event should not retry pending tcp overflow");
  testAssertTrue(session->tcpReadPaused, "timeout event should keep tcp reads paused while overflow is pending");
  testAssertTrue(client.tunReadPaused, "timeout event should keep tun reads paused while overflow is pending");

  sessionDestroy(session);
  teardownSplitPollers(&poller);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientHeartbeatUsesConfiguredInterval(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  client_t client;
  int tunPair[2];
  int tcpPair[2];
  sessionHeartbeatConfig_t testCfg = {
      .intervalMs = 2000,
      .timeoutMs = 6000,
  };

  memset(key, 0x31, sizeof(key));
  setupPairs(tunPair, tcpPair);
  testAssertTrue(setupSplitPollers(&poller, tunPair[0], tcpPair[0]) == 0, "setup split pollers should succeed");
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &testCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, &poller, &client);

  fakeNowMs = 1999;
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client should continue before configured heartbeat interval");
  testAssertTrue(!client.heartbeatAckPending, "heartbeat should not be pending before configured interval");

  fakeNowMs = 2000;
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client should send heartbeat at configured interval");
  testAssertTrue(client.heartbeatAckPending, "heartbeat should be pending at configured interval");

  sessionDestroy(session);
  teardownSplitPollers(&poller);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientHeartbeatTimeoutUsesConfiguredTimeout(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  client_t client;
  int tunPair[2];
  int tcpPair[2];
  sessionHeartbeatConfig_t testCfg = {
      .intervalMs = 2000,
      .timeoutMs = 6000,
  };

  memset(key, 0x32, sizeof(key));
  setupPairs(tunPair, tcpPair);
  testAssertTrue(setupSplitPollers(&poller, tunPair[0], tcpPair[0]) == 0, "setup split pollers should succeed");
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &testCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, &poller, &client);

  fakeNowMs = 2000;
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client should send heartbeat request");
  testAssertTrue(client.heartbeatAckPending, "heartbeat request should be pending");

  fakeNowMs = 7999;
  testAssertTrue(
      runSessionStepWithSuppressedStderr(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client should continue before configured timeout");

  fakeNowMs = 8000;
  testAssertTrue(
      runSessionStepWithSuppressedStderr(session, &poller, ioEventTimeout, key) == sessionStepStop,
      "client should stop at configured timeout");

  sessionDestroy(session);
  teardownSplitPollers(&poller);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientHeartbeatRequestAndAckFlow(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  client_t client;
  int tunPair[2];
  int tcpPair[2];
  char wire[ProtocolFrameSize];
  long wireNbytes;

  memset(key, 0x22, sizeof(key));
  setupPairs(tunPair, tcpPair);
  testAssertTrue(setupSplitPollers(&poller, tunPair[0], tcpPair[0]) == 0, "setup split pollers should succeed");
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, &poller, &client);

  testAssertTrue(
      runSessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client should continue before heartbeat interval");
  testAssertTrue(!client.heartbeatAckPending, "heartbeat should not be pending before idle interval");

  fakeNowMs = 6000;
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client should stay alive when sending heartbeat request");
  testAssertTrue(client.heartbeatAckPending, "heartbeat should become pending after idle interval");

  wireNbytes = writeSecureWire(key, protocolMsgHeartbeatAck, NULL, 0, wire);
  testAssertTrue(write(tcpPair[1], wire, (size_t)wireNbytes) == wireNbytes, "tcp write should succeed");
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTcpRead, key) == sessionStepContinue,
      "client should continue after heartbeat ack");
  testAssertTrue(!client.heartbeatAckPending, "heartbeat pending should clear after ack");

  sessionDestroy(session);
  teardownSplitPollers(&poller);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientHeartbeatStillSendsWhenInboundRecentlyActive(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  client_t client;
  int tunPair[2];
  int tcpPair[2];
  char wire[ProtocolFrameSize];
  long wireNbytes;
  static const char payload[] = "recv-only";

  memset(key, 0x25, sizeof(key));
  setupPairs(tunPair, tcpPair);
  testAssertTrue(setupSplitPollers(&poller, tunPair[0], tcpPair[0]) == 0, "setup split pollers should succeed");
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, &poller, &client);

  fakeNowMs = 5500;
  wireNbytes = writeSecureWire(key, protocolMsgData, payload, (long)(sizeof(payload) - 1), wire);
  testAssertTrue(write(tcpPair[1], wire, (size_t)wireNbytes) == wireNbytes, "tcp write should succeed");
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTcpRead, key) == sessionStepContinue,
      "client should continue after receiving inbound data");
  testAssertTrue(client.lastDataRecvMs == 5500, "inbound data should refresh receive timestamp");
  testAssertTrue(client.heartbeatAckPending, "client should send heartbeat request even when inbound data is recent");

  sessionDestroy(session);
  teardownSplitPollers(&poller);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientHeartbeatPendingSetOnlyWhenReqEnqueueSucceeds(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  client_t client;
  int tunPair[2];
  int tcpPair[2];
  char fill[IoPollerQueueCapacity];

  memset(key, 0x24, sizeof(key));
  memset(fill, 'h', sizeof(fill));
  setupPairs(tunPair, tcpPair);
  testAssertTrue(setupSplitPollers(&poller, tunPair[0], tcpPair[0]) == 0, "setup split pollers should succeed");
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, &poller, &client);

  testAssertTrue(ioTcpWrite(&poller.tcpPoller, fill, IoPollerQueueCapacity), "prefill tcp queue should succeed");
  fakeNowMs = 6000;
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client heartbeat tick should continue when request enqueue is blocked");
  testAssertTrue(!client.heartbeatAckPending, "heartbeat should remain non-pending when req enqueue is blocked");
  testAssertTrue(client.heartbeatReqPending, "blocked heartbeat request should stay pending for retry");
  testAssertTrue(client.runtimeOverflowNbytes == 0, "blocked heartbeat request should not consume runtime overflow buffer");

  sessionDestroy(session);
  teardownSplitPollers(&poller);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientHeartbeatBlockedReqEventuallyTracksPendingForAck(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  client_t client;
  int tunPair[2];
  int tcpPair[2];
  char fill[IoPollerQueueCapacity];
  char wire[ProtocolFrameSize];
  long wireNbytes;

  memset(key, 0x26, sizeof(key));
  memset(fill, 'i', sizeof(fill));
  setupPairs(tunPair, tcpPair);
  testAssertTrue(setupSplitPollers(&poller, tunPair[0], tcpPair[0]) == 0, "setup split pollers should succeed");
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, &poller, &client);

  testAssertTrue(ioTcpWrite(&poller.tcpPoller, fill, IoPollerQueueCapacity), "prefill tcp queue should succeed");
  fakeNowMs = 6000;
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client heartbeat tick should continue when initial request enqueue is blocked");
  testAssertTrue(!client.heartbeatAckPending, "heartbeat should not be pending before request is queued");

  poller.tcpPoller.outOffset = 0;
  poller.tcpPoller.outNbytes = IoPollerLowWatermark;
  fakeNowMs = 6001;
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTimeout, key) == sessionStepContinue,
      "client should keep running while request stays pending on timeout tick");
  testAssertTrue(client.heartbeatReqPending, "heartbeat request should stay pending before tcp write retry");
  testAssertTrue(!client.heartbeatAckPending, "heartbeat ack wait should remain off before tcp write retry");
  testAssertTrue(
      clientServiceBackpressure(
          &client,
          session,
          ioEventTcpWrite,
          key),
      "client backpressure service should retry heartbeat request on tcp write");
  testAssertTrue(client.heartbeatAckPending, "client should track pending heartbeat after tcp write retry queues request");

  wireNbytes = writeSecureWire(key, protocolMsgHeartbeatAck, NULL, 0, wire);
  testAssertTrue(write(tcpPair[1], wire, (size_t)wireNbytes) == wireNbytes, "tcp write should succeed");
  testAssertTrue(
      runSessionStep(session, &poller, ioEventTcpRead, key) == sessionStepContinue,
      "client should accept ack for retried heartbeat request");
  testAssertTrue(!client.heartbeatAckPending, "client should clear pending heartbeat after ack");

  sessionDestroy(session);
  teardownSplitPollers(&poller);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientRejectsInboundHeartbeatRequest(void) {
  unsigned char key[ProtocolPskSize];
  splitPollersFixture_t poller;
  client_t client;
  int tunPair[2];
  int tcpPair[2];
  char wire[ProtocolFrameSize];
  long wireNbytes;

  memset(key, 0x23, sizeof(key));
  setupPairs(tunPair, tcpPair);
  testAssertTrue(setupSplitPollers(&poller, tunPair[0], tcpPair[0]) == 0, "setup split pollers should succeed");
  session_t *session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, &poller, &client);
  wireNbytes = writeSecureWire(key, protocolMsgHeartbeatReq, NULL, 0, wire);
  testAssertTrue(write(tcpPair[1], wire, (size_t)wireNbytes) == wireNbytes, "tcp write should succeed");
  testAssertTrue(
      runSessionStepWithSuppressedStderr(session, &poller, ioEventTcpRead, key) == sessionStepStop,
      "client should stop on inbound heartbeat request");

  sessionDestroy(session);
  teardownSplitPollers(&poller);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

void runClientTests(void) {
  testClientWriteRawMsgWritesValidWireFrame();
  testClientReadRawMsgSyncReadsValidWireFrame();
  testClientWriteSecureMsgWritesDecodablePayload();
  testClientReadSecureMsgSyncReadsValidWireFrame();
  testClientServeConnRejectsInvalidArgs();
  testClientServeConnFailsOnInvalidChallengeLength();
  testClientServeConnHandshakeAndStopOnPeerClose();
  testClientSessionRuntimeWiringAcceptsClientContext();
  testClientQueueBackpressureBlocksAndStoresPendingPayload();
  testClientInboundHandlerAcceptsHeartbeatAckAndRefreshesTimestamp();
  testClientHeartbeatTickSetsPendingAndTimestamps();
  testClientBackpressureServiceSucceedsWithoutPendingBytes();
  testClientBackpressureServiceSkipsRetryOnTimeoutEvent();
  testClientHeartbeatUsesConfiguredInterval();
  testClientHeartbeatTimeoutUsesConfiguredTimeout();
  testClientHeartbeatRequestAndAckFlow();
  testClientHeartbeatStillSendsWhenInboundRecentlyActive();
  testClientHeartbeatPendingSetOnlyWhenReqEnqueueSucceeds();
  testClientHeartbeatBlockedReqEventuallyTracksPendingForAck();
  testClientRejectsInboundHeartbeatRequest();
}
