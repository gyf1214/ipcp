#include "sessionTest.h"

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
  client_t client;
  runtimeEventFixture_t events;
} clientFixture_t;

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

static int clientFixtureSetup(
    clientFixture_t *fixture,
    int tunFd,
    int tcpFd,
    int heartbeatIntervalMs,
    int heartbeatTimeoutMs) {
  if (fixture == NULL) {
    return -1;
  }

  memset(&fixture->client, 0, sizeof(fixture->client));
  clientResetHeartbeatState(&fixture->client, heartbeatIntervalMs, heartbeatTimeoutMs, 0);
  if (!ioReactorInit(&fixture->client.reactor)) {
    return -1;
  }
  runtimeEventFixtureReset(&fixture->events);

  memset(&fixture->client.tunPoller, 0, sizeof(fixture->client.tunPoller));
  fixture->client.tunPoller.poller.reactor = NULL;
  fixture->client.tunPoller.poller.fd = tunFd;
  fixture->client.tunPoller.poller.events = EPOLLRDHUP;
  fixture->client.tunPoller.poller.kind = ioPollerKindTun;
  if (!ioReactorAddPoller(
          &fixture->client.reactor,
          &fixture->client.tunPoller.poller,
          &runtimeEventFixtureCallbacks,
          &fixture->events,
          true)) {
    ioReactorDispose(&fixture->client.reactor);
    return -1;
  }

  memset(&fixture->client.tcpPoller, 0, sizeof(fixture->client.tcpPoller));
  fixture->client.tcpPoller.poller.reactor = NULL;
  fixture->client.tcpPoller.poller.fd = tcpFd;
  fixture->client.tcpPoller.poller.events = EPOLLRDHUP;
  fixture->client.tcpPoller.poller.kind = ioPollerKindTcp;
  if (!ioReactorAddPoller(
          &fixture->client.reactor,
          &fixture->client.tcpPoller.poller,
          &runtimeEventFixtureCallbacks,
          &fixture->events,
          true)) {
    ioReactorDispose(&fixture->client.reactor);
    return -1;
  }

  return 0;
}

static void clientFixtureTeardown(clientFixture_t *fixture) {
  if (fixture != NULL) {
    ioReactorDispose(&fixture->client.reactor);
  }
}

static bool clientFixtureWaitEventOfKind(clientFixture_t *fixture, int timeoutMs, ioEvent_t expected) {
  if (fixture == NULL) {
    return false;
  }
  return runtimeEventFixtureWaitEventOfKind(&fixture->events, &fixture->client.reactor, timeoutMs, expected);
}

static bool clientFixtureDrainWriteQueue(clientFixture_t *fixture, ioSource_t source, int timeoutMs) {
  int attempts;
  long queued;

  if (fixture == NULL) {
    return false;
  }
  for (attempts = 0; attempts < 8; attempts++) {
    queued = source == ioSourceTcp
        ? ioTcpQueuedBytes(&fixture->client.tcpPoller)
        : ioTunQueuedBytes(&fixture->client.tunPoller);
    if (queued == 0) {
      return true;
    }
    if (queued < 0) {
      return false;
    }
    if (ioReactorStep(&fixture->client.reactor, timeoutMs) == ioReactorStepError) {
      return false;
    }
  }
  return false;
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

static sessionStepResult_t runSessionStep(session_t *session, clientFixture_t *fixture, ioEvent_t event, const unsigned char key[ProtocolPskSize]) {
  return sessionStep(session, &fixture->client.tcpPoller, &fixture->client.tunPoller, event, key);
}

static sessionStepResult_t runSessionStepWithSuppressedStderr(
    session_t *session,
    clientFixture_t *fixture,
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

  result = runSessionStep(session, fixture, event, key);

  fflush(stderr);
  testAssertTrue(dup2(savedStderr, STDERR_FILENO) >= 0, "restore stderr should succeed");
  close(savedStderr);
  return result;
}

static void wireClientSession(session_t *session, client_t *client) {
  sessionAttachClient(session, client);
}

static int setNonBlockingFd(int fd) {
  int flags;

  flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    return -1;
  }
  return 0;
}

static int clientRunLoopOnFds(
    int tunFd,
    int tcpFd,
    const unsigned char *claim,
    long claimNbytes,
    const unsigned char key[ProtocolPskSize],
    const sessionHeartbeatConfig_t *cfg) {
  client_t client;
  session_t *session = NULL;
  int result = -1;

  if (tunFd < 0 || tcpFd < 0 || claim == NULL || claimNbytes <= 0 || key == NULL || cfg == NULL) {
    return -1;
  }
  if (setNonBlockingFd(tunFd) != 0 || setNonBlockingFd(tcpFd) != 0) {
    return -1;
  }

  memset(&client, 0, sizeof(client));
  clientResetHeartbeatState(&client, cfg->intervalMs, cfg->timeoutMs, 0);
  session = sessionCreate(false, cfg, NULL, NULL);
  if (session == NULL) {
    return -1;
  }

  sessionAttachClient(session, &client);
  client.claim = claim;
  client.claimNbytes = claimNbytes;
  client.key = key;
  client.session = session;

  if (!ioReactorInit(&client.reactor)) {
    goto cleanup;
  }

  client.tunPoller.poller.fd = tunFd;
  client.tunPoller.poller.kind = ioPollerKindTun;
  client.tunPoller.poller.events = EPOLLIN | EPOLLRDHUP;
  client.tunPoller.poller.readEnabled = true;

  client.tcpPoller.poller.fd = tcpFd;
  client.tcpPoller.poller.kind = ioPollerKindTcp;
  client.tcpPoller.poller.events = EPOLLIN | EPOLLRDHUP;
  client.tcpPoller.poller.readEnabled = true;

  if (!clientRegisterRuntimePollers(&client)) {
    goto cleanup;
  }

  result = clientRunLoop(&client);

cleanup:
  ioReactorDispose(&client.reactor);
  sessionDestroy(session);
  return result;
}

static void testClientRunLoopRejectsInvalidArgs(void) {
  testAssertTrue(
      clientRunLoopOnFds(-1, -1, NULL, 0, NULL, &heartbeatCfg) != 0,
      "client loop harness should reject invalid args");
}

static void testSessionRunClientRejectsInvalidConfig(void) {
  sessionClientConfig_t cfg = {
      .ifName = "tun0",
      .ifMode = ioIfModeTun,
      .remoteIP = "127.0.0.1",
      .port = 4455,
      .claim = testClaim,
      .claimNbytes = (long)sizeof(testClaim),
      .key = testClientKey,
      .heartbeat = heartbeatCfg,
  };
  testAssertTrue(sessionRunClient(NULL) != 0, "sessionRunClient should reject null config");

  cfg.ifName = NULL;
  testAssertTrue(sessionRunClient(&cfg) != 0, "sessionRunClient should reject null interface name");
  cfg.ifName = "tun0";
  cfg.ifMode = (ioIfMode_t)99;
  testAssertTrue(sessionRunClient(&cfg) != 0, "sessionRunClient should reject invalid interface mode");
  cfg.ifMode = ioIfModeTun;
  cfg.remoteIP = NULL;
  testAssertTrue(sessionRunClient(&cfg) != 0, "sessionRunClient should reject null remote ip");
  cfg.remoteIP = "127.0.0.1";
  cfg.port = 0;
  testAssertTrue(sessionRunClient(&cfg) != 0, "sessionRunClient should reject invalid remote port");
  cfg.port = 4455;
  cfg.claim = NULL;
  testAssertTrue(sessionRunClient(&cfg) != 0, "sessionRunClient should reject null claim");
  cfg.claim = testClaim;
  cfg.claimNbytes = 0;
  testAssertTrue(sessionRunClient(&cfg) != 0, "sessionRunClient should reject non-positive claim length");
  cfg.claimNbytes = (long)sizeof(testClaim);
  cfg.key = NULL;
  testAssertTrue(sessionRunClient(&cfg) != 0, "sessionRunClient should reject null key");
  cfg.key = testClientKey;
  cfg.heartbeat.intervalMs = 0;
  testAssertTrue(sessionRunClient(&cfg) != 0, "sessionRunClient should reject non-positive heartbeat interval");
  cfg.heartbeat.intervalMs = heartbeatCfg.intervalMs;
  cfg.heartbeat.timeoutMs = heartbeatCfg.intervalMs;
  testAssertTrue(sessionRunClient(&cfg) != 0, "sessionRunClient should reject heartbeat timeout <= interval");
}

static void testClientRunLoopFailsOnInvalidChallengeLength(void) {
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
    _exit(clientRunLoopOnFds(tunPair[0], tcpPair[0], testClaim, sizeof(testClaim), testClientKey, &heartbeatCfg) == 0 ? 0 : 1);
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

static void testClientRunLoopHandshakeAndStopOnPeerClose(void) {
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
    _exit(clientRunLoopOnFds(tunPair[0], tcpPair[0], testClaim, sizeof(testClaim), testClientKey, &heartbeatCfg) == 0 ? 0 : 1);
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

static void testClientResetHeartbeatStateInitializesRuntimeScaffold(void) {
  clientFixture_t fixture;
  int tunPair[2];
  int tcpPair[2];
  client_t *client = NULL;

  setupPairs(tunPair, tcpPair);
  testAssertTrue(clientFixtureSetup(&fixture, tunPair[0], tcpPair[0], heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs) == 0, "setup split pollers should succeed");
  client = &fixture.client;
  client->preAuthState = clientPreAuthFailed;
  client->runFailed = true;

  clientResetHeartbeatState(client, heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs, 11);
  testAssertTrue(client->preAuthState == clientPreAuthSendClaim, "client runtime state should reset to send-claim");
  testAssertTrue(!client->runFailed, "client runtime reset should clear run-failed flag");
  testAssertTrue(client->reactor.epollFd >= 0, "client runtime reset should preserve embedded reactor registration");

  clientFixtureTeardown(&fixture);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientQueueBackpressureBlocksAndStoresPendingPayload(void) {
  clientFixture_t fixture;
  int tunPair[2];
  int tcpPair[2];
  client_t *client = NULL;
  char fill[IoPollerQueueCapacity];
  char payload[128];
  sessionQueueResult_t result;

  memset(fill, 'w', sizeof(fill));
  memset(payload, 'z', sizeof(payload));
  setupPairs(tunPair, tcpPair);
  testAssertTrue(clientFixtureSetup(&fixture, tunPair[0], tcpPair[0], heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs) == 0, "setup split pollers should succeed");
  client = &fixture.client;

  testAssertTrue(
      ioTcpWrite(&client->tcpPoller, fill, IoPollerQueueCapacity - 16),
      "prefill client tcp queue should succeed");
  result = clientQueueTcpWithBackpressure(
      client,
      payload,
      sizeof(payload));
  testAssertTrue(result == sessionQueueResultBlocked, "client queue api should block on overflow");
  testAssertTrue(client->tunReadPaused, "client queue api should pause tun reads on overflow");
  testAssertTrue(client->runtimeOverflowNbytes > 0, "client queue api should store pending tcp payload");

  clientFixtureTeardown(&fixture);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientInboundHandlerAcceptsHeartbeatAckAndRefreshesTimestamp(void) {
  clientFixture_t fixture;
  int tunPair[2];
  int tcpPair[2];
  client_t *client = NULL;
  long long lastValidInboundMs = 17;
  protocolMessage_t ack = {.type = protocolMsgHeartbeatAck, .nbytes = 0, .buf = NULL};
  sessionQueueResult_t result;

  setupPairs(tunPair, tcpPair);
  testAssertTrue(clientFixtureSetup(&fixture, tunPair[0], tcpPair[0], heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs) == 0, "setup split pollers should succeed");
  client = &fixture.client;
  clientResetHeartbeatState(client, heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs, 0);
  client->heartbeatAckPending = true;

  result = clientHandleInboundMessage(
      client,
      1000,
      &lastValidInboundMs,
      &ack);
  testAssertTrue(result == sessionQueueResultQueued, "client inbound ack should route through client handler");
  testAssertTrue(lastValidInboundMs == 1000, "client handler should refresh last valid inbound timestamp");
  testAssertTrue(!client->heartbeatAckPending, "client handler should clear heartbeat pending on ack");

  clientFixtureTeardown(&fixture);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientHeartbeatTickSetsPendingAndTimestamps(void) {
  clientFixture_t fixture;
  int tunPair[2];
  int tcpPair[2];
  client_t *client = NULL;
  bool ok;

  setupPairs(tunPair, tcpPair);
  testAssertTrue(clientFixtureSetup(&fixture, tunPair[0], tcpPair[0], heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs) == 0, "setup split pollers should succeed");
  client = &fixture.client;

  ok = clientHeartbeatTick(client, 6000, testClientKey);
  testAssertTrue(ok, "client heartbeat tick should continue");
  testAssertTrue(client->heartbeatAckPending, "client heartbeat handler should set pending when request queues");
  testAssertTrue(client->heartbeatSentMs == 6000, "client heartbeat handler should capture send timestamp");
  testAssertTrue(client->lastHeartbeatReqMs == 6000, "client heartbeat handler should capture last request timestamp");

  clientFixtureTeardown(&fixture);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientBackpressureServiceSucceedsWithoutPendingBytes(void) {
  clientFixture_t fixture;
  int tunPair[2];
  int tcpPair[2];
  client_t *client = NULL;
  session_t *session;

  setupPairs(tunPair, tcpPair);
  testAssertTrue(clientFixtureSetup(&fixture, tunPair[0], tcpPair[0], heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs) == 0, "setup split pollers should succeed");
  session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  client = &fixture.client;
  sessionAttachClient(session, client);

  testAssertTrue(
      clientServiceBackpressure(
          client,
          session,
          ioEventTimeout,
          testClientKey),
      "client backpressure service should succeed without pending bytes");

  sessionDestroy(session);
  clientFixtureTeardown(&fixture);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientBackpressureServiceSkipsRetryOnTimeoutEvent(void) {
  clientFixture_t fixture;
  int tunPair[2];
  int tcpPair[2];
  client_t *client = NULL;
  session_t *session;
  const char tunPayload[] = "pending-tun";
  const char tcpPayload[] = "pending-tcp";

  setupPairs(tunPair, tcpPair);
  testAssertTrue(clientFixtureSetup(&fixture, tunPair[0], tcpPair[0], heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs) == 0, "setup split pollers should succeed");
  session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  client = &fixture.client;
  sessionAttachClient(session, client);

  memcpy(session->overflowBuf, tunPayload, sizeof(tunPayload));
  session->overflowNbytes = sizeof(tunPayload);
  session->tcpReadPaused = true;
  memcpy(client->runtimeOverflowBuf, tcpPayload, sizeof(tcpPayload));
  client->runtimeOverflowNbytes = sizeof(tcpPayload);
  client->tunReadPaused = true;

  testAssertTrue(
      clientServiceBackpressure(
          client,
          session,
          ioEventTimeout,
          testClientKey),
      "client backpressure service should continue on timeout event");
  testAssertTrue(session->overflowNbytes == (long)sizeof(tunPayload), "timeout event should not retry pending tun overflow");
  testAssertTrue(client->runtimeOverflowNbytes == (long)sizeof(tcpPayload), "timeout event should not retry pending tcp overflow");
  testAssertTrue(session->tcpReadPaused, "timeout event should keep tcp reads paused while overflow is pending");
  testAssertTrue(client->tunReadPaused, "timeout event should keep tun reads paused while overflow is pending");

  sessionDestroy(session);
  clientFixtureTeardown(&fixture);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientHeartbeatUsesConfiguredInterval(void) {
  unsigned char key[ProtocolPskSize];
  clientFixture_t fixture;
  client_t *client = &fixture.client;
  int tunPair[2];
  int tcpPair[2];
  sessionHeartbeatConfig_t testCfg = {
      .intervalMs = 2000,
      .timeoutMs = 6000,
  };

  memset(key, 0x31, sizeof(key));
  setupPairs(tunPair, tcpPair);
  testAssertTrue(clientFixtureSetup(&fixture, tunPair[0], tcpPair[0], heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs) == 0, "setup split pollers should succeed");
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &testCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, client);

  fakeNowMs = 1999;
  testAssertTrue(
      runSessionStep(session, &fixture, ioEventTimeout, key) == sessionStepContinue,
      "client should continue before configured heartbeat interval");
  testAssertTrue(!client->heartbeatAckPending, "heartbeat should not be pending before configured interval");

  fakeNowMs = 2000;
  testAssertTrue(
      runSessionStep(session, &fixture, ioEventTimeout, key) == sessionStepContinue,
      "client should send heartbeat at configured interval");
  testAssertTrue(client->heartbeatAckPending, "heartbeat should be pending at configured interval");

  sessionDestroy(session);
  clientFixtureTeardown(&fixture);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientHeartbeatTimeoutUsesConfiguredTimeout(void) {
  unsigned char key[ProtocolPskSize];
  clientFixture_t fixture;
  client_t *client = &fixture.client;
  int tunPair[2];
  int tcpPair[2];
  sessionHeartbeatConfig_t testCfg = {
      .intervalMs = 2000,
      .timeoutMs = 6000,
  };

  memset(key, 0x32, sizeof(key));
  setupPairs(tunPair, tcpPair);
  testAssertTrue(clientFixtureSetup(&fixture, tunPair[0], tcpPair[0], heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs) == 0, "setup split pollers should succeed");
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &testCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, client);

  fakeNowMs = 2000;
  testAssertTrue(
      runSessionStep(session, &fixture, ioEventTimeout, key) == sessionStepContinue,
      "client should send heartbeat request");
  testAssertTrue(client->heartbeatAckPending, "heartbeat request should be pending");

  fakeNowMs = 7999;
  testAssertTrue(
      runSessionStepWithSuppressedStderr(session, &fixture, ioEventTimeout, key) == sessionStepContinue,
      "client should continue before configured timeout");

  fakeNowMs = 8000;
  testAssertTrue(
      runSessionStepWithSuppressedStderr(session, &fixture, ioEventTimeout, key) == sessionStepStop,
      "client should stop at configured timeout");

  sessionDestroy(session);
  clientFixtureTeardown(&fixture);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientHeartbeatRequestAndAckFlow(void) {
  unsigned char key[ProtocolPskSize];
  clientFixture_t fixture;
  client_t *client = &fixture.client;
  int tunPair[2];
  int tcpPair[2];
  char wire[ProtocolFrameSize];
  long wireNbytes;
  ioEvent_t event;

  memset(key, 0x22, sizeof(key));
  setupPairs(tunPair, tcpPair);
  testAssertTrue(clientFixtureSetup(&fixture, tunPair[0], tcpPair[0], heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs) == 0, "setup split pollers should succeed");
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, client);

  testAssertTrue(
      runSessionStep(session, &fixture, ioEventTimeout, key) == sessionStepContinue,
      "client should continue before heartbeat interval");
  testAssertTrue(!client->heartbeatAckPending, "heartbeat should not be pending before idle interval");

  fakeNowMs = 6000;
  testAssertTrue(
      runSessionStep(session, &fixture, ioEventTimeout, key) == sessionStepContinue,
      "client should stay alive when sending heartbeat request");
  testAssertTrue(client->heartbeatAckPending, "heartbeat should become pending after idle interval");

  wireNbytes = writeSecureWire(key, protocolMsgHeartbeatAck, NULL, 0, wire);
  testAssertTrue(write(tcpPair[1], wire, (size_t)wireNbytes) == wireNbytes, "tcp write should succeed");
  testAssertTrue(clientFixtureWaitEventOfKind(&fixture, 100, ioEventTcpRead), "reactor callback should capture tcp readable event");
  event = ioEventTcpRead;
  testAssertTrue(
      runSessionStep(session, &fixture, event, key) == sessionStepContinue,
      "client should continue after heartbeat ack");
  testAssertTrue(!client->heartbeatAckPending, "heartbeat pending should clear after ack");

  sessionDestroy(session);
  clientFixtureTeardown(&fixture);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientTunReadQueuesEncryptedTcpFrame(void) {
  unsigned char key[ProtocolPskSize];
  clientFixture_t fixture;
  client_t *client = &fixture.client;
  int tunPair[2];
  int tcpPair[2];
  char out[ProtocolFrameSize];
  long nbytes;
  protocolDecoder_t decoder;
  protocolMessage_t msg;
  long consumed = 0;
  const char payload[] = "tun-payload";
  ioEvent_t event;

  memset(key, 0x44, sizeof(key));
  setupPairs(tunPair, tcpPair);
  testAssertTrue(clientFixtureSetup(&fixture, tunPair[0], tcpPair[0], heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs) == 0, "setup split pollers should succeed");
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, client);

  testAssertTrue(
      write(tunPair[1], payload, strlen(payload)) == (ssize_t)strlen(payload),
      "tun write should succeed");
  testAssertTrue(clientFixtureWaitEventOfKind(&fixture, 100, ioEventTunRead), "reactor callback should capture tun readable event");
  event = ioEventTunRead;
  testAssertTrue(
      runSessionStep(session, &fixture, event, key) == sessionStepContinue,
      "tun read event should continue");
  testAssertTrue(clientFixtureDrainWriteQueue(&fixture, ioSourceTcp, 50), "reactor should flush queued tcp payload");

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
  clientFixtureTeardown(&fixture);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientTcpReadQueuesTunWrite(void) {
  unsigned char key[ProtocolPskSize];
  clientFixture_t fixture;
  client_t *client = &fixture.client;
  int tunPair[2];
  int tcpPair[2];
  char wire[ProtocolFrameSize];
  long wireNbytes;
  char out[128];
  const char payload[] = "tcp-payload";
  ioEvent_t event;

  memset(key, 0x45, sizeof(key));
  setupPairs(tunPair, tcpPair);
  testAssertTrue(clientFixtureSetup(&fixture, tunPair[0], tcpPair[0], heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs) == 0, "setup split pollers should succeed");
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, client);

  wireNbytes = writeSecureWire(key, protocolMsgData, payload, (long)strlen(payload), wire);
  testAssertTrue(write(tcpPair[1], wire, (size_t)wireNbytes) == wireNbytes, "tcp write should succeed");
  testAssertTrue(clientFixtureWaitEventOfKind(&fixture, 100, ioEventTcpRead), "reactor callback should capture tcp readable event");
  event = ioEventTcpRead;
  testAssertTrue(
      runSessionStep(session, &fixture, event, key) == sessionStepContinue,
      "tcp read event should continue");
  testAssertTrue(clientFixtureDrainWriteQueue(&fixture, ioSourceTun, 50), "reactor should flush queued tun payload");

  testAssertTrue(
      recv(tunPair[1], out, sizeof(out), MSG_DONTWAIT) == (ssize_t)strlen(payload),
      "tun peer should receive payload");
  testAssertTrue(memcmp(out, payload, strlen(payload)) == 0, "tun payload should match");

  sessionDestroy(session);
  clientFixtureTeardown(&fixture);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientHeartbeatStillSendsWhenInboundRecentlyActive(void) {
  unsigned char key[ProtocolPskSize];
  clientFixture_t fixture;
  client_t *client = &fixture.client;
  int tunPair[2];
  int tcpPair[2];
  char wire[ProtocolFrameSize];
  long wireNbytes;
  static const char payload[] = "recv-only";
  ioEvent_t event;

  memset(key, 0x25, sizeof(key));
  setupPairs(tunPair, tcpPair);
  testAssertTrue(clientFixtureSetup(&fixture, tunPair[0], tcpPair[0], heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs) == 0, "setup split pollers should succeed");
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, client);

  fakeNowMs = 5500;
  wireNbytes = writeSecureWire(key, protocolMsgData, payload, (long)(sizeof(payload) - 1), wire);
  testAssertTrue(write(tcpPair[1], wire, (size_t)wireNbytes) == wireNbytes, "tcp write should succeed");
  testAssertTrue(clientFixtureWaitEventOfKind(&fixture, 100, ioEventTcpRead), "reactor callback should capture tcp readable event");
  event = ioEventTcpRead;
  testAssertTrue(
      runSessionStep(session, &fixture, event, key) == sessionStepContinue,
      "client should continue after receiving inbound data");
  testAssertTrue(client->lastDataRecvMs == 5500, "inbound data should refresh receive timestamp");
  testAssertTrue(client->heartbeatAckPending, "client should send heartbeat request even when inbound data is recent");

  sessionDestroy(session);
  clientFixtureTeardown(&fixture);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientHeartbeatPendingSetOnlyWhenReqEnqueueSucceeds(void) {
  unsigned char key[ProtocolPskSize];
  clientFixture_t fixture;
  client_t *client = &fixture.client;
  int tunPair[2];
  int tcpPair[2];
  char fill[IoPollerQueueCapacity];

  memset(key, 0x24, sizeof(key));
  memset(fill, 'h', sizeof(fill));
  setupPairs(tunPair, tcpPair);
  testAssertTrue(clientFixtureSetup(&fixture, tunPair[0], tcpPair[0], heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs) == 0, "setup split pollers should succeed");
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, client);

  testAssertTrue(ioTcpWrite(&fixture.client.tcpPoller, fill, IoPollerQueueCapacity), "prefill tcp queue should succeed");
  fakeNowMs = 6000;
  testAssertTrue(
      runSessionStep(session, &fixture, ioEventTimeout, key) == sessionStepContinue,
      "client heartbeat tick should continue when request enqueue is blocked");
  testAssertTrue(!client->heartbeatAckPending, "heartbeat should remain non-pending when req enqueue is blocked");
  testAssertTrue(client->heartbeatReqPending, "blocked heartbeat request should stay pending for retry");
  testAssertTrue(client->runtimeOverflowNbytes == 0, "blocked heartbeat request should not consume runtime overflow buffer");

  sessionDestroy(session);
  clientFixtureTeardown(&fixture);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientHeartbeatBlockedReqEventuallyTracksPendingForAck(void) {
  unsigned char key[ProtocolPskSize];
  clientFixture_t fixture;
  client_t *client = &fixture.client;
  int tunPair[2];
  int tcpPair[2];
  char fill[IoPollerQueueCapacity];
  char wire[ProtocolFrameSize];
  long wireNbytes;
  ioEvent_t event;

  memset(key, 0x26, sizeof(key));
  memset(fill, 'i', sizeof(fill));
  setupPairs(tunPair, tcpPair);
  testAssertTrue(clientFixtureSetup(&fixture, tunPair[0], tcpPair[0], heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs) == 0, "setup split pollers should succeed");
  fakeNowMs = 0;
  session_t *session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, client);

  testAssertTrue(ioTcpWrite(&fixture.client.tcpPoller, fill, IoPollerQueueCapacity), "prefill tcp queue should succeed");
  fakeNowMs = 6000;
  testAssertTrue(
      runSessionStep(session, &fixture, ioEventTimeout, key) == sessionStepContinue,
      "client heartbeat tick should continue when initial request enqueue is blocked");
  testAssertTrue(!client->heartbeatAckPending, "heartbeat should not be pending before request is queued");

  fixture.client.tcpPoller.outOffset = 0;
  fixture.client.tcpPoller.outNbytes = IoPollerLowWatermark;
  fakeNowMs = 6001;
  testAssertTrue(
      runSessionStep(session, &fixture, ioEventTimeout, key) == sessionStepContinue,
      "client should keep running while request stays pending on timeout tick");
  testAssertTrue(client->heartbeatReqPending, "heartbeat request should stay pending before tcp write retry");
  testAssertTrue(!client->heartbeatAckPending, "heartbeat ack wait should remain off before tcp write retry");
  testAssertTrue(
      clientServiceBackpressure(
          client,
          session,
          ioEventTimeout,
          key),
      "client backpressure service should retry heartbeat request on timeout when queue is available");
  testAssertTrue(client->heartbeatAckPending, "client should track pending heartbeat after timeout retry queues request");

  wireNbytes = writeSecureWire(key, protocolMsgHeartbeatAck, NULL, 0, wire);
  testAssertTrue(write(tcpPair[1], wire, (size_t)wireNbytes) == wireNbytes, "tcp write should succeed");
  testAssertTrue(clientFixtureWaitEventOfKind(&fixture, 100, ioEventTcpRead), "reactor callback should capture tcp readable event");
  event = ioEventTcpRead;
  testAssertTrue(
      runSessionStep(session, &fixture, event, key) == sessionStepContinue,
      "client should accept ack for retried heartbeat request");
  testAssertTrue(!client->heartbeatAckPending, "client should clear pending heartbeat after ack");

  sessionDestroy(session);
  clientFixtureTeardown(&fixture);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testClientRejectsInboundHeartbeatRequest(void) {
  unsigned char key[ProtocolPskSize];
  clientFixture_t fixture;
  client_t *client = &fixture.client;
  int tunPair[2];
  int tcpPair[2];
  char wire[ProtocolFrameSize];
  long wireNbytes;
  ioEvent_t event;

  memset(key, 0x23, sizeof(key));
  setupPairs(tunPair, tcpPair);
  testAssertTrue(clientFixtureSetup(&fixture, tunPair[0], tcpPair[0], heartbeatCfg.intervalMs, heartbeatCfg.timeoutMs) == 0, "setup split pollers should succeed");
  session_t *session = sessionCreate(false, &heartbeatCfg, fakeNow, NULL);
  testAssertTrue(session != NULL, "session create should succeed");
  wireClientSession(session, client);
  wireNbytes = writeSecureWire(key, protocolMsgHeartbeatReq, NULL, 0, wire);
  testAssertTrue(write(tcpPair[1], wire, (size_t)wireNbytes) == wireNbytes, "tcp write should succeed");
  testAssertTrue(clientFixtureWaitEventOfKind(&fixture, 100, ioEventTcpRead), "reactor callback should capture tcp readable event");
  event = ioEventTcpRead;
  testAssertTrue(
      runSessionStepWithSuppressedStderr(session, &fixture, event, key) == sessionStepStop,
      "client should stop on inbound heartbeat request");

  sessionDestroy(session);
  clientFixtureTeardown(&fixture);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

void runClientTests(void) {
  testClientRunLoopRejectsInvalidArgs();
  testSessionRunClientRejectsInvalidConfig();
  testClientRunLoopFailsOnInvalidChallengeLength();
  testClientRunLoopHandshakeAndStopOnPeerClose();
  testClientSessionRuntimeWiringAcceptsClientContext();
  testClientResetHeartbeatStateInitializesRuntimeScaffold();
  testClientQueueBackpressureBlocksAndStoresPendingPayload();
  testClientInboundHandlerAcceptsHeartbeatAckAndRefreshesTimestamp();
  testClientHeartbeatTickSetsPendingAndTimestamps();
  testClientBackpressureServiceSucceedsWithoutPendingBytes();
  testClientBackpressureServiceSkipsRetryOnTimeoutEvent();
  testClientHeartbeatUsesConfiguredInterval();
  testClientHeartbeatTimeoutUsesConfiguredTimeout();
  testClientHeartbeatRequestAndAckFlow();
  testClientTunReadQueuesEncryptedTcpFrame();
  testClientTcpReadQueuesTunWrite();
  testClientHeartbeatStillSendsWhenInboundRecentlyActive();
  testClientHeartbeatPendingSetOnlyWhenReqEnqueueSucceeds();
  testClientHeartbeatBlockedReqEventuallyTracksPendingForAck();
  testClientRejectsInboundHeartbeatRequest();
}
