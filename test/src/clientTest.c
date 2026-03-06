#include "clientTest.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

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
  client_t runtime = {0};
  sessionStats_t stats;

  testAssertTrue(session != NULL, "session create should succeed");
  sessionSetClient(session, &runtime);
  testAssertTrue(sessionGetStats(session, &stats), "sessionGetStats should succeed");
  testAssertTrue(!stats.isServer, "session should remain in client mode after runtime wiring");

  sessionDestroy(session);
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
}
