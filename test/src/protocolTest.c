#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>

#include "log.h"
#include "protocol.h"

void assertTrue(int cond, const char *msg) {
  if (!cond) {
    fprintf(stderr, "FAIL: %s\n", msg);
    exit(1);
  }
}

void testEncode() {
  const char *payload = "abc";
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncode(payload, 3, &frame);

  assertTrue(status == protocolStatusOk, "encode should succeed");
  assertTrue(frame.nbytes == 3, "encoded length should match input");
  assertTrue(memcmp(frame.buf, payload, 3) == 0, "encoded payload should match");
}

void testDecodeSplitFrame() {
  const char *payload = "hello";
  protocolFrame_t encoded;
  protocolStatus_t status = protocolEncode(payload, 5, &encoded);
  assertTrue(status == protocolStatusOk, "encode should succeed");

  protocolDecoder_t decoder;
  protocolDecoderInit(&decoder);

  const char *raw = (const char *)&encoded;
  long rawLen = (long)sizeof(encoded.nbytes) + encoded.nbytes;
  long consumed = 0;

  status = protocolDecodeFeed(&decoder, raw, 2, &consumed);
  assertTrue(status == protocolStatusNeedMore, "partial header should require more");
  assertTrue(consumed == 2, "should consume provided bytes");
  assertTrue(!protocolDecoderHasFrame(&decoder), "frame should not be ready");

  status = protocolDecodeFeed(&decoder, raw + 2, rawLen - 2, &consumed);
  assertTrue(status == protocolStatusOk, "rest of frame should decode");
  assertTrue(consumed == rawLen - 2, "should consume remaining bytes");
  assertTrue(protocolDecoderHasFrame(&decoder), "frame should be ready");

  protocolFrame_t decoded;
  status = protocolDecoderTake(&decoder, &decoded);
  assertTrue(status == protocolStatusOk, "take should succeed");
  assertTrue(decoded.nbytes == 5, "decoded length should match");
  assertTrue(memcmp(decoded.buf, payload, 5) == 0, "decoded payload should match");
}

void testDecodeRejectBadLength() {
  protocolDecoder_t decoder;
  protocolDecoderInit(&decoder);

  long badSize = ProtocolFrameSize + 1;
  long consumed = 0;
  protocolStatus_t status = protocolDecodeFeed(
      &decoder, &badSize, sizeof(badSize), &consumed);
  assertTrue(status == protocolStatusBadFrame, "invalid size should fail");
}

void testGenericLoggingAvailable() {
  const char *ts = logTimeStr();
  assertTrue(ts != NULL, "logTimeStr should return a string");
  assertTrue(ts[0] != '\0', "logTimeStr should not be empty");
  logf("generic logging smoke test");
}

void testEncryptDecryptRoundTrip() {
  unsigned char key[ProtocolPskSize];
  memset(key, 0x2a, sizeof(key));

  const char *payload = "secret-payload";
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncode(payload, (long)strlen(payload), &frame);
  assertTrue(status == protocolStatusOk, "encode should succeed");

  status = protocolFrameEncrypt(&frame, key);
  assertTrue(status == protocolStatusOk, "encrypt should succeed");
  assertTrue(frame.nbytes > (long)strlen(payload), "encrypted frame should be larger than plaintext");

  status = protocolFrameDecrypt(&frame, key);
  assertTrue(status == protocolStatusOk, "decrypt should succeed");
  assertTrue(frame.nbytes == (long)strlen(payload), "decrypted length should match");
  assertTrue(memcmp(frame.buf, payload, (size_t)frame.nbytes) == 0, "decrypted payload should match");
}

void testDecryptRejectTamper() {
  unsigned char key[ProtocolPskSize];
  memset(key, 0x7f, sizeof(key));

  const char *payload = "auth-check";
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncode(payload, (long)strlen(payload), &frame);
  assertTrue(status == protocolStatusOk, "encode should succeed");

  status = protocolFrameEncrypt(&frame, key);
  assertTrue(status == protocolStatusOk, "encrypt should succeed");

  frame.buf[frame.nbytes - 1] ^= 0x1;
  status = protocolFrameDecrypt(&frame, key);
  assertTrue(status == protocolStatusBadFrame, "tampered payload should fail authentication");
}

void testMessageDataRoundTrip() {
  const char *payload = "typed-data";
  protocolMessage_t in = {
      .type = protocolMsgData,
      .nbytes = (long)strlen(payload),
      .buf = payload,
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolMessageEncodeFrame(&in, &frame);
  assertTrue(status == protocolStatusOk, "data message encode should succeed");

  protocolMessage_t out;
  status = protocolMessageDecodeFrame(&frame, &out);
  assertTrue(status == protocolStatusOk, "data message decode should succeed");
  assertTrue(out.type == protocolMsgData, "decoded data message type should match");
  assertTrue(out.nbytes == in.nbytes, "decoded data payload length should match");
  assertTrue(memcmp(out.buf, payload, (size_t)out.nbytes) == 0, "decoded data payload should match");
}

void testMessageHeartbeatReqRoundTrip() {
  protocolMessage_t in = {
      .type = protocolMsgHeartbeatReq,
      .nbytes = 0,
      .buf = NULL,
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolMessageEncodeFrame(&in, &frame);
  assertTrue(status == protocolStatusOk, "heartbeat request encode should succeed");

  protocolMessage_t out;
  status = protocolMessageDecodeFrame(&frame, &out);
  assertTrue(status == protocolStatusOk, "heartbeat request decode should succeed");
  assertTrue(out.type == protocolMsgHeartbeatReq, "decoded heartbeat request type should match");
  assertTrue(out.nbytes == 0, "decoded heartbeat request should be empty");
}

void testMessageHeartbeatAckRoundTrip() {
  protocolMessage_t in = {
      .type = protocolMsgHeartbeatAck,
      .nbytes = 0,
      .buf = NULL,
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolMessageEncodeFrame(&in, &frame);
  assertTrue(status == protocolStatusOk, "heartbeat ack encode should succeed");

  protocolMessage_t out;
  status = protocolMessageDecodeFrame(&frame, &out);
  assertTrue(status == protocolStatusOk, "heartbeat ack decode should succeed");
  assertTrue(out.type == protocolMsgHeartbeatAck, "decoded heartbeat ack type should match");
  assertTrue(out.nbytes == 0, "decoded heartbeat ack should be empty");
}

void testMessageRejectInvalidType() {
  protocolFrame_t frame;
  frame.buf[0] = (char)0x7f;
  frame.nbytes = 1;
  protocolMessage_t out;
  protocolStatus_t status = protocolMessageDecodeFrame(&frame, &out);
  assertTrue(status == protocolStatusBadFrame, "invalid message type should fail");
}

void testMessageRejectInvalidSizeTypeCombo() {
  const char *payload = "x";
  protocolMessage_t hbReqBad = {
      .type = protocolMsgHeartbeatReq,
      .nbytes = 1,
      .buf = payload,
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolMessageEncodeFrame(&hbReqBad, &frame);
  assertTrue(status == protocolStatusBadFrame, "heartbeat request with payload should fail");

  protocolMessage_t dataBad = {
      .type = protocolMsgData,
      .nbytes = 0,
      .buf = NULL,
  };
  status = protocolMessageEncodeFrame(&dataBad, &frame);
  assertTrue(status == protocolStatusBadFrame, "data message without payload should fail");
}

int main() {
  assertTrue(sodium_init() >= 0, "sodium init should succeed");
  testEncode();
  testDecodeSplitFrame();
  testDecodeRejectBadLength();
  testGenericLoggingAvailable();
  testEncryptDecryptRoundTrip();
  testDecryptRejectTamper();
  testMessageDataRoundTrip();
  testMessageHeartbeatReqRoundTrip();
  testMessageHeartbeatAckRoundTrip();
  testMessageRejectInvalidType();
  testMessageRejectInvalidSizeTypeCombo();
  fprintf(stderr, "PASS protocol tests\n");
  return 0;
}
