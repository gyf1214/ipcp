#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>

#include "log.h"
#include "protocol.h"
#include "ioTest.h"

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

void testEncodeRejectNullPayloadWithPositiveLength() {
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncode(NULL, 1, &frame);
  assertTrue(status == protocolStatusBadFrame, "encode should reject NULL payload with positive length");
}

void testDecodeSplitFrame() {
  const char *payload = "hello";
  protocolDecoder_t decoder;
  protocolDecoderInit(&decoder);

  const unsigned char raw[] = {
      0x00, 0x00, 0x00, 0x05,
      'h', 'e', 'l', 'l', 'o',
  };
  long rawLen = (long)sizeof(raw);
  long consumed = 0;
  protocolStatus_t status;

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

  const unsigned char badSize[] = {
      0x00, 0x00, 0x10, 0x01,
  };
  long consumed = 0;
  protocolStatus_t status = protocolDecodeFeed(
      &decoder, &badSize, sizeof(badSize), &consumed);
  assertTrue(status == protocolStatusBadFrame, "invalid size should fail");
}

void testDecodeUsesFixedBigEndianLengthHeader() {
  protocolDecoder_t decoder;
  protocolDecoderInit(&decoder);

  const unsigned char raw[] = {
      0x00, 0x00, 0x00, 0x03,
      'a', 'b', 'c',
  };
  long consumed = 0;
  protocolStatus_t status = protocolDecodeFeed(&decoder, raw, (long)sizeof(raw), &consumed);
  assertTrue(status == protocolStatusOk, "decoder should accept fixed 32-bit length header");
  assertTrue(consumed == (long)sizeof(raw), "decoder should consume full frame bytes");
  assertTrue(protocolDecoderHasFrame(&decoder), "decoder should expose a frame");

  protocolFrame_t frame;
  status = protocolDecoderTake(&decoder, &frame);
  assertTrue(status == protocolStatusOk, "taking decoded frame should succeed");
  assertTrue(frame.nbytes == 3, "decoded frame length should match header");
  assertTrue(memcmp(frame.buf, "abc", 3) == 0, "decoded frame payload should match");
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

void testMessageEncodeUsesFixedBigEndianLengthHeader() {
  const char *payload = "abc";
  protocolMessage_t msg = {
      .type = protocolMsgData,
      .nbytes = 3,
      .buf = payload,
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolMessageEncodeFrame(&msg, &frame);
  assertTrue(status == protocolStatusOk, "message encode should succeed");
  assertTrue(frame.nbytes == 8, "message wire size should be type + 32-bit length + payload");
  assertTrue((unsigned char)frame.buf[0] == (unsigned char)protocolMsgData, "encoded type should match");
  assertTrue((unsigned char)frame.buf[1] == 0x00, "length byte 0 should be big-endian");
  assertTrue((unsigned char)frame.buf[2] == 0x00, "length byte 1 should be big-endian");
  assertTrue((unsigned char)frame.buf[3] == 0x00, "length byte 2 should be big-endian");
  assertTrue((unsigned char)frame.buf[4] == 0x03, "length byte 3 should be big-endian");
  assertTrue(memcmp(frame.buf + 5, payload, 3) == 0, "encoded payload should match");
}

void testMessageDecodeUsesFixedBigEndianLengthHeader() {
  protocolFrame_t frame = {
      .nbytes = 8,
      .buf = {
          (char)protocolMsgData,
          0x00, 0x00, 0x00, 0x03,
          'x', 'y', 'z',
      },
  };
  protocolMessage_t msg;
  protocolStatus_t status = protocolMessageDecodeFrame(&frame, &msg);
  assertTrue(status == protocolStatusOk, "message decode should parse fixed big-endian length");
  assertTrue(msg.type == protocolMsgData, "decoded type should match");
  assertTrue(msg.nbytes == 3, "decoded payload length should match");
  assertTrue(memcmp(msg.buf, "xyz", 3) == 0, "decoded payload should match");
}

int main() {
  assertTrue(sodium_init() >= 0, "sodium init should succeed");
  testEncode();
  testEncodeRejectNullPayloadWithPositiveLength();
  testDecodeSplitFrame();
  testDecodeRejectBadLength();
  testDecodeUsesFixedBigEndianLengthHeader();
  testGenericLoggingAvailable();
  testEncryptDecryptRoundTrip();
  testDecryptRejectTamper();
  testMessageDataRoundTrip();
  testMessageHeartbeatReqRoundTrip();
  testMessageHeartbeatAckRoundTrip();
  testMessageRejectInvalidType();
  testMessageRejectInvalidSizeTypeCombo();
  testMessageEncodeUsesFixedBigEndianLengthHeader();
  testMessageDecodeUsesFixedBigEndianLengthHeader();
  runIoTests();
  fprintf(stderr, "PASS protocol tests\n");
  return 0;
}
