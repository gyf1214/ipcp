#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>

#include "log.h"
#include "protocol.h"
#include "testAssert.h"

void testEncode() {
  const char *payload = "abc";
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncode(payload, 3, &frame);

  testAssertTrue(status == protocolStatusOk, "encode should succeed");
  testAssertTrue(frame.nbytes == 3, "encoded length should match input");
  testAssertTrue(memcmp(frame.buf, payload, 3) == 0, "encoded payload should match");
}

void testEncodeRejectNullPayloadWithPositiveLength() {
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncode(NULL, 1, &frame);
  testAssertTrue(status == protocolStatusBadFrame, "encode should reject NULL payload with positive length");
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
  testAssertTrue(status == protocolStatusNeedMore, "partial header should require more");
  testAssertTrue(consumed == 2, "should consume provided bytes");
  testAssertTrue(!protocolDecoderHasFrame(&decoder), "frame should not be ready");

  status = protocolDecodeFeed(&decoder, raw + 2, rawLen - 2, &consumed);
  testAssertTrue(status == protocolStatusOk, "rest of frame should decode");
  testAssertTrue(consumed == rawLen - 2, "should consume remaining bytes");
  testAssertTrue(protocolDecoderHasFrame(&decoder), "frame should be ready");

  protocolFrame_t decoded;
  status = protocolDecoderTake(&decoder, &decoded);
  testAssertTrue(status == protocolStatusOk, "take should succeed");
  testAssertTrue(decoded.nbytes == 5, "decoded length should match");
  testAssertTrue(memcmp(decoded.buf, payload, 5) == 0, "decoded payload should match");
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
  testAssertTrue(status == protocolStatusBadFrame, "invalid size should fail");
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
  testAssertTrue(status == protocolStatusOk, "decoder should accept fixed 32-bit length header");
  testAssertTrue(consumed == (long)sizeof(raw), "decoder should consume full frame bytes");
  testAssertTrue(protocolDecoderHasFrame(&decoder), "decoder should expose a frame");

  protocolFrame_t frame;
  status = protocolDecoderTake(&decoder, &frame);
  testAssertTrue(status == protocolStatusOk, "taking decoded frame should succeed");
  testAssertTrue(frame.nbytes == 3, "decoded frame length should match header");
  testAssertTrue(memcmp(frame.buf, "abc", 3) == 0, "decoded frame payload should match");
}

void testGenericLoggingAvailable() {
  const char *ts = logTimeStr();
  testAssertTrue(ts != NULL, "logTimeStr should return a string");
  testAssertTrue(ts[0] != '\0', "logTimeStr should not be empty");
  logf("generic logging smoke test");
}

void testEncryptDecryptRoundTrip() {
  unsigned char key[ProtocolPskSize];
  memset(key, 0x2a, sizeof(key));

  const char *payload = "secret-payload";
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncode(payload, (long)strlen(payload), &frame);
  testAssertTrue(status == protocolStatusOk, "encode should succeed");

  status = protocolFrameEncrypt(&frame, key);
  testAssertTrue(status == protocolStatusOk, "encrypt should succeed");
  testAssertTrue(frame.nbytes > (long)strlen(payload), "encrypted frame should be larger than plaintext");

  status = protocolFrameDecrypt(&frame, key);
  testAssertTrue(status == protocolStatusOk, "decrypt should succeed");
  testAssertTrue(frame.nbytes == (long)strlen(payload), "decrypted length should match");
  testAssertTrue(memcmp(frame.buf, payload, (size_t)frame.nbytes) == 0, "decrypted payload should match");
}

void testDecryptRejectTamper() {
  unsigned char key[ProtocolPskSize];
  memset(key, 0x7f, sizeof(key));

  const char *payload = "auth-check";
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncode(payload, (long)strlen(payload), &frame);
  testAssertTrue(status == protocolStatusOk, "encode should succeed");

  status = protocolFrameEncrypt(&frame, key);
  testAssertTrue(status == protocolStatusOk, "encrypt should succeed");

  frame.buf[frame.nbytes - 1] ^= 0x1;
  status = protocolFrameDecrypt(&frame, key);
  testAssertTrue(status == protocolStatusBadFrame, "tampered payload should fail authentication");
}

void testSecureMessageRoundTrip() {
  unsigned char key[ProtocolPskSize];
  memset(key, 0x33, sizeof(key));

  const char *payload = "secure-message";
  protocolMessage_t in = {
      .type = protocolMsgData,
      .nbytes = (long)strlen(payload),
      .buf = payload,
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolSecureEncodeMessage(&in, key, &frame);
  testAssertTrue(status == protocolStatusOk, "secure encode should succeed");

  protocolMessage_t out;
  status = protocolSecureDecodeFrame(&frame, key, &out);
  testAssertTrue(status == protocolStatusOk, "secure decode should succeed");
  testAssertTrue(out.type == protocolMsgData, "decoded secure message type should match");
  testAssertTrue(out.nbytes == in.nbytes, "decoded secure payload length should match");
  testAssertTrue(memcmp(out.buf, payload, (size_t)out.nbytes) == 0, "decoded secure payload should match");
}

void testSecureMessageRejectTamper() {
  unsigned char key[ProtocolPskSize];
  memset(key, 0x19, sizeof(key));

  protocolMessage_t in = {
      .type = protocolMsgHeartbeatReq,
      .nbytes = 0,
      .buf = NULL,
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolSecureEncodeMessage(&in, key, &frame);
  testAssertTrue(status == protocolStatusOk, "secure encode for heartbeat should succeed");

  frame.buf[frame.nbytes - 1] ^= 0x1;
  protocolMessage_t out;
  status = protocolSecureDecodeFrame(&frame, key, &out);
  testAssertTrue(status == protocolStatusBadFrame, "secure decode should reject tampered frame");
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
  testAssertTrue(status == protocolStatusOk, "data message encode should succeed");

  protocolMessage_t out;
  status = protocolMessageDecodeFrame(&frame, &out);
  testAssertTrue(status == protocolStatusOk, "data message decode should succeed");
  testAssertTrue(out.type == protocolMsgData, "decoded data message type should match");
  testAssertTrue(out.nbytes == in.nbytes, "decoded data payload length should match");
  testAssertTrue(memcmp(out.buf, payload, (size_t)out.nbytes) == 0, "decoded data payload should match");
}

void testMessageHeartbeatReqRoundTrip() {
  protocolMessage_t in = {
      .type = protocolMsgHeartbeatReq,
      .nbytes = 0,
      .buf = NULL,
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolMessageEncodeFrame(&in, &frame);
  testAssertTrue(status == protocolStatusOk, "heartbeat request encode should succeed");

  protocolMessage_t out;
  status = protocolMessageDecodeFrame(&frame, &out);
  testAssertTrue(status == protocolStatusOk, "heartbeat request decode should succeed");
  testAssertTrue(out.type == protocolMsgHeartbeatReq, "decoded heartbeat request type should match");
  testAssertTrue(out.nbytes == 0, "decoded heartbeat request should be empty");
}

void testMessageHeartbeatAckRoundTrip() {
  protocolMessage_t in = {
      .type = protocolMsgHeartbeatAck,
      .nbytes = 0,
      .buf = NULL,
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolMessageEncodeFrame(&in, &frame);
  testAssertTrue(status == protocolStatusOk, "heartbeat ack encode should succeed");

  protocolMessage_t out;
  status = protocolMessageDecodeFrame(&frame, &out);
  testAssertTrue(status == protocolStatusOk, "heartbeat ack decode should succeed");
  testAssertTrue(out.type == protocolMsgHeartbeatAck, "decoded heartbeat ack type should match");
  testAssertTrue(out.nbytes == 0, "decoded heartbeat ack should be empty");
}

void testMessageRejectInvalidType() {
  protocolFrame_t frame;
  frame.buf[0] = (char)0x7f;
  frame.nbytes = 1;
  protocolMessage_t out;
  protocolStatus_t status = protocolMessageDecodeFrame(&frame, &out);
  testAssertTrue(status == protocolStatusBadFrame, "invalid message type should fail");
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
  testAssertTrue(status == protocolStatusBadFrame, "heartbeat request with payload should fail");

  protocolMessage_t dataBad = {
      .type = protocolMsgData,
      .nbytes = 0,
      .buf = NULL,
  };
  status = protocolMessageEncodeFrame(&dataBad, &frame);
  testAssertTrue(status == protocolStatusBadFrame, "data message without payload should fail");
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
  testAssertTrue(status == protocolStatusOk, "message encode should succeed");
  testAssertTrue(frame.nbytes == 8, "message wire size should be type + 32-bit length + payload");
  testAssertTrue((unsigned char)frame.buf[0] == (unsigned char)protocolMsgData, "encoded type should match");
  testAssertTrue((unsigned char)frame.buf[1] == 0x00, "length byte 0 should be big-endian");
  testAssertTrue((unsigned char)frame.buf[2] == 0x00, "length byte 1 should be big-endian");
  testAssertTrue((unsigned char)frame.buf[3] == 0x00, "length byte 2 should be big-endian");
  testAssertTrue((unsigned char)frame.buf[4] == 0x03, "length byte 3 should be big-endian");
  testAssertTrue(memcmp(frame.buf + 5, payload, 3) == 0, "encoded payload should match");
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
  testAssertTrue(status == protocolStatusOk, "message decode should parse fixed big-endian length");
  testAssertTrue(msg.type == protocolMsgData, "decoded type should match");
  testAssertTrue(msg.nbytes == 3, "decoded payload length should match");
  testAssertTrue(memcmp(msg.buf, "xyz", 3) == 0, "decoded payload should match");
}

void runProtocolTests(void) {
  testAssertTrue(sodium_init() >= 0, "sodium init should succeed");
  testEncode();
  testEncodeRejectNullPayloadWithPositiveLength();
  testDecodeSplitFrame();
  testDecodeRejectBadLength();
  testDecodeUsesFixedBigEndianLengthHeader();
  testGenericLoggingAvailable();
  testEncryptDecryptRoundTrip();
  testDecryptRejectTamper();
  testSecureMessageRoundTrip();
  testSecureMessageRejectTamper();
  testMessageDataRoundTrip();
  testMessageHeartbeatReqRoundTrip();
  testMessageHeartbeatAckRoundTrip();
  testMessageRejectInvalidType();
  testMessageRejectInvalidSizeTypeCombo();
  testMessageEncodeUsesFixedBigEndianLengthHeader();
  testMessageDecodeUsesFixedBigEndianLengthHeader();
  fprintf(stderr, "PASS protocol tests\n");
}
