#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>

#include "log.h"
#include "packet.h"
#include "protocol.h"
#include "protocolInternal.h"
#include "testAssert.h"

static long writeWireFrame(const protocolFrame_t *frame, unsigned char *wire) {
  memcpy(wire, frame->buf, (size_t)frame->nbytes);
  return frame->nbytes;
}

static protocolStatus_t decodeSecureFrameForTest(
    const protocolFrame_t *frame,
    const unsigned char key[ProtocolPskSize],
    protocolMessage_t *msg) {
  protocolDecoder_t decoder;
  unsigned char wire[ProtocolFrameSize];
  long consumed = 0;
  long wireNbytes = writeWireFrame(frame, wire);

  protocolDecoderInit(&decoder);
  return protocolDecodeSecureMsg(&decoder, key, wire, wireNbytes, &consumed, msg);
}

void testRawEncode() {
  protocolRawMsg_t msg = {
      .nbytes = 3,
      .buf = "abc",
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncodeRaw(&msg, &frame);

  testAssertTrue(status == protocolStatusOk, "raw encode should succeed");
  testAssertTrue(frame.nbytes == 7, "encoded wire frame should include header and payload");
  testAssertTrue((unsigned char)frame.buf[0] == 0x00, "header byte 0 should be big-endian");
  testAssertTrue((unsigned char)frame.buf[1] == 0x00, "header byte 1 should be big-endian");
  testAssertTrue((unsigned char)frame.buf[2] == 0x00, "header byte 2 should be big-endian");
  testAssertTrue((unsigned char)frame.buf[3] == 0x03, "header byte 3 should be big-endian");
  testAssertTrue(memcmp(frame.buf + ProtocolWireLengthSize, msg.buf, 3) == 0, "encoded payload should match");
}

void testRawEncodeReturnsFullWireFrame() {
  protocolRawMsg_t msg = {
      .nbytes = 3,
      .buf = "abc",
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncodeRaw(&msg, &frame);

  testAssertTrue(status == protocolStatusOk, "raw encode should succeed");
  testAssertTrue(
      frame.nbytes == ProtocolWireLengthSize + msg.nbytes,
      "raw encode should include wire header bytes");
  testAssertTrue((unsigned char)frame.buf[0] == 0x00, "raw header byte 0 should be big-endian");
  testAssertTrue((unsigned char)frame.buf[1] == 0x00, "raw header byte 1 should be big-endian");
  testAssertTrue((unsigned char)frame.buf[2] == 0x00, "raw header byte 2 should be big-endian");
  testAssertTrue((unsigned char)frame.buf[3] == 0x03, "raw header byte 3 should be big-endian");
  testAssertTrue(
      memcmp(frame.buf + ProtocolWireLengthSize, msg.buf, (size_t)msg.nbytes) == 0,
      "raw payload should start after wire header");
}

void testRawEncodeBoundaryAtWireAdjustedMax() {
  char maxPayload[ProtocolFrameSize - ProtocolWireLengthSize];
  memset(maxPayload, 0x5a, sizeof(maxPayload));
  protocolRawMsg_t msg = {
      .nbytes = (long)sizeof(maxPayload),
      .buf = maxPayload,
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncodeRaw(&msg, &frame);
  testAssertTrue(status == protocolStatusOk, "raw encode should accept wire-adjusted max payload");
  testAssertTrue(frame.nbytes == ProtocolFrameSize, "max payload should fill full wire frame size");
}

void testRawEncodeRejectsOverWireAdjustedMax() {
  char tooLargePayload[ProtocolFrameSize - ProtocolWireLengthSize + 1];
  memset(tooLargePayload, 0x6b, sizeof(tooLargePayload));
  protocolRawMsg_t msg = {
      .nbytes = (long)sizeof(tooLargePayload),
      .buf = tooLargePayload,
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncodeRaw(&msg, &frame);
  testAssertTrue(status == protocolStatusBadFrame, "raw encode should reject payload larger than max");
}

void testRawEncodeRejectNullPayloadWithPositiveLength() {
  protocolRawMsg_t msg = {
      .nbytes = 1,
      .buf = NULL,
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncodeRaw(&msg, &frame);
  testAssertTrue(status == protocolStatusBadFrame, "raw encode should reject NULL payload with positive length");
}

void testRawDecodeSplitFrame() {
  protocolRawMsg_t in = {
      .nbytes = 5,
      .buf = "hello",
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncodeRaw(&in, &frame);
  testAssertTrue(status == protocolStatusOk, "raw encode should succeed");

  unsigned char wire[ProtocolFrameSize];
  long wireNbytes = writeWireFrame(&frame, wire);
  protocolDecoder_t decoder;
  protocolDecoderInit(&decoder);

  protocolRawMsg_t out;
  long consumed = 0;
  status = protocolDecodeRaw(&decoder, wire, 3, &consumed, &out);
  testAssertTrue(status == protocolStatusNeedMore, "partial header should require more");
  testAssertTrue(consumed == 3, "decoder should consume provided bytes");

  status = protocolDecodeRaw(&decoder, wire + 3, wireNbytes - 3, &consumed, &out);
  testAssertTrue(status == protocolStatusOk, "remaining bytes should decode");
  testAssertTrue(consumed == wireNbytes - 3, "decoder should consume remaining bytes");
  testAssertTrue(out.nbytes == 5, "decoded payload length should match");
  testAssertTrue(memcmp(out.buf, "hello", 5) == 0, "decoded payload should match");
}

void testRawDecodeRejectBadLength() {
  protocolDecoder_t decoder;
  protocolDecoderInit(&decoder);

  const unsigned char badSize[] = {
      0x00, 0x00, 0x10, 0x01,
  };
  protocolRawMsg_t out;
  long consumed = 0;
  protocolStatus_t status = protocolDecodeRaw(
      &decoder, badSize, (long)sizeof(badSize), &consumed, &out);
  testAssertTrue(status == protocolStatusBadFrame, "invalid size should fail");
}

void testRawDecodeRejectBadArgs() {
  protocolDecoder_t decoder;
  protocolDecoderInit(&decoder);
  protocolRawMsg_t out;
  long consumed = -1;

  protocolStatus_t status = protocolDecodeRaw(NULL, "\x00", 1, &consumed, &out);
  testAssertTrue(status == protocolStatusBadFrame, "NULL decoder should fail");
  testAssertTrue(consumed == 0, "NULL decoder should zero consumed");

  consumed = -1;
  status = protocolDecodeRaw(&decoder, NULL, 1, &consumed, &out);
  testAssertTrue(status == protocolStatusBadFrame, "NULL data with positive length should fail");
  testAssertTrue(consumed == 0, "NULL data should zero consumed");

  consumed = -1;
  status = protocolDecodeRaw(&decoder, NULL, 0, &consumed, &out);
  testAssertTrue(status == protocolStatusNeedMore, "NULL data with zero length should need more");
  testAssertTrue(consumed == 0, "zero-byte feed should zero consumed");
}

void testSecureDecodeSplitFrame() {
  unsigned char key[ProtocolPskSize];
  memset(key, 0x44, sizeof(key));
  protocolMessage_t in = {
      .type = protocolMsgData,
      .nbytes = 5,
      .buf = "hello",
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncodeSecureMsg(&in, key, &frame);
  testAssertTrue(status == protocolStatusOk, "secure encode should succeed");

  unsigned char wire[ProtocolFrameSize];
  long wireNbytes = writeWireFrame(&frame, wire);
  protocolDecoder_t decoder;
  protocolDecoderInit(&decoder);

  protocolMessage_t out;
  long consumed = 0;
  status = protocolDecodeSecureMsg(&decoder, key, wire, 3, &consumed, &out);
  testAssertTrue(status == protocolStatusNeedMore, "partial header should require more");
  testAssertTrue(consumed == 3, "should consume provided bytes");

  status = protocolDecodeSecureMsg(&decoder, key, wire + 3, wireNbytes - 3, &consumed, &out);
  testAssertTrue(status == protocolStatusOk, "rest of frame should decode");
  testAssertTrue(consumed == wireNbytes - 3, "should consume remaining bytes");
  testAssertTrue(out.type == protocolMsgData, "decoded message type should match");
  testAssertTrue(out.nbytes == 5, "decoded payload length should match");
  testAssertTrue(memcmp(out.buf, "hello", 5) == 0, "decoded payload should match");
}

void testSecureEncodeReturnsFullWireFrame() {
  unsigned char key[ProtocolPskSize];
  memset(key, 0x4d, sizeof(key));
  protocolMessage_t in = {
      .type = protocolMsgData,
      .nbytes = 5,
      .buf = "hello",
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncodeSecureMsg(&in, key, &frame);
  testAssertTrue(status == protocolStatusOk, "secure encode should succeed");
  testAssertTrue(frame.nbytes > ProtocolWireLengthSize, "secure frame should include wire header");
  testAssertTrue((unsigned char)frame.buf[0] == 0x00, "secure header byte 0 should be big-endian");
  testAssertTrue((unsigned char)frame.buf[1] == 0x00, "secure header byte 1 should be big-endian");
}

void testSecureEncodeBoundaryAtWireAdjustedMax() {
  unsigned char key[ProtocolPskSize];
  char payload[ProtocolFrameSize];
  protocolMessage_t msg;
  protocolFrame_t frame;
  protocolStatus_t status;

  memset(key, 0x36, sizeof(key));
  memset(payload, 0x41, sizeof(payload));
  msg.type = protocolMsgData;
  msg.nbytes = protocolMessageMaxPayloadSize();
  msg.buf = payload;

  status = protocolEncodeSecureMsg(&msg, key, &frame);
  testAssertTrue(status == protocolStatusOk, "secure encode should accept max payload");
  testAssertTrue(frame.nbytes == ProtocolFrameSize, "secure max payload should fill full wire frame");
}

void testSecureEncodeRejectsOverWireAdjustedMax() {
  unsigned char key[ProtocolPskSize];
  char payload[ProtocolFrameSize];
  protocolMessage_t msg;
  protocolFrame_t frame;
  protocolStatus_t status;

  memset(key, 0x37, sizeof(key));
  memset(payload, 0x42, sizeof(payload));
  msg.type = protocolMsgData;
  msg.nbytes = protocolMessageMaxPayloadSize() + 1;
  msg.buf = payload;

  status = protocolEncodeSecureMsg(&msg, key, &frame);
  testAssertTrue(status == protocolStatusBadFrame, "secure encode should reject oversized payload");
}

void testWireHeaderEncodesContentLengthNotTotalFrameLength() {
  unsigned char key[ProtocolPskSize];
  protocolMessage_t msg = {
      .type = protocolMsgData,
      .nbytes = 3,
      .buf = "abc",
  };
  protocolFrame_t frame;
  protocolStatus_t status;
  long encodedLen;

  memset(key, 0x38, sizeof(key));
  status = protocolEncodeSecureMsg(&msg, key, &frame);
  testAssertTrue(status == protocolStatusOk, "secure encode should succeed");

  encodedLen = ((long)(unsigned char)frame.buf[0] << 24)
      | ((long)(unsigned char)frame.buf[1] << 16)
      | ((long)(unsigned char)frame.buf[2] << 8)
      | (long)(unsigned char)frame.buf[3];
  testAssertTrue(encodedLen == frame.nbytes - ProtocolWireLengthSize, "wire header should encode content length");
  testAssertTrue(encodedLen != frame.nbytes, "wire header must not encode total frame length");
}

void testDecodeUsesFixedBigEndianLengthHeader() {
  unsigned char key[ProtocolPskSize];
  memset(key, 0x31, sizeof(key));
  protocolMessage_t in = {
      .type = protocolMsgData,
      .nbytes = 3,
      .buf = "abc",
  };
  protocolFrame_t secureFrame;
  protocolStatus_t status = protocolEncodeSecureMsg(&in, key, &secureFrame);
  testAssertTrue(status == protocolStatusOk, "secure encode should succeed");

  unsigned char raw[ProtocolFrameSize];
  long rawNbytes = writeWireFrame(&secureFrame, raw);
  protocolDecoder_t decoder;
  protocolDecoderInit(&decoder);
  long consumed = 0;
  protocolMessage_t out;
  status = protocolDecodeSecureMsg(&decoder, key, raw, rawNbytes, &consumed, &out);
  testAssertTrue(status == protocolStatusOk, "decoder should accept fixed 32-bit length header");
  testAssertTrue(consumed == rawNbytes, "decoder should consume full frame bytes");
  testAssertTrue(out.type == protocolMsgData, "decoded message type should match");
  testAssertTrue(out.nbytes == 3, "decoded payload length should match");
  testAssertTrue(memcmp(out.buf, "abc", 3) == 0, "decoded payload should match");
}

void testSecureDecodeRejectsTamper() {
  unsigned char key[ProtocolPskSize];
  memset(key, 0x52, sizeof(key));
  protocolMessage_t in = {
      .type = protocolMsgHeartbeatReq,
      .nbytes = 0,
      .buf = NULL,
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncodeSecureMsg(&in, key, &frame);
  testAssertTrue(status == protocolStatusOk, "secure encode should succeed");
  frame.buf[frame.nbytes - 1] ^= 0x1;

  unsigned char wire[ProtocolFrameSize];
  long wireNbytes = writeWireFrame(&frame, wire);
  protocolDecoder_t decoder;
  protocolDecoderInit(&decoder);

  protocolMessage_t out;
  long consumed = 0;
  status = protocolDecodeSecureMsg(&decoder, key, wire, wireNbytes, &consumed, &out);
  testAssertTrue(status == protocolStatusBadFrame, "tampered secure frame should fail");
}

void testSecureDecodeNeedMore() {
  unsigned char key[ProtocolPskSize];
  memset(key, 0x08, sizeof(key));
  protocolDecoder_t decoder;
  protocolDecoderInit(&decoder);
  protocolMessage_t out;
  long consumed = 0;
  protocolStatus_t status =
      protocolDecodeSecureMsg(&decoder, key, "\x00\x00", 2, &consumed, &out);
  testAssertTrue(status == protocolStatusNeedMore, "incomplete wire header should need more bytes");
  testAssertTrue(consumed == 2, "decoder should consume provided bytes");
}

void testSecureDecodeRejectBadArgs() {
  unsigned char key[ProtocolPskSize];
  memset(key, 0x18, sizeof(key));
  protocolDecoder_t decoder;
  protocolDecoderInit(&decoder);
  protocolMessage_t out;
  long consumed = -1;

  protocolStatus_t status =
      protocolDecodeSecureMsg(NULL, key, "\x00", 1, &consumed, &out);
  testAssertTrue(status == protocolStatusBadFrame, "NULL decoder should fail");
  testAssertTrue(consumed == 0, "NULL decoder should zero consumed");

  consumed = -1;
  status = protocolDecodeSecureMsg(&decoder, NULL, "\x00", 1, &consumed, &out);
  testAssertTrue(status == protocolStatusBadFrame, "NULL key should fail");
  testAssertTrue(consumed == 0, "NULL key should zero consumed");

  consumed = -1;
  status = protocolDecodeSecureMsg(&decoder, key, "\x00", 1, &consumed, NULL);
  testAssertTrue(status == protocolStatusBadFrame, "NULL message should fail");
  testAssertTrue(consumed == 0, "NULL message should zero consumed");

  consumed = -1;
  status = protocolDecodeSecureMsg(&decoder, key, NULL, 1, &consumed, &out);
  testAssertTrue(status == protocolStatusBadFrame, "NULL data with positive length should fail");
  testAssertTrue(consumed == 0, "NULL data should zero consumed");
}

void testRawDecodeConsumesSingleFrameFromConcatenatedInput() {
  protocolRawMsg_t inA = {
      .nbytes = 5,
      .buf = "first",
  };
  protocolRawMsg_t inB = {
      .nbytes = 6,
      .buf = "second",
  };
  protocolFrame_t frameA;
  protocolFrame_t frameB;
  protocolRawMsg_t out;
  protocolDecoder_t decoder;
  protocolStatus_t status;
  char wire[ProtocolFrameSize * 2];
  long consumed = 0;
  long offset = 0;

  status = protocolEncodeRaw(&inA, &frameA);
  testAssertTrue(status == protocolStatusOk, "raw encode A should succeed");
  status = protocolEncodeRaw(&inB, &frameB);
  testAssertTrue(status == protocolStatusOk, "raw encode B should succeed");

  memcpy(wire, frameA.buf, (size_t)frameA.nbytes);
  memcpy(wire + frameA.nbytes, frameB.buf, (size_t)frameB.nbytes);
  protocolDecoderInit(&decoder);

  status = protocolDecodeRaw(&decoder, wire, frameA.nbytes + frameB.nbytes, &consumed, &out);
  testAssertTrue(status == protocolStatusOk, "first decode should return one complete frame");
  testAssertTrue(consumed == frameA.nbytes, "first decode should consume exactly first frame bytes");
  testAssertTrue(out.nbytes == inA.nbytes, "first decoded payload length should match");
  testAssertTrue(memcmp(out.buf, inA.buf, (size_t)inA.nbytes) == 0, "first decoded payload should match");

  offset += consumed;
  status = protocolDecodeRaw(&decoder, wire + offset, frameB.nbytes, &consumed, &out);
  testAssertTrue(status == protocolStatusOk, "second decode should parse remaining frame");
  testAssertTrue(consumed == frameB.nbytes, "second decode should consume remaining frame bytes");
  testAssertTrue(out.nbytes == inB.nbytes, "second decoded payload length should match");
  testAssertTrue(memcmp(out.buf, inB.buf, (size_t)inB.nbytes) == 0, "second decoded payload should match");
}

void testRawDecodeFragmentedHeaderBodyKeepsByteContinuity() {
  protocolRawMsg_t in = {
      .nbytes = 9,
      .buf = "frag-data",
  };
  protocolFrame_t frame;
  protocolRawMsg_t out;
  protocolDecoder_t decoder;
  protocolStatus_t status;
  long consumed = 0;
  long offset = 0;
  const long chunks[] = {1, 1, 2, 3, 6};
  size_t i;

  status = protocolEncodeRaw(&in, &frame);
  testAssertTrue(status == protocolStatusOk, "raw encode should succeed");
  protocolDecoderInit(&decoder);

  for (i = 0; i < sizeof(chunks) / sizeof(chunks[0]); ++i) {
    status = protocolDecodeRaw(&decoder, frame.buf + offset, chunks[i], &consumed, &out);
    offset += chunks[i];
    if (i + 1 < sizeof(chunks) / sizeof(chunks[0])) {
      testAssertTrue(status == protocolStatusNeedMore, "intermediate fragment should need more bytes");
    } else {
      testAssertTrue(status == protocolStatusOk, "final fragment should complete frame");
      testAssertTrue(out.nbytes == in.nbytes, "decoded payload length should match");
      testAssertTrue(memcmp(out.buf, in.buf, (size_t)in.nbytes) == 0, "decoded payload should match");
    }
    testAssertTrue(consumed == chunks[i], "decoder should consume exactly chunk bytes");
  }
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

  protocolRawMsg_t msg = {
      .nbytes = 14,
      .buf = "secret-payload",
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncodeRaw(&msg, &frame);
  testAssertTrue(status == protocolStatusOk, "raw encode should succeed");

  status = protocolFrameEncrypt(&frame, key);
  testAssertTrue(status == protocolStatusOk, "encrypt should succeed");
  testAssertTrue(frame.nbytes > msg.nbytes, "encrypted frame should be larger than plaintext");

  status = protocolFrameDecrypt(&frame, key);
  testAssertTrue(status == protocolStatusOk, "decrypt should succeed");
  testAssertTrue(
      frame.nbytes == ProtocolWireLengthSize + msg.nbytes,
      "decrypted frame should restore wire header and payload");
  testAssertTrue((unsigned char)frame.buf[0] == 0x00, "decrypted header byte 0 should be big-endian");
  testAssertTrue((unsigned char)frame.buf[1] == 0x00, "decrypted header byte 1 should be big-endian");
  testAssertTrue((unsigned char)frame.buf[2] == 0x00, "decrypted header byte 2 should be big-endian");
  testAssertTrue((unsigned char)frame.buf[3] == 0x0e, "decrypted header byte 3 should match payload length");
  testAssertTrue(
      memcmp(frame.buf + ProtocolWireLengthSize, msg.buf, (size_t)msg.nbytes) == 0,
      "decrypted payload should match");
}

void testDecryptRejectTamper() {
  unsigned char key[ProtocolPskSize];
  memset(key, 0x7f, sizeof(key));

  protocolRawMsg_t msg = {
      .nbytes = 10,
      .buf = "auth-check",
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolEncodeRaw(&msg, &frame);
  testAssertTrue(status == protocolStatusOk, "raw encode should succeed");

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
  protocolStatus_t status = protocolEncodeSecureMsg(&in, key, &frame);
  testAssertTrue(status == protocolStatusOk, "secure encode should succeed");

  protocolMessage_t out;
  status = decodeSecureFrameForTest(&frame, key, &out);
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
  protocolStatus_t status = protocolEncodeSecureMsg(&in, key, &frame);
  testAssertTrue(status == protocolStatusOk, "secure encode for heartbeat should succeed");

  frame.buf[frame.nbytes - 1] ^= 0x1;
  protocolMessage_t out;
  status = decodeSecureFrameForTest(&frame, key, &out);
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

void testMessageClientHelloRoundTrip() {
  unsigned char nonces[ProtocolNonceSize * 2];
  memset(nonces, 0x29, sizeof(nonces));
  protocolMessage_t in = {
      .type = protocolMsgClientHello,
      .nbytes = ProtocolNonceSize * 2,
      .buf = (const char *)nonces,
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolMessageEncodeFrame(&in, &frame);
  testAssertTrue(status == protocolStatusOk, "client hello encode should succeed");

  protocolMessage_t out;
  status = protocolMessageDecodeFrame(&frame, &out);
  testAssertTrue(status == protocolStatusOk, "client hello decode should succeed");
  testAssertTrue(out.type == protocolMsgClientHello, "decoded client hello type should match");
  testAssertTrue(out.nbytes == ProtocolNonceSize * 2, "decoded client hello nonce pair size should match");
  testAssertTrue(memcmp(out.buf, nonces, ProtocolNonceSize * 2) == 0, "decoded client hello payload should match");
}

void testMessageRejectInvalidType() {
  protocolFrame_t frame;
  frame.buf[0] = (char)0x7f;
  frame.nbytes = 1;
  protocolMessage_t out;
  protocolStatus_t status = protocolMessageDecodeFrame(&frame, &out);
  testAssertTrue(status == protocolStatusBadFrame, "invalid message type should fail");
}

void testMessageRejectLegacyChallengeTypeValue() {
  unsigned char nonce[ProtocolNonceSize];
  memset(nonce, 0x17, sizeof(nonce));
  protocolMessage_t challenge = {
      .type = (protocolMessageType_t)4,
      .nbytes = ProtocolNonceSize,
      .buf = (const char *)nonce,
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolMessageEncodeFrame(&challenge, &frame);
  testAssertTrue(status == protocolStatusBadFrame, "legacy challenge type value should be rejected");
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

  protocolMessage_t helloBad = {
      .type = protocolMsgClientHello,
      .nbytes = ProtocolNonceSize,
      .buf = payload,
  };
  status = protocolMessageEncodeFrame(&helloBad, &frame);
  testAssertTrue(status == protocolStatusBadFrame, "client hello with wrong payload size should fail");
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

void testPacketParseTunIpv4Destination(void) {
  unsigned char packet[] = {
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 0, 0, 1,
      10, 0, 0, 2,
  };
  packetDestination_t destination;
  packetParseStatus_t status = packetParseDestination(packetParseModeTunIpv4, packet, sizeof(packet), &destination);
  unsigned char expected[] = {10, 0, 0, 2};

  testAssertTrue(status == packetParseStatusOk, "tun ipv4 parser should succeed");
  testAssertTrue(destination.classification == packetDestinationOk, "unicast packet should be routable");
  testAssertTrue(destination.claimNbytes == 4, "tun destination claim should be 4 bytes");
  testAssertTrue(memcmp(destination.claim, expected, sizeof(expected)) == 0, "tun destination claim should match");
}

void testPacketParseTunIpv4DestinationWithPiHeader(void) {
  unsigned char packet[] = {
      0x00, 0x00, 0x08, 0x00,
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 0, 0, 1,
      10, 0, 0, 2,
  };
  packetDestination_t destination;
  packetParseStatus_t status = packetParseDestination(packetParseModeTunIpv4, packet, sizeof(packet), &destination);
  unsigned char expected[] = {10, 0, 0, 2};

  testAssertTrue(status == packetParseStatusOk, "tun parser should accept packet info header");
  testAssertTrue(destination.classification == packetDestinationOk, "pi-prefixed unicast packet should be routable");
  testAssertTrue(destination.claimNbytes == 4, "tun destination claim should be 4 bytes");
  testAssertTrue(memcmp(destination.claim, expected, sizeof(expected)) == 0, "tun destination claim should match");
}

void testPacketParseTunRejectsMalformed(void) {
  unsigned char shortPacket[] = {0x45, 0x00, 0x00, 0x14, 0x00, 0x00};
  packetDestination_t destination;
  packetParseStatus_t status =
      packetParseDestination(packetParseModeTunIpv4, shortPacket, sizeof(shortPacket), &destination);

  testAssertTrue(status == packetParseStatusOk, "malformed packet parse should return classification");
  testAssertTrue(destination.classification == packetDestinationDropMalformed, "short ipv4 packet should drop malformed");
  testAssertTrue(destination.claimNbytes == 0, "malformed packet should not expose claim");
}

void testPacketParseTunClassifiesMulticastAndBroadcast(void) {
  unsigned char multicastPacket[] = {
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 0, 0, 1,
      224, 1, 2, 3,
  };
  unsigned char broadcastPacket[] = {
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 0, 0, 1,
      255, 255, 255, 255,
  };
  packetDestination_t destination;
  packetParseStatus_t status =
      packetParseDestination(packetParseModeTunIpv4, multicastPacket, sizeof(multicastPacket), &destination);
  testAssertTrue(status == packetParseStatusOk, "multicast packet parse should succeed");
  testAssertTrue(destination.classification == packetDestinationDropMulticast, "multicast destination should drop");

  status = packetParseDestination(packetParseModeTunIpv4, broadcastPacket, sizeof(broadcastPacket), &destination);
  testAssertTrue(status == packetParseStatusOk, "broadcast packet parse should succeed");
  testAssertTrue(
      destination.classification == packetDestinationBroadcastL3Candidate,
      "broadcast destination should classify as tun broadcast candidate");
  testAssertTrue(destination.claimNbytes == 4, "tun broadcast candidate should retain 4-byte destination");
  testAssertTrue(
      destination.claim[0] == 255 && destination.claim[1] == 255 && destination.claim[2] == 255
          && destination.claim[3] == 255,
      "tun broadcast candidate bytes should match destination ip");
}

void testPacketParseTapEthernetDestination(void) {
  unsigned char frame[] = {
      0x02, 0x00, 0x5e, 0x10, 0x20, 0x30,
      0x02, 0x00, 0x5e, 0x00, 0x00, 0x01,
      0x08, 0x00,
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 0, 0, 1,
      10, 0, 0, 2,
  };
  unsigned char expected[] = {0x02, 0x00, 0x5e, 0x10, 0x20, 0x30};
  packetDestination_t destination;
  packetParseStatus_t status = packetParseDestination(packetParseModeTapEthernet, frame, sizeof(frame), &destination);

  testAssertTrue(status == packetParseStatusOk, "tap ethernet parser should succeed");
  testAssertTrue(destination.classification == packetDestinationOk, "tap unicast frame should be routable");
  testAssertTrue(destination.claimNbytes == 6, "tap destination claim should be 6 bytes");
  testAssertTrue(
      memcmp(destination.claim, expected, sizeof(expected)) == 0,
      "tap destination claim should match destination mac");
}

void testPacketParseTapEthernetDestinationWithPiHeader(void) {
  unsigned char frame[] = {
      0x00, 0x00, 0x08, 0x00,
      0x02, 0x00, 0x5e, 0x10, 0x20, 0x30,
      0x02, 0x00, 0x5e, 0x00, 0x00, 0x01,
      0x08, 0x00,
      0x45, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      10, 0, 0, 1,
      10, 0, 0, 2,
  };
  unsigned char expected[] = {0x02, 0x00, 0x5e, 0x10, 0x20, 0x30};
  packetDestination_t destination;
  packetParseStatus_t status = packetParseDestination(packetParseModeTapEthernet, frame, sizeof(frame), &destination);

  testAssertTrue(status == packetParseStatusOk, "tap parser should accept packet info header");
  testAssertTrue(destination.classification == packetDestinationOk, "pi-prefixed tap unicast frame should be routable");
  testAssertTrue(destination.claimNbytes == 6, "tap destination claim should be 6 bytes");
  testAssertTrue(
      memcmp(destination.claim, expected, sizeof(expected)) == 0,
      "tap destination claim should match destination mac");
}

void testPacketParseTapClassifiesBroadcastMulticastAndMalformed(void) {
  unsigned char multicastFrame[] = {
      0x01, 0x00, 0x5e, 0x10, 0x20, 0x30,
      0x02, 0x00, 0x5e, 0x00, 0x00, 0x01,
      0x08, 0x00,
  };
  unsigned char broadcastFrame[] = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0x02, 0x00, 0x5e, 0x00, 0x00, 0x01,
      0x08, 0x00,
  };
  unsigned char malformedFrame[] = {0x00, 0x01, 0x02, 0x03, 0x04};
  packetDestination_t destination;
  packetParseStatus_t status =
      packetParseDestination(packetParseModeTapEthernet, multicastFrame, sizeof(multicastFrame), &destination);
  testAssertTrue(status == packetParseStatusOk, "tap multicast parse should succeed");
  testAssertTrue(destination.classification == packetDestinationDropMulticast, "tap multicast should drop");

  status = packetParseDestination(packetParseModeTapEthernet, broadcastFrame, sizeof(broadcastFrame), &destination);
  testAssertTrue(status == packetParseStatusOk, "tap broadcast parse should succeed");
  testAssertTrue(destination.classification == packetDestinationBroadcastL2, "tap broadcast should classify as L2");

  status = packetParseDestination(packetParseModeTapEthernet, malformedFrame, sizeof(malformedFrame), &destination);
  testAssertTrue(status == packetParseStatusOk, "tap malformed parse should succeed");
  testAssertTrue(destination.classification == packetDestinationDropMalformed, "short ethernet frame should drop");
}

void runProtocolTests(void) {
  testAssertTrue(sodium_init() >= 0, "sodium init should succeed");
  testRawEncode();
  testRawEncodeReturnsFullWireFrame();
  testRawEncodeBoundaryAtWireAdjustedMax();
  testRawEncodeRejectsOverWireAdjustedMax();
  testRawEncodeRejectNullPayloadWithPositiveLength();
  testRawDecodeSplitFrame();
  testRawDecodeRejectBadLength();
  testRawDecodeRejectBadArgs();
  testSecureDecodeSplitFrame();
  testSecureEncodeReturnsFullWireFrame();
  testSecureEncodeBoundaryAtWireAdjustedMax();
  testSecureEncodeRejectsOverWireAdjustedMax();
  testWireHeaderEncodesContentLengthNotTotalFrameLength();
  testDecodeUsesFixedBigEndianLengthHeader();
  testSecureDecodeRejectsTamper();
  testSecureDecodeNeedMore();
  testSecureDecodeRejectBadArgs();
  testRawDecodeConsumesSingleFrameFromConcatenatedInput();
  testRawDecodeFragmentedHeaderBodyKeepsByteContinuity();
  testGenericLoggingAvailable();
  testEncryptDecryptRoundTrip();
  testDecryptRejectTamper();
  testSecureMessageRoundTrip();
  testSecureMessageRejectTamper();
  testMessageDataRoundTrip();
  testMessageHeartbeatReqRoundTrip();
  testMessageHeartbeatAckRoundTrip();
  testMessageClientHelloRoundTrip();
  testMessageRejectInvalidType();
  testMessageRejectLegacyChallengeTypeValue();
  testMessageRejectInvalidSizeTypeCombo();
  testMessageEncodeUsesFixedBigEndianLengthHeader();
  testMessageDecodeUsesFixedBigEndianLengthHeader();
  testPacketParseTunIpv4Destination();
  testPacketParseTunIpv4DestinationWithPiHeader();
  testPacketParseTunRejectsMalformed();
  testPacketParseTunClassifiesMulticastAndBroadcast();
  testPacketParseTapEthernetDestination();
  testPacketParseTapEthernetDestinationWithPiHeader();
  testPacketParseTapClassifiesBroadcastMulticastAndMalformed();
}
