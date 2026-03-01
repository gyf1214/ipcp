#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>

#include "log.h"
#include "protocol.h"
#include "protocolInternal.h"
#include "testAssert.h"

static long writeWireFrame(const protocolFrame_t *frame, unsigned char *wire) {
  unsigned long nbytes = (unsigned long)frame->nbytes;
  wire[0] = (unsigned char)((nbytes >> 24) & 0xff);
  wire[1] = (unsigned char)((nbytes >> 16) & 0xff);
  wire[2] = (unsigned char)((nbytes >> 8) & 0xff);
  wire[3] = (unsigned char)(nbytes & 0xff);
  memcpy(wire + ProtocolWireLengthSize, frame->buf, (size_t)frame->nbytes);
  return ProtocolWireLengthSize + frame->nbytes;
}

static protocolStatus_t decodeSecureFrameForTest(
    const protocolFrame_t *frame,
    const unsigned char key[ProtocolPskSize],
    protocolMessage_t *msg) {
  protocolDecoder_t decoder;
  unsigned char wire[ProtocolWireLengthSize + ProtocolFrameSize];
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
  testAssertTrue(frame.nbytes == 3, "encoded length should match input");
  testAssertTrue(memcmp(frame.buf, msg.buf, 3) == 0, "encoded payload should match");
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

  unsigned char wire[ProtocolWireLengthSize + ProtocolFrameSize];
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

  unsigned char wire[ProtocolWireLengthSize + ProtocolFrameSize];
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

  unsigned char raw[ProtocolWireLengthSize + ProtocolFrameSize];
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

  unsigned char wire[ProtocolWireLengthSize + ProtocolFrameSize];
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
  testAssertTrue(frame.nbytes == msg.nbytes, "decrypted length should match");
  testAssertTrue(memcmp(frame.buf, msg.buf, (size_t)frame.nbytes) == 0, "decrypted payload should match");
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

void testMessageRejectAuthChallengeType() {
  unsigned char nonce[ProtocolNonceSize];
  memset(nonce, 0x17, sizeof(nonce));
  protocolMessage_t challenge = {
      .type = protocolMsgAuthChallenge,
      .nbytes = ProtocolNonceSize,
      .buf = (const char *)nonce,
  };
  protocolFrame_t frame;
  protocolStatus_t status = protocolMessageEncodeFrame(&challenge, &frame);
  testAssertTrue(status == protocolStatusBadFrame, "typed auth challenge should no longer encode");
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

void runProtocolTests(void) {
  testAssertTrue(sodium_init() >= 0, "sodium init should succeed");
  testRawEncode();
  testRawEncodeRejectNullPayloadWithPositiveLength();
  testRawDecodeSplitFrame();
  testRawDecodeRejectBadLength();
  testRawDecodeRejectBadArgs();
  testSecureDecodeSplitFrame();
  testDecodeUsesFixedBigEndianLengthHeader();
  testSecureDecodeRejectsTamper();
  testSecureDecodeNeedMore();
  testSecureDecodeRejectBadArgs();
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
  testMessageRejectAuthChallengeType();
  testMessageRejectInvalidSizeTypeCombo();
  testMessageEncodeUsesFixedBigEndianLengthHeader();
  testMessageDecodeUsesFixedBigEndianLengthHeader();
}
