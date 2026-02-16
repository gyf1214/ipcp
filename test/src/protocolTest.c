#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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

int main() {
  testEncode();
  testDecodeSplitFrame();
  testDecodeRejectBadLength();
  fprintf(stderr, "PASS protocol tests\n");
  return 0;
}
