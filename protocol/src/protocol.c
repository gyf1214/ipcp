#include <string.h>

#include "protocol.h"

static long protocolExpectedSize(const protocolDecoder_t *decoder) {
  if (decoder->offset < (long)sizeof(decoder->frame.nbytes)) {
    return (long)sizeof(decoder->frame.nbytes);
  }
  return (long)sizeof(decoder->frame.nbytes) + decoder->frame.nbytes;
}

protocolStatus_t protocolEncode(const void *payload, long nbytes, protocolFrame_t *frame) {
  if (nbytes <= 0 || nbytes > ProtocolFrameSize) {
    return protocolStatusBadFrame;
  }

  frame->nbytes = nbytes;
  memcpy(frame->buf, payload, (size_t)nbytes);
  return protocolStatusOk;
}

void protocolDecoderInit(protocolDecoder_t *decoder) {
  memset(decoder, 0, sizeof(*decoder));
}

protocolStatus_t protocolDecodeFeed(
    protocolDecoder_t *decoder, const void *data, long nbytes, long *consumed) {
  long totalConsumed = 0;
  if (nbytes <= 0) {
    if (consumed != NULL) {
      *consumed = 0;
    }
    return protocolStatusNeedMore;
  }

  const char *input = (const char *)data;
  while (totalConsumed < nbytes && !decoder->hasFrame) {
    long expected = protocolExpectedSize(decoder);
    long remain = expected - decoder->offset;
    long available = nbytes - totalConsumed;
    if (remain > available) {
      remain = available;
    }

    memcpy(
        (char *)&decoder->frame + decoder->offset,
        input + totalConsumed,
        (size_t)remain);
    decoder->offset += remain;
    totalConsumed += remain;

    if (decoder->offset < (long)sizeof(decoder->frame.nbytes)) {
      continue;
    }
    if (decoder->frame.nbytes <= 0 || decoder->frame.nbytes > ProtocolFrameSize) {
      if (consumed != NULL) {
        *consumed = totalConsumed;
      }
      return protocolStatusBadFrame;
    }

    expected = protocolExpectedSize(decoder);
    if (decoder->offset >= expected) {
      decoder->hasFrame = 1;
    }
  }

  if (consumed != NULL) {
    *consumed = totalConsumed;
  }

  return decoder->hasFrame ? protocolStatusOk : protocolStatusNeedMore;
}

int protocolDecoderHasFrame(const protocolDecoder_t *decoder) {
  return decoder->hasFrame;
}

protocolStatus_t protocolDecoderTake(protocolDecoder_t *decoder, protocolFrame_t *frame) {
  if (!decoder->hasFrame) {
    return protocolStatusNeedMore;
  }

  memcpy(frame, &decoder->frame, (size_t)sizeof(frame->nbytes) + (size_t)decoder->frame.nbytes);
  protocolDecoderInit(decoder);
  return protocolStatusOk;
}
