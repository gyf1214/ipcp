#include <string.h>
#include <sodium.h>

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

long protocolMaxPlaintextSize() {
  return ProtocolFrameSize - ProtocolNonceSize - ProtocolAuthTagSize;
}

protocolStatus_t protocolFrameEncrypt(protocolFrame_t *frame, const unsigned char key[ProtocolPskSize]) {
  if (frame->nbytes <= 0 || frame->nbytes > protocolMaxPlaintextSize()) {
    return protocolStatusBadFrame;
  }

  unsigned char nonce[ProtocolNonceSize];
  unsigned char out[ProtocolFrameSize];
  randombytes_buf(nonce, sizeof(nonce));
  memcpy(out, nonce, sizeof(nonce));

  if (crypto_secretbox_easy(
          out + ProtocolNonceSize,
          (unsigned char *)frame->buf,
          (unsigned long long)frame->nbytes,
          nonce,
          key) != 0) {
    return protocolStatusBadFrame;
  }

  frame->nbytes += ProtocolNonceSize + ProtocolAuthTagSize;
  memcpy(frame->buf, out, (size_t)frame->nbytes);
  return protocolStatusOk;
}

protocolStatus_t protocolFrameDecrypt(protocolFrame_t *frame, const unsigned char key[ProtocolPskSize]) {
  if (frame->nbytes <= ProtocolNonceSize + ProtocolAuthTagSize || frame->nbytes > ProtocolFrameSize) {
    return protocolStatusBadFrame;
  }

  unsigned char out[ProtocolFrameSize];
  unsigned char nonce[ProtocolNonceSize];
  long cipherBytes = frame->nbytes - ProtocolNonceSize;
  long plainBytes = cipherBytes - ProtocolAuthTagSize;

  memcpy(nonce, frame->buf, sizeof(nonce));
  if (crypto_secretbox_open_easy(
          out,
          (unsigned char *)frame->buf + ProtocolNonceSize,
          (unsigned long long)cipherBytes,
          nonce,
          key) != 0) {
    return protocolStatusBadFrame;
  }

  frame->nbytes = plainBytes;
  memcpy(frame->buf, out, (size_t)plainBytes);
  return protocolStatusOk;
}
