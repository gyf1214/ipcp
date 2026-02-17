#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sodium.h>

#include "protocol.h"

static long protocolMessageHeaderSize() {
  return (long)sizeof(unsigned char) + ProtocolWireLengthSize;
}

static int protocolMessageTypeValid(protocolMessageType_t type) {
  return type == protocolMsgData
      || type == protocolMsgHeartbeatReq
      || type == protocolMsgHeartbeatAck;
}

static long protocolExpectedSize(const protocolDecoder_t *decoder) {
  if (decoder->offset < ProtocolWireLengthSize) {
    return ProtocolWireLengthSize;
  }
  return ProtocolWireLengthSize + decoder->frame.nbytes;
}

static int protocolLengthToWire(long nbytes, unsigned char out[ProtocolWireLengthSize]) {
  if (nbytes < 0 || nbytes > ProtocolFrameSize) {
    return 0;
  }

  uint32_t wire = htonl((uint32_t)nbytes);
  memcpy(out, &wire, ProtocolWireLengthSize);
  return 1;
}

static int protocolLengthFromWire(const unsigned char in[ProtocolWireLengthSize], long *nbytes) {
  uint32_t wire = 0;
  memcpy(&wire, in, ProtocolWireLengthSize);
  *nbytes = (long)ntohl(wire);
  return *nbytes >= 0 && *nbytes <= ProtocolFrameSize;
}

protocolStatus_t protocolEncode(const void *payload, long nbytes, protocolFrame_t *frame) {
  if (frame == NULL || nbytes <= 0 || nbytes > ProtocolFrameSize) {
    return protocolStatusBadFrame;
  }
  if (payload == NULL) {
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

    if (decoder->offset < ProtocolWireLengthSize) {
      memcpy(decoder->header + decoder->offset, input + totalConsumed, (size_t)remain);
      decoder->offset += remain;
      totalConsumed += remain;

      if (decoder->offset < ProtocolWireLengthSize) {
        continue;
      }
      if (!protocolLengthFromWire(decoder->header, &decoder->frame.nbytes)) {
        if (consumed != NULL) {
          *consumed = totalConsumed;
        }
        return protocolStatusBadFrame;
      }
      if (decoder->frame.nbytes <= 0) {
        if (consumed != NULL) {
          *consumed = totalConsumed;
        }
        return protocolStatusBadFrame;
      }
      continue;
    }

    memcpy(
        decoder->frame.buf + (decoder->offset - ProtocolWireLengthSize),
        input + totalConsumed,
        (size_t)remain);
    decoder->offset += remain;
    totalConsumed += remain;

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

long protocolMessageMaxPayloadSize() {
  return protocolMaxPlaintextSize() - protocolMessageHeaderSize();
}

protocolStatus_t protocolMessageEncodeFrame(const protocolMessage_t *msg, protocolFrame_t *frame) {
  if (msg == NULL || frame == NULL || !protocolMessageTypeValid(msg->type)) {
    return protocolStatusBadFrame;
  }
  if (msg->nbytes < 0 || msg->nbytes > protocolMessageMaxPayloadSize()) {
    return protocolStatusBadFrame;
  }
  if (msg->type == protocolMsgData && msg->nbytes <= 0) {
    return protocolStatusBadFrame;
  }
  if ((msg->type == protocolMsgHeartbeatReq || msg->type == protocolMsgHeartbeatAck) && msg->nbytes != 0) {
    return protocolStatusBadFrame;
  }
  if (msg->nbytes > 0 && msg->buf == NULL) {
    return protocolStatusBadFrame;
  }

  long headerSize = protocolMessageHeaderSize();
  unsigned char wireLength[ProtocolWireLengthSize];
  if (!protocolLengthToWire(msg->nbytes, wireLength)) {
    return protocolStatusBadFrame;
  }
  frame->buf[0] = (char)msg->type;
  memcpy(frame->buf + sizeof(unsigned char), wireLength, ProtocolWireLengthSize);
  if (msg->nbytes > 0) {
    memcpy(frame->buf + headerSize, msg->buf, (size_t)msg->nbytes);
  }
  frame->nbytes = headerSize + msg->nbytes;
  return protocolStatusOk;
}

protocolStatus_t protocolMessageDecodeFrame(const protocolFrame_t *frame, protocolMessage_t *msg) {
  if (frame == NULL || msg == NULL || frame->nbytes < protocolMessageHeaderSize()) {
    return protocolStatusBadFrame;
  }

  protocolMessageType_t type = (protocolMessageType_t)(unsigned char)frame->buf[0];
  if (!protocolMessageTypeValid(type)) {
    return protocolStatusBadFrame;
  }

  long nbytes = 0;
  if (!protocolLengthFromWire((const unsigned char *)(frame->buf + sizeof(unsigned char)), &nbytes)) {
    return protocolStatusBadFrame;
  }
  if (nbytes > protocolMessageMaxPayloadSize()) {
    return protocolStatusBadFrame;
  }

  long expected = protocolMessageHeaderSize() + nbytes;
  if (expected != frame->nbytes) {
    return protocolStatusBadFrame;
  }
  if (type == protocolMsgData && nbytes <= 0) {
    return protocolStatusBadFrame;
  }
  if ((type == protocolMsgHeartbeatReq || type == protocolMsgHeartbeatAck) && nbytes != 0) {
    return protocolStatusBadFrame;
  }

  msg->type = type;
  msg->nbytes = nbytes;
  msg->buf = nbytes > 0 ? frame->buf + protocolMessageHeaderSize() : NULL;
  return protocolStatusOk;
}

protocolStatus_t protocolSecureEncodeMessage(
    const protocolMessage_t *msg, const unsigned char key[ProtocolPskSize], protocolFrame_t *frame) {
  protocolStatus_t status = protocolMessageEncodeFrame(msg, frame);
  if (status != protocolStatusOk) {
    return status;
  }
  return protocolFrameEncrypt(frame, key);
}

protocolStatus_t protocolSecureDecodeFrame(
    protocolFrame_t *frame, const unsigned char key[ProtocolPskSize], protocolMessage_t *msg) {
  protocolStatus_t status = protocolFrameDecrypt(frame, key);
  if (status != protocolStatusOk) {
    return status;
  }
  return protocolMessageDecodeFrame(frame, msg);
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
