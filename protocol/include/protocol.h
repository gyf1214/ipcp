#pragma once

#define ProtocolFrameSize 4096

typedef struct {
  long nbytes;
  char buf[ProtocolFrameSize];
} protocolFrame_t;

typedef struct {
  protocolFrame_t frame;
  long offset;
  int hasFrame;
} protocolDecoder_t;

typedef enum {
  protocolStatusOk,
  protocolStatusNeedMore,
  protocolStatusBadFrame,
} protocolStatus_t;

protocolStatus_t protocolEncode(const void *payload, long nbytes, protocolFrame_t *frame);
void protocolDecoderInit(protocolDecoder_t *decoder);
protocolStatus_t protocolDecodeFeed(
    protocolDecoder_t *decoder, const void *data, long nbytes, long *consumed);
int protocolDecoderHasFrame(const protocolDecoder_t *decoder);
protocolStatus_t protocolDecoderTake(protocolDecoder_t *decoder, protocolFrame_t *frame);
