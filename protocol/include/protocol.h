#pragma once

#define ProtocolFrameSize 4096
#define ProtocolPskSize 32
#define ProtocolNonceSize 24
#define ProtocolAuthTagSize 16

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

typedef enum {
  protocolMsgData = 1,
  protocolMsgHeartbeatReq = 2,
  protocolMsgHeartbeatAck = 3,
} protocolMessageType_t;

typedef struct {
  protocolMessageType_t type;
  long nbytes;
  const char *buf;
} protocolMessage_t;

protocolStatus_t protocolEncode(const void *payload, long nbytes, protocolFrame_t *frame);
void protocolDecoderInit(protocolDecoder_t *decoder);
protocolStatus_t protocolDecodeFeed(
    protocolDecoder_t *decoder, const void *data, long nbytes, long *consumed);
int protocolDecoderHasFrame(const protocolDecoder_t *decoder);
protocolStatus_t protocolDecoderTake(protocolDecoder_t *decoder, protocolFrame_t *frame);
long protocolMessageMaxPayloadSize();
protocolStatus_t protocolMessageEncodeFrame(const protocolMessage_t *msg, protocolFrame_t *frame);
protocolStatus_t protocolMessageDecodeFrame(const protocolFrame_t *frame, protocolMessage_t *msg);

long protocolMaxPlaintextSize();
protocolStatus_t protocolFrameEncrypt(protocolFrame_t *frame, const unsigned char key[ProtocolPskSize]);
protocolStatus_t protocolFrameDecrypt(protocolFrame_t *frame, const unsigned char key[ProtocolPskSize]);
