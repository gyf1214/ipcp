#pragma once

#define ProtocolFrameSize 4096
#define ProtocolWireLengthSize 4
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
  unsigned char header[ProtocolWireLengthSize];
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
  protocolMsgAuthChallenge = 4,
  protocolMsgClientHello = 5,
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
protocolStatus_t protocolDecoderTakeMessage(protocolDecoder_t *decoder, protocolMessage_t *msg);
protocolStatus_t protocolSecureEncodeMessage(
    const protocolMessage_t *msg, const unsigned char key[ProtocolPskSize], protocolFrame_t *frame);
protocolStatus_t protocolSecureDecoderReadMessage(
    protocolDecoder_t *decoder,
    const unsigned char key[ProtocolPskSize],
    const void *data,
    long nbytes,
    long *consumed,
    protocolMessage_t *msg);
protocolStatus_t protocolSecureDecodeFrame(
    protocolFrame_t *frame, const unsigned char key[ProtocolPskSize], protocolMessage_t *msg);

long protocolMaxPlaintextSize();
