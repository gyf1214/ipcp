#pragma once

#include "protocol.h"

long protocolMessageMaxPayloadSize();
protocolStatus_t protocolMessageEncodeFrame(const protocolMessage_t *msg, protocolFrame_t *frame);
protocolStatus_t protocolMessageDecodeFrame(const protocolFrame_t *frame, protocolMessage_t *msg);
protocolStatus_t protocolFrameEncrypt(protocolFrame_t *frame, const unsigned char key[ProtocolPskSize]);
protocolStatus_t protocolFrameDecrypt(protocolFrame_t *frame, const unsigned char key[ProtocolPskSize]);
