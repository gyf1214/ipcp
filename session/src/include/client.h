#pragma once

#include "protocol.h"

int clientWriteRawMsg(int fd, const protocolRawMsg_t *msg);
int clientWriteSecureMsg(
    int fd, const protocolMessage_t *msg, const unsigned char key[ProtocolPskSize]);
