#pragma once

#include "protocol.h"
#include "sessionInternal.h"

typedef struct client_t {
  ioTunPoller_t *tunPoller;
  ioTcpPoller_t *tcpPoller;
} client_t;

int clientWriteRawMsg(int fd, const protocolRawMsg_t *msg);
int clientReadRawMsg(int fd, protocolRawMsg_t *msg);
int clientWriteSecureMsg(
    int fd, const protocolMessage_t *msg, const unsigned char key[ProtocolPskSize]);
int clientReadSecureMsg(int fd, const unsigned char key[ProtocolPskSize], protocolMessage_t *msg);
int clientServeConn(
    int tunFd,
    int connFd,
    const unsigned char *claim,
    long claimNbytes,
    const unsigned char key[ProtocolPskSize],
    const sessionHeartbeatConfig_t *heartbeatCfg);
