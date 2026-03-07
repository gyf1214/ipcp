#pragma once

#include "protocol.h"
#include "sessionInternal.h"

typedef struct client_t {
  ioTunPoller_t *tunPoller;
  ioTcpPoller_t *tcpPoller;
  bool tunReadPaused;
  long tcpWritePendingNbytes;
  char tcpWritePendingBuf[ProtocolFrameSize];
  bool heartbeatPending;
  long long heartbeatSentMs;
  long long lastHeartbeatReqMs;
  long long lastDataSentMs;
  long long lastDataRecvMs;
  int heartbeatIntervalMs;
  int heartbeatTimeoutMs;
} client_t;

void clientResetHeartbeatState(
    client_t *client,
    int heartbeatIntervalMs,
    int heartbeatTimeoutMs,
    long long nowMs);

sessionQueueResult_t clientQueueTcpWithBackpressure(
    client_t *client,
    const void *data,
    long nbytes);
sessionQueueResult_t clientSendMessage(
    client_t *client,
    const unsigned char key[ProtocolPskSize],
    long long nowMs,
    const protocolMessage_t *msg);
sessionQueueResult_t clientHandleInboundMessage(
    client_t *client,
    long long nowMs,
    long long *lastValidInboundMs,
    const protocolMessage_t *msg);
bool clientHeartbeatTick(
    client_t *client,
    long long nowMs,
    const unsigned char key[ProtocolPskSize]);
bool clientServiceBackpressure(
    client_t *client,
    bool *tcpReadPaused,
    long *tunWritePendingNbytes,
    char tunWritePendingBuf[ProtocolFrameSize]);

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
