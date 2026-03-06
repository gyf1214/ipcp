#pragma once

#include "protocol.h"
#include "sessionInternal.h"

typedef struct client_t {
  ioTunPoller_t *tunPoller;
  ioTcpPoller_t *tcpPoller;
  bool heartbeatPending;
  long long heartbeatSentMs;
  long long lastHeartbeatReqMs;
  long long lastDataSentMs;
  long long lastDataRecvMs;
  int heartbeatIntervalMs;
  int heartbeatTimeoutMs;
} client_t;

void clientResetHeartbeatState(
    client_t *runtime,
    int heartbeatIntervalMs,
    int heartbeatTimeoutMs,
    long long nowMs);

sessionQueueResult_t clientQueueTcpWithBackpressure(
    client_t *runtime,
    bool *tunReadPaused,
    long *tcpWritePendingNbytes,
    char tcpWritePendingBuf[ProtocolFrameSize],
    const void *data,
    long nbytes);
sessionQueueResult_t clientQueueTunWithBackpressure(
    client_t *runtime,
    bool *tcpReadPaused,
    long *tunWritePendingNbytes,
    char tunWritePendingBuf[ProtocolFrameSize],
    const void *data,
    long nbytes);
sessionQueueResult_t clientSendMessage(
    client_t *runtime,
    bool *tunReadPaused,
    long *tcpWritePendingNbytes,
    char tcpWritePendingBuf[ProtocolFrameSize],
    const unsigned char key[ProtocolPskSize],
    long long nowMs,
    const protocolMessage_t *msg);
sessionQueueResult_t clientHandleInboundMessage(
    client_t *runtime,
    bool *tcpReadPaused,
    long *tunWritePendingNbytes,
    char tunWritePendingBuf[ProtocolFrameSize],
    long long nowMs,
    long long *lastValidInboundMs,
    const protocolMessage_t *msg);
bool clientHeartbeatTick(
    client_t *runtime,
    long long nowMs,
    bool *tunReadPaused,
    long *tcpWritePendingNbytes,
    char tcpWritePendingBuf[ProtocolFrameSize],
    const unsigned char key[ProtocolPskSize]);
bool clientServiceBackpressure(
    client_t *runtime,
    bool *tunReadPaused,
    bool *tcpReadPaused,
    long *tcpWritePendingNbytes,
    char tcpWritePendingBuf[ProtocolFrameSize],
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
