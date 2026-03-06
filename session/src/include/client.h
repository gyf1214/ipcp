#pragma once

#include "protocol.h"
#include "sessionInternal.h"

typedef struct client_t {
  ioTunPoller_t *tunPoller;
  ioTcpPoller_t *tcpPoller;
} client_t;

sessionQueueResult_t clientQueueTcpWithBackpressure(
    client_t *runtime,
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    bool *tunReadPaused,
    long *tcpWritePendingNbytes,
    char tcpWritePendingBuf[ProtocolFrameSize],
    const void *data,
    long nbytes);
sessionQueueResult_t clientQueueTunWithBackpressure(
    client_t *runtime,
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    bool *tcpReadPaused,
    long *tunWritePendingNbytes,
    char tunWritePendingBuf[ProtocolFrameSize],
    const void *data,
    long nbytes);
sessionQueueResult_t clientSendMessage(
    client_t *runtime,
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    bool *tunReadPaused,
    long *tcpWritePendingNbytes,
    char tcpWritePendingBuf[ProtocolFrameSize],
    const unsigned char key[ProtocolPskSize],
    const protocolMessage_t *msg);
sessionQueueResult_t clientHandleInboundMessage(
    client_t *runtime,
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    bool *tcpReadPaused,
    long *tunWritePendingNbytes,
    char tunWritePendingBuf[ProtocolFrameSize],
    bool *heartbeatPending,
    long long nowMs,
    long long *lastValidInboundMs,
    long long *lastDataRecvMs,
    const unsigned char key[ProtocolPskSize],
    const protocolMessage_t *msg);
bool clientHeartbeatTick(
    client_t *runtime,
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    bool *heartbeatPending,
    long long nowMs,
    int intervalMs,
    int timeoutMs,
    long long *heartbeatSentMs,
    long long *lastHeartbeatReqMs,
    long long lastDataSentMs,
    long long lastDataRecvMs,
    bool *tunReadPaused,
    long *tcpWritePendingNbytes,
    char tcpWritePendingBuf[ProtocolFrameSize],
    const unsigned char key[ProtocolPskSize]);
bool clientServiceBackpressure(
    client_t *runtime,
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    ioEvent_t event,
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
