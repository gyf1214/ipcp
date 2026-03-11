#pragma once

#include <stdbool.h>

#include "sessionInternal.h"

typedef struct server_t server_t;

typedef enum {
  serverPendingRetryQueued = 0,
  serverPendingRetryBlocked,
  serverPendingRetryError,
} serverPendingRetry_t;

typedef struct {
  int connFd;
  long long authDeadlineMs;
  int resolvedActiveSlot;
  unsigned char resolvedKey[ProtocolPskSize];
  unsigned char serverNonce[ProtocolNonceSize];
  unsigned char claim[SessionClaimSize];
  long claimNbytes;
  protocolDecoder_t decoder;
  char tcpReadCarryBuf[ProtocolFrameSize];
  long tcpReadCarryNbytes;
  char authWriteBuf[ProtocolFrameSize];
  long authWriteOffset;
  long authWriteNbytes;
  int authState;
  bool active;
} preAuthConn_t;

typedef struct {
  int connFd;
  session_t *session;
  ioTcpPoller_t tcpPoller;
  const unsigned char *keyRef;
  int keySlot;
  unsigned char claim[SessionClaimSize];
  long claimNbytes;
  bool heartbeatAckPending;
  bool active;
} activeConn_t;

struct server_t {
  int listenFd;
  int epollFd;
  ioReactor_t reactor;
  ioTunPoller_t tunPoller;
  bool tunReadPaused;
  int pendingOwnerSlot;
  long runtimeOverflowNbytes;
  unsigned char runtimeOverflowBuf[ProtocolFrameSize];
  unsigned char *authoritativeKeys;
  int retryCursor;
  int maxActiveSessions;
  int activeCount;
  activeConn_t *activeConns;
  int maxPreAuthSessions;
  int preAuthCount;
  preAuthConn_t *preAuthConns;
  sessionServerIdentity_t serverIdentity;
  sessionIfMode_t mode;
  sessionHeartbeatConfig_t heartbeatCfg;
  sessionNowMsFn_t nowMsFn;
  void *nowCtx;
};

bool serverInit(
    server_t *server,
    int tunFd,
    int listenFd,
    int maxActiveSessions,
    int maxPreAuthSessions,
    const sessionHeartbeatConfig_t *heartbeatCfg,
    sessionNowMsFn_t nowMsFn,
    void *nowCtx);
void serverDeinit(server_t *server);

int serverAddClient(
    server_t *server,
    int activeSlot,
    int connFd,
    const unsigned char key[ProtocolPskSize],
    const unsigned char *claim,
    long claimNbytes);
bool serverRemoveClient(server_t *server, int slot);

int serverFindSlotByFd(const server_t *server, int connFd);
int serverFindSlotByClaim(const server_t *server, const unsigned char *claim, long claimNbytes);
int serverFindPreAuthSlotByFd(const server_t *server, int connFd);
int serverPickEgressClient(const server_t *server);
int serverClientCount(const server_t *server);
long long serverNowMs(const server_t *server);

bool serverServiceTunWriteEvent(server_t *server);
int serverRetryBlockedTunRoundRobin(server_t *server);
bool serverSetTunReadEnabled(server_t *server, bool enabled);
bool serverHasPendingTunToTcp(const server_t *server);
int serverPendingTunToTcpOwner(const server_t *server);
bool serverStorePendingTunToTcp(server_t *server, int ownerSlot, const void *data, long nbytes);
serverPendingRetry_t serverRetryPendingTunToTcp(
    server_t *server, int ownerSlot, ioTcpPoller_t *ownerPoller);
bool serverDropPendingTunToTcpByOwner(server_t *server, int ownerSlot);
sessionQueueResult_t serverQueueTcpWithBackpressure(
    server_t *server, ioTcpPoller_t *tcpPoller, const void *data, long nbytes);
sessionQueueResult_t serverQueueTcpWithDrop(
    ioTcpPoller_t *tcpPoller, const void *data, long nbytes);
sessionQueueResult_t serverSendMessage(
    server_t *server,
    ioTcpPoller_t *tcpPoller,
    const unsigned char key[ProtocolPskSize],
    const protocolMessage_t *msg);
sessionQueueResult_t serverHandleInboundMessage(
    server_t *server,
    ioTcpPoller_t *tcpPoller,
    const unsigned char key[ProtocolPskSize],
    long long *lastValidInboundMs,
    const protocolMessage_t *msg);
bool serverHeartbeatTick(long long nowMs, long long lastValidInboundMs, long long timeoutMs);
bool serverServiceBackpressure(server_t *server, int slot, ioEvent_t event);

session_t *serverSessionAt(server_t *server, int slot);
int serverConnFdAt(const server_t *server, int slot);
const unsigned char *serverKeyAt(const server_t *server, int slot);
const unsigned char *serverAuthoritativeKeyAt(const server_t *server, int slot);
bool serverHasActiveClaim(const server_t *server, const unsigned char *claim, long claimNbytes);
bool serverRouteTunIngressPacket(server_t *server, const void *packet, long packetNbytes);
bool serverRouteTcpIngressPacket(server_t *server, int sourceConnFd, const void *packet, long packetNbytes);

int serverCreatePreAuthConn(server_t *server, int connFd, long long authDeadlineMs);
bool serverRemovePreAuthConn(server_t *server, int preAuthSlot);
preAuthConn_t *serverPreAuthAt(server_t *server, int preAuthSlot);
bool serverPromoteToActiveSlot(server_t *server, int preAuthSlot);

int serverServeMultiClient(
    int tunFd,
    int listenFd,
    sessionServerResolveClaimFn_t resolveClaimFn,
    void *resolveClaimCtx,
    sessionIfMode_t mode,
    const sessionServerIdentity_t *serverIdentity,
    int authTimeoutMs,
    const sessionHeartbeatConfig_t *heartbeatCfg,
    int maxActiveSessions,
    int maxPreAuthSessions);
