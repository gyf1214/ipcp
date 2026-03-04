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
  unsigned char key[ProtocolPskSize];
  unsigned char claim[SessionClaimSize];
  long claimNbytes;
  bool active;
} activeConn_t;

struct server_t {
  int listenFd;
  int epollFd;
  ioTunPoller_t tunPoller;
  int pendingOwnerSlot;
  long pendingTunToTcpNbytes;
  unsigned char pendingTunToTcpBuf[ProtocolFrameSize];
  int retryCursor;
  int maxActiveSessions;
  int activeCount;
  activeConn_t *activeConns;
  int maxPreAuthSessions;
  int preAuthCount;
  preAuthConn_t *preAuthConns;
  sessionHeartbeatConfig_t heartbeatCfg;
  sessionNowMsFn_t nowMsFn;
  void *nowCtx;
};

bool serverInit(
    server_t *runtime,
    int tunFd,
    int listenFd,
    int maxActiveSessions,
    int maxPreAuthSessions,
    const sessionHeartbeatConfig_t *heartbeatCfg,
    sessionNowMsFn_t nowMsFn,
    void *nowCtx);
void serverDeinit(server_t *runtime);

int serverAddClient(
    server_t *runtime,
    int activeSlot,
    int connFd,
    const unsigned char key[ProtocolPskSize],
    const unsigned char *claim,
    long claimNbytes);
bool serverRemoveClient(server_t *runtime, int slot);

int serverFindSlotByFd(const server_t *runtime, int connFd);
int serverFindSlotByClaim(const server_t *runtime, const unsigned char *claim, long claimNbytes);
int serverFindPreAuthSlotByFd(const server_t *runtime, int connFd);
int serverPickEgressClient(const server_t *runtime);
int serverClientCount(const server_t *runtime);
long serverQueuedTunBytes(const server_t *runtime);
long long serverNowMs(const server_t *runtime);

bool serverSyncTunWriteInterest(server_t *runtime);
bool serverQueueTunWrite(server_t *runtime, const void *data, long nbytes);
bool serverServiceTunWriteEvent(server_t *runtime);
int serverRetryBlockedTunRoundRobin(server_t *runtime);
bool serverSetTunReadEnabled(server_t *runtime, bool enabled);
bool serverHasPendingTunToTcp(const server_t *runtime);
int serverPendingTunToTcpOwner(const server_t *runtime);
bool serverStorePendingTunToTcp(server_t *runtime, int ownerSlot, const void *data, long nbytes);
serverPendingRetry_t serverRetryPendingTunToTcp(
    server_t *runtime, int ownerSlot, ioTcpPoller_t *ownerPoller);
bool serverDropPendingTunToTcpByOwner(server_t *runtime, int ownerSlot);

session_t *serverSessionAt(server_t *runtime, int slot);
int serverConnFdAt(const server_t *runtime, int slot);
const unsigned char *serverKeyAt(const server_t *runtime, int slot);
bool serverHasActiveClaim(const server_t *runtime, const unsigned char *claim, long claimNbytes);
bool serverRouteTunIngressPacket(server_t *runtime, const char *ifModeLabel, const void *packet, long packetNbytes);

int serverCreatePreAuthConn(server_t *runtime, int connFd, long long authDeadlineMs);
bool serverRemovePreAuthConn(server_t *runtime, int preAuthSlot);
preAuthConn_t *serverPreAuthAt(server_t *runtime, int preAuthSlot);
bool serverPromoteToActiveSlot(server_t *runtime, int preAuthSlot);

int serverServeMultiClient(
    int tunFd,
    int listenFd,
    sessionServerResolveClaimFn_t resolveClaimFn,
    void *resolveClaimCtx,
    const char *ifModeLabel,
    int authTimeoutMs,
    const sessionHeartbeatConfig_t *heartbeatCfg,
    int maxActiveSessions,
    int maxPreAuthSessions);
