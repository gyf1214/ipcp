#pragma once

#include <stdbool.h>

#include "session.h"

#define SessionClaimSize 128

typedef struct serverRuntime_t serverRuntime_t;

typedef enum {
  serverRuntimePendingRetryQueued = 0,
  serverRuntimePendingRetryBlocked,
  serverRuntimePendingRetryError,
} serverRuntimePendingRetry_t;

typedef struct {
  int connFd;
  long long authDeadlineMs;
  int resolvedActiveSlot;
  unsigned char resolvedKey[ProtocolPskSize];
  unsigned char serverNonce[ProtocolNonceSize];
  char claim[SessionClaimSize];
  protocolDecoder_t decoder;
  char tcpReadCarryBuf[ProtocolFrameSize];
  long tcpReadCarryNbytes;
  char authWriteBuf[ProtocolWireLengthSize + ProtocolFrameSize];
  long authWriteOffset;
  long authWriteNbytes;
  int authState;
  bool active;
} preAuthConn_t;

typedef struct {
  int connFd;
  session_t *session;
  ioPoller_t poller;
  unsigned char key[ProtocolPskSize];
  char claim[SessionClaimSize];
  bool active;
} activeConn_t;

struct serverRuntime_t {
  int tunFd;
  int listenFd;
  int epollFd;
  unsigned int tunEvents;
  long tunOutOffset;
  long tunOutNbytes;
  unsigned char tunOutBuf[IoPollerQueueCapacity];
  int pendingOwnerSlot;
  long pendingTunToTcpNbytes;
  unsigned char pendingTunToTcpBuf[ProtocolWireLengthSize + ProtocolFrameSize];
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

bool serverRuntimeInit(
    serverRuntime_t *runtime,
    int tunFd,
    int listenFd,
    int maxActiveSessions,
    int maxPreAuthSessions,
    const sessionHeartbeatConfig_t *heartbeatCfg,
    sessionNowMsFn_t nowMsFn,
    void *nowCtx);
void serverRuntimeDeinit(serverRuntime_t *runtime);

int serverRuntimeAddClient(
    serverRuntime_t *runtime,
    int activeSlot,
    int connFd,
    const unsigned char key[ProtocolPskSize],
    const char *claim);
bool serverRuntimeRemoveClient(serverRuntime_t *runtime, int slot);

int serverRuntimeFindSlotByFd(const serverRuntime_t *runtime, int connFd);
int serverRuntimeFindPreAuthSlotByFd(const serverRuntime_t *runtime, int connFd);
int serverRuntimePickEgressClient(const serverRuntime_t *runtime);
int serverRuntimeClientCount(const serverRuntime_t *runtime);
long serverRuntimeQueuedTunBytes(const serverRuntime_t *runtime);
long long serverRuntimeNowMs(const serverRuntime_t *runtime);

bool serverRuntimeSyncTunWriteInterest(serverRuntime_t *runtime);
bool serverRuntimeQueueTunWrite(serverRuntime_t *runtime, const void *data, long nbytes);
bool serverRuntimeServiceTunWriteEvent(serverRuntime_t *runtime);
int serverRuntimeRetryBlockedTunRoundRobin(serverRuntime_t *runtime);
bool serverRuntimeSetTunReadEnabled(serverRuntime_t *runtime, bool enabled);
bool serverRuntimeHasPendingTunToTcp(const serverRuntime_t *runtime);
int serverRuntimePendingTunToTcpOwner(const serverRuntime_t *runtime);
bool serverRuntimeStorePendingTunToTcp(serverRuntime_t *runtime, int ownerSlot, const void *data, long nbytes);
serverRuntimePendingRetry_t serverRuntimeRetryPendingTunToTcp(
    serverRuntime_t *runtime, int ownerSlot, ioPoller_t *ownerPoller);
bool serverRuntimeDropPendingTunToTcpByOwner(serverRuntime_t *runtime, int ownerSlot);

session_t *serverRuntimeSessionAt(serverRuntime_t *runtime, int slot);
int serverRuntimeConnFdAt(const serverRuntime_t *runtime, int slot);
const unsigned char *serverRuntimeKeyAt(const serverRuntime_t *runtime, int slot);
bool serverRuntimeHasActiveClaim(const serverRuntime_t *runtime, const char *claim);

int serverRuntimeCreatePreAuthConn(serverRuntime_t *runtime, int connFd, long long authDeadlineMs);
bool serverRuntimeRemovePreAuthConn(serverRuntime_t *runtime, int preAuthSlot);
preAuthConn_t *serverRuntimePreAuthAt(serverRuntime_t *runtime, int preAuthSlot);
bool serverRuntimePromoteToActiveSlot(serverRuntime_t *runtime, int preAuthSlot);
