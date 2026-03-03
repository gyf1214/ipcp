#pragma once

#include <stdbool.h>

#include "io.h"
#include "protocol.h"

#define SessionClaimSize 16

typedef struct session_t session_t;
struct server_t;

typedef long long (*sessionNowMsFn_t)(void *ctx);
typedef int (*sessionServerResolveClaimFn_t)(
    void *ctx,
    const unsigned char *claim,
    long claimNbytes,
    unsigned char key[ProtocolPskSize],
    int *outActiveSlot);

typedef struct {
  int intervalMs;
  int timeoutMs;
} sessionHeartbeatConfig_t;

typedef enum {
  sessionStepContinue = 0,
  sessionStepStop,
} sessionStepResult_t;

typedef struct {
  bool isServer;
  long long lastValidInboundMs;
  long long lastDataSentMs;
  long long lastDataRecvMs;
  bool heartbeatPending;
  long long heartbeatSentMs;
  long long lastHeartbeatReqMs;
  bool tunReadPaused;
  bool tcpReadPaused;
  long tcpWritePendingNbytes;
  long tunWritePendingNbytes;
  long tcpReadCarryNbytes;
} sessionStats_t;

session_t *sessionCreate(
    bool isServer, const sessionHeartbeatConfig_t *heartbeatCfg, sessionNowMsFn_t nowFn, void *nowCtx);
void sessionDestroy(session_t *session);
void sessionReset(session_t *session);
bool sessionGetStats(const session_t *session, sessionStats_t *outStats);
void sessionSetServer(session_t *session, struct server_t *runtime);
bool sessionPromoteFromPreAuth(
    session_t *session,
    const protocolDecoder_t *decoder,
    const char *carryBuf,
    long carryNbytes);
bool sessionHasPendingTunEgress(const session_t *session);
bool sessionServiceBackpressure(session_t *session, ioTcpPoller_t *tcpPoller, ioTunPoller_t *tunPoller);
sessionStepResult_t sessionStep(
    session_t *session,
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    ioEvent_t event,
    const unsigned char key[ProtocolPskSize]);
int sessionServeMultiClient(
    int tunFd,
    int listenFd,
    sessionServerResolveClaimFn_t resolveClaimFn,
    void *resolveClaimCtx,
    const char *ifModeLabel,
    int authTimeoutMs,
    const sessionHeartbeatConfig_t *heartbeatCfg,
    int maxActiveSessions,
    int maxPreAuthSessions);
int sessionServeClient(
    int tunFd,
    int connFd,
    const unsigned char *claim,
    long claimNbytes,
    const unsigned char key[ProtocolPskSize],
    const sessionHeartbeatConfig_t *heartbeatCfg);

bool sessionApiSmoke(void);
