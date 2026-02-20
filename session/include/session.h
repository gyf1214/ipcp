#pragma once

#include <stdbool.h>

#include "io.h"
#include "protocol.h"

typedef struct session_t session_t;
struct serverRuntime_t;

typedef long long (*sessionNowMsFn_t)(void *ctx);
typedef int (*sessionServerKeyLookupFn_t)(void *ctx, const char *claim, unsigned char key[ProtocolPskSize]);

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
  long pendingTcpNbytes;
  long pendingTunNbytes;
  long tcpBufferedNbytes;
} sessionStats_t;

session_t *sessionCreate(
    bool isServer, const sessionHeartbeatConfig_t *heartbeatCfg, sessionNowMsFn_t nowFn, void *nowCtx);
void sessionDestroy(session_t *session);
void sessionReset(session_t *session);
bool sessionGetStats(const session_t *session, sessionStats_t *outStats);
void sessionSetServerRuntime(session_t *session, struct serverRuntime_t *runtime);
bool sessionHasPendingTunEgress(const session_t *session);
bool sessionServiceBackpressure(session_t *session, ioPoller_t *poller);
sessionStepResult_t sessionStep(
    session_t *session, ioPoller_t *poller, ioEvent_t event, const unsigned char key[ProtocolPskSize]);
int sessionServeMultiClient(
    int tunFd,
    int listenFd,
    sessionServerKeyLookupFn_t keyLookupFn,
    void *keyLookupCtx,
    const char *ifModeLabel,
    int authTimeoutMs,
    const sessionHeartbeatConfig_t *heartbeatCfg,
    int maxSessions);

bool sessionApiSmoke(void);
