#pragma once

#include <stdbool.h>

#include "io.h"
#include "protocol.h"

typedef struct session_t session_t;

typedef long long (*sessionNowMsFn_t)(void *ctx);

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
sessionStepResult_t sessionStep(
    session_t *session, ioPoller_t *poller, ioEvent_t event, const unsigned char key[ProtocolPskSize]);
int sessionServeMultiClient(
    int tunFd,
    int listenFd,
    const unsigned char key[ProtocolPskSize],
    const sessionHeartbeatConfig_t *heartbeatCfg,
    int maxSessions);

bool sessionApiSmoke(void);
