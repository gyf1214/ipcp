#pragma once

#include <stdbool.h>

#include "io.h"
#include "protocol.h"
#include "session.h"

typedef struct session_t session_t;
struct server_t;
struct client_t;

typedef long long (*sessionNowMsFn_t)(void *ctx);

typedef enum {
  sessionStepContinue = 0,
  sessionStepStop,
} sessionStepResult_t;

typedef enum {
  sessionQueueResultQueued = 0,
  sessionQueueResultBlocked,
  sessionQueueResultError,
} sessionQueueResult_t;

struct session_t {
  bool isServer;
  void *runtime;
  sessionNowMsFn_t nowFn;
  void *nowCtx;
  protocolDecoder_t tcpDecoder;
  char tcpReadBuf[ProtocolFrameSize];
  char tcpReadCarryBuf[ProtocolFrameSize];
  long tcpReadCarryNbytes;
  long long lastValidInboundMs;
  int heartbeatIntervalMs;
  int heartbeatTimeoutMs;
  bool tcpReadPaused;
  long overflowNbytes;
  char overflowBuf[ProtocolFrameSize];
};

session_t *sessionCreate(
    bool isServer, const sessionHeartbeatConfig_t *heartbeatCfg, sessionNowMsFn_t nowFn, void *nowCtx);
void sessionDestroy(session_t *session);
void sessionReset(session_t *session);
void sessionAttachServer(session_t *session, struct server_t *server);
void sessionAttachClient(session_t *session, struct client_t *client);
bool sessionPromoteFromPreAuth(
    session_t *session,
    const protocolDecoder_t *decoder,
    const char *carryBuf,
    long carryNbytes);
bool sessionHasOverflow(const session_t *session);
bool sessionRetryOverflow(session_t *session, ioTcpPoller_t *tcpPoller, ioTunPoller_t *tunPoller);
sessionStepResult_t sessionFinalizeStep(
    session_t *session,
    ioTcpPoller_t *tcpPoller,
    ioEvent_t event,
    const unsigned char key[ProtocolPskSize]);
sessionStepResult_t sessionHandleConnEvent(
    session_t *session,
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    ioEvent_t event,
    const unsigned char key[ProtocolPskSize]);
sessionStepResult_t sessionStep(
    session_t *session,
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    ioEvent_t event,
    const unsigned char key[ProtocolPskSize]);

bool sessionApiSmoke(void);
