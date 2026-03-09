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

typedef enum {
  sessionOverflowNone = 0,
  sessionOverflowToTun,
  sessionOverflowToClient,
} sessionOverflowKind_t;

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
  sessionOverflowKind_t overflowKind;
  int overflowDestSlot;
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
bool sessionOverflowTargetsDestSlot(const session_t *session, int destSlot);
sessionQueueResult_t sessionQueueTunWithBackpressure(
    ioTcpPoller_t *tcpPoller, ioTunPoller_t *tunPoller, session_t *session, const void *data, long nbytes);
sessionQueueResult_t sessionQueueTunWithDrop(ioTunPoller_t *tunPoller, const void *data, long nbytes);
sessionQueueResult_t sessionQueueTcpWithBackpressure(
    ioTcpPoller_t *sourcePoller,
    ioTcpPoller_t *destPoller,
    session_t *session,
    int destSlot,
    const void *data,
    long nbytes);
sessionQueueResult_t sessionQueueTcpWithDrop(
    ioTcpPoller_t *destPoller, session_t *session, int destSlot, const void *data, long nbytes);
bool sessionRetryOverflowToTcp(
    session_t *session, ioTcpPoller_t *sourcePoller, ioTcpPoller_t *destPoller, int destSlot);
bool sessionDropOverflow(session_t *session, ioTcpPoller_t *sourcePoller, int destSlot);
bool sessionRetryOverflow(session_t *session, ioTcpPoller_t *tcpPoller, ioTunPoller_t *tunPoller, ioEvent_t event);
sessionStepResult_t sessionFinalizeStep(
    session_t *session,
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
