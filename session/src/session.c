#include "sessionInternal.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "client.h"
#include "server.h"

struct session_t {
  bool isServer;
  server_t *runtime;
  sessionNowMsFn_t nowFn;
  void *nowCtx;
  protocolDecoder_t tcpDecoder;
  char tcpReadBuf[ProtocolFrameSize];
  char tcpReadCarryBuf[ProtocolFrameSize];
  long tcpReadCarryNbytes;
  long long lastValidInboundMs;
  long long lastDataSentMs;
  long long lastDataRecvMs;
  int heartbeatIntervalMs;
  int heartbeatTimeoutMs;
  bool heartbeatPending;
  long long heartbeatSentMs;
  long long lastHeartbeatReqMs;
  bool tunReadPaused;
  bool tcpReadPaused;
  long tcpWritePendingNbytes;
  char tcpWritePendingBuf[ProtocolWireLengthSize + ProtocolFrameSize];
  long tunWritePendingNbytes;
  char tunWritePendingBuf[ProtocolFrameSize];
};

typedef enum {
  queueResultQueued = 0,
  queueResultBlocked,
  queueResultError,
} queueResult_t;

static long long defaultNowMs(void *ctx) {
  struct timespec ts;
  (void)ctx;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long long)ts.tv_sec * 1000 + (long long)ts.tv_nsec / 1000000;
}

static long long sessionNowMs(const session_t *session) {
  return session->nowFn(session->nowCtx);
}

static long long heartbeatTimeoutMs(const session_t *session) {
  return session->heartbeatTimeoutMs;
}

static long messageHeaderSize(void) {
  return (long)sizeof(unsigned char) + ProtocolWireLengthSize;
}

static bool pauseReadSource(
    ioTcpPoller_t *tcpPoller, ioTunPoller_t *tunPoller, ioSource_t source, bool *paused) {
  if (*paused) {
    return true;
  }
  if (source == ioSourceTun) {
    if (!ioTunSetReadEnabled(tunPoller, false)) {
      return false;
    }
  } else {
    if (!ioTcpSetReadEnabled(tcpPoller, false)) {
      return false;
    }
  }
  *paused = true;
  return true;
}

static bool canToggleReadInterest(const session_t *session, ioSource_t source) {
  if (session != NULL && session->isServer && session->runtime != NULL && source == ioSourceTun) {
    return false;
  }
  return true;
}

static bool pauseReadSourceForSession(
    session_t *session, ioTcpPoller_t *tcpPoller, ioTunPoller_t *tunPoller, ioSource_t source, bool *paused) {
  if (*paused) {
    return true;
  }
  if (!canToggleReadInterest(session, source)) {
    *paused = true;
    return true;
  }
  return pauseReadSource(tcpPoller, tunPoller, source, paused);
}

static long queuedBytesForDestination(
    const session_t *session, ioTcpPoller_t *tcpPoller, ioTunPoller_t *tunPoller, ioSource_t destination) {
  if (session != NULL && session->isServer && session->runtime != NULL && destination == ioSourceTun) {
    return serverQueuedTunBytes(session->runtime);
  }
  if (destination == ioSourceTun) {
    return ioTunQueuedBytes(tunPoller);
  }
  return ioTcpQueuedBytes(tcpPoller);
}

static bool maybeResumeReadSource(
    session_t *session,
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    ioSource_t source,
    ioSource_t destination,
    bool *paused,
    long pendingNbytes) {
  long queued;
  if (!*paused || pendingNbytes > 0) {
    return true;
  }

  queued = queuedBytesForDestination(session, tcpPoller, tunPoller, destination);
  if (queued < 0) {
    return false;
  }
  if (queued > IoPollerLowWatermark) {
    return true;
  }
  if (!canToggleReadInterest(session, source)) {
    *paused = false;
    return true;
  }
  if (source == ioSourceTun) {
    if (!ioTunSetReadEnabled(tunPoller, true)) {
      return false;
    }
  } else {
    if (!ioTcpSetReadEnabled(tcpPoller, true)) {
      return false;
    }
  }
  *paused = false;
  return true;
}

static queueResult_t queueTcpWithBackpressure(
    ioTcpPoller_t *tcpPoller, ioTunPoller_t *tunPoller, session_t *session, const void *data, long nbytes) {
  long queued;
  int ownerSlot;

  if (session->tcpWritePendingNbytes > 0) {
    return queueResultBlocked;
  }
  if (session->isServer && session->runtime != NULL && serverHasPendingTunToTcp(session->runtime)) {
    session->tunReadPaused = true;
    return queueResultBlocked;
  }
  if (ioTcpWrite(tcpPoller, data, nbytes)) {
    return queueResultQueued;
  }

  queued = ioTcpQueuedBytes(tcpPoller);
  if (queued < 0) {
    return queueResultError;
  }
  if (queued + nbytes > IoPollerQueueCapacity) {
    if (session->isServer && session->runtime != NULL) {
      ownerSlot = serverFindSlotByFd(session->runtime, tcpPoller->tcpFd);
      if (ownerSlot < 0) {
        return queueResultError;
      }
      if (!serverStorePendingTunToTcp(session->runtime, ownerSlot, data, nbytes)) {
        return queueResultError;
      }
      session->tunReadPaused = true;
      return queueResultBlocked;
    }
    memcpy(session->tcpWritePendingBuf, data, (size_t)nbytes);
    session->tcpWritePendingNbytes = nbytes;
    if (!pauseReadSourceForSession(session, tcpPoller, tunPoller, ioSourceTun, &session->tunReadPaused)) {
      return queueResultError;
    }
    return queueResultBlocked;
  }
  return queueResultError;
}

static queueResult_t queueTunWithBackpressure(
    ioTcpPoller_t *tcpPoller, ioTunPoller_t *tunPoller, session_t *session, const void *data, long nbytes) {
  long queued;

  if (session->tunWritePendingNbytes > 0) {
    return queueResultBlocked;
  }
  if (session->isServer && session->runtime != NULL) {
    if (serverQueueTunWrite(session->runtime, data, nbytes)) {
      return queueResultQueued;
    }
    queued = serverQueuedTunBytes(session->runtime);
  } else if (ioTunWrite(tunPoller, data, nbytes)) {
    return queueResultQueued;
  } else {
    queued = ioTunQueuedBytes(tunPoller);
  }
  if (queued < 0) {
    return queueResultError;
  }
  if (queued + nbytes > IoPollerQueueCapacity) {
    memcpy(session->tunWritePendingBuf, data, (size_t)nbytes);
    session->tunWritePendingNbytes = nbytes;
    if (!pauseReadSourceForSession(session, tcpPoller, tunPoller, ioSourceTcp, &session->tcpReadPaused)) {
      return queueResultError;
    }
    return queueResultBlocked;
  }
  return queueResultError;
}

static bool serviceBackpressure(
    ioTcpPoller_t *tcpPoller, ioTunPoller_t *tunPoller, session_t *session, ioEvent_t event) {
  long queued;
  bool serverMode;

  serverMode = session->isServer && session->runtime != NULL;

  if (serverMode && serverHasPendingTunToTcp(session->runtime)) {
    int ownerSlot = serverPendingTunToTcpOwner(session->runtime);
    int slot = serverFindSlotByFd(session->runtime, tcpPoller->tcpFd);
    if (slot < 0) {
      return false;
    }
    if (event == ioEventTcpWrite && slot == ownerSlot) {
      serverPendingRetry_t retry =
          serverRetryPendingTunToTcp(session->runtime, ownerSlot, tcpPoller);
      if (retry == serverPendingRetryError) {
        return false;
      }
    }
  }

  if (!serverMode && session->tcpWritePendingNbytes > 0) {
    if (ioTcpWrite(tcpPoller, session->tcpWritePendingBuf, session->tcpWritePendingNbytes)) {
      session->tcpWritePendingNbytes = 0;
    } else {
      queued = ioTcpQueuedBytes(tcpPoller);
      if (queued < 0 || queued + session->tcpWritePendingNbytes <= IoPollerQueueCapacity) {
        return false;
      }
    }
  }

  if (session->tunWritePendingNbytes > 0) {
    bool queuedTun = false;
    if (session->isServer && session->runtime != NULL) {
      queuedTun = serverQueueTunWrite(session->runtime, session->tunWritePendingBuf, session->tunWritePendingNbytes);
    } else {
      queuedTun = ioTunWrite(tunPoller, session->tunWritePendingBuf, session->tunWritePendingNbytes);
    }
    if (queuedTun) {
      session->tunWritePendingNbytes = 0;
    } else {
      queued = queuedBytesForDestination(session, tcpPoller, tunPoller, ioSourceTun);
      if (queued < 0 || queued + session->tunWritePendingNbytes <= IoPollerQueueCapacity) {
        return false;
      }
    }
  }

  if (!maybeResumeReadSource(
          session, tcpPoller, tunPoller, ioSourceTcp, ioSourceTun, &session->tcpReadPaused,
          session->tunWritePendingNbytes)) {
    return false;
  }

  if (serverMode) {
    if (serverHasPendingTunToTcp(session->runtime)) {
      session->tunReadPaused = true;
      return true;
    }

    queued = ioTcpQueuedBytes(tcpPoller);
    if (queued < 0) {
      return false;
    }
    if (queued > IoPollerLowWatermark) {
      session->tunReadPaused = true;
      return true;
    }
    if (!serverSetTunReadEnabled(session->runtime, true)) {
      return false;
    }
    session->tunReadPaused = false;
    return true;
  }

  return maybeResumeReadSource(
      session, tcpPoller, tunPoller, ioSourceTun, ioSourceTcp, &session->tunReadPaused, session->tcpWritePendingNbytes);
}

static queueResult_t sendMessage(
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    const unsigned char key[ProtocolPskSize],
    session_t *session,
    const protocolMessage_t *msg) {
  protocolFrame_t frame;
  char wireBuf[ProtocolWireLengthSize + ProtocolFrameSize];
  long wireNbytes;
  uint32_t wireLength;

  if (protocolEncodeSecureMsg(msg, key, &frame) != protocolStatusOk) {
    return queueResultError;
  }

  wireLength = htonl((uint32_t)frame.nbytes);
  memcpy(wireBuf, &wireLength, ProtocolWireLengthSize);
  memcpy(wireBuf + ProtocolWireLengthSize, frame.buf, (size_t)frame.nbytes);
  wireNbytes = ProtocolWireLengthSize + frame.nbytes;
  return queueTcpWithBackpressure(tcpPoller, tunPoller, session, wireBuf, wireNbytes);
}

static bool pipeTun(
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    const unsigned char key[ProtocolPskSize],
    session_t *session) {
  char payload[ProtocolFrameSize];
  long maxPayload = protocolMaxPlaintextSize() - messageHeaderSize();
  long nbytes = 0;
  ioStatus_t status;
  protocolMessage_t msg;
  queueResult_t result;

  if (maxPayload <= 0) {
    return false;
  }

  status = ioTunRead(tunPoller->tunFd, payload, maxPayload, &nbytes);
  if (status == ioStatusWouldBlock) {
    return true;
  }
  if (status != ioStatusOk) {
    return false;
  }

  msg.type = protocolMsgData;
  msg.nbytes = nbytes;
  msg.buf = payload;
  result = sendMessage(tcpPoller, tunPoller, key, session, &msg);
  if (result == queueResultError) {
    return false;
  }
  if (result == queueResultBlocked) {
    return true;
  }

  if (!session->isServer) {
    session->lastDataSentMs = sessionNowMs(session);
  }

  dbgf("sent %ld bytes of data", nbytes);
  return true;
}

static queueResult_t handleInboundMessage(
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    const unsigned char key[ProtocolPskSize],
    session_t *session,
    const protocolMessage_t *msg) {
  long long now = sessionNowMs(session);
  session->lastValidInboundMs = now;

  if (msg->type == protocolMsgData) {
    queueResult_t result = queueTunWithBackpressure(tcpPoller, tunPoller, session, msg->buf, msg->nbytes);
    if (result != queueResultQueued) {
      return result;
    }
    if (!session->isServer) {
      session->lastDataRecvMs = now;
    }
    dbgf("received %ld bytes of data", msg->nbytes);
    return queueResultQueued;
  }

  if (msg->type == protocolMsgHeartbeatReq) {
    protocolMessage_t ack;
    queueResult_t result;
    if (!session->isServer) {
      logf("unexpected heartbeat request on client");
      return queueResultError;
    }

    ack.type = protocolMsgHeartbeatAck;
    ack.nbytes = 0;
    ack.buf = NULL;
    result = sendMessage(tcpPoller, tunPoller, key, session, &ack);
    if (result != queueResultQueued) {
      return result;
    }
    dbgf("heartbeat request received, sent ack");
    return queueResultQueued;
  }

  if (msg->type == protocolMsgHeartbeatAck) {
    if (session->isServer || !session->heartbeatPending) {
      logf("unexpected heartbeat ack");
      return queueResultError;
    }

    session->heartbeatPending = false;
    dbgf("heartbeat ack received");
    return queueResultQueued;
  }

  return queueResultError;
}

static bool pipeTcpBytes(
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    const unsigned char key[ProtocolPskSize],
    session_t *session,
    const char *buf,
    int k,
    int *outConsumed) {
  int offset = 0;
  long consumed = 0;
  protocolMessage_t msg;
  protocolStatus_t status;
  queueResult_t result;

  while (offset < k) {
    consumed = 0;
    status = protocolDecodeSecureMsg(
        &session->tcpDecoder, key, buf + offset, k - offset, &consumed, &msg);
    if (status == protocolStatusBadFrame) {
      logf("bad frame");
      return false;
    }
    if (consumed <= 0) {
      break;
    }
    offset += (int)consumed;

    if (status == protocolStatusNeedMore) {
      continue;
    }

    result = handleInboundMessage(tcpPoller, tunPoller, key, session, &msg);
    if (result == queueResultError) {
      return false;
    }
    if (result == queueResultBlocked) {
      break;
    }
  }

  *outConsumed = offset;
  return true;
}

static bool pipeTcp(
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    const unsigned char key[ProtocolPskSize],
    session_t *session) {
  long nbytes = 0;
  int consumed = 0;
  int k;
  ioStatus_t readStatus;

  if (session->tcpReadCarryNbytes > 0) {
    if (!pipeTcpBytes(
            tcpPoller, tunPoller, key, session, session->tcpReadCarryBuf, (int)session->tcpReadCarryNbytes, &consumed)) {
      return false;
    }
    if (consumed < session->tcpReadCarryNbytes) {
      long rem = session->tcpReadCarryNbytes - consumed;
      memmove(session->tcpReadCarryBuf, session->tcpReadCarryBuf + consumed, (size_t)rem);
      session->tcpReadCarryNbytes = rem;
      return true;
    }
    session->tcpReadCarryNbytes = 0;
  }

  readStatus = ioTcpRead(tcpPoller->tcpFd, session->tcpReadBuf, sizeof(session->tcpReadBuf), &nbytes);
  if (readStatus == ioStatusWouldBlock) {
    return true;
  }
  if (readStatus != ioStatusOk) {
    return false;
  }
  k = (int)nbytes;
  if (!pipeTcpBytes(tcpPoller, tunPoller, key, session, session->tcpReadBuf, k, &consumed)) {
    return false;
  }
  if (consumed < k) {
    long rem = (long)(k - consumed);
    memcpy(session->tcpReadCarryBuf, session->tcpReadBuf + consumed, (size_t)rem);
    session->tcpReadCarryNbytes = rem;
  }

  return true;
}

static bool heartbeatTick(
    ioTcpPoller_t *tcpPoller, ioTunPoller_t *tunPoller, const unsigned char key[ProtocolPskSize], session_t *session) {
  long long now = sessionNowMs(session);
  long long timeoutMs = heartbeatTimeoutMs(session);

  if (session->isServer) {
    if (now - session->lastValidInboundMs >= timeoutMs) {
      logf("server heartbeat timeout");
      return false;
    }
    return true;
  }

  if (!session->heartbeatPending) {
    bool idleSend = now - session->lastDataSentMs >= session->heartbeatIntervalMs;
    bool idleRecv = now - session->lastDataRecvMs >= session->heartbeatIntervalMs;
    bool intervalElapsed = now - session->lastHeartbeatReqMs >= session->heartbeatIntervalMs;
    if (idleSend && idleRecv && intervalElapsed) {
      protocolMessage_t req;
      queueResult_t result;
      req.type = protocolMsgHeartbeatReq;
      req.nbytes = 0;
      req.buf = NULL;
      result = sendMessage(tcpPoller, tunPoller, key, session, &req);
      if (result == queueResultError) {
        return false;
      }
      if (result == queueResultBlocked) {
        return true;
      }

      session->heartbeatPending = true;
      session->heartbeatSentMs = now;
      session->lastHeartbeatReqMs = now;
      dbgf("sent heartbeat request");
    }
  }

  if (session->heartbeatPending && now - session->heartbeatSentMs >= timeoutMs) {
    logf("client heartbeat timeout waiting for ack");
    return false;
  }

  return true;
}

session_t *sessionCreate(
    bool isServer, const sessionHeartbeatConfig_t *heartbeatCfg, sessionNowMsFn_t nowFn, void *nowCtx) {
  session_t *session = calloc(1, sizeof(*session));
  if (session == NULL) {
    return NULL;
  }
  if (heartbeatCfg == NULL || heartbeatCfg->intervalMs <= 0 || heartbeatCfg->timeoutMs <= heartbeatCfg->intervalMs) {
    free(session);
    return NULL;
  }
  session->isServer = isServer;
  session->nowFn = nowFn == NULL ? defaultNowMs : nowFn;
  session->nowCtx = nowCtx;
  session->heartbeatIntervalMs = heartbeatCfg->intervalMs;
  session->heartbeatTimeoutMs = heartbeatCfg->timeoutMs;
  sessionReset(session);
  return session;
}

void sessionDestroy(session_t *session) {
  if (session != NULL) {
    free(session);
  }
}

void sessionReset(session_t *session) {
  long long now;
  bool isServer;
  server_t *runtime;
  sessionNowMsFn_t nowFn;
  void *nowCtx;
  int heartbeatIntervalMs;
  int heartbeatTimeoutMs;
  if (session == NULL) {
    return;
  }

  isServer = session->isServer;
  runtime = session->runtime;
  nowFn = session->nowFn;
  nowCtx = session->nowCtx;
  heartbeatIntervalMs = session->heartbeatIntervalMs;
  heartbeatTimeoutMs = session->heartbeatTimeoutMs;
  memset(session, 0, sizeof(*session));
  session->isServer = isServer;
  session->runtime = runtime;
  session->nowFn = nowFn;
  session->nowCtx = nowCtx;
  session->heartbeatIntervalMs = heartbeatIntervalMs;
  session->heartbeatTimeoutMs = heartbeatTimeoutMs;
  now = sessionNowMs(session);
  protocolDecoderInit(&session->tcpDecoder);
  session->lastValidInboundMs = now;
  session->lastDataSentMs = now;
  session->lastDataRecvMs = now;
  session->lastHeartbeatReqMs = now;
}

bool sessionGetStats(const session_t *session, sessionStats_t *outStats) {
  if (session == NULL || outStats == NULL) {
    return false;
  }

  memset(outStats, 0, sizeof(*outStats));
  outStats->isServer = session->isServer;
  outStats->lastValidInboundMs = session->lastValidInboundMs;
  outStats->lastDataSentMs = session->lastDataSentMs;
  outStats->lastDataRecvMs = session->lastDataRecvMs;
  outStats->heartbeatPending = session->heartbeatPending;
  outStats->heartbeatSentMs = session->heartbeatSentMs;
  outStats->lastHeartbeatReqMs = session->lastHeartbeatReqMs;
  outStats->tunReadPaused = session->tunReadPaused;
  outStats->tcpReadPaused = session->tcpReadPaused;
  outStats->tcpWritePendingNbytes = session->tcpWritePendingNbytes;
  outStats->tunWritePendingNbytes = session->tunWritePendingNbytes;
  outStats->tcpReadCarryNbytes = session->tcpReadCarryNbytes;
  return true;
}

void sessionSetServer(session_t *session, server_t *runtime) {
  if (session == NULL) {
    return;
  }
  session->runtime = runtime;
}

bool sessionPromoteFromPreAuth(
    session_t *session,
    const protocolDecoder_t *decoder,
    const char *carryBuf,
    long carryNbytes) {
  if (session == NULL || decoder == NULL || carryNbytes < 0 || carryNbytes > ProtocolFrameSize) {
    return false;
  }
  session->tcpDecoder = *decoder;
  if (carryNbytes > 0) {
    if (carryBuf == NULL) {
      return false;
    }
    memcpy(session->tcpReadCarryBuf, carryBuf, (size_t)carryNbytes);
  }
  session->tcpReadCarryNbytes = carryNbytes;
  return true;
}

bool sessionHasPendingTunEgress(const session_t *session) {
  if (session == NULL) {
    return false;
  }
  return session->tunWritePendingNbytes > 0;
}

bool sessionServiceBackpressure(session_t *session, ioTcpPoller_t *tcpPoller, ioTunPoller_t *tunPoller) {
  if (session == NULL || tcpPoller == NULL || tunPoller == NULL) {
    return false;
  }
  return serviceBackpressure(tcpPoller, tunPoller, session, ioEventTimeout);
}

sessionStepResult_t sessionStep(
    session_t *session,
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    ioEvent_t event,
    const unsigned char key[ProtocolPskSize]) {
  bool result = true;
  if (session == NULL || tcpPoller == NULL || tunPoller == NULL || key == NULL) {
    return sessionStepStop;
  }
  if (event == ioEventError) {
    return sessionStepStop;
  }

  if (event == ioEventTunRead) {
    result = pipeTun(tcpPoller, tunPoller, key, session);
  } else if (event == ioEventTcpRead) {
    result = pipeTcp(tcpPoller, tunPoller, key, session);
  }
  if (!result) {
    return sessionStepStop;
  }

  if (!serviceBackpressure(tcpPoller, tunPoller, session, event)) {
    logf("backpressure handling failure");
    return sessionStepStop;
  }

  if (!heartbeatTick(tcpPoller, tunPoller, key, session)) {
    logf("heartbeat failure");
    return sessionStepStop;
  }

  return sessionStepContinue;
}

int sessionRunServer(
    int tunFd,
    int listenFd,
    sessionServerResolveClaimFn_t resolveClaimFn,
    void *resolveClaimCtx,
    const char *ifModeLabel,
    int authTimeoutMs,
    const sessionHeartbeatConfig_t *heartbeatCfg,
    int maxActiveSessions,
    int maxPreAuthSessions) {
  return serverServeMultiClient(
      tunFd,
      listenFd,
      resolveClaimFn,
      resolveClaimCtx,
      ifModeLabel,
      authTimeoutMs,
      heartbeatCfg,
      maxActiveSessions,
      maxPreAuthSessions);
}

int sessionRunClient(
    int tunFd,
    int connFd,
    const unsigned char *claim,
    long claimNbytes,
    const unsigned char key[ProtocolPskSize],
    const sessionHeartbeatConfig_t *heartbeatCfg) {
  return clientServeConn(tunFd, connFd, claim, claimNbytes, key, heartbeatCfg);
}

bool sessionApiSmoke(void) {
  return true;
}
