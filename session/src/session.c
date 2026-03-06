#include "sessionInternal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "client.h"
#include "server.h"

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
  char tcpWritePendingBuf[ProtocolFrameSize];
  long tunWritePendingNbytes;
  char tunWritePendingBuf[ProtocolFrameSize];
};

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

static server_t *sessionServer(session_t *session) {
  if (session == NULL || !session->isServer) {
    return NULL;
  }
  return (server_t *)session->runtime;
}

static client_t *sessionClient(session_t *session) {
  if (session == NULL || session->isServer) {
    return NULL;
  }
  return (client_t *)session->runtime;
}

static long messageHeaderSize(void) {
  return (long)sizeof(unsigned char) + ProtocolWireLengthSize;
}

static bool serviceBackpressure(
    ioTcpPoller_t *tcpPoller, ioTunPoller_t *tunPoller, session_t *session, ioEvent_t event) {
  server_t *runtime = sessionServer(session);
  client_t *client = sessionClient(session);

  if (runtime != NULL) {
    long queued;
    if (!serverServiceBackpressure(runtime, tcpPoller, tunPoller, event)) {
      return false;
    }
    if (serverHasPendingTunToTcp(runtime)) {
      session->tunReadPaused = true;
      return true;
    }
    queued = ioTcpQueuedBytes(tcpPoller);
    if (queued < 0) {
      return false;
    }
    session->tunReadPaused = queued > IoPollerLowWatermark;
    return true;
  }

  return clientServiceBackpressure(
      client,
      tcpPoller,
      tunPoller,
      event,
      &session->tunReadPaused,
      &session->tcpReadPaused,
      &session->tcpWritePendingNbytes,
      session->tcpWritePendingBuf,
      &session->tunWritePendingNbytes,
      session->tunWritePendingBuf);
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
  sessionQueueResult_t result;
  server_t *runtime = sessionServer(session);
  client_t *client = sessionClient(session);

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
  if (runtime != NULL) {
    result = serverSendMessage(runtime, tcpPoller, key, &msg);
  } else {
    result = clientSendMessage(
        client,
        tcpPoller,
        tunPoller,
        &session->tunReadPaused,
        &session->tcpWritePendingNbytes,
        session->tcpWritePendingBuf,
        key,
        &msg);
  }
  if (result == sessionQueueResultError) {
    return false;
  }
  if (result == sessionQueueResultBlocked) {
    return true;
  }

  if (!session->isServer) {
    session->lastDataSentMs = sessionNowMs(session);
  }

  dbgf("sent %ld bytes of data", nbytes);
  return true;
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
  sessionQueueResult_t result;
  server_t *runtime = sessionServer(session);
  client_t *client = sessionClient(session);
  long long now = sessionNowMs(session);

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

    if (runtime != NULL) {
      result = serverHandleInboundMessage(
          runtime, tcpPoller, tunPoller, key, &session->heartbeatPending, &session->lastValidInboundMs, &msg);
    } else {
      result = clientHandleInboundMessage(
          client,
          tcpPoller,
          tunPoller,
          &session->tcpReadPaused,
          &session->tunWritePendingNbytes,
          session->tunWritePendingBuf,
          &session->heartbeatPending,
          now,
          &session->lastValidInboundMs,
          &session->lastDataRecvMs,
          key,
          &msg);
    }
    if (result == sessionQueueResultError) {
      return false;
    }
    if (result == sessionQueueResultBlocked) {
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
  void *runtime;
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
  if (session == NULL || !session->isServer) {
    return;
  }
  session->runtime = runtime;
}

void sessionSetClient(session_t *session, client_t *runtime) {
  if (session == NULL || session->isServer) {
    return;
  }
  session->runtime = runtime;
  (void)sessionClient(session);
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

static sessionStepResult_t sessionFinalizeStep(
    session_t *session,
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    ioEvent_t event,
    const unsigned char key[ProtocolPskSize]) {
  server_t *runtime = sessionServer(session);
  client_t *client = sessionClient(session);
  long long now = sessionNowMs(session);
  long long timeoutMs = heartbeatTimeoutMs(session);

  if (!serviceBackpressure(tcpPoller, tunPoller, session, event)) {
    logf("backpressure handling failure");
    return sessionStepStop;
  }

  if (session->isServer) {
    bool ok = runtime != NULL
        ? serverHeartbeatTick(runtime, now, session->lastValidInboundMs, timeoutMs)
        : (now - session->lastValidInboundMs < timeoutMs);
    if (!ok) {
      logf("server heartbeat timeout");
      return sessionStepStop;
    }
  } else if (!clientHeartbeatTick(
                 client,
                 tcpPoller,
                 tunPoller,
                 &session->heartbeatPending,
                 now,
                 session->heartbeatIntervalMs,
                 (int)timeoutMs,
                 &session->heartbeatSentMs,
                 &session->lastHeartbeatReqMs,
                 session->lastDataSentMs,
                 session->lastDataRecvMs,
                 &session->tunReadPaused,
                 &session->tcpWritePendingNbytes,
                 session->tcpWritePendingBuf,
                 key)) {
    logf("heartbeat failure");
    return sessionStepStop;
  }

  return sessionStepContinue;
}

sessionStepResult_t sessionHandleTunIngressPayload(
    session_t *session,
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    const unsigned char key[ProtocolPskSize],
    const void *payload,
    long payloadNbytes) {
  protocolMessage_t msg;
  sessionQueueResult_t result;

  if (session == NULL
      || tcpPoller == NULL
      || tunPoller == NULL
      || key == NULL
      || payload == NULL
      || payloadNbytes <= 0) {
    return sessionStepStop;
  }

  msg.type = protocolMsgData;
  msg.nbytes = payloadNbytes;
  msg.buf = (const char *)payload;
  if (sessionServer(session) != NULL) {
    result = serverSendMessage(sessionServer(session), tcpPoller, key, &msg);
  } else {
    result = clientSendMessage(
        sessionClient(session),
        tcpPoller,
        tunPoller,
        &session->tunReadPaused,
        &session->tcpWritePendingNbytes,
        session->tcpWritePendingBuf,
        key,
        &msg);
  }
  if (result == sessionQueueResultError) {
    return sessionStepStop;
  }
  if (result == sessionQueueResultQueued && !session->isServer) {
    session->lastDataSentMs = sessionNowMs(session);
  }

  return sessionFinalizeStep(session, tcpPoller, tunPoller, ioEventTunRead, key);
}

sessionStepResult_t sessionHandleConnEvent(
    session_t *session,
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    ioEvent_t event,
    const unsigned char key[ProtocolPskSize]) {
  if (session == NULL || tcpPoller == NULL || tunPoller == NULL || key == NULL) {
    return sessionStepStop;
  }
  if (event == ioEventError || event == ioEventTunRead) {
    return sessionStepStop;
  }
  if (event == ioEventTcpRead && !pipeTcp(tcpPoller, tunPoller, key, session)) {
    return sessionStepStop;
  }
  return sessionFinalizeStep(session, tcpPoller, tunPoller, event, key);
}

sessionStepResult_t sessionStep(
    session_t *session,
    ioTcpPoller_t *tcpPoller,
    ioTunPoller_t *tunPoller,
    ioEvent_t event,
    const unsigned char key[ProtocolPskSize]) {
  if (event == ioEventTunRead) {
    if (session == NULL || tcpPoller == NULL || tunPoller == NULL || key == NULL) {
      return sessionStepStop;
    }
    if (!pipeTun(tcpPoller, tunPoller, key, session)) {
      return sessionStepStop;
    }
    return sessionFinalizeStep(session, tcpPoller, tunPoller, event, key);
  }
  return sessionHandleConnEvent(session, tcpPoller, tunPoller, event, key);
}

int sessionRunServer(
    int tunFd,
    int listenFd,
    sessionServerResolveClaimFn_t resolveClaimFn,
    void *resolveClaimCtx,
    const char *ifModeLabel,
    const sessionTunSubnet_t *tunSubnet,
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
      tunSubnet,
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
