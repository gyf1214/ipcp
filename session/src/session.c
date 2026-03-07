#include "sessionInternal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "client.h"
#include "server.h"

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
  dbgAssertf(session != NULL);
  dbgAssertf(session->isServer);
  dbgAssertf(session->runtime != NULL);
  return (server_t *)session->runtime;
}

static client_t *sessionClient(session_t *session) {
  dbgAssertf(session != NULL);
  dbgAssertf(!session->isServer);
  dbgAssertf(session->runtime != NULL);
  return (client_t *)session->runtime;
}

static long messageHeaderSize(void) {
  return (long)sizeof(unsigned char) + ProtocolWireLengthSize;
}

static void sessionResetClientHeartbeatState(session_t *session) {
  if (session == NULL || session->isServer || session->runtime == NULL) {
    return;
  }
  clientResetHeartbeatState(
      sessionClient(session),
      session->heartbeatIntervalMs,
      session->heartbeatTimeoutMs,
      sessionNowMs(session));
}

static bool serviceBackpressure(
    ioTcpPoller_t *tcpPoller, session_t *session, ioEvent_t event) {
  if (session->isServer) {
    server_t *server = sessionServer(session);
    return serverServiceBackpressure(server, tcpPoller, event);
  }

  client_t *client = sessionClient(session);
  return clientServiceBackpressure(client, session);
}

static sessionQueueResult_t queueTunWithBackpressure(
    ioTcpPoller_t *tcpPoller, ioTunPoller_t *tunPoller, session_t *session, const void *data, long nbytes) {
  long queued;

  if (tcpPoller == NULL || tunPoller == NULL || session == NULL || data == NULL || nbytes <= 0) {
    return sessionQueueResultError;
  }
  if (session->overflowNbytes > 0) {
    return sessionQueueResultBlocked;
  }
  if (ioTunWrite(tunPoller, data, nbytes)) {
    return sessionQueueResultQueued;
  }

  queued = ioTunQueuedBytes(tunPoller);
  if (queued < 0) {
    return sessionQueueResultError;
  }
  if (queued + nbytes > IoPollerQueueCapacity) {
    memcpy(session->overflowBuf, data, (size_t)nbytes);
    session->overflowNbytes = nbytes;
    if (!session->tcpReadPaused) {
      if (!ioTcpSetReadEnabled(tcpPoller, false)) {
        return sessionQueueResultError;
      }
      session->tcpReadPaused = true;
    }
    return sessionQueueResultBlocked;
  }
  return sessionQueueResultError;
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
  long long nowMs;

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

  nowMs = sessionNowMs(session);
  msg.type = protocolMsgData;
  msg.nbytes = nbytes;
  msg.buf = payload;
  if (session->isServer) {
    result = serverSendMessage(sessionServer(session), tcpPoller, key, &msg);
  } else {
    client_t *client = sessionClient(session);
    result = clientSendMessage(
        client,
        key,
        nowMs,
        &msg);
  }
  if (result == sessionQueueResultError) {
    return false;
  }
  if (result == sessionQueueResultBlocked) {
    return true;
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

    if (msg.type == protocolMsgData) {
      result = queueTunWithBackpressure(tcpPoller, tunPoller, session, msg.buf, msg.nbytes);
      if (result == sessionQueueResultQueued && !session->isServer) {
        client_t *client = sessionClient(session);
        client->lastDataRecvMs = now;
      }
      session->lastValidInboundMs = now;
    } else if (session->isServer) {
      result = serverHandleInboundMessage(
          sessionServer(session), tcpPoller, key, &session->lastValidInboundMs, &msg);
    } else {
      client_t *client = sessionClient(session);
      result = clientHandleInboundMessage(
          client,
          now,
          &session->lastValidInboundMs,
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
  sessionResetClientHeartbeatState(session);
}

void sessionAttachServer(session_t *session, server_t *server) {
  if (session == NULL || !session->isServer) {
    return;
  }
  session->runtime = server;
}

void sessionAttachClient(session_t *session, client_t *client) {
  if (session == NULL || session->isServer) {
    return;
  }
  session->runtime = client;
  sessionResetClientHeartbeatState(session);
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

bool sessionHasOverflow(const session_t *session) {
  if (session == NULL) {
    return false;
  }
  return session->overflowNbytes > 0;
}

bool sessionRetryOverflow(session_t *session, ioTcpPoller_t *tcpPoller, ioTunPoller_t *tunPoller) {
  long queued;
  if (session == NULL || tcpPoller == NULL || tunPoller == NULL) {
    return false;
  }
  if (session->overflowNbytes > 0) {
    if (ioTunWrite(tunPoller, session->overflowBuf, session->overflowNbytes)) {
      session->overflowNbytes = 0;
    } else {
      queued = ioTunQueuedBytes(tunPoller);
      if (queued < 0 || queued + session->overflowNbytes <= IoPollerQueueCapacity) {
        return false;
      }
    }
  }
  if (session->tcpReadPaused && session->overflowNbytes == 0) {
    queued = ioTunQueuedBytes(tunPoller);
    if (queued < 0) {
      return false;
    }
    if (queued <= IoPollerLowWatermark) {
      if (!ioTcpSetReadEnabled(tcpPoller, true)) {
        return false;
      }
      session->tcpReadPaused = false;
    }
  }
  return true;
}

sessionStepResult_t sessionFinalizeStep(
    session_t *session,
    ioTcpPoller_t *tcpPoller,
    ioEvent_t event,
    const unsigned char key[ProtocolPskSize]) {
  long long now = sessionNowMs(session);
  long long timeoutMs = heartbeatTimeoutMs(session);

  if (!serviceBackpressure(tcpPoller, session, event)) {
    logf("backpressure handling failure");
    return sessionStepStop;
  }

  if (session->isServer) {
    bool ok = serverHeartbeatTick(now, session->lastValidInboundMs, timeoutMs);
    if (!ok) {
      logf("server heartbeat timeout");
      return sessionStepStop;
    }
  } else {
    client_t *client = sessionClient(session);
    if (!clientHeartbeatTick(
            client,
            now,
            key)) {
      logf("heartbeat failure");
      return sessionStepStop;
    }
  }

  return sessionStepContinue;
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
  return sessionFinalizeStep(session, tcpPoller, event, key);
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
    return sessionFinalizeStep(session, tcpPoller, event, key);
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
