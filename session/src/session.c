#include "session.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>
#include <sodium.h>

#include "log.h"
#include "serverRuntime.h"

struct session_t {
  bool isServer;
  serverRuntime_t *runtime;
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
    return serverRuntimeQueuedTunBytes(session->runtime);
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
  if (session->isServer && session->runtime != NULL && serverRuntimeHasPendingTunToTcp(session->runtime)) {
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
      ownerSlot = serverRuntimeFindSlotByFd(session->runtime, tcpPoller->tcpFd);
      if (ownerSlot < 0) {
        return queueResultError;
      }
      if (!serverRuntimeStorePendingTunToTcp(session->runtime, ownerSlot, data, nbytes)) {
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
    if (serverRuntimeQueueTunWrite(session->runtime, data, nbytes)) {
      return queueResultQueued;
    }
    queued = serverRuntimeQueuedTunBytes(session->runtime);
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

  if (serverMode && serverRuntimeHasPendingTunToTcp(session->runtime)) {
    int ownerSlot = serverRuntimePendingTunToTcpOwner(session->runtime);
    int slot = serverRuntimeFindSlotByFd(session->runtime, tcpPoller->tcpFd);
    if (slot < 0) {
      return false;
    }
    if (event == ioEventTcpWrite && slot == ownerSlot) {
      serverRuntimePendingRetry_t retry =
          serverRuntimeRetryPendingTunToTcp(session->runtime, ownerSlot, tcpPoller);
      if (retry == serverRuntimePendingRetryError) {
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
      queuedTun = serverRuntimeQueueTunWrite(session->runtime, session->tunWritePendingBuf, session->tunWritePendingNbytes);
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
    if (serverRuntimeHasPendingTunToTcp(session->runtime)) {
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
    if (!serverRuntimeSetTunReadEnabled(session->runtime, true)) {
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
  serverRuntime_t *runtime;
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

void sessionSetServerRuntime(session_t *session, serverRuntime_t *runtime) {
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

static bool serverEpollCtl(int epollFd, int op, int fd, unsigned int events) {
  struct epoll_event event;
  memset(&event, 0, sizeof(event));
  event.events = events;
  event.data.fd = fd;
  return epoll_ctl(epollFd, op, fd, &event) == 0;
}

static int isValidTunClaim(const unsigned char *claim, long claimNbytes) {
  return claim != NULL && claimNbytes == 4;
}

static int isValidTapClaim(const unsigned char *claim, long claimNbytes) {
  return claim != NULL && claimNbytes == 6;
}

typedef enum {
  preAuthStateWaitClaim = 0,
  preAuthStateSendChallenge,
  preAuthStateWaitHello,
} preAuthState_t;

static bool serverClosePreAuthConn(serverRuntime_t *runtime, int preAuthSlot) {
  int connFd = -1;
  preAuthConn_t *conn = serverRuntimePreAuthAt(runtime, preAuthSlot);
  if (conn == NULL) {
    return false;
  }
  connFd = conn->connFd;
  (void)serverEpollCtl(runtime->epollFd, EPOLL_CTL_DEL, connFd, 0);
  close(connFd);
  return serverRuntimeRemovePreAuthConn(runtime, preAuthSlot);
}

static bool serverSetPreAuthWriteEnabled(serverRuntime_t *runtime, int connFd, bool writeEnabled) {
  unsigned int events = EPOLLIN | EPOLLRDHUP;
  if (writeEnabled) {
    events |= EPOLLOUT;
  }
  return serverEpollCtl(runtime->epollFd, EPOLL_CTL_MOD, connFd, events);
}

static bool preAuthReadIntoCarry(preAuthConn_t *conn) {
  long nbytes = 0;
  ioStatus_t status;

  if (conn->tcpReadCarryNbytes >= (long)sizeof(conn->tcpReadCarryBuf)) {
    return false;
  }
  status = ioTcpRead(
      conn->connFd,
      conn->tcpReadCarryBuf + conn->tcpReadCarryNbytes,
      (long)sizeof(conn->tcpReadCarryBuf) - conn->tcpReadCarryNbytes,
      &nbytes);
  if (status == ioStatusWouldBlock) {
    return true;
  }
  if (status != ioStatusOk || nbytes <= 0) {
    return false;
  }
  conn->tcpReadCarryNbytes += nbytes;
  return true;
}

static void preAuthDropConsumedCarry(preAuthConn_t *conn, long consumedNbytes) {
  long remaining;
  if (consumedNbytes <= 0) {
    return;
  }
  if (consumedNbytes >= conn->tcpReadCarryNbytes) {
    conn->tcpReadCarryNbytes = 0;
    return;
  }
  remaining = conn->tcpReadCarryNbytes - consumedNbytes;
  memmove(conn->tcpReadCarryBuf, conn->tcpReadCarryBuf + consumedNbytes, (size_t)remaining);
  conn->tcpReadCarryNbytes = remaining;
}

static bool preAuthDecodeClaim(preAuthConn_t *conn, bool *outReady) {
  protocolRawMsg_t rawMsg;
  long offset = 0;

  *outReady = false;
  while (offset < conn->tcpReadCarryNbytes) {
    long consumed = 0;
    protocolStatus_t status = protocolDecodeRaw(
        &conn->decoder,
        conn->tcpReadCarryBuf + offset,
        conn->tcpReadCarryNbytes - offset,
        &consumed,
        &rawMsg);
    if (status == protocolStatusBadFrame) {
      return false;
    }
    if (consumed <= 0) {
      break;
    }
    offset += consumed;
    if (status == protocolStatusOk) {
      if (rawMsg.nbytes <= 0 || rawMsg.nbytes > SessionClaimSize) {
        return false;
      }
      memcpy(conn->claim, rawMsg.buf, (size_t)rawMsg.nbytes);
      conn->claimNbytes = rawMsg.nbytes;
      *outReady = true;
      break;
    }
  }
  preAuthDropConsumedCarry(conn, offset);
  return true;
}

static bool preAuthQueueChallenge(preAuthConn_t *conn) {
  protocolRawMsg_t rawMsg;
  protocolFrame_t frame;
  uint32_t wireLength = 0;

  randombytes_buf(conn->serverNonce, sizeof(conn->serverNonce));
  rawMsg.nbytes = ProtocolNonceSize;
  rawMsg.buf = (const char *)conn->serverNonce;
  if (protocolEncodeRaw(&rawMsg, &frame) != protocolStatusOk) {
    return false;
  }
  wireLength = htonl((uint32_t)frame.nbytes);
  memcpy(conn->authWriteBuf, &wireLength, ProtocolWireLengthSize);
  memcpy(conn->authWriteBuf + ProtocolWireLengthSize, frame.buf, (size_t)frame.nbytes);
  conn->authWriteOffset = 0;
  conn->authWriteNbytes = ProtocolWireLengthSize + frame.nbytes;
  return true;
}

static bool preAuthFlushChallenge(preAuthConn_t *conn) {
  while (conn->authWriteNbytes > 0) {
    ssize_t wrote =
        write(conn->connFd, conn->authWriteBuf + conn->authWriteOffset, (size_t)conn->authWriteNbytes);
    if (wrote > 0) {
      conn->authWriteOffset += (long)wrote;
      conn->authWriteNbytes -= (long)wrote;
      continue;
    }
    if (wrote == 0) {
      return false;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return true;
    }
    return false;
  }
  conn->authWriteOffset = 0;
  return true;
}

static bool preAuthDecodeHello(preAuthConn_t *conn, bool *outReady) {
  protocolMessage_t msg;
  long offset = 0;

  *outReady = false;
  while (offset < conn->tcpReadCarryNbytes) {
    long consumed = 0;
    protocolStatus_t status = protocolDecodeSecureMsg(
        &conn->decoder,
        conn->resolvedKey,
        conn->tcpReadCarryBuf + offset,
        conn->tcpReadCarryNbytes - offset,
        &consumed,
        &msg);
    if (status == protocolStatusBadFrame) {
      return false;
    }
    if (consumed <= 0) {
      break;
    }
    offset += consumed;
    if (status == protocolStatusOk) {
      if (msg.type != protocolMsgClientHello || msg.nbytes != ProtocolNonceSize * 2) {
        return false;
      }
      if (memcmp(msg.buf, conn->serverNonce, ProtocolNonceSize) != 0) {
        return false;
      }
      *outReady = true;
      break;
    }
  }
  preAuthDropConsumedCarry(conn, offset);
  return true;
}

static bool serverDispatchPreAuth(
    serverRuntime_t *runtime,
    int preAuthSlot,
    ioEvent_t event,
    const char *ifModeLabel,
    sessionServerResolveClaimFn_t resolveClaimFn,
    void *resolveClaimCtx) {
  preAuthConn_t *conn;
  long long nowMs;

  conn = serverRuntimePreAuthAt(runtime, preAuthSlot);
  if (conn == NULL || resolveClaimFn == NULL || ifModeLabel == NULL) {
    return false;
  }

  nowMs = serverRuntimeNowMs(runtime);
  if (nowMs < 0) {
    return false;
  }
  if (nowMs >= conn->authDeadlineMs) {
    return serverClosePreAuthConn(runtime, preAuthSlot);
  }

  if (conn->authState == preAuthStateWaitClaim && event == ioEventTcpRead) {
    bool claimReady = false;

    if (!preAuthReadIntoCarry(conn)) {
      return serverClosePreAuthConn(runtime, preAuthSlot);
    }
    if (!preAuthDecodeClaim(conn, &claimReady)) {
      return serverClosePreAuthConn(runtime, preAuthSlot);
    }
    if (!claimReady) {
      return true;
    }

    if ((strcmp(ifModeLabel, "tun") == 0 && !isValidTunClaim(conn->claim, conn->claimNbytes))
        || (strcmp(ifModeLabel, "tap") == 0 && !isValidTapClaim(conn->claim, conn->claimNbytes))) {
      return serverClosePreAuthConn(runtime, preAuthSlot);
    }
    if (resolveClaimFn(resolveClaimCtx, conn->claim, conn->claimNbytes, conn->resolvedKey, &conn->resolvedActiveSlot)
        != 0) {
      return serverClosePreAuthConn(runtime, preAuthSlot);
    }
    if (conn->resolvedActiveSlot < 0 || conn->resolvedActiveSlot >= runtime->maxActiveSessions) {
      return serverClosePreAuthConn(runtime, preAuthSlot);
    }
    if (!preAuthQueueChallenge(conn)) {
      return serverClosePreAuthConn(runtime, preAuthSlot);
    }
    conn->authState = preAuthStateSendChallenge;
    if (!serverSetPreAuthWriteEnabled(runtime, conn->connFd, true)) {
      return false;
    }
  }

  if (conn->authState == preAuthStateSendChallenge && (event == ioEventTcpWrite || event == ioEventTimeout)) {
    if (!preAuthFlushChallenge(conn)) {
      return serverClosePreAuthConn(runtime, preAuthSlot);
    }
    if (conn->authWriteNbytes == 0) {
      conn->authState = preAuthStateWaitHello;
      if (!serverSetPreAuthWriteEnabled(runtime, conn->connFd, false)) {
        return false;
      }
    }
  }

  if (conn->authState == preAuthStateWaitHello && event == ioEventTcpRead) {
    bool helloReady = false;
    int activeSlot;
    int activeConnFd;
    protocolDecoder_t helloDecoder;
    char helloCarryBuf[ProtocolFrameSize];
    long helloCarryNbytes = 0;
    session_t *activeSession;

    if (!preAuthReadIntoCarry(conn)) {
      return serverClosePreAuthConn(runtime, preAuthSlot);
    }
    if (!preAuthDecodeHello(conn, &helloReady)) {
      return serverClosePreAuthConn(runtime, preAuthSlot);
    }
    if (!helloReady) {
      return true;
    }
    if (serverRuntimeHasActiveClaim(runtime, conn->claim, conn->claimNbytes)) {
      return serverClosePreAuthConn(runtime, preAuthSlot);
    }
    helloDecoder = conn->decoder;
    helloCarryNbytes = conn->tcpReadCarryNbytes;
    if (helloCarryNbytes > 0) {
      memcpy(helloCarryBuf, conn->tcpReadCarryBuf, (size_t)helloCarryNbytes);
    }
    activeSlot = conn->resolvedActiveSlot;
    if (!serverRuntimePromoteToActiveSlot(runtime, preAuthSlot)) {
      return serverClosePreAuthConn(runtime, preAuthSlot);
    }
    activeSession = serverRuntimeSessionAt(runtime, activeSlot);
    if (activeSession == NULL
        || !sessionPromoteFromPreAuth(
            activeSession, &helloDecoder, helloCarryNbytes > 0 ? helloCarryBuf : NULL, helloCarryNbytes)) {
      int failedConnFd = serverRuntimeConnFdAt(runtime, activeSlot);
      if (failedConnFd >= 0) {
        close(failedConnFd);
      }
      (void)serverRuntimeRemoveClient(runtime, activeSlot);
      return false;
    }
    activeConnFd = serverRuntimeConnFdAt(runtime, activeSlot);
    runtime->activeConns[activeSlot].tcpPoller.epollFd = runtime->epollFd;
    if (!serverEpollCtl(runtime->epollFd, EPOLL_CTL_MOD, activeConnFd, runtime->activeConns[activeSlot].tcpPoller.events)) {
      close(activeConnFd);
      (void)serverRuntimeRemoveClient(runtime, activeSlot);
      return false;
    }
  }

  return true;
}

static bool serverDispatchClient(serverRuntime_t *runtime, int slot, ioEvent_t event) {
  session_t *session = serverRuntimeSessionAt(runtime, slot);
  int connFd = serverRuntimeConnFdAt(runtime, slot);
  const unsigned char *key = serverRuntimeKeyAt(runtime, slot);
  if (session == NULL || connFd < 0) {
    return false;
  }
  if (key == NULL) {
    return false;
  }

  if (sessionStep(
          session, &runtime->activeConns[slot].tcpPoller, &runtime->tunPoller, event, key)
      == sessionStepStop) {
    (void)serverEpollCtl(runtime->epollFd, EPOLL_CTL_DEL, connFd, 0);
    close(connFd);
    return serverRuntimeRemoveClient(runtime, slot);
  }
  return true;
}

static bool serverTickAllClients(serverRuntime_t *runtime) {
  int slot;
  for (slot = 0; slot < runtime->maxActiveSessions; slot++) {
    if (!runtime->activeConns[slot].active) {
      continue;
    }
    if (!serverDispatchClient(runtime, slot, ioEventTimeout)) {
      return false;
    }
  }
  return true;
}

static bool serverTickPreAuth(
    serverRuntime_t *runtime,
    const char *ifModeLabel,
    sessionServerResolveClaimFn_t resolveClaimFn,
    void *resolveClaimCtx) {
  int slot;

  for (slot = 0; slot < runtime->maxPreAuthSessions; slot++) {
    preAuthConn_t *conn = serverRuntimePreAuthAt(runtime, slot);
    if (conn == NULL) {
      continue;
    }
    if (!serverDispatchPreAuth(runtime, slot, ioEventTimeout, ifModeLabel, resolveClaimFn, resolveClaimCtx)) {
      return false;
    }
  }
  return true;
}

int sessionServeMultiClient(
    int tunFd,
    int listenFd,
    sessionServerResolveClaimFn_t resolveClaimFn,
    void *resolveClaimCtx,
    const char *ifModeLabel,
    int authTimeoutMs,
    const sessionHeartbeatConfig_t *heartbeatCfg,
    int maxActiveSessions,
    int maxPreAuthSessions) {
  serverRuntime_t runtime;
  struct epoll_event events[16];
  int epollFd = -1;
  int rc = -1;
  int i;

  if (tunFd < 0
      || listenFd < 0
      || resolveClaimFn == NULL
      || ifModeLabel == NULL
      || authTimeoutMs <= 0
      || heartbeatCfg == NULL
      || maxActiveSessions <= 0
      || maxPreAuthSessions <= 0) {
    return -1;
  }
  if (!serverRuntimeInit(
          &runtime,
          tunFd,
          listenFd,
          maxActiveSessions,
          maxPreAuthSessions,
          heartbeatCfg,
          NULL,
          NULL)) {
    return -1;
  }

  epollFd = epoll_create1(0);
  if (epollFd < 0) {
    serverRuntimeDeinit(&runtime);
    return -1;
  }
  runtime.epollFd = epollFd;
  runtime.tunPoller.epollFd = epollFd;

  if (!serverEpollCtl(epollFd, EPOLL_CTL_ADD, listenFd, EPOLLIN | EPOLLRDHUP)
      || !serverEpollCtl(epollFd, EPOLL_CTL_ADD, tunFd, runtime.tunPoller.events)) {
    goto cleanup;
  }

  while (1) {
    int n = epoll_wait(epollFd, events, (int)(sizeof(events) / sizeof(events[0])), 200);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }

    for (i = 0; i < n; i++) {
      int fd = events[i].data.fd;
      unsigned int ev = events[i].events;

      if (fd == listenFd) {
        while (1) {
          int connFd = -1;
          char clientIp[256];
          int clientPort = 0;
          ioStatus_t status = ioTcpAcceptNonBlocking(listenFd, &connFd, clientIp, sizeof(clientIp), &clientPort);
          long long nowMs;
          int preAuthSlot;
          if (status == ioStatusWouldBlock) {
            break;
          }
          if (status != ioStatusOk) {
            goto cleanup;
          }
          logf("connected with %s:%d", clientIp, clientPort);
          nowMs = serverRuntimeNowMs(&runtime);
          if (nowMs < 0) {
            close(connFd);
            goto cleanup;
          }
          preAuthSlot = serverRuntimeCreatePreAuthConn(&runtime, connFd, nowMs + authTimeoutMs);
          if (preAuthSlot < 0) {
            close(connFd);
            continue;
          }
          if (!serverEpollCtl(epollFd, EPOLL_CTL_ADD, connFd, EPOLLIN | EPOLLRDHUP)) {
            close(connFd);
            (void)serverRuntimeRemovePreAuthConn(&runtime, preAuthSlot);
            goto cleanup;
          }
        }
        continue;
      }

      {
        int preAuthSlot = serverRuntimeFindPreAuthSlotByFd(&runtime, fd);
        if (preAuthSlot >= 0) {
          if ((ev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
            if (!serverClosePreAuthConn(&runtime, preAuthSlot)) {
              goto cleanup;
            }
            continue;
          }
          if ((ev & EPOLLIN) != 0
              && !serverDispatchPreAuth(
                  &runtime, preAuthSlot, ioEventTcpRead, ifModeLabel, resolveClaimFn, resolveClaimCtx)) {
            goto cleanup;
          }
          if ((ev & EPOLLOUT) != 0
              && !serverDispatchPreAuth(
                  &runtime, preAuthSlot, ioEventTcpWrite, ifModeLabel, resolveClaimFn, resolveClaimCtx)) {
            goto cleanup;
          }
          continue;
        }
      }

      if (fd == tunFd) {
        if ((ev & EPOLLIN) != 0) {
          int connFd = serverRuntimePickEgressClient(&runtime);
          int slot = serverRuntimeFindSlotByFd(&runtime, connFd);
          if (slot >= 0 && !serverDispatchClient(&runtime, slot, ioEventTunRead)) {
            goto cleanup;
          }
        }
        if ((ev & EPOLLOUT) != 0) {
          if (!serverRuntimeServiceTunWriteEvent(&runtime)) {
            goto cleanup;
          }
          if (ioTunQueuedBytes(&runtime.tunPoller) <= IoPollerLowWatermark) {
            if (serverRuntimeRetryBlockedTunRoundRobin(&runtime) < 0) {
              goto cleanup;
            }
            if (!serverRuntimeSyncTunWriteInterest(&runtime)) {
              goto cleanup;
            }
          }
        }
        if ((ev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
          goto cleanup;
        }
        continue;
      }

      {
        int slot = serverRuntimeFindSlotByFd(&runtime, fd);
        if (slot < 0) {
          (void)serverEpollCtl(epollFd, EPOLL_CTL_DEL, fd, 0);
          close(fd);
          continue;
        }
        if ((ev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
          (void)serverEpollCtl(epollFd, EPOLL_CTL_DEL, fd, 0);
          close(fd);
          (void)serverRuntimeRemoveClient(&runtime, slot);
          continue;
        }
        if ((ev & EPOLLIN) != 0 && !serverDispatchClient(&runtime, slot, ioEventTcpRead)) {
          goto cleanup;
        }
        if ((ev & EPOLLOUT) != 0) {
          if (!ioTcpServiceWriteEvent(&runtime.activeConns[slot].tcpPoller)) {
            goto cleanup;
          }
          if (!serverDispatchClient(&runtime, slot, ioEventTcpWrite)) {
            goto cleanup;
          }
        }
      }
    }

    if (!serverTickAllClients(&runtime)) {
      goto cleanup;
    }
    if (!serverTickPreAuth(&runtime, ifModeLabel, resolveClaimFn, resolveClaimCtx)) {
      goto cleanup;
    }
  }

cleanup:
  for (i = 0; i < runtime.maxActiveSessions; i++) {
    int connFd = serverRuntimeConnFdAt(&runtime, i);
    if (connFd >= 0) {
      (void)serverEpollCtl(epollFd, EPOLL_CTL_DEL, connFd, 0);
      close(connFd);
    }
  }
  for (i = 0; i < runtime.maxPreAuthSessions; i++) {
    preAuthConn_t *conn = serverRuntimePreAuthAt(&runtime, i);
    if (conn != NULL && conn->connFd >= 0) {
      (void)serverEpollCtl(epollFd, EPOLL_CTL_DEL, conn->connFd, 0);
      close(conn->connFd);
      (void)serverRuntimeRemovePreAuthConn(&runtime, i);
    }
  }
  serverRuntimeDeinit(&runtime);
  if (epollFd >= 0) {
    close(epollFd);
  }
  return rc;
}

bool sessionApiSmoke(void) {
  return true;
}
