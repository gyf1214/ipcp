#include "session.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"

#define HEARTBEAT_DEFAULT_INTERVAL_MS 5000
#define HEARTBEAT_DEFAULT_TIMEOUT_MS  15000

struct session_t {
  bool isServer;
  sessionNowMsFn_t nowFn;
  void *nowCtx;
  protocolDecoder_t tcpDecoder;
  char tcpBuf[ProtocolFrameSize];
  char tcpBufferedBuf[ProtocolFrameSize];
  long tcpBufferedNbytes;
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
  long pendingTcpNbytes;
  char pendingTcpBuf[ProtocolWireLengthSize + ProtocolFrameSize];
  long pendingTunNbytes;
  char pendingTunBuf[ProtocolFrameSize];
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

static bool pauseReadSource(ioPoller_t *poller, ioSource_t source, bool *paused) {
  if (*paused) {
    return true;
  }
  if (!ioPollerSetReadEnabled(poller, source, false)) {
    return false;
  }
  *paused = true;
  return true;
}

static bool maybeResumeReadSource(
    ioPoller_t *poller, ioSource_t source, ioSource_t destination, bool *paused, long pendingNbytes) {
  long queued;
  if (!*paused || pendingNbytes > 0) {
    return true;
  }

  queued = ioPollerQueuedBytes(poller, destination);
  if (queued < 0) {
    return false;
  }
  if (queued > IoPollerLowWatermark) {
    return true;
  }
  if (!ioPollerSetReadEnabled(poller, source, true)) {
    return false;
  }
  *paused = false;
  return true;
}

static queueResult_t queueTcpWithBackpressure(ioPoller_t *poller, session_t *session, const void *data, long nbytes) {
  long queued;

  if (session->pendingTcpNbytes > 0) {
    return queueResultBlocked;
  }
  if (ioPollerQueueWrite(poller, ioSourceTcp, data, nbytes)) {
    return queueResultQueued;
  }

  queued = ioPollerQueuedBytes(poller, ioSourceTcp);
  if (queued < 0) {
    return queueResultError;
  }
  if (queued + nbytes > IoPollerQueueCapacity) {
    memcpy(session->pendingTcpBuf, data, (size_t)nbytes);
    session->pendingTcpNbytes = nbytes;
    if (!pauseReadSource(poller, ioSourceTun, &session->tunReadPaused)) {
      return queueResultError;
    }
    return queueResultBlocked;
  }
  return queueResultError;
}

static queueResult_t queueTunWithBackpressure(ioPoller_t *poller, session_t *session, const void *data, long nbytes) {
  long queued;

  if (session->pendingTunNbytes > 0) {
    return queueResultBlocked;
  }
  if (ioPollerQueueWrite(poller, ioSourceTun, data, nbytes)) {
    return queueResultQueued;
  }

  queued = ioPollerQueuedBytes(poller, ioSourceTun);
  if (queued < 0) {
    return queueResultError;
  }
  if (queued + nbytes > IoPollerQueueCapacity) {
    memcpy(session->pendingTunBuf, data, (size_t)nbytes);
    session->pendingTunNbytes = nbytes;
    if (!pauseReadSource(poller, ioSourceTcp, &session->tcpReadPaused)) {
      return queueResultError;
    }
    return queueResultBlocked;
  }
  return queueResultError;
}

static bool serviceBackpressure(ioPoller_t *poller, session_t *session) {
  long queued;

  if (session->pendingTcpNbytes > 0) {
    if (ioPollerQueueWrite(poller, ioSourceTcp, session->pendingTcpBuf, session->pendingTcpNbytes)) {
      session->pendingTcpNbytes = 0;
    } else {
      queued = ioPollerQueuedBytes(poller, ioSourceTcp);
      if (queued < 0 || queued + session->pendingTcpNbytes <= IoPollerQueueCapacity) {
        return false;
      }
    }
  }

  if (session->pendingTunNbytes > 0) {
    if (ioPollerQueueWrite(poller, ioSourceTun, session->pendingTunBuf, session->pendingTunNbytes)) {
      session->pendingTunNbytes = 0;
    } else {
      queued = ioPollerQueuedBytes(poller, ioSourceTun);
      if (queued < 0 || queued + session->pendingTunNbytes <= IoPollerQueueCapacity) {
        return false;
      }
    }
  }

  return maybeResumeReadSource(
             poller, ioSourceTun, ioSourceTcp, &session->tunReadPaused, session->pendingTcpNbytes)
      && maybeResumeReadSource(
             poller, ioSourceTcp, ioSourceTun, &session->tcpReadPaused, session->pendingTunNbytes);
}

static queueResult_t sendMessage(
    ioPoller_t *poller, const unsigned char key[ProtocolPskSize], session_t *session, const protocolMessage_t *msg) {
  protocolFrame_t frame;
  char wireBuf[ProtocolWireLengthSize + ProtocolFrameSize];
  long wireNbytes;
  uint32_t wireLength;

  if (protocolSecureEncodeMessage(msg, key, &frame) != protocolStatusOk) {
    return queueResultError;
  }

  wireLength = htonl((uint32_t)frame.nbytes);
  memcpy(wireBuf, &wireLength, ProtocolWireLengthSize);
  memcpy(wireBuf + ProtocolWireLengthSize, frame.buf, (size_t)frame.nbytes);
  wireNbytes = ProtocolWireLengthSize + frame.nbytes;
  return queueTcpWithBackpressure(poller, session, wireBuf, wireNbytes);
}

static bool pipeTun(
    ioPoller_t *poller,
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

  status = ioReadSome(poller->tunFd, payload, maxPayload, &nbytes);
  if (status == ioStatusWouldBlock) {
    return true;
  }
  if (status != ioStatusOk) {
    return false;
  }

  msg.type = protocolMsgData;
  msg.nbytes = nbytes;
  msg.buf = payload;
  result = sendMessage(poller, key, session, &msg);
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
    ioPoller_t *poller,
    const unsigned char key[ProtocolPskSize],
    session_t *session,
    const protocolMessage_t *msg) {
  long long now = sessionNowMs(session);
  session->lastValidInboundMs = now;

  if (msg->type == protocolMsgData) {
    queueResult_t result = queueTunWithBackpressure(poller, session, msg->buf, msg->nbytes);
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
    result = sendMessage(poller, key, session, &ack);
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
    ioPoller_t *poller,
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
    status = protocolSecureDecoderReadMessage(
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

    result = handleInboundMessage(poller, key, session, &msg);
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
    ioPoller_t *poller,
    const unsigned char key[ProtocolPskSize],
    session_t *session) {
  long nbytes = 0;
  int consumed = 0;
  int k;
  ioStatus_t readStatus;

  if (session->tcpBufferedNbytes > 0) {
    if (!pipeTcpBytes(poller, key, session, session->tcpBufferedBuf, (int)session->tcpBufferedNbytes, &consumed)) {
      return false;
    }
    if (consumed < session->tcpBufferedNbytes) {
      long rem = session->tcpBufferedNbytes - consumed;
      memmove(session->tcpBufferedBuf, session->tcpBufferedBuf + consumed, (size_t)rem);
      session->tcpBufferedNbytes = rem;
      return true;
    }
    session->tcpBufferedNbytes = 0;
  }

  readStatus = ioReadSome(poller->tcpFd, session->tcpBuf, sizeof(session->tcpBuf), &nbytes);
  if (readStatus == ioStatusWouldBlock) {
    return true;
  }
  if (readStatus != ioStatusOk) {
    return false;
  }
  k = (int)nbytes;
  if (!pipeTcpBytes(poller, key, session, session->tcpBuf, k, &consumed)) {
    return false;
  }
  if (consumed < k) {
    long rem = (long)(k - consumed);
    memcpy(session->tcpBufferedBuf, session->tcpBuf + consumed, (size_t)rem);
    session->tcpBufferedNbytes = rem;
  }

  return true;
}

static bool heartbeatTick(ioPoller_t *poller, const unsigned char key[ProtocolPskSize], session_t *session) {
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
      result = sendMessage(poller, key, session, &req);
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
  int intervalMs = HEARTBEAT_DEFAULT_INTERVAL_MS;
  int timeoutMs = HEARTBEAT_DEFAULT_TIMEOUT_MS;
  if (session == NULL) {
    return NULL;
  }
  if (heartbeatCfg != NULL) {
    intervalMs = heartbeatCfg->intervalMs;
    timeoutMs = heartbeatCfg->timeoutMs;
  }
  session->isServer = isServer;
  session->nowFn = nowFn == NULL ? defaultNowMs : nowFn;
  session->nowCtx = nowCtx;
  session->heartbeatIntervalMs = intervalMs;
  session->heartbeatTimeoutMs = timeoutMs;
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
  sessionNowMsFn_t nowFn;
  void *nowCtx;
  int heartbeatIntervalMs;
  int heartbeatTimeoutMs;
  if (session == NULL) {
    return;
  }

  isServer = session->isServer;
  nowFn = session->nowFn;
  nowCtx = session->nowCtx;
  heartbeatIntervalMs = session->heartbeatIntervalMs;
  heartbeatTimeoutMs = session->heartbeatTimeoutMs;
  memset(session, 0, sizeof(*session));
  session->isServer = isServer;
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
  outStats->pendingTcpNbytes = session->pendingTcpNbytes;
  outStats->pendingTunNbytes = session->pendingTunNbytes;
  outStats->tcpBufferedNbytes = session->tcpBufferedNbytes;
  return true;
}

sessionStepResult_t sessionStep(
    session_t *session, ioPoller_t *poller, ioEvent_t event, const unsigned char key[ProtocolPskSize]) {
  bool result = true;
  if (session == NULL || poller == NULL || key == NULL) {
    return sessionStepStop;
  }
  if (event == ioEventError) {
    return sessionStepStop;
  }

  if (event == ioEventTunRead) {
    result = pipeTun(poller, key, session);
  } else if (event == ioEventTcpRead) {
    result = pipeTcp(poller, key, session);
  }
  if (!result) {
    return sessionStepStop;
  }

  if (!serviceBackpressure(poller, session)) {
    logf("backpressure handling failure");
    return sessionStepStop;
  }

  if (!heartbeatTick(poller, key, session)) {
    logf("heartbeat failure");
    return sessionStepStop;
  }

  return sessionStepContinue;
}

bool sessionApiSmoke(void) {
  return true;
}
