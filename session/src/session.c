#include "session.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
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

static bool canToggleReadInterest(const session_t *session, ioSource_t source) {
  if (session != NULL && session->isServer && session->runtime != NULL && source == ioSourceTun) {
    return false;
  }
  return true;
}

static bool pauseReadSourceForSession(session_t *session, ioPoller_t *poller, ioSource_t source, bool *paused) {
  if (*paused) {
    return true;
  }
  if (!canToggleReadInterest(session, source)) {
    *paused = true;
    return true;
  }
  return pauseReadSource(poller, source, paused);
}

static long queuedBytesForDestination(const session_t *session, ioPoller_t *poller, ioSource_t destination) {
  if (session != NULL && session->isServer && session->runtime != NULL && destination == ioSourceTun) {
    return serverRuntimeQueuedTunBytes(session->runtime);
  }
  return ioPollerQueuedBytes(poller, destination);
}

static bool maybeResumeReadSource(
    session_t *session, ioPoller_t *poller, ioSource_t source, ioSource_t destination, bool *paused, long pendingNbytes) {
  long queued;
  if (!*paused || pendingNbytes > 0) {
    return true;
  }

  queued = queuedBytesForDestination(session, poller, destination);
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
  if (!ioPollerSetReadEnabled(poller, source, true)) {
    return false;
  }
  *paused = false;
  return true;
}

static queueResult_t queueTcpWithBackpressure(ioPoller_t *poller, session_t *session, const void *data, long nbytes) {
  long queued;
  int ownerSlot;

  if (session->pendingTcpNbytes > 0) {
    return queueResultBlocked;
  }
  if (session->isServer && session->runtime != NULL && serverRuntimeHasPendingTunToTcp(session->runtime)) {
    session->tunReadPaused = true;
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
    if (session->isServer && session->runtime != NULL) {
      ownerSlot = serverRuntimeFindSlotByFd(session->runtime, poller->tcpFd);
      if (ownerSlot < 0) {
        return queueResultError;
      }
      if (!serverRuntimeStorePendingTunToTcp(session->runtime, ownerSlot, data, nbytes)) {
        return queueResultError;
      }
      session->tunReadPaused = true;
      return queueResultBlocked;
    }
    memcpy(session->pendingTcpBuf, data, (size_t)nbytes);
    session->pendingTcpNbytes = nbytes;
    if (!pauseReadSourceForSession(session, poller, ioSourceTun, &session->tunReadPaused)) {
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
  if (session->isServer && session->runtime != NULL) {
    if (serverRuntimeQueueTunWrite(session->runtime, data, nbytes)) {
      return queueResultQueued;
    }
    queued = serverRuntimeQueuedTunBytes(session->runtime);
  } else if (ioPollerQueueWrite(poller, ioSourceTun, data, nbytes)) {
    return queueResultQueued;
  } else {
    queued = ioPollerQueuedBytes(poller, ioSourceTun);
  }
  if (queued < 0) {
    return queueResultError;
  }
  if (queued + nbytes > IoPollerQueueCapacity) {
    memcpy(session->pendingTunBuf, data, (size_t)nbytes);
    session->pendingTunNbytes = nbytes;
    if (!pauseReadSourceForSession(session, poller, ioSourceTcp, &session->tcpReadPaused)) {
      return queueResultError;
    }
    return queueResultBlocked;
  }
  return queueResultError;
}

static bool serviceBackpressure(ioPoller_t *poller, session_t *session, ioEvent_t event) {
  long queued;
  bool serverMode;

  serverMode = session->isServer && session->runtime != NULL;

  if (serverMode && serverRuntimeHasPendingTunToTcp(session->runtime)) {
    int ownerSlot = serverRuntimePendingTunToTcpOwner(session->runtime);
    int slot = serverRuntimeFindSlotByFd(session->runtime, poller->tcpFd);
    if (slot < 0) {
      return false;
    }
    if (event == ioEventTcpWrite && slot == ownerSlot) {
      serverRuntimePendingRetry_t retry =
          serverRuntimeRetryPendingTunToTcp(session->runtime, ownerSlot, poller);
      if (retry == serverRuntimePendingRetryError) {
        return false;
      }
    }
  }

  if (!serverMode && session->pendingTcpNbytes > 0) {
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
    bool queuedTun = false;
    if (session->isServer && session->runtime != NULL) {
      queuedTun = serverRuntimeQueueTunWrite(session->runtime, session->pendingTunBuf, session->pendingTunNbytes);
    } else {
      queuedTun = ioPollerQueueWrite(poller, ioSourceTun, session->pendingTunBuf, session->pendingTunNbytes);
    }
    if (queuedTun) {
      session->pendingTunNbytes = 0;
    } else {
      queued = queuedBytesForDestination(session, poller, ioSourceTun);
      if (queued < 0 || queued + session->pendingTunNbytes <= IoPollerQueueCapacity) {
        return false;
      }
    }
  }

  if (!maybeResumeReadSource(session, poller, ioSourceTcp, ioSourceTun, &session->tcpReadPaused, session->pendingTunNbytes)) {
    return false;
  }

  if (serverMode) {
    if (serverRuntimeHasPendingTunToTcp(session->runtime)) {
      session->tunReadPaused = true;
      return true;
    }

    queued = ioPollerQueuedBytes(poller, ioSourceTcp);
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
      session, poller, ioSourceTun, ioSourceTcp, &session->tunReadPaused, session->pendingTcpNbytes);
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
  outStats->pendingTcpNbytes = session->pendingTcpNbytes;
  outStats->pendingTunNbytes = session->pendingTunNbytes;
  outStats->tcpBufferedNbytes = session->tcpBufferedNbytes;
  return true;
}

void sessionSetServerRuntime(session_t *session, serverRuntime_t *runtime) {
  if (session == NULL) {
    return;
  }
  session->runtime = runtime;
}

bool sessionHasPendingTunEgress(const session_t *session) {
  if (session == NULL) {
    return false;
  }
  return session->pendingTunNbytes > 0;
}

bool sessionServiceBackpressure(session_t *session, ioPoller_t *poller) {
  if (session == NULL || poller == NULL) {
    return false;
  }
  return serviceBackpressure(poller, session, ioEventTimeout);
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

  if (!serviceBackpressure(poller, session, event)) {
    logf("backpressure handling failure");
    return sessionStepStop;
  }

  if (!heartbeatTick(poller, key, session)) {
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

static int isValidTunClaim(const char *claim) {
  struct in_addr addr;
  return claim != NULL && inet_pton(AF_INET, claim, &addr) == 1;
}

static int isValidTapClaim(const char *claim) {
  int i;
  if (claim == NULL || strlen(claim) != 17) {
    return 0;
  }
  for (i = 0; i < 17; i++) {
    if ((i % 3) == 2) {
      if (claim[i] != ':') {
        return 0;
      }
    } else if (!isxdigit((unsigned char)claim[i])) {
      return 0;
    }
  }
  return 1;
}

static bool authReadExactWithTimeout(int fd, void *buf, long nbytes, int timeoutMs) {
  long offset = 0;
  while (offset < nbytes) {
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
    };
    int prc = poll(&pfd, 1, timeoutMs);
    if (prc <= 0) {
      return false;
    }
    if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
      return false;
    }
    {
      ssize_t n = read(fd, (char *)buf + offset, (size_t)(nbytes - offset));
      if (n <= 0) {
        return false;
      }
      offset += (long)n;
    }
  }
  return true;
}

static bool authWriteAll(int fd, const void *buf, long nbytes) {
  long offset = 0;
  while (offset < nbytes) {
    ssize_t n = write(fd, (const char *)buf + offset, (size_t)(nbytes - offset));
    if (n <= 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    offset += (long)n;
  }
  return true;
}

static bool authReadWireFrame(int fd, int timeoutMs, protocolFrame_t *frame) {
  uint32_t wireNbytes = 0;
  if (frame == NULL) {
    return false;
  }
  if (!authReadExactWithTimeout(fd, &wireNbytes, ProtocolWireLengthSize, timeoutMs)) {
    return false;
  }
  frame->nbytes = (long)ntohl(wireNbytes);
  if (frame->nbytes <= 0 || frame->nbytes > ProtocolFrameSize) {
    return false;
  }
  return authReadExactWithTimeout(fd, frame->buf, frame->nbytes, timeoutMs);
}

static bool authWriteWireFrame(int fd, const protocolFrame_t *frame) {
  uint32_t wireNbytes;
  if (frame == NULL || frame->nbytes <= 0 || frame->nbytes > ProtocolFrameSize) {
    return false;
  }
  wireNbytes = htonl((uint32_t)frame->nbytes);
  if (!authWriteAll(fd, &wireNbytes, ProtocolWireLengthSize)) {
    return false;
  }
  return authWriteAll(fd, frame->buf, frame->nbytes);
}

static bool serverAuthenticateClient(
    int connFd,
    const char *ifModeLabel,
    sessionServerKeyLookupFn_t keyLookupFn,
    void *keyLookupCtx,
    int authTimeoutMs,
    char outClaim[SessionClaimSize],
    unsigned char outKey[ProtocolPskSize]) {
  protocolFrame_t frame;
  protocolMessage_t msg;
  unsigned char serverNonce[ProtocolNonceSize];
  unsigned char helloPayload[ProtocolNonceSize * 2];

  if (ifModeLabel == NULL || keyLookupFn == NULL || outClaim == NULL || outKey == NULL || authTimeoutMs <= 0) {
    return false;
  }

  if (!authReadWireFrame(connFd, authTimeoutMs, &frame)) {
    return false;
  }
  if (frame.nbytes <= 0 || frame.nbytes >= SessionClaimSize) {
    return false;
  }
  memcpy(outClaim, frame.buf, (size_t)frame.nbytes);
  outClaim[frame.nbytes] = '\0';

  if ((strcmp(ifModeLabel, "tun") == 0 && !isValidTunClaim(outClaim))
      || (strcmp(ifModeLabel, "tap") == 0 && !isValidTapClaim(outClaim))) {
    return false;
  }
  if (keyLookupFn(keyLookupCtx, outClaim, outKey) != 0) {
    return false;
  }

  randombytes_buf(serverNonce, sizeof(serverNonce));
  msg.type = protocolMsgAuthChallenge;
  msg.nbytes = ProtocolNonceSize;
  msg.buf = (const char *)serverNonce;
  if (protocolMessageEncodeFrame(&msg, &frame) != protocolStatusOk || !authWriteWireFrame(connFd, &frame)) {
    return false;
  }

  if (!authReadWireFrame(connFd, authTimeoutMs, &frame)) {
    return false;
  }
  if (protocolSecureDecodeFrame(&frame, outKey, &msg) != protocolStatusOk) {
    return false;
  }
  if (msg.type != protocolMsgClientHello || msg.nbytes != ProtocolNonceSize * 2) {
    return false;
  }
  memcpy(helloPayload, msg.buf, sizeof(helloPayload));
  if (memcmp(helloPayload, serverNonce, ProtocolNonceSize) != 0) {
    return false;
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

  if (sessionStep(session, &runtime->slots[slot].poller, event, key) == sessionStepStop) {
    (void)serverEpollCtl(runtime->epollFd, EPOLL_CTL_DEL, connFd, 0);
    close(connFd);
    return serverRuntimeRemoveClient(runtime, slot);
  }
  return true;
}

static bool serverTickAllClients(serverRuntime_t *runtime) {
  int slot;
  for (slot = 0; slot < runtime->maxSessions; slot++) {
    if (!runtime->slots[slot].active) {
      continue;
    }
    if (!serverDispatchClient(runtime, slot, ioEventTimeout)) {
      return false;
    }
  }
  return true;
}

int sessionServeMultiClient(
    int tunFd,
    int listenFd,
    sessionServerKeyLookupFn_t keyLookupFn,
    void *keyLookupCtx,
    const char *ifModeLabel,
    int authTimeoutMs,
    const sessionHeartbeatConfig_t *heartbeatCfg,
    int maxSessions) {
  serverRuntime_t runtime;
  struct epoll_event events[16];
  int epollFd = -1;
  int rc = -1;
  int i;

  if (tunFd < 0
      || listenFd < 0
      || keyLookupFn == NULL
      || ifModeLabel == NULL
      || authTimeoutMs <= 0
      || heartbeatCfg == NULL
      || maxSessions <= 0) {
    return -1;
  }
  if (!serverRuntimeInit(&runtime, tunFd, listenFd, maxSessions, heartbeatCfg)) {
    return -1;
  }

  epollFd = epoll_create1(0);
  if (epollFd < 0) {
    serverRuntimeDeinit(&runtime);
    return -1;
  }
  runtime.epollFd = epollFd;

  if (!serverEpollCtl(epollFd, EPOLL_CTL_ADD, listenFd, EPOLLIN | EPOLLRDHUP)
      || !serverEpollCtl(epollFd, EPOLL_CTL_ADD, tunFd, runtime.tunEvents)) {
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
          int slot;
          char claim[SessionClaimSize];
          unsigned char key[ProtocolPskSize];
          if (status == ioStatusWouldBlock) {
            break;
          }
          if (status != ioStatusOk) {
            goto cleanup;
          }
          logf("connected with %s:%d", clientIp, clientPort);
          if (!serverAuthenticateClient(
                  connFd, ifModeLabel, keyLookupFn, keyLookupCtx, authTimeoutMs, claim, key)) {
            close(connFd);
            continue;
          }
          if (serverRuntimeHasActiveClaim(&runtime, claim)) {
            close(connFd);
            continue;
          }
          slot = serverRuntimeAddClient(&runtime, connFd, key, claim);
          sodium_memzero(key, sizeof(key));
          if (slot < 0) {
            close(connFd);
            continue;
          }
          runtime.slots[slot].poller.epollFd = epollFd;
          if (!serverEpollCtl(epollFd, EPOLL_CTL_ADD, connFd, runtime.slots[slot].poller.tcpEvents)) {
            close(connFd);
            (void)serverRuntimeRemoveClient(&runtime, slot);
            goto cleanup;
          }
        }
        continue;
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
          if (runtime.tunOutNbytes <= IoPollerLowWatermark) {
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
          if (!ioPollerServiceWriteEvent(&runtime.slots[slot].poller, ioSourceTcp)) {
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
  }

cleanup:
  for (i = 0; i < runtime.maxSessions; i++) {
    int connFd = serverRuntimeConnFdAt(&runtime, i);
    if (connFd >= 0) {
      (void)serverEpollCtl(epollFd, EPOLL_CTL_DEL, connFd, 0);
      close(connFd);
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
