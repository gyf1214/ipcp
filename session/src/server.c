#include "server.h"

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
#include "packet.h"

static long long defaultNowMs(void *ctx) {
  struct timespec ts;
  (void)ctx;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long long)ts.tv_sec * 1000 + (long long)ts.tv_nsec / 1000000;
}

static bool activeSlotIndexValid(const server_t *runtime, int slot) {
  return runtime != NULL && runtime->activeConns != NULL && slot >= 0 && slot < runtime->maxActiveSessions;
}

static bool preAuthSlotIndexValid(const server_t *runtime, int slot) {
  return runtime != NULL && runtime->preAuthConns != NULL && slot >= 0 && slot < runtime->maxPreAuthSessions;
}

static bool runtimeTunEpollCtl(server_t *runtime, unsigned int events) {
  struct epoll_event event;

  if (runtime == NULL || runtime->tunPoller.tunFd < 0) {
    return false;
  }
  if (runtime->epollFd < 0) {
    runtime->tunPoller.events = events;
    return true;
  }

  memset(&event, 0, sizeof(event));
  event.events = events;
  event.data.fd = runtime->tunPoller.tunFd;
  if (epoll_ctl(runtime->epollFd, EPOLL_CTL_MOD, runtime->tunPoller.tunFd, &event) < 0) {
    return false;
  }
  runtime->tunPoller.events = events;
  return true;
}

bool serverInit(
    server_t *runtime,
    int tunFd,
    int listenFd,
    int maxActiveSessions,
    int maxPreAuthSessions,
    const sessionHeartbeatConfig_t *heartbeatCfg,
    sessionNowMsFn_t nowMsFn,
    void *nowCtx) {
  int i;

  if (runtime == NULL
      || heartbeatCfg == NULL
      || maxActiveSessions <= 0
      || maxPreAuthSessions <= 0
      || tunFd < 0
      || listenFd < 0) {
    return false;
  }

  memset(runtime, 0, sizeof(*runtime));
  runtime->activeConns = calloc((size_t)maxActiveSessions, sizeof(*runtime->activeConns));
  runtime->preAuthConns = calloc((size_t)maxPreAuthSessions, sizeof(*runtime->preAuthConns));
  if (runtime->activeConns == NULL || runtime->preAuthConns == NULL) {
    free(runtime->activeConns);
    free(runtime->preAuthConns);
    memset(runtime, 0, sizeof(*runtime));
    return false;
  }

  runtime->tunPoller.epollFd = -1;
  runtime->tunPoller.tunFd = tunFd;
  runtime->listenFd = listenFd;
  runtime->epollFd = -1;
  runtime->tunPoller.events = EPOLLIN | EPOLLRDHUP;
  runtime->tunPoller.readPos = 0;
  runtime->tunPoller.writePos = 0;
  runtime->tunPoller.queuedBytes = 0;
  runtime->tunPoller.frameHead = 0;
  runtime->tunPoller.frameTail = 0;
  runtime->tunPoller.frameCount = 0;
  memset(runtime->tunPoller.outBuf, 0, sizeof(runtime->tunPoller.outBuf));
  runtime->pendingOwnerSlot = -1;
  runtime->pendingTunToTcpNbytes = 0;
  runtime->retryCursor = 0;
  runtime->maxActiveSessions = maxActiveSessions;
  runtime->activeCount = 0;
  runtime->maxPreAuthSessions = maxPreAuthSessions;
  runtime->preAuthCount = 0;
  runtime->heartbeatCfg = *heartbeatCfg;
  runtime->nowMsFn = nowMsFn == NULL ? defaultNowMs : nowMsFn;
  runtime->nowCtx = nowCtx;

  for (i = 0; i < runtime->maxActiveSessions; i++) {
    runtime->activeConns[i].connFd = -1;
  }
  for (i = 0; i < runtime->maxPreAuthSessions; i++) {
    runtime->preAuthConns[i].connFd = -1;
    runtime->preAuthConns[i].resolvedActiveSlot = -1;
  }

  return true;
}

void serverDeinit(server_t *runtime) {
  int i;

  if (runtime == NULL) {
    return;
  }

  if (runtime->activeConns != NULL) {
    for (i = 0; i < runtime->maxActiveSessions; i++) {
      if (runtime->activeConns[i].session != NULL) {
        sessionDestroy(runtime->activeConns[i].session);
      }
    }
  }

  free(runtime->activeConns);
  free(runtime->preAuthConns);
  memset(runtime, 0, sizeof(*runtime));
}

int serverAddClient(
    server_t *runtime,
    int activeSlot,
    int connFd,
    const unsigned char key[ProtocolPskSize],
    const unsigned char *claim,
    long claimNbytes) {
  session_t *session;

  if (runtime == NULL
      || runtime->activeConns == NULL
      || connFd < 0
      || key == NULL
      || claim == NULL
      || claimNbytes <= 0
      || claimNbytes > SessionClaimSize) {
    return -1;
  }
  if (!activeSlotIndexValid(runtime, activeSlot)) {
    return -1;
  }
  if (runtime->activeConns[activeSlot].active) {
    return -1;
  }
  if (runtime->activeCount >= runtime->maxActiveSessions) {
    return -1;
  }

  session = sessionCreate(true, &runtime->heartbeatCfg, NULL, NULL);
  if (session == NULL) {
    return -1;
  }

  runtime->activeConns[activeSlot].connFd = connFd;
  runtime->activeConns[activeSlot].session = session;
  sessionSetServer(session, runtime);
  runtime->activeConns[activeSlot].tcpPoller.epollFd = runtime->epollFd;
  runtime->activeConns[activeSlot].tcpPoller.tcpFd = connFd;
  runtime->activeConns[activeSlot].tcpPoller.events = EPOLLIN | EPOLLRDHUP;
  runtime->activeConns[activeSlot].tcpPoller.outOffset = 0;
  runtime->activeConns[activeSlot].tcpPoller.outNbytes = 0;
  memset(runtime->activeConns[activeSlot].tcpPoller.outBuf, 0, sizeof(runtime->activeConns[activeSlot].tcpPoller.outBuf));
  memcpy(runtime->activeConns[activeSlot].key, key, ProtocolPskSize);
  memcpy(runtime->activeConns[activeSlot].claim, claim, (size_t)claimNbytes);
  runtime->activeConns[activeSlot].claimNbytes = claimNbytes;
  runtime->activeConns[activeSlot].active = true;
  runtime->activeCount++;
  return activeSlot;
}

bool serverRemoveClient(server_t *runtime, int slot) {
  if (!activeSlotIndexValid(runtime, slot) || !runtime->activeConns[slot].active) {
    return false;
  }

  if (!serverDropPendingTunToTcpByOwner(runtime, slot)) {
    return false;
  }
  sessionDestroy(runtime->activeConns[slot].session);
  runtime->activeConns[slot].tcpPoller.outOffset = 0;
  runtime->activeConns[slot].tcpPoller.outNbytes = 0;
  memset(runtime->activeConns[slot].tcpPoller.outBuf, 0, sizeof(runtime->activeConns[slot].tcpPoller.outBuf));
  memset(runtime->activeConns[slot].key, 0, sizeof(runtime->activeConns[slot].key));
  memset(runtime->activeConns[slot].claim, 0, sizeof(runtime->activeConns[slot].claim));
  runtime->activeConns[slot].claimNbytes = 0;
  runtime->activeConns[slot].connFd = -1;
  runtime->activeConns[slot].session = NULL;
  runtime->activeConns[slot].active = false;
  runtime->activeCount--;
  return true;
}

int serverFindSlotByFd(const server_t *runtime, int connFd) {
  int i;

  if (runtime == NULL || runtime->activeConns == NULL || connFd < 0) {
    return -1;
  }

  for (i = 0; i < runtime->maxActiveSessions; i++) {
    if (runtime->activeConns[i].active && runtime->activeConns[i].connFd == connFd) {
      return i;
    }
  }

  return -1;
}

int serverFindSlotByClaim(const server_t *runtime, const unsigned char *claim, long claimNbytes) {
  int i;

  if (runtime == NULL || runtime->activeConns == NULL || claim == NULL || claimNbytes <= 0) {
    return -1;
  }

  for (i = 0; i < runtime->maxActiveSessions; i++) {
    if (!runtime->activeConns[i].active) {
      continue;
    }
    if (runtime->activeConns[i].claimNbytes != claimNbytes) {
      continue;
    }
    if (memcmp(runtime->activeConns[i].claim, claim, (size_t)claimNbytes) == 0) {
      return i;
    }
  }

  return -1;
}

int serverFindPreAuthSlotByFd(const server_t *runtime, int connFd) {
  int i;

  if (runtime == NULL || runtime->preAuthConns == NULL || connFd < 0) {
    return -1;
  }

  for (i = 0; i < runtime->maxPreAuthSessions; i++) {
    if (runtime->preAuthConns[i].active && runtime->preAuthConns[i].connFd == connFd) {
      return i;
    }
  }

  return -1;
}

int serverPickEgressClient(const server_t *runtime) {
  int i;

  if (runtime == NULL || runtime->activeConns == NULL) {
    return -1;
  }

  for (i = 0; i < runtime->maxActiveSessions; i++) {
    if (runtime->activeConns[i].active) {
      return runtime->activeConns[i].connFd;
    }
  }

  return -1;
}

int serverClientCount(const server_t *runtime) {
  if (runtime == NULL || runtime->activeConns == NULL) {
    return -1;
  }
  return runtime->activeCount;
}

long serverQueuedTunBytes(const server_t *runtime) {
  if (runtime == NULL) {
    return -1;
  }
  return ioTunQueuedBytes(&runtime->tunPoller);
}

long long serverNowMs(const server_t *runtime) {
  if (runtime == NULL || runtime->nowMsFn == NULL) {
    return -1;
  }
  return runtime->nowMsFn(runtime->nowCtx);
}

bool serverSyncTunWriteInterest(server_t *runtime) {
  unsigned int nextEvents;
  bool needWrite;

  if (runtime == NULL) {
    return false;
  }
  if (runtime->epollFd < 0) {
    return true;
  }

  needWrite = ioTunQueuedBytes(&runtime->tunPoller) > 0;
  nextEvents = runtime->tunPoller.events;
  if (needWrite) {
    nextEvents |= EPOLLOUT;
  } else {
    nextEvents &= ~EPOLLOUT;
  }
  if (nextEvents == runtime->tunPoller.events) {
    return true;
  }
  return runtimeTunEpollCtl(runtime, nextEvents);
}

bool serverQueueTunWrite(server_t *runtime, const void *data, long nbytes) {
  if (runtime == NULL) {
    return false;
  }
  if (runtime->epollFd >= 0) {
    runtime->tunPoller.epollFd = runtime->epollFd;
  }
  if (!ioTunWrite(&runtime->tunPoller, data, nbytes)) {
    return false;
  }
  return true;
}

bool serverServiceTunWriteEvent(server_t *runtime) {
  if (runtime == NULL) {
    return false;
  }
  return ioTunServiceWriteEvent(&runtime->tunPoller);
}

int serverRetryBlockedTunRoundRobin(server_t *runtime) {
  int i;
  int start;
  int nextCursor = -1;

  if (runtime == NULL || runtime->activeConns == NULL || runtime->maxActiveSessions <= 0) {
    return -1;
  }

  start = runtime->retryCursor % runtime->maxActiveSessions;
  for (i = 0; i < runtime->maxActiveSessions; i++) {
    int slot = (start + i) % runtime->maxActiveSessions;
    session_t *session;
    if (!runtime->activeConns[slot].active) {
      continue;
    }
    session = runtime->activeConns[slot].session;
    if (session == NULL) {
      continue;
    }
    if (!sessionHasPendingTunEgress(session)) {
      continue;
    }
      if (!sessionServiceBackpressure(session, &runtime->activeConns[slot].tcpPoller, &runtime->tunPoller)) {
        return -1;
      }
  }

  for (i = 1; i <= runtime->maxActiveSessions; i++) {
    int slot = (start + i) % runtime->maxActiveSessions;
    if (runtime->activeConns[slot].active) {
      nextCursor = slot;
      break;
    }
  }
  if (nextCursor < 0) {
    nextCursor = 0;
  }
  runtime->retryCursor = nextCursor;
  return runtime->retryCursor;
}

bool serverSetTunReadEnabled(server_t *runtime, bool enabled) {
  unsigned int nextEvents;

  if (runtime == NULL) {
    return false;
  }

  nextEvents = runtime->tunPoller.events;
  if (enabled) {
    nextEvents |= EPOLLIN;
  } else {
    nextEvents &= ~EPOLLIN;
  }
  if (nextEvents == runtime->tunPoller.events) {
    return true;
  }
  return runtimeTunEpollCtl(runtime, nextEvents);
}

bool serverHasPendingTunToTcp(const server_t *runtime) {
  return runtime != NULL && runtime->pendingTunToTcpNbytes > 0 && runtime->pendingOwnerSlot >= 0;
}

int serverPendingTunToTcpOwner(const server_t *runtime) {
  if (runtime == NULL) {
    return -1;
  }
  return runtime->pendingOwnerSlot;
}

bool serverStorePendingTunToTcp(server_t *runtime, int ownerSlot, const void *data, long nbytes) {
  if (runtime == NULL || data == NULL || nbytes <= 0 || nbytes > (long)sizeof(runtime->pendingTunToTcpBuf)) {
    return false;
  }
  if (!activeSlotIndexValid(runtime, ownerSlot) || !runtime->activeConns[ownerSlot].active) {
    return false;
  }
  if (serverHasPendingTunToTcp(runtime)) {
    return false;
  }

  memcpy(runtime->pendingTunToTcpBuf, data, (size_t)nbytes);
  runtime->pendingTunToTcpNbytes = nbytes;
  runtime->pendingOwnerSlot = ownerSlot;
  return serverSetTunReadEnabled(runtime, false);
}

serverPendingRetry_t serverRetryPendingTunToTcp(
    server_t *runtime, int ownerSlot, ioTcpPoller_t *ownerPoller) {
  long queued;

  if (runtime == NULL || ownerPoller == NULL) {
    return serverPendingRetryError;
  }
  if (!serverHasPendingTunToTcp(runtime)) {
    return serverPendingRetryQueued;
  }
  if (runtime->pendingOwnerSlot != ownerSlot) {
    return serverPendingRetryBlocked;
  }

  if (ioTcpWrite(ownerPoller, runtime->pendingTunToTcpBuf, runtime->pendingTunToTcpNbytes)) {
    runtime->pendingTunToTcpNbytes = 0;
    runtime->pendingOwnerSlot = -1;
    return serverPendingRetryQueued;
  }

  queued = ioTcpQueuedBytes(ownerPoller);
  if (queued < 0 || queued + runtime->pendingTunToTcpNbytes <= IoPollerQueueCapacity) {
    return serverPendingRetryError;
  }
  return serverPendingRetryBlocked;
}

bool serverDropPendingTunToTcpByOwner(server_t *runtime, int ownerSlot) {
  if (runtime == NULL) {
    return false;
  }
  if (!serverHasPendingTunToTcp(runtime) || runtime->pendingOwnerSlot != ownerSlot) {
    return true;
  }

  runtime->pendingTunToTcpNbytes = 0;
  runtime->pendingOwnerSlot = -1;
  return serverSetTunReadEnabled(runtime, true);
}

session_t *serverSessionAt(server_t *runtime, int slot) {
  if (!activeSlotIndexValid(runtime, slot) || !runtime->activeConns[slot].active) {
    return NULL;
  }
  return runtime->activeConns[slot].session;
}

int serverConnFdAt(const server_t *runtime, int slot) {
  if (!activeSlotIndexValid(runtime, slot) || !runtime->activeConns[slot].active) {
    return -1;
  }
  return runtime->activeConns[slot].connFd;
}

const unsigned char *serverKeyAt(const server_t *runtime, int slot) {
  if (!activeSlotIndexValid(runtime, slot) || !runtime->activeConns[slot].active) {
    return NULL;
  }
  return runtime->activeConns[slot].key;
}

bool serverHasActiveClaim(const server_t *runtime, const unsigned char *claim, long claimNbytes) {
  int i;
  if (runtime == NULL || runtime->activeConns == NULL || claim == NULL || claimNbytes <= 0) {
    return false;
  }
  for (i = 0; i < runtime->maxActiveSessions; i++) {
    if (!runtime->activeConns[i].active) {
      continue;
    }
    if (runtime->activeConns[i].claimNbytes == claimNbytes
        && memcmp(runtime->activeConns[i].claim, claim, (size_t)claimNbytes) == 0) {
      return true;
    }
  }
  return false;
}

int serverCreatePreAuthConn(server_t *runtime, int connFd, long long authDeadlineMs) {
  int i;

  if (runtime == NULL || runtime->preAuthConns == NULL || connFd < 0) {
    return -1;
  }
  if (runtime->preAuthCount >= runtime->maxPreAuthSessions) {
    return -1;
  }

  for (i = 0; i < runtime->maxPreAuthSessions; i++) {
    preAuthConn_t *conn = &runtime->preAuthConns[i];
    if (conn->active) {
      continue;
    }
    memset(conn, 0, sizeof(*conn));
    conn->connFd = connFd;
    conn->authDeadlineMs = authDeadlineMs;
    conn->resolvedActiveSlot = -1;
    protocolDecoderInit(&conn->decoder);
    conn->active = true;
    runtime->preAuthCount++;
    return i;
  }

  return -1;
}

bool serverRemovePreAuthConn(server_t *runtime, int preAuthSlot) {
  preAuthConn_t *conn;

  if (!preAuthSlotIndexValid(runtime, preAuthSlot)) {
    return false;
  }
  conn = &runtime->preAuthConns[preAuthSlot];
  if (!conn->active) {
    return false;
  }

  memset(conn->resolvedKey, 0, sizeof(conn->resolvedKey));
  memset(conn->serverNonce, 0, sizeof(conn->serverNonce));
  memset(conn->claim, 0, sizeof(conn->claim));
  conn->claimNbytes = 0;
  memset(conn->tcpReadCarryBuf, 0, sizeof(conn->tcpReadCarryBuf));
  conn->tcpReadCarryNbytes = 0;
  memset(conn->authWriteBuf, 0, sizeof(conn->authWriteBuf));
  conn->authWriteOffset = 0;
  conn->authWriteNbytes = 0;
  conn->authState = 0;
  conn->authDeadlineMs = 0;
  conn->resolvedActiveSlot = -1;
  conn->connFd = -1;
  conn->active = false;
  runtime->preAuthCount--;
  return true;
}

preAuthConn_t *serverPreAuthAt(server_t *runtime, int preAuthSlot) {
  if (!preAuthSlotIndexValid(runtime, preAuthSlot) || !runtime->preAuthConns[preAuthSlot].active) {
    return NULL;
  }
  return &runtime->preAuthConns[preAuthSlot];
}

bool serverPromoteToActiveSlot(server_t *runtime, int preAuthSlot) {
  preAuthConn_t *preAuth;
  int connFd;

  if (runtime == NULL) {
    return false;
  }
  preAuth = serverPreAuthAt(runtime, preAuthSlot);
  if (preAuth == NULL || !activeSlotIndexValid(runtime, preAuth->resolvedActiveSlot)) {
    return false;
  }
  if (runtime->activeConns[preAuth->resolvedActiveSlot].active) {
    return false;
  }

  connFd = preAuth->connFd;
  if (serverAddClient(
          runtime, preAuth->resolvedActiveSlot, connFd, preAuth->resolvedKey, preAuth->claim, preAuth->claimNbytes)
      < 0) {
    return false;
  }
  return serverRemovePreAuthConn(runtime, preAuthSlot);
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

static bool serverClosePreAuthConn(server_t *runtime, int preAuthSlot) {
  int connFd = -1;
  preAuthConn_t *conn = serverPreAuthAt(runtime, preAuthSlot);
  if (conn == NULL) {
    return false;
  }
  connFd = conn->connFd;
  (void)serverEpollCtl(runtime->epollFd, EPOLL_CTL_DEL, connFd, 0);
  close(connFd);
  return serverRemovePreAuthConn(runtime, preAuthSlot);
}

static bool serverSetPreAuthWriteEnabled(server_t *runtime, int connFd, bool writeEnabled) {
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

  randombytes_buf(conn->serverNonce, sizeof(conn->serverNonce));
  rawMsg.nbytes = ProtocolNonceSize;
  rawMsg.buf = (const char *)conn->serverNonce;
  if (protocolEncodeRaw(&rawMsg, &frame) != protocolStatusOk) {
    return false;
  }
  memcpy(conn->authWriteBuf, frame.buf, (size_t)frame.nbytes);
  conn->authWriteOffset = 0;
  conn->authWriteNbytes = frame.nbytes;
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
    server_t *runtime,
    int preAuthSlot,
    ioEvent_t event,
    const char *ifModeLabel,
    sessionServerResolveClaimFn_t resolveClaimFn,
    void *resolveClaimCtx) {
  preAuthConn_t *conn;
  long long nowMs;

  conn = serverPreAuthAt(runtime, preAuthSlot);
  if (conn == NULL || resolveClaimFn == NULL || ifModeLabel == NULL) {
    return false;
  }

  nowMs = serverNowMs(runtime);
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
    if (serverHasActiveClaim(runtime, conn->claim, conn->claimNbytes)) {
      return serverClosePreAuthConn(runtime, preAuthSlot);
    }
    helloDecoder = conn->decoder;
    helloCarryNbytes = conn->tcpReadCarryNbytes;
    if (helloCarryNbytes > 0) {
      memcpy(helloCarryBuf, conn->tcpReadCarryBuf, (size_t)helloCarryNbytes);
    }
    activeSlot = conn->resolvedActiveSlot;
    if (!serverPromoteToActiveSlot(runtime, preAuthSlot)) {
      return serverClosePreAuthConn(runtime, preAuthSlot);
    }
    activeSession = serverSessionAt(runtime, activeSlot);
    if (activeSession == NULL
        || !sessionPromoteFromPreAuth(
            activeSession, &helloDecoder, helloCarryNbytes > 0 ? helloCarryBuf : NULL, helloCarryNbytes)) {
      int failedConnFd = serverConnFdAt(runtime, activeSlot);
      if (failedConnFd >= 0) {
        close(failedConnFd);
      }
      (void)serverRemoveClient(runtime, activeSlot);
      return false;
    }
    activeConnFd = serverConnFdAt(runtime, activeSlot);
    runtime->activeConns[activeSlot].tcpPoller.epollFd = runtime->epollFd;
    if (!serverEpollCtl(runtime->epollFd, EPOLL_CTL_MOD, activeConnFd, runtime->activeConns[activeSlot].tcpPoller.events)) {
      close(activeConnFd);
      (void)serverRemoveClient(runtime, activeSlot);
      return false;
    }
  }

  return true;
}

static bool serverDispatchClient(server_t *runtime, int slot, ioEvent_t event) {
  session_t *session = serverSessionAt(runtime, slot);
  int connFd = serverConnFdAt(runtime, slot);
  const unsigned char *key = serverKeyAt(runtime, slot);
  sessionStepResult_t stepResult;

  if (session == NULL || connFd < 0) {
    return false;
  }
  if (key == NULL) {
    return false;
  }
  if (event == ioEventTunRead) {
    return false;
  }

  stepResult =
      sessionHandleConnEvent(session, &runtime->activeConns[slot].tcpPoller, &runtime->tunPoller, event, key);
  if (stepResult == sessionStepStop) {
    (void)serverEpollCtl(runtime->epollFd, EPOLL_CTL_DEL, connFd, 0);
    close(connFd);
    return serverRemoveClient(runtime, slot);
  }
  return true;
}

static bool serverDispatchTunIngressToSlot(
    server_t *runtime, int slot, const void *payload, long payloadNbytes) {
  session_t *session = serverSessionAt(runtime, slot);
  int connFd = serverConnFdAt(runtime, slot);
  const unsigned char *key = serverKeyAt(runtime, slot);

  if (session == NULL || connFd < 0 || key == NULL) {
    return false;
  }
  if (sessionHandleTunIngressPayload(
          session, &runtime->activeConns[slot].tcpPoller, &runtime->tunPoller, key, payload, payloadNbytes)
      == sessionStepStop) {
    (void)serverEpollCtl(runtime->epollFd, EPOLL_CTL_DEL, connFd, 0);
    close(connFd);
    return serverRemoveClient(runtime, slot);
  }
  return true;
}

bool serverRouteTunIngressPacket(server_t *runtime, const char *ifModeLabel, const void *packet, long packetNbytes) {
  packetParseMode_t mode;
  packetDestination_t destination;
  packetParseStatus_t parseStatus;
  int slot;

  if (runtime == NULL || ifModeLabel == NULL || packet == NULL || packetNbytes <= 0) {
    return false;
  }

  if (strcmp(ifModeLabel, "tun") == 0) {
    mode = packetParseModeTunIpv4;
  } else if (strcmp(ifModeLabel, "tap") == 0) {
    mode = packetParseModeTapEthernet;
  } else {
    return false;
  }

  parseStatus = packetParseDestination(mode, packet, packetNbytes, &destination);
  if (parseStatus != packetParseStatusOk) {
    return false;
  }
  if (destination.classification != packetDestinationOk) {
    return true;
  }

  slot = serverFindSlotByClaim(runtime, destination.claim, destination.claimNbytes);
  if (slot < 0) {
    return true;
  }
  return serverDispatchTunIngressToSlot(runtime, slot, packet, packetNbytes);
}

static bool serverHandleTunRead(server_t *runtime, const char *ifModeLabel) {
  char packet[ProtocolFrameSize];
  long packetNbytes = 0;
  long maxPayload = protocolMaxPlaintextSize() - ((long)sizeof(unsigned char) + ProtocolWireLengthSize);
  ioStatus_t status;

  if (runtime == NULL || ifModeLabel == NULL || maxPayload <= 0 || maxPayload > (long)sizeof(packet)) {
    return false;
  }

  status = ioTunRead(runtime->tunPoller.tunFd, packet, maxPayload, &packetNbytes);
  if (status == ioStatusWouldBlock) {
    return true;
  }
  if (status != ioStatusOk) {
    return false;
  }

  return serverRouteTunIngressPacket(runtime, ifModeLabel, packet, packetNbytes);
}

static bool serverTickAllClients(server_t *runtime) {
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
    server_t *runtime,
    const char *ifModeLabel,
    sessionServerResolveClaimFn_t resolveClaimFn,
    void *resolveClaimCtx) {
  int slot;

  for (slot = 0; slot < runtime->maxPreAuthSessions; slot++) {
    preAuthConn_t *conn = serverPreAuthAt(runtime, slot);
    if (conn == NULL) {
      continue;
    }
    if (!serverDispatchPreAuth(runtime, slot, ioEventTimeout, ifModeLabel, resolveClaimFn, resolveClaimCtx)) {
      return false;
    }
  }
  return true;
}

int serverServeMultiClient(
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
  server_t runtime;
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
  if (!serverInit(
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
  if (tunSubnet != NULL) {
    runtime.tunSubnet = *tunSubnet;
  }

  epollFd = epoll_create1(0);
  if (epollFd < 0) {
    serverDeinit(&runtime);
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
          nowMs = serverNowMs(&runtime);
          if (nowMs < 0) {
            close(connFd);
            goto cleanup;
          }
          preAuthSlot = serverCreatePreAuthConn(&runtime, connFd, nowMs + authTimeoutMs);
          if (preAuthSlot < 0) {
            close(connFd);
            continue;
          }
          if (!serverEpollCtl(epollFd, EPOLL_CTL_ADD, connFd, EPOLLIN | EPOLLRDHUP)) {
            close(connFd);
            (void)serverRemovePreAuthConn(&runtime, preAuthSlot);
            goto cleanup;
          }
        }
        continue;
      }

      {
        int preAuthSlot = serverFindPreAuthSlotByFd(&runtime, fd);
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
          if (!serverHandleTunRead(&runtime, ifModeLabel)) {
            goto cleanup;
          }
        }
        if ((ev & EPOLLOUT) != 0) {
          if (!serverServiceTunWriteEvent(&runtime)) {
            goto cleanup;
          }
          if (ioTunQueuedBytes(&runtime.tunPoller) <= IoPollerLowWatermark) {
            if (serverRetryBlockedTunRoundRobin(&runtime) < 0) {
              goto cleanup;
            }
            if (!serverSyncTunWriteInterest(&runtime)) {
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
        int slot = serverFindSlotByFd(&runtime, fd);
        if (slot < 0) {
          (void)serverEpollCtl(epollFd, EPOLL_CTL_DEL, fd, 0);
          close(fd);
          continue;
        }
        if ((ev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
          (void)serverEpollCtl(epollFd, EPOLL_CTL_DEL, fd, 0);
          close(fd);
          (void)serverRemoveClient(&runtime, slot);
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
    int connFd = serverConnFdAt(&runtime, i);
    if (connFd >= 0) {
      (void)serverEpollCtl(epollFd, EPOLL_CTL_DEL, connFd, 0);
      close(connFd);
    }
  }
  for (i = 0; i < runtime.maxPreAuthSessions; i++) {
    preAuthConn_t *conn = serverPreAuthAt(&runtime, i);
    if (conn != NULL && conn->connFd >= 0) {
      (void)serverEpollCtl(epollFd, EPOLL_CTL_DEL, conn->connFd, 0);
      close(conn->connFd);
      (void)serverRemovePreAuthConn(&runtime, i);
    }
  }
  serverDeinit(&runtime);
  if (epollFd >= 0) {
    close(epollFd);
  }
  return rc;
}
