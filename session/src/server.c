#include "server.h"

#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

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
