#include "serverRuntime.h"

#include <errno.h>
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

static bool activeSlotIndexValid(const serverRuntime_t *runtime, int slot) {
  return runtime != NULL && runtime->activeConns != NULL && slot >= 0 && slot < runtime->maxActiveSessions;
}

static bool preAuthSlotIndexValid(const serverRuntime_t *runtime, int slot) {
  return runtime != NULL && runtime->preAuthConns != NULL && slot >= 0 && slot < runtime->maxPreAuthSessions;
}

static bool runtimeTunEpollCtl(serverRuntime_t *runtime, unsigned int events) {
  struct epoll_event event;

  if (runtime == NULL || runtime->tunFd < 0) {
    return false;
  }
  if (runtime->epollFd < 0) {
    runtime->tunEvents = events;
    return true;
  }

  memset(&event, 0, sizeof(event));
  event.events = events;
  event.data.fd = runtime->tunFd;
  if (epoll_ctl(runtime->epollFd, EPOLL_CTL_MOD, runtime->tunFd, &event) < 0) {
    return false;
  }
  runtime->tunEvents = events;
  return true;
}

bool serverRuntimeInit(
    serverRuntime_t *runtime,
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

  runtime->tunFd = tunFd;
  runtime->listenFd = listenFd;
  runtime->epollFd = -1;
  runtime->tunEvents = EPOLLIN | EPOLLRDHUP;
  runtime->tunOutOffset = 0;
  runtime->tunOutNbytes = 0;
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

void serverRuntimeDeinit(serverRuntime_t *runtime) {
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

int serverRuntimeAddClient(
    serverRuntime_t *runtime,
    int activeSlot,
    int connFd,
    const unsigned char key[ProtocolPskSize],
    const char *claim) {
  session_t *session;

  if (runtime == NULL || runtime->activeConns == NULL || connFd < 0 || key == NULL || claim == NULL) {
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
  sessionSetServerRuntime(session, runtime);
  runtime->activeConns[activeSlot].poller.epollFd = runtime->epollFd;
  runtime->activeConns[activeSlot].poller.tunFd = runtime->tunFd;
  runtime->activeConns[activeSlot].poller.tcpFd = connFd;
  runtime->activeConns[activeSlot].poller.tunEvents = runtime->tunEvents;
  runtime->activeConns[activeSlot].poller.tcpEvents = EPOLLIN | EPOLLRDHUP;
  runtime->activeConns[activeSlot].poller.tunOutOffset = 0;
  runtime->activeConns[activeSlot].poller.tunOutNbytes = 0;
  runtime->activeConns[activeSlot].poller.tcpOutOffset = 0;
  runtime->activeConns[activeSlot].poller.tcpOutNbytes = 0;
  memcpy(runtime->activeConns[activeSlot].key, key, ProtocolPskSize);
  strncpy(runtime->activeConns[activeSlot].claim, claim, sizeof(runtime->activeConns[activeSlot].claim) - 1);
  runtime->activeConns[activeSlot].claim[sizeof(runtime->activeConns[activeSlot].claim) - 1] = '\0';
  runtime->activeConns[activeSlot].active = true;
  runtime->activeCount++;
  return activeSlot;
}

bool serverRuntimeRemoveClient(serverRuntime_t *runtime, int slot) {
  if (!activeSlotIndexValid(runtime, slot) || !runtime->activeConns[slot].active) {
    return false;
  }

  if (!serverRuntimeDropPendingTunToTcpByOwner(runtime, slot)) {
    return false;
  }
  sessionDestroy(runtime->activeConns[slot].session);
  runtime->activeConns[slot].poller.tcpOutOffset = 0;
  runtime->activeConns[slot].poller.tcpOutNbytes = 0;
  memset(runtime->activeConns[slot].key, 0, sizeof(runtime->activeConns[slot].key));
  memset(runtime->activeConns[slot].claim, 0, sizeof(runtime->activeConns[slot].claim));
  runtime->activeConns[slot].connFd = -1;
  runtime->activeConns[slot].session = NULL;
  runtime->activeConns[slot].active = false;
  runtime->activeCount--;
  return true;
}

int serverRuntimeFindSlotByFd(const serverRuntime_t *runtime, int connFd) {
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

int serverRuntimeFindPreAuthSlotByFd(const serverRuntime_t *runtime, int connFd) {
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

int serverRuntimePickEgressClient(const serverRuntime_t *runtime) {
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

int serverRuntimeClientCount(const serverRuntime_t *runtime) {
  if (runtime == NULL || runtime->activeConns == NULL) {
    return -1;
  }
  return runtime->activeCount;
}

long serverRuntimeQueuedTunBytes(const serverRuntime_t *runtime) {
  if (runtime == NULL) {
    return -1;
  }
  return runtime->tunOutNbytes;
}

long long serverRuntimeNowMs(const serverRuntime_t *runtime) {
  if (runtime == NULL || runtime->nowMsFn == NULL) {
    return -1;
  }
  return runtime->nowMsFn(runtime->nowCtx);
}

bool serverRuntimeSyncTunWriteInterest(serverRuntime_t *runtime) {
  unsigned int nextEvents;
  bool needWrite;

  if (runtime == NULL) {
    return false;
  }
  if (runtime->epollFd < 0) {
    return true;
  }

  needWrite = runtime->tunOutNbytes > 0;
  nextEvents = runtime->tunEvents;
  if (needWrite) {
    nextEvents |= EPOLLOUT;
  } else {
    nextEvents &= ~EPOLLOUT;
  }
  if (nextEvents == runtime->tunEvents) {
    return true;
  }
  return runtimeTunEpollCtl(runtime, nextEvents);
}

bool serverRuntimeQueueTunWrite(serverRuntime_t *runtime, const void *data, long nbytes) {
  long used;

  if (runtime == NULL || data == NULL || nbytes <= 0 || nbytes > IoPollerQueueCapacity) {
    return false;
  }

  used = runtime->tunOutOffset + runtime->tunOutNbytes;
  if (used + nbytes > IoPollerQueueCapacity && runtime->tunOutOffset > 0) {
    memmove(runtime->tunOutBuf, runtime->tunOutBuf + runtime->tunOutOffset, (size_t)runtime->tunOutNbytes);
    runtime->tunOutOffset = 0;
    used = runtime->tunOutNbytes;
  }

  if (used + nbytes > IoPollerQueueCapacity) {
    return false;
  }

  memcpy(runtime->tunOutBuf + used, data, (size_t)nbytes);
  runtime->tunOutNbytes += nbytes;
  return serverRuntimeSyncTunWriteInterest(runtime);
}

bool serverRuntimeServiceTunWriteEvent(serverRuntime_t *runtime) {
  while (runtime != NULL && runtime->tunOutNbytes > 0) {
    long wrote = (long)write(runtime->tunFd, runtime->tunOutBuf + runtime->tunOutOffset, (size_t)runtime->tunOutNbytes);
    if (wrote > 0) {
      runtime->tunOutOffset += wrote;
      runtime->tunOutNbytes -= wrote;
      continue;
    }
    if (wrote == 0) {
      return false;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return serverRuntimeSyncTunWriteInterest(runtime);
    }
    return false;
  }

  if (runtime == NULL) {
    return false;
  }
  runtime->tunOutOffset = 0;
  return serverRuntimeSyncTunWriteInterest(runtime);
}

int serverRuntimeRetryBlockedTunRoundRobin(serverRuntime_t *runtime) {
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
    if (!sessionServiceBackpressure(session, &runtime->activeConns[slot].poller)) {
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

bool serverRuntimeSetTunReadEnabled(serverRuntime_t *runtime, bool enabled) {
  unsigned int nextEvents;

  if (runtime == NULL) {
    return false;
  }

  nextEvents = runtime->tunEvents;
  if (enabled) {
    nextEvents |= EPOLLIN;
  } else {
    nextEvents &= ~EPOLLIN;
  }
  if (nextEvents == runtime->tunEvents) {
    return true;
  }
  return runtimeTunEpollCtl(runtime, nextEvents);
}

bool serverRuntimeHasPendingTunToTcp(const serverRuntime_t *runtime) {
  return runtime != NULL && runtime->pendingTunToTcpNbytes > 0 && runtime->pendingOwnerSlot >= 0;
}

int serverRuntimePendingTunToTcpOwner(const serverRuntime_t *runtime) {
  if (runtime == NULL) {
    return -1;
  }
  return runtime->pendingOwnerSlot;
}

bool serverRuntimeStorePendingTunToTcp(serverRuntime_t *runtime, int ownerSlot, const void *data, long nbytes) {
  if (runtime == NULL || data == NULL || nbytes <= 0 || nbytes > (long)sizeof(runtime->pendingTunToTcpBuf)) {
    return false;
  }
  if (!activeSlotIndexValid(runtime, ownerSlot) || !runtime->activeConns[ownerSlot].active) {
    return false;
  }
  if (serverRuntimeHasPendingTunToTcp(runtime)) {
    return false;
  }

  memcpy(runtime->pendingTunToTcpBuf, data, (size_t)nbytes);
  runtime->pendingTunToTcpNbytes = nbytes;
  runtime->pendingOwnerSlot = ownerSlot;
  return serverRuntimeSetTunReadEnabled(runtime, false);
}

serverRuntimePendingRetry_t serverRuntimeRetryPendingTunToTcp(
    serverRuntime_t *runtime, int ownerSlot, ioPoller_t *ownerPoller) {
  long queued;

  if (runtime == NULL || ownerPoller == NULL) {
    return serverRuntimePendingRetryError;
  }
  if (!serverRuntimeHasPendingTunToTcp(runtime)) {
    return serverRuntimePendingRetryQueued;
  }
  if (runtime->pendingOwnerSlot != ownerSlot) {
    return serverRuntimePendingRetryBlocked;
  }

  if (ioPollerQueueWrite(ownerPoller, ioSourceTcp, runtime->pendingTunToTcpBuf, runtime->pendingTunToTcpNbytes)) {
    runtime->pendingTunToTcpNbytes = 0;
    runtime->pendingOwnerSlot = -1;
    return serverRuntimePendingRetryQueued;
  }

  queued = ioPollerQueuedBytes(ownerPoller, ioSourceTcp);
  if (queued < 0 || queued + runtime->pendingTunToTcpNbytes <= IoPollerQueueCapacity) {
    return serverRuntimePendingRetryError;
  }
  return serverRuntimePendingRetryBlocked;
}

bool serverRuntimeDropPendingTunToTcpByOwner(serverRuntime_t *runtime, int ownerSlot) {
  if (runtime == NULL) {
    return false;
  }
  if (!serverRuntimeHasPendingTunToTcp(runtime) || runtime->pendingOwnerSlot != ownerSlot) {
    return true;
  }

  runtime->pendingTunToTcpNbytes = 0;
  runtime->pendingOwnerSlot = -1;
  return serverRuntimeSetTunReadEnabled(runtime, true);
}

session_t *serverRuntimeSessionAt(serverRuntime_t *runtime, int slot) {
  if (!activeSlotIndexValid(runtime, slot) || !runtime->activeConns[slot].active) {
    return NULL;
  }
  return runtime->activeConns[slot].session;
}

int serverRuntimeConnFdAt(const serverRuntime_t *runtime, int slot) {
  if (!activeSlotIndexValid(runtime, slot) || !runtime->activeConns[slot].active) {
    return -1;
  }
  return runtime->activeConns[slot].connFd;
}

const unsigned char *serverRuntimeKeyAt(const serverRuntime_t *runtime, int slot) {
  if (!activeSlotIndexValid(runtime, slot) || !runtime->activeConns[slot].active) {
    return NULL;
  }
  return runtime->activeConns[slot].key;
}

bool serverRuntimeHasActiveClaim(const serverRuntime_t *runtime, const char *claim) {
  int i;
  if (runtime == NULL || runtime->activeConns == NULL || claim == NULL) {
    return false;
  }
  for (i = 0; i < runtime->maxActiveSessions; i++) {
    if (!runtime->activeConns[i].active) {
      continue;
    }
    if (strcmp(runtime->activeConns[i].claim, claim) == 0) {
      return true;
    }
  }
  return false;
}

int serverRuntimeCreatePreAuthConn(serverRuntime_t *runtime, int connFd, long long authDeadlineMs) {
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
    protocolDecoderInit(&conn->rawDecoder);
    protocolDecoderInit(&conn->secureDecoder);
    conn->active = true;
    runtime->preAuthCount++;
    return i;
  }

  return -1;
}

bool serverRuntimeRemovePreAuthConn(serverRuntime_t *runtime, int preAuthSlot) {
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

preAuthConn_t *serverRuntimePreAuthAt(serverRuntime_t *runtime, int preAuthSlot) {
  if (!preAuthSlotIndexValid(runtime, preAuthSlot) || !runtime->preAuthConns[preAuthSlot].active) {
    return NULL;
  }
  return &runtime->preAuthConns[preAuthSlot];
}

bool serverRuntimePromoteToActiveSlot(serverRuntime_t *runtime, int preAuthSlot) {
  preAuthConn_t *preAuth;
  int connFd;

  if (runtime == NULL) {
    return false;
  }
  preAuth = serverRuntimePreAuthAt(runtime, preAuthSlot);
  if (preAuth == NULL || !activeSlotIndexValid(runtime, preAuth->resolvedActiveSlot)) {
    return false;
  }
  if (runtime->activeConns[preAuth->resolvedActiveSlot].active) {
    return false;
  }

  connFd = preAuth->connFd;
  if (serverRuntimeAddClient(runtime, preAuth->resolvedActiveSlot, connFd, preAuth->resolvedKey, preAuth->claim) < 0) {
    return false;
  }
  return serverRuntimeRemovePreAuthConn(runtime, preAuthSlot);
}
