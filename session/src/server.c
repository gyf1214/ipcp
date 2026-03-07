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

static bool activeSlotIndexValid(const server_t *server, int slot) {
  return server != NULL && server->activeConns != NULL && slot >= 0 && slot < server->maxActiveSessions;
}

static bool preAuthSlotIndexValid(const server_t *server, int slot) {
  return server != NULL && server->preAuthConns != NULL && slot >= 0 && slot < server->maxPreAuthSessions;
}

static bool runtimeTunEpollCtl(server_t *server, unsigned int events) {
  struct epoll_event event;

  if (server == NULL || server->tunPoller.tunFd < 0) {
    return false;
  }
  if (server->epollFd < 0) {
    server->tunPoller.events = events;
    return true;
  }

  memset(&event, 0, sizeof(event));
  event.events = events;
  event.data.fd = server->tunPoller.tunFd;
  if (epoll_ctl(server->epollFd, EPOLL_CTL_MOD, server->tunPoller.tunFd, &event) < 0) {
    return false;
  }
  server->tunPoller.events = events;
  return true;
}

bool serverInit(
    server_t *server,
    int tunFd,
    int listenFd,
    int maxActiveSessions,
    int maxPreAuthSessions,
    const sessionHeartbeatConfig_t *heartbeatCfg,
    sessionNowMsFn_t nowMsFn,
    void *nowCtx) {
  int i;

  if (server == NULL
      || heartbeatCfg == NULL
      || maxActiveSessions <= 0
      || maxPreAuthSessions <= 0
      || tunFd < 0
      || listenFd < 0) {
    return false;
  }

  memset(server, 0, sizeof(*server));
  server->activeConns = calloc((size_t)maxActiveSessions, sizeof(*server->activeConns));
  server->preAuthConns = calloc((size_t)maxPreAuthSessions, sizeof(*server->preAuthConns));
  if (server->activeConns == NULL || server->preAuthConns == NULL) {
    free(server->activeConns);
    free(server->preAuthConns);
    memset(server, 0, sizeof(*server));
    return false;
  }

  server->tunPoller.epollFd = -1;
  server->tunPoller.tunFd = tunFd;
  server->listenFd = listenFd;
  server->epollFd = -1;
  server->tunPoller.events = EPOLLIN | EPOLLRDHUP;
  server->tunPoller.readPos = 0;
  server->tunPoller.writePos = 0;
  server->tunPoller.queuedBytes = 0;
  server->tunPoller.frameHead = 0;
  server->tunPoller.frameTail = 0;
  server->tunPoller.frameCount = 0;
  memset(server->tunPoller.outBuf, 0, sizeof(server->tunPoller.outBuf));
  server->pendingOwnerSlot = -1;
  server->runtimeOverflowNbytes = 0;
  server->retryCursor = 0;
  server->maxActiveSessions = maxActiveSessions;
  server->activeCount = 0;
  server->maxPreAuthSessions = maxPreAuthSessions;
  server->preAuthCount = 0;
  server->heartbeatCfg = *heartbeatCfg;
  server->nowMsFn = nowMsFn == NULL ? defaultNowMs : nowMsFn;
  server->nowCtx = nowCtx;

  for (i = 0; i < server->maxActiveSessions; i++) {
    server->activeConns[i].connFd = -1;
  }
  for (i = 0; i < server->maxPreAuthSessions; i++) {
    server->preAuthConns[i].connFd = -1;
    server->preAuthConns[i].resolvedActiveSlot = -1;
  }

  return true;
}

void serverDeinit(server_t *server) {
  int i;

  if (server == NULL) {
    return;
  }

  if (server->activeConns != NULL) {
    for (i = 0; i < server->maxActiveSessions; i++) {
      if (server->activeConns[i].session != NULL) {
        sessionDestroy(server->activeConns[i].session);
      }
    }
  }

  free(server->activeConns);
  free(server->preAuthConns);
  memset(server, 0, sizeof(*server));
}

int serverAddClient(
    server_t *server,
    int activeSlot,
    int connFd,
    const unsigned char key[ProtocolPskSize],
    const unsigned char *claim,
    long claimNbytes) {
  session_t *session;

  if (server == NULL
      || server->activeConns == NULL
      || connFd < 0
      || key == NULL
      || claim == NULL
      || claimNbytes <= 0
      || claimNbytes > SessionClaimSize) {
    return -1;
  }
  if (!activeSlotIndexValid(server, activeSlot)) {
    return -1;
  }
  if (server->activeConns[activeSlot].active) {
    return -1;
  }
  if (server->activeCount >= server->maxActiveSessions) {
    return -1;
  }

  session = sessionCreate(true, &server->heartbeatCfg, NULL, NULL);
  if (session == NULL) {
    return -1;
  }

  server->activeConns[activeSlot].connFd = connFd;
  server->activeConns[activeSlot].session = session;
  sessionAttachServer(session, server);
  server->activeConns[activeSlot].tcpPoller.epollFd = server->epollFd;
  server->activeConns[activeSlot].tcpPoller.tcpFd = connFd;
  server->activeConns[activeSlot].tcpPoller.events = EPOLLIN | EPOLLRDHUP;
  server->activeConns[activeSlot].tcpPoller.outOffset = 0;
  server->activeConns[activeSlot].tcpPoller.outNbytes = 0;
  memset(server->activeConns[activeSlot].tcpPoller.outBuf, 0, sizeof(server->activeConns[activeSlot].tcpPoller.outBuf));
  memcpy(server->activeConns[activeSlot].key, key, ProtocolPskSize);
  memcpy(server->activeConns[activeSlot].claim, claim, (size_t)claimNbytes);
  server->activeConns[activeSlot].claimNbytes = claimNbytes;
  server->activeConns[activeSlot].active = true;
  server->activeCount++;
  return activeSlot;
}

bool serverRemoveClient(server_t *server, int slot) {
  if (!activeSlotIndexValid(server, slot) || !server->activeConns[slot].active) {
    return false;
  }

  if (!serverDropPendingTunToTcpByOwner(server, slot)) {
    return false;
  }
  sessionDestroy(server->activeConns[slot].session);
  server->activeConns[slot].tcpPoller.outOffset = 0;
  server->activeConns[slot].tcpPoller.outNbytes = 0;
  memset(server->activeConns[slot].tcpPoller.outBuf, 0, sizeof(server->activeConns[slot].tcpPoller.outBuf));
  memset(server->activeConns[slot].key, 0, sizeof(server->activeConns[slot].key));
  memset(server->activeConns[slot].claim, 0, sizeof(server->activeConns[slot].claim));
  server->activeConns[slot].claimNbytes = 0;
  server->activeConns[slot].connFd = -1;
  server->activeConns[slot].session = NULL;
  server->activeConns[slot].active = false;
  server->activeCount--;
  return true;
}

int serverFindSlotByFd(const server_t *server, int connFd) {
  int i;

  if (server == NULL || server->activeConns == NULL || connFd < 0) {
    return -1;
  }

  for (i = 0; i < server->maxActiveSessions; i++) {
    if (server->activeConns[i].active && server->activeConns[i].connFd == connFd) {
      return i;
    }
  }

  return -1;
}

int serverFindSlotByClaim(const server_t *server, const unsigned char *claim, long claimNbytes) {
  int i;

  if (server == NULL || server->activeConns == NULL || claim == NULL || claimNbytes <= 0) {
    return -1;
  }

  for (i = 0; i < server->maxActiveSessions; i++) {
    if (!server->activeConns[i].active) {
      continue;
    }
    if (server->activeConns[i].claimNbytes != claimNbytes) {
      continue;
    }
    if (memcmp(server->activeConns[i].claim, claim, (size_t)claimNbytes) == 0) {
      return i;
    }
  }

  return -1;
}

int serverFindPreAuthSlotByFd(const server_t *server, int connFd) {
  int i;

  if (server == NULL || server->preAuthConns == NULL || connFd < 0) {
    return -1;
  }

  for (i = 0; i < server->maxPreAuthSessions; i++) {
    if (server->preAuthConns[i].active && server->preAuthConns[i].connFd == connFd) {
      return i;
    }
  }

  return -1;
}

int serverPickEgressClient(const server_t *server) {
  int i;

  if (server == NULL || server->activeConns == NULL) {
    return -1;
  }

  for (i = 0; i < server->maxActiveSessions; i++) {
    if (server->activeConns[i].active) {
      return server->activeConns[i].connFd;
    }
  }

  return -1;
}

int serverClientCount(const server_t *server) {
  if (server == NULL || server->activeConns == NULL) {
    return -1;
  }
  return server->activeCount;
}

long long serverNowMs(const server_t *server) {
  if (server == NULL || server->nowMsFn == NULL) {
    return -1;
  }
  return server->nowMsFn(server->nowCtx);
}

bool serverSyncTunWriteInterest(server_t *server) {
  unsigned int nextEvents;
  bool needWrite;

  if (server == NULL) {
    return false;
  }
  if (server->epollFd < 0) {
    return true;
  }

  needWrite = ioTunQueuedBytes(&server->tunPoller) > 0;
  nextEvents = server->tunPoller.events;
  if (needWrite) {
    nextEvents |= EPOLLOUT;
  } else {
    nextEvents &= ~EPOLLOUT;
  }
  if (nextEvents == server->tunPoller.events) {
    return true;
  }
  return runtimeTunEpollCtl(server, nextEvents);
}

bool serverQueueTunWrite(server_t *server, const void *data, long nbytes) {
  if (server == NULL) {
    return false;
  }
  if (server->epollFd >= 0) {
    server->tunPoller.epollFd = server->epollFd;
  }
  if (!ioTunWrite(&server->tunPoller, data, nbytes)) {
    return false;
  }
  return true;
}

bool serverServiceTunWriteEvent(server_t *server) {
  if (server == NULL) {
    return false;
  }
  return ioTunServiceWriteEvent(&server->tunPoller);
}

int serverRetryBlockedTunRoundRobin(server_t *server) {
  int i;
  int start;
  int nextCursor = -1;

  if (server == NULL || server->activeConns == NULL || server->maxActiveSessions <= 0) {
    return -1;
  }

  start = server->retryCursor % server->maxActiveSessions;
  for (i = 0; i < server->maxActiveSessions; i++) {
    int slot = (start + i) % server->maxActiveSessions;
    session_t *session;
    if (!server->activeConns[slot].active) {
      continue;
    }
    session = server->activeConns[slot].session;
    if (session == NULL) {
      continue;
    }
    if (!sessionHasOverflow(session)) {
      continue;
    }
    if (!sessionRetryOverflow(session, &server->activeConns[slot].tcpPoller, &server->tunPoller, ioEventTunWrite)) {
      return -1;
    }
  }

  for (i = 1; i <= server->maxActiveSessions; i++) {
    int slot = (start + i) % server->maxActiveSessions;
    if (server->activeConns[slot].active) {
      nextCursor = slot;
      break;
    }
  }
  if (nextCursor < 0) {
    nextCursor = 0;
  }
  server->retryCursor = nextCursor;
  return server->retryCursor;
}

bool serverSetTunReadEnabled(server_t *server, bool enabled) {
  unsigned int nextEvents;

  if (server == NULL) {
    return false;
  }

  nextEvents = server->tunPoller.events;
  if (enabled) {
    nextEvents |= EPOLLIN;
  } else {
    nextEvents &= ~EPOLLIN;
  }
  if (nextEvents == server->tunPoller.events) {
    server->tunReadPaused = !enabled;
    return true;
  }
  if (!runtimeTunEpollCtl(server, nextEvents)) {
    return false;
  }
  server->tunReadPaused = !enabled;
  return true;
}

bool serverHasPendingTunToTcp(const server_t *server) {
  return server != NULL && server->runtimeOverflowNbytes > 0 && server->pendingOwnerSlot >= 0;
}

int serverPendingTunToTcpOwner(const server_t *server) {
  if (server == NULL) {
    return -1;
  }
  return server->pendingOwnerSlot;
}

bool serverStorePendingTunToTcp(server_t *server, int ownerSlot, const void *data, long nbytes) {
  if (server == NULL || data == NULL || nbytes <= 0 || nbytes > (long)sizeof(server->runtimeOverflowBuf)) {
    return false;
  }
  if (!activeSlotIndexValid(server, ownerSlot) || !server->activeConns[ownerSlot].active) {
    return false;
  }
  if (serverHasPendingTunToTcp(server)) {
    return false;
  }

  memcpy(server->runtimeOverflowBuf, data, (size_t)nbytes);
  server->runtimeOverflowNbytes = nbytes;
  server->pendingOwnerSlot = ownerSlot;
  if (!server->tunReadPaused) {
    return serverSetTunReadEnabled(server, false);
  }
  return true;
}

serverPendingRetry_t serverRetryPendingTunToTcp(
    server_t *server, int ownerSlot, ioTcpPoller_t *ownerPoller) {
  long queued;

  if (server == NULL || ownerPoller == NULL) {
    return serverPendingRetryError;
  }
  if (!serverHasPendingTunToTcp(server)) {
    return serverPendingRetryQueued;
  }
  if (server->pendingOwnerSlot != ownerSlot) {
    return serverPendingRetryBlocked;
  }

  if (ioTcpWrite(ownerPoller, server->runtimeOverflowBuf, server->runtimeOverflowNbytes)) {
    server->runtimeOverflowNbytes = 0;
    server->pendingOwnerSlot = -1;
    return serverPendingRetryQueued;
  }

  queued = ioTcpQueuedBytes(ownerPoller);
  if (queued < 0 || queued + server->runtimeOverflowNbytes <= IoPollerQueueCapacity) {
    return serverPendingRetryError;
  }
  return serverPendingRetryBlocked;
}

bool serverDropPendingTunToTcpByOwner(server_t *server, int ownerSlot) {
  if (server == NULL) {
    return false;
  }
  if (!serverHasPendingTunToTcp(server) || server->pendingOwnerSlot != ownerSlot) {
    return true;
  }

  server->runtimeOverflowNbytes = 0;
  server->pendingOwnerSlot = -1;
  if (server->tunReadPaused) {
    return serverSetTunReadEnabled(server, true);
  }
  return true;
}

sessionQueueResult_t serverQueueTcpWithBackpressure(
    server_t *server, ioTcpPoller_t *tcpPoller, const void *data, long nbytes) {
  long queued;
  int ownerSlot;

  if (server == NULL || tcpPoller == NULL || data == NULL || nbytes <= 0) {
    return sessionQueueResultError;
  }
  if (serverHasPendingTunToTcp(server)) {
    return sessionQueueResultBlocked;
  }
  if (ioTcpWrite(tcpPoller, data, nbytes)) {
    return sessionQueueResultQueued;
  }

  queued = ioTcpQueuedBytes(tcpPoller);
  if (queued < 0) {
    return sessionQueueResultError;
  }
  if (queued + nbytes > IoPollerQueueCapacity) {
    ownerSlot = serverFindSlotByFd(server, tcpPoller->tcpFd);
    if (ownerSlot < 0) {
      return sessionQueueResultError;
    }
    if (!serverStorePendingTunToTcp(server, ownerSlot, data, nbytes)) {
      return sessionQueueResultError;
    }
    return sessionQueueResultBlocked;
  }
  return sessionQueueResultError;
}

sessionQueueResult_t serverQueueTcpWithDrop(
    ioTcpPoller_t *tcpPoller, const void *data, long nbytes) {
  long used;

  if (tcpPoller == NULL || data == NULL || nbytes <= 0) {
    return sessionQueueResultError;
  }

  used = tcpPoller->outOffset + tcpPoller->outNbytes;
  if (used + nbytes > IoPollerQueueCapacity && tcpPoller->outOffset > 0) {
    used = tcpPoller->outNbytes;
  }
  if (used + nbytes > IoPollerQueueCapacity) {
    return sessionQueueResultBlocked;
  }
  if (ioTcpWrite(tcpPoller, data, nbytes)) {
    return sessionQueueResultQueued;
  }
  return sessionQueueResultBlocked;
}

sessionQueueResult_t serverSendMessage(
    server_t *server,
    ioTcpPoller_t *tcpPoller,
    const unsigned char key[ProtocolPskSize],
    const protocolMessage_t *msg) {
  protocolFrame_t frame;

  if (key == NULL || msg == NULL) {
    return sessionQueueResultError;
  }
  if (protocolEncodeSecureMsg(msg, key, &frame) != protocolStatusOk) {
    return sessionQueueResultError;
  }
  return serverQueueTcpWithBackpressure(server, tcpPoller, frame.buf, frame.nbytes);
}

sessionQueueResult_t serverHandleInboundMessage(
    server_t *server,
    ioTcpPoller_t *tcpPoller,
    const unsigned char key[ProtocolPskSize],
    long long *lastValidInboundMs,
    const protocolMessage_t *msg) {
  long long nowMs;

  if (server == NULL || tcpPoller == NULL || key == NULL || lastValidInboundMs == NULL || msg == NULL) {
    return sessionQueueResultError;
  }

  nowMs = serverNowMs(server);
  *lastValidInboundMs = nowMs;

  if (msg->type == protocolMsgData) {
    logf("unexpected data message in server inbound handler");
    return sessionQueueResultError;
  }
  if (msg->type == protocolMsgHeartbeatReq) {
    protocolMessage_t ack = {.type = protocolMsgHeartbeatAck, .nbytes = 0, .buf = NULL};
    sessionQueueResult_t result = serverSendMessage(server, tcpPoller, key, &ack);
    if (result != sessionQueueResultQueued) {
      return result;
    }
    dbgf("heartbeat request received, sent ack");
    return sessionQueueResultQueued;
  }
  if (msg->type == protocolMsgHeartbeatAck) {
    logf("unexpected heartbeat ack");
    return sessionQueueResultError;
  }
  return sessionQueueResultError;
}

bool serverHeartbeatTick(long long nowMs, long long lastValidInboundMs, long long timeoutMs) {
  return nowMs - lastValidInboundMs < timeoutMs;
}

bool serverServiceBackpressure(server_t *server, int slot, ioEvent_t event) {
  long queued;
  int ownerSlot;
  ioTcpPoller_t *ownerPoller;
  serverPendingRetry_t retry;

  if (server == NULL || event != ioEventTcpWrite || !serverHasPendingTunToTcp(server)) {
    return true;
  }

  ownerSlot = serverPendingTunToTcpOwner(server);
  if (slot != ownerSlot || !activeSlotIndexValid(server, ownerSlot) || !server->activeConns[ownerSlot].active) {
    return true;
  }
  ownerPoller = &server->activeConns[ownerSlot].tcpPoller;
  queued = ioTcpQueuedBytes(ownerPoller);
  if (queued < 0) {
    return false;
  }
  if (queued > IoPollerLowWatermark) {
    return true;
  }

  retry = serverRetryPendingTunToTcp(server, ownerSlot, ownerPoller);
  if (retry == serverPendingRetryError) {
    return false;
  }
  if (serverHasPendingTunToTcp(server)) {
    return true;
  }
  if (!server->tunReadPaused) {
    return true;
  }
  return serverSetTunReadEnabled(server, true);
}

session_t *serverSessionAt(server_t *server, int slot) {
  if (!activeSlotIndexValid(server, slot) || !server->activeConns[slot].active) {
    return NULL;
  }
  return server->activeConns[slot].session;
}

int serverConnFdAt(const server_t *server, int slot) {
  if (!activeSlotIndexValid(server, slot) || !server->activeConns[slot].active) {
    return -1;
  }
  return server->activeConns[slot].connFd;
}

const unsigned char *serverKeyAt(const server_t *server, int slot) {
  if (!activeSlotIndexValid(server, slot) || !server->activeConns[slot].active) {
    return NULL;
  }
  return server->activeConns[slot].key;
}

bool serverHasActiveClaim(const server_t *server, const unsigned char *claim, long claimNbytes) {
  int i;
  if (server == NULL || server->activeConns == NULL || claim == NULL || claimNbytes <= 0) {
    return false;
  }
  for (i = 0; i < server->maxActiveSessions; i++) {
    if (!server->activeConns[i].active) {
      continue;
    }
    if (server->activeConns[i].claimNbytes == claimNbytes
        && memcmp(server->activeConns[i].claim, claim, (size_t)claimNbytes) == 0) {
      return true;
    }
  }
  return false;
}

int serverCreatePreAuthConn(server_t *server, int connFd, long long authDeadlineMs) {
  int i;

  if (server == NULL || server->preAuthConns == NULL || connFd < 0) {
    return -1;
  }
  if (server->preAuthCount >= server->maxPreAuthSessions) {
    return -1;
  }

  for (i = 0; i < server->maxPreAuthSessions; i++) {
    preAuthConn_t *conn = &server->preAuthConns[i];
    if (conn->active) {
      continue;
    }
    memset(conn, 0, sizeof(*conn));
    conn->connFd = connFd;
    conn->authDeadlineMs = authDeadlineMs;
    conn->resolvedActiveSlot = -1;
    protocolDecoderInit(&conn->decoder);
    conn->active = true;
    server->preAuthCount++;
    return i;
  }

  return -1;
}

bool serverRemovePreAuthConn(server_t *server, int preAuthSlot) {
  preAuthConn_t *conn;

  if (!preAuthSlotIndexValid(server, preAuthSlot)) {
    return false;
  }
  conn = &server->preAuthConns[preAuthSlot];
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
  server->preAuthCount--;
  return true;
}

preAuthConn_t *serverPreAuthAt(server_t *server, int preAuthSlot) {
  if (!preAuthSlotIndexValid(server, preAuthSlot) || !server->preAuthConns[preAuthSlot].active) {
    return NULL;
  }
  return &server->preAuthConns[preAuthSlot];
}

bool serverPromoteToActiveSlot(server_t *server, int preAuthSlot) {
  preAuthConn_t *preAuth;
  int connFd;

  if (server == NULL) {
    return false;
  }
  preAuth = serverPreAuthAt(server, preAuthSlot);
  if (preAuth == NULL || !activeSlotIndexValid(server, preAuth->resolvedActiveSlot)) {
    return false;
  }
  if (server->activeConns[preAuth->resolvedActiveSlot].active) {
    return false;
  }

  connFd = preAuth->connFd;
  if (serverAddClient(
          server, preAuth->resolvedActiveSlot, connFd, preAuth->resolvedKey, preAuth->claim, preAuth->claimNbytes)
      < 0) {
    return false;
  }
  return serverRemovePreAuthConn(server, preAuthSlot);
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

static bool serverClosePreAuthConn(server_t *server, int preAuthSlot) {
  int connFd = -1;
  preAuthConn_t *conn = serverPreAuthAt(server, preAuthSlot);
  if (conn == NULL) {
    return false;
  }
  connFd = conn->connFd;
  (void)serverEpollCtl(server->epollFd, EPOLL_CTL_DEL, connFd, 0);
  close(connFd);
  return serverRemovePreAuthConn(server, preAuthSlot);
}

static bool serverSetPreAuthWriteEnabled(server_t *server, int connFd, bool writeEnabled) {
  unsigned int events = EPOLLIN | EPOLLRDHUP;
  if (writeEnabled) {
    events |= EPOLLOUT;
  }
  return serverEpollCtl(server->epollFd, EPOLL_CTL_MOD, connFd, events);
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
    server_t *server,
    int preAuthSlot,
    ioEvent_t event,
    const char *ifModeLabel,
    sessionServerResolveClaimFn_t resolveClaimFn,
    void *resolveClaimCtx) {
  preAuthConn_t *conn;
  long long nowMs;

  conn = serverPreAuthAt(server, preAuthSlot);
  if (conn == NULL || resolveClaimFn == NULL || ifModeLabel == NULL) {
    return false;
  }

  nowMs = serverNowMs(server);
  if (nowMs < 0) {
    return false;
  }
  if (nowMs >= conn->authDeadlineMs) {
    return serverClosePreAuthConn(server, preAuthSlot);
  }

  if (conn->authState == preAuthStateWaitClaim && event == ioEventTcpRead) {
    bool claimReady = false;

    if (!preAuthReadIntoCarry(conn)) {
      return serverClosePreAuthConn(server, preAuthSlot);
    }
    if (!preAuthDecodeClaim(conn, &claimReady)) {
      return serverClosePreAuthConn(server, preAuthSlot);
    }
    if (!claimReady) {
      return true;
    }

    if ((strcmp(ifModeLabel, "tun") == 0 && !isValidTunClaim(conn->claim, conn->claimNbytes))
        || (strcmp(ifModeLabel, "tap") == 0 && !isValidTapClaim(conn->claim, conn->claimNbytes))) {
      return serverClosePreAuthConn(server, preAuthSlot);
    }
    if (resolveClaimFn(resolveClaimCtx, conn->claim, conn->claimNbytes, conn->resolvedKey, &conn->resolvedActiveSlot)
        != 0) {
      return serverClosePreAuthConn(server, preAuthSlot);
    }
    if (conn->resolvedActiveSlot < 0 || conn->resolvedActiveSlot >= server->maxActiveSessions) {
      return serverClosePreAuthConn(server, preAuthSlot);
    }
    if (!preAuthQueueChallenge(conn)) {
      return serverClosePreAuthConn(server, preAuthSlot);
    }
    conn->authState = preAuthStateSendChallenge;
    if (!serverSetPreAuthWriteEnabled(server, conn->connFd, true)) {
      return false;
    }
  }

  if (conn->authState == preAuthStateSendChallenge && (event == ioEventTcpWrite || event == ioEventTimeout)) {
    if (!preAuthFlushChallenge(conn)) {
      return serverClosePreAuthConn(server, preAuthSlot);
    }
    if (conn->authWriteNbytes == 0) {
      conn->authState = preAuthStateWaitHello;
      if (!serverSetPreAuthWriteEnabled(server, conn->connFd, false)) {
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
      return serverClosePreAuthConn(server, preAuthSlot);
    }
    if (!preAuthDecodeHello(conn, &helloReady)) {
      return serverClosePreAuthConn(server, preAuthSlot);
    }
    if (!helloReady) {
      return true;
    }
    if (serverHasActiveClaim(server, conn->claim, conn->claimNbytes)) {
      return serverClosePreAuthConn(server, preAuthSlot);
    }
    helloDecoder = conn->decoder;
    helloCarryNbytes = conn->tcpReadCarryNbytes;
    if (helloCarryNbytes > 0) {
      memcpy(helloCarryBuf, conn->tcpReadCarryBuf, (size_t)helloCarryNbytes);
    }
    activeSlot = conn->resolvedActiveSlot;
    if (!serverPromoteToActiveSlot(server, preAuthSlot)) {
      return serverClosePreAuthConn(server, preAuthSlot);
    }
    activeSession = serverSessionAt(server, activeSlot);
    if (activeSession == NULL
        || !sessionPromoteFromPreAuth(
            activeSession, &helloDecoder, helloCarryNbytes > 0 ? helloCarryBuf : NULL, helloCarryNbytes)) {
      int failedConnFd = serverConnFdAt(server, activeSlot);
      if (failedConnFd >= 0) {
        close(failedConnFd);
      }
      (void)serverRemoveClient(server, activeSlot);
      return false;
    }
    activeConnFd = serverConnFdAt(server, activeSlot);
    server->activeConns[activeSlot].tcpPoller.epollFd = server->epollFd;
    if (!serverEpollCtl(server->epollFd, EPOLL_CTL_MOD, activeConnFd, server->activeConns[activeSlot].tcpPoller.events)) {
      close(activeConnFd);
      (void)serverRemoveClient(server, activeSlot);
      return false;
    }
  }

  return true;
}

static bool serverDispatchClient(server_t *server, int slot, ioEvent_t event) {
  session_t *session = serverSessionAt(server, slot);
  int connFd = serverConnFdAt(server, slot);
  const unsigned char *key = serverKeyAt(server, slot);
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
      sessionHandleConnEvent(session, &server->activeConns[slot].tcpPoller, &server->tunPoller, event, key);
  if (stepResult == sessionStepStop) {
    (void)serverEpollCtl(server->epollFd, EPOLL_CTL_DEL, connFd, 0);
    close(connFd);
    return serverRemoveClient(server, slot);
  }
  return true;
}

static bool serverDispatchTunIngressToSlot(
    server_t *server, int slot, const void *payload, long payloadNbytes) {
  session_t *session = serverSessionAt(server, slot);
  int connFd = serverConnFdAt(server, slot);
  const unsigned char *key = serverKeyAt(server, slot);
  protocolMessage_t msg;
  sessionQueueResult_t result;

  if (session == NULL || connFd < 0 || key == NULL || payload == NULL || payloadNbytes <= 0) {
    return false;
  }

  msg.type = protocolMsgData;
  msg.nbytes = payloadNbytes;
  msg.buf = (const char *)payload;
  result = serverSendMessage(server, &server->activeConns[slot].tcpPoller, key, &msg);
  if (result == sessionQueueResultError) {
    (void)serverEpollCtl(server->epollFd, EPOLL_CTL_DEL, connFd, 0);
    close(connFd);
    return serverRemoveClient(server, slot);
  }
  if (sessionFinalizeStep(session, key) == sessionStepStop) {
    (void)serverEpollCtl(server->epollFd, EPOLL_CTL_DEL, connFd, 0);
    close(connFd);
    return serverRemoveClient(server, slot);
  }
  return true;
}

static bool serverTunDestinationIsLimitedBroadcast(const packetDestination_t *destination) {
  return destination != NULL
      && destination->claimNbytes == 4
      && destination->claim[0] == 255
      && destination->claim[1] == 255
      && destination->claim[2] == 255
      && destination->claim[3] == 255;
}

static bool serverTunDestinationMatchesDirectedBroadcast(
    const server_t *server, const packetDestination_t *destination) {
  return server != NULL
      && destination != NULL
      && server->tunSubnet.enabled
      && destination->claimNbytes == 4
      && memcmp(destination->claim, server->tunSubnet.broadcast, 4) == 0;
}

static bool serverFanoutTunIngressToAll(
    server_t *server, const void *payload, long payloadNbytes) {
  int slot;

  if (server == NULL || payload == NULL || payloadNbytes <= 0) {
    return false;
  }

  for (slot = 0; slot < server->maxActiveSessions; slot++) {
    session_t *session;
    int connFd;
    const unsigned char *key;
    protocolMessage_t msg;
    protocolFrame_t frame;
    sessionQueueResult_t result;

    if (!server->activeConns[slot].active) {
      continue;
    }
    session = serverSessionAt(server, slot);
    connFd = serverConnFdAt(server, slot);
    key = serverKeyAt(server, slot);
    if (session == NULL || connFd < 0 || key == NULL) {
      return false;
    }

    msg.type = protocolMsgData;
    msg.nbytes = payloadNbytes;
    msg.buf = (const char *)payload;
    if (protocolEncodeSecureMsg(&msg, key, &frame) != protocolStatusOk) {
      (void)serverEpollCtl(server->epollFd, EPOLL_CTL_DEL, connFd, 0);
      close(connFd);
      return serverRemoveClient(server, slot);
    }

    result = serverQueueTcpWithDrop(&server->activeConns[slot].tcpPoller, frame.buf, frame.nbytes);
    if (result == sessionQueueResultError) {
      (void)serverEpollCtl(server->epollFd, EPOLL_CTL_DEL, connFd, 0);
      close(connFd);
      return serverRemoveClient(server, slot);
    }
    if (result == sessionQueueResultBlocked) {
      continue;
    }

    if (sessionFinalizeStep(session, key) == sessionStepStop) {
      (void)serverEpollCtl(server->epollFd, EPOLL_CTL_DEL, connFd, 0);
      close(connFd);
      return serverRemoveClient(server, slot);
    }
  }

  return true;
}

bool serverRouteTunIngressPacket(server_t *server, const char *ifModeLabel, const void *packet, long packetNbytes) {
  packetParseMode_t mode;
  packetDestination_t destination;
  packetParseStatus_t parseStatus;
  int slot;

  if (server == NULL || ifModeLabel == NULL || packet == NULL || packetNbytes <= 0) {
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
  if (destination.classification == packetDestinationDropMalformed
      || destination.classification == packetDestinationDropMulticast) {
    return true;
  }
  if (destination.classification == packetDestinationBroadcastL2) {
    return serverFanoutTunIngressToAll(server, packet, packetNbytes);
  }
  if (mode == packetParseModeTunIpv4) {
    if (destination.classification == packetDestinationBroadcastL3Candidate) {
      if (serverTunDestinationIsLimitedBroadcast(&destination)
          || serverTunDestinationMatchesDirectedBroadcast(server, &destination)) {
        return serverFanoutTunIngressToAll(server, packet, packetNbytes);
      }
      return true;
    }
    if (destination.classification == packetDestinationOk
        && serverTunDestinationMatchesDirectedBroadcast(server, &destination)) {
      return serverFanoutTunIngressToAll(server, packet, packetNbytes);
    }
  }
  if (destination.classification != packetDestinationOk) {
    return true;
  }

  slot = serverFindSlotByClaim(server, destination.claim, destination.claimNbytes);
  if (slot < 0) {
    return true;
  }
  return serverDispatchTunIngressToSlot(server, slot, packet, packetNbytes);
}

static bool serverHandleTunRead(server_t *server, const char *ifModeLabel) {
  char packet[ProtocolFrameSize];
  long packetNbytes = 0;
  long maxPayload = protocolMaxPlaintextSize() - ((long)sizeof(unsigned char) + ProtocolWireLengthSize);
  ioStatus_t status;

  if (server == NULL || ifModeLabel == NULL || maxPayload <= 0 || maxPayload > (long)sizeof(packet)) {
    return false;
  }

  status = ioTunRead(server->tunPoller.tunFd, packet, maxPayload, &packetNbytes);
  if (status == ioStatusWouldBlock) {
    return true;
  }
  if (status != ioStatusOk) {
    return false;
  }

  return serverRouteTunIngressPacket(server, ifModeLabel, packet, packetNbytes);
}

static bool serverTickAllClients(server_t *server) {
  int slot;
  for (slot = 0; slot < server->maxActiveSessions; slot++) {
    if (!server->activeConns[slot].active) {
      continue;
    }
    if (!serverDispatchClient(server, slot, ioEventTimeout)) {
      return false;
    }
  }
  return true;
}

static bool serverTickPreAuth(
    server_t *server,
    const char *ifModeLabel,
    sessionServerResolveClaimFn_t resolveClaimFn,
    void *resolveClaimCtx) {
  int slot;

  for (slot = 0; slot < server->maxPreAuthSessions; slot++) {
    preAuthConn_t *conn = serverPreAuthAt(server, slot);
    if (conn == NULL) {
      continue;
    }
    if (!serverDispatchPreAuth(server, slot, ioEventTimeout, ifModeLabel, resolveClaimFn, resolveClaimCtx)) {
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
  server_t server;
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
          &server,
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
    server.tunSubnet = *tunSubnet;
  }

  epollFd = epoll_create1(0);
  if (epollFd < 0) {
    serverDeinit(&server);
    return -1;
  }
  server.epollFd = epollFd;
  server.tunPoller.epollFd = epollFd;

  if (!serverEpollCtl(epollFd, EPOLL_CTL_ADD, listenFd, EPOLLIN | EPOLLRDHUP)
      || !serverEpollCtl(epollFd, EPOLL_CTL_ADD, tunFd, server.tunPoller.events)) {
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
          nowMs = serverNowMs(&server);
          if (nowMs < 0) {
            close(connFd);
            goto cleanup;
          }
          preAuthSlot = serverCreatePreAuthConn(&server, connFd, nowMs + authTimeoutMs);
          if (preAuthSlot < 0) {
            close(connFd);
            continue;
          }
          if (!serverEpollCtl(epollFd, EPOLL_CTL_ADD, connFd, EPOLLIN | EPOLLRDHUP)) {
            close(connFd);
            (void)serverRemovePreAuthConn(&server, preAuthSlot);
            goto cleanup;
          }
        }
        continue;
      }

      {
        int preAuthSlot = serverFindPreAuthSlotByFd(&server, fd);
        if (preAuthSlot >= 0) {
          if ((ev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
            if (!serverClosePreAuthConn(&server, preAuthSlot)) {
              goto cleanup;
            }
            continue;
          }
          if ((ev & EPOLLIN) != 0
              && !serverDispatchPreAuth(
                  &server, preAuthSlot, ioEventTcpRead, ifModeLabel, resolveClaimFn, resolveClaimCtx)) {
            goto cleanup;
          }
          if ((ev & EPOLLOUT) != 0
              && !serverDispatchPreAuth(
                  &server, preAuthSlot, ioEventTcpWrite, ifModeLabel, resolveClaimFn, resolveClaimCtx)) {
            goto cleanup;
          }
          continue;
        }
      }

      if (fd == tunFd) {
        if ((ev & EPOLLIN) != 0) {
          if (!serverHandleTunRead(&server, ifModeLabel)) {
            goto cleanup;
          }
        }
        if ((ev & EPOLLOUT) != 0) {
          if (!serverServiceTunWriteEvent(&server)) {
            goto cleanup;
          }
          if (ioTunQueuedBytes(&server.tunPoller) <= IoPollerLowWatermark) {
            if (serverRetryBlockedTunRoundRobin(&server) < 0) {
              goto cleanup;
            }
            if (!serverSyncTunWriteInterest(&server)) {
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
        int slot = serverFindSlotByFd(&server, fd);
        if (slot < 0) {
          (void)serverEpollCtl(epollFd, EPOLL_CTL_DEL, fd, 0);
          close(fd);
          continue;
        }
        if ((ev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
          (void)serverEpollCtl(epollFd, EPOLL_CTL_DEL, fd, 0);
          close(fd);
          (void)serverRemoveClient(&server, slot);
          continue;
        }
        if ((ev & EPOLLIN) != 0 && !serverDispatchClient(&server, slot, ioEventTcpRead)) {
          goto cleanup;
        }
        if ((ev & EPOLLOUT) != 0) {
          if (!ioTcpServiceWriteEvent(&server.activeConns[slot].tcpPoller)) {
            goto cleanup;
          }
          if (!serverServiceBackpressure(&server, slot, ioEventTcpWrite)) {
            goto cleanup;
          }
          if (!serverDispatchClient(&server, slot, ioEventTcpWrite)) {
            goto cleanup;
          }
        }
      }
    }

    if (!serverTickAllClients(&server)) {
      goto cleanup;
    }
    if (!serverTickPreAuth(&server, ifModeLabel, resolveClaimFn, resolveClaimCtx)) {
      goto cleanup;
    }
  }

cleanup:
  for (i = 0; i < server.maxActiveSessions; i++) {
    int connFd = serverConnFdAt(&server, i);
    if (connFd >= 0) {
      (void)serverEpollCtl(epollFd, EPOLL_CTL_DEL, connFd, 0);
      close(connFd);
    }
  }
  for (i = 0; i < server.maxPreAuthSessions; i++) {
    preAuthConn_t *conn = serverPreAuthAt(&server, i);
    if (conn != NULL && conn->connFd >= 0) {
      (void)serverEpollCtl(epollFd, EPOLL_CTL_DEL, conn->connFd, 0);
      close(conn->connFd);
      (void)serverRemovePreAuthConn(&server, i);
    }
  }
  serverDeinit(&server);
  if (epollFd >= 0) {
    close(epollFd);
  }
  return rc;
}
