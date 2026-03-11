#include "server.h"

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <sodium.h>

#include "log.h"
#include "packet.h"

static const ioPollerCallbacks_t serverActiveCallbacks;
static const ioPollerCallbacks_t serverPreAuthCallbacks;
static void serverActiveConnDispose(server_t *server, int slot);
static void serverPreAuthConnDispose(server_t *server, int preAuthSlot);

static long long defaultNowMs(void *ctx) {
  struct timespec ts;
  (void)ctx;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long long)ts.tv_sec * 1000 + (long long)ts.tv_nsec / 1000000;
}

static bool serverPacketParseMode(const server_t *server, packetParseMode_t *outMode) {
  if (server == NULL || outMode == NULL) {
    return false;
  }
  if (server->mode == ioIfModeTun) {
    *outMode = packetParseModeTunIpv4;
    return true;
  }
  if (server->mode == ioIfModeTap) {
    *outMode = packetParseModeTapEthernet;
    return true;
  }
  return false;
}

static bool activeSlotIndexValid(const server_t *server, int slot) {
  return server != NULL && server->activeConns != NULL && slot >= 0 && slot < server->maxActiveSessions;
}

static bool preAuthSlotIndexValid(const server_t *server, int slot) {
  return server != NULL && server->preAuthConns != NULL && slot >= 0 && slot < server->maxPreAuthSessions;
}

static int serverFindFreePreAuthSlot(const server_t *server) {
  int slot;
  if (server == NULL || server->preAuthConns == NULL) {
    return -1;
  }
  for (slot = 0; slot < server->maxPreAuthSessions; slot++) {
    if (!server->preAuthConns[slot].active) {
      return slot;
    }
  }
  return -1;
}

static int serverActiveSlotFromConn(const server_t *server, const activeConn_t *conn) {
  ptrdiff_t slot;
  if (server == NULL || server->activeConns == NULL || conn == NULL) {
    return -1;
  }
  slot = conn - server->activeConns;
  if (slot < 0 || slot >= server->maxActiveSessions) {
    return -1;
  }
  if (&server->activeConns[slot] != conn) {
    return -1;
  }
  return (int)slot;
}

static int serverPreAuthSlotFromConn(const server_t *server, const preAuthConn_t *conn) {
  ptrdiff_t slot;
  if (server == NULL || server->preAuthConns == NULL || conn == NULL) {
    return -1;
  }
  slot = conn - server->preAuthConns;
  if (slot < 0 || slot >= server->maxPreAuthSessions) {
    return -1;
  }
  if (&server->preAuthConns[slot] != conn) {
    return -1;
  }
  return (int)slot;
}

static unsigned char *serverAuthoritativeKeySlot(server_t *server, int slot) {
  if (server == NULL || server->authoritativeKeys == NULL || slot < 0 || slot >= server->maxActiveSessions) {
    return NULL;
  }
  return server->authoritativeKeys + ((size_t)slot * ProtocolPskSize);
}

static const unsigned char *serverAuthoritativeKeySlotConst(const server_t *server, int slot) {
  if (server == NULL || server->authoritativeKeys == NULL || slot < 0 || slot >= server->maxActiveSessions) {
    return NULL;
  }
  return server->authoritativeKeys + ((size_t)slot * ProtocolPskSize);
}

bool serverInit(
    server_t *server,
    int maxActiveSessions,
    int maxPreAuthSessions,
    const sessionHeartbeatConfig_t *heartbeatCfg,
    sessionNowMsFn_t nowMsFn,
    void *nowCtx) {
  int i;

  if (server == NULL
      || heartbeatCfg == NULL
      || maxActiveSessions <= 0
      || maxPreAuthSessions <= 0) {
    return false;
  }

  memset(server, 0, sizeof(*server));
  server->activeConns = calloc((size_t)maxActiveSessions, sizeof(*server->activeConns));
  server->preAuthConns = calloc((size_t)maxPreAuthSessions, sizeof(*server->preAuthConns));
  server->authoritativeKeys = calloc((size_t)maxActiveSessions, ProtocolPskSize);
  if (server->activeConns == NULL || server->preAuthConns == NULL || server->authoritativeKeys == NULL) {
    free(server->activeConns);
    free(server->preAuthConns);
    free(server->authoritativeKeys);
    memset(server, 0, sizeof(*server));
    return false;
  }

  server->listenPoller.poller.reactor = NULL;
  server->listenPoller.poller.fd = -1;
  server->listenPoller.poller.kind = ioPollerKindListen;
  server->listenPoller.poller.events = EPOLLIN | EPOLLRDHUP;
  server->listenPoller.poller.readEnabled = true;

  server->tunPoller.poller.reactor = NULL;
  server->tunPoller.poller.fd = -1;
  server->tunPoller.poller.kind = ioPollerKindTun;
  server->reactor.epollFd = -1;
  server->tunPoller.poller.events = EPOLLIN | EPOLLRDHUP;
  server->tunPoller.poller.readEnabled = true;
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
  server->mode = ioIfModeTun;
  server->heartbeatCfg = *heartbeatCfg;
  server->nowMsFn = nowMsFn == NULL ? defaultNowMs : nowMsFn;
  server->nowCtx = nowCtx;

  for (i = 0; i < server->maxActiveSessions; i++) {
    server->activeConns[i].owner = server;
    server->activeConns[i].keyRef = NULL;
    server->activeConns[i].keySlot = -1;
  }
  for (i = 0; i < server->maxPreAuthSessions; i++) {
    server->preAuthConns[i].owner = server;
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
  if (server->authoritativeKeys != NULL) {
    sodium_memzero(server->authoritativeKeys, (size_t)server->maxActiveSessions * ProtocolPskSize);
  }
  free(server->authoritativeKeys);
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
  unsigned char *keySlot;

  if (server == NULL
      || server->activeConns == NULL
      || server->authoritativeKeys == NULL
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
  keySlot = serverAuthoritativeKeySlot(server, activeSlot);
  if (keySlot == NULL) {
    return -1;
  }
  if (server->activeConns[activeSlot].active) {
    return -1;
  }
  if (server->activeCount >= server->maxActiveSessions) {
    return -1;
  }

  session = sessionCreate(true, &server->heartbeatCfg, server->nowMsFn, server->nowCtx);
  if (session == NULL) {
    return -1;
  }

  server->activeConns[activeSlot].owner = server;
  server->activeConns[activeSlot].session = session;
  sessionAttachServer(session, server);
  server->activeConns[activeSlot].tcpPoller.poller.reactor = server->reactor.epollFd >= 0 ? &server->reactor : NULL;
  server->activeConns[activeSlot].tcpPoller.poller.fd = connFd;
  server->activeConns[activeSlot].tcpPoller.poller.events = EPOLLIN | EPOLLRDHUP;
  server->activeConns[activeSlot].tcpPoller.poller.kind = ioPollerKindTcp;
  server->activeConns[activeSlot].tcpPoller.poller.callbacks = NULL;
  server->activeConns[activeSlot].tcpPoller.poller.ctx = &server->activeConns[activeSlot];
  server->activeConns[activeSlot].tcpPoller.poller.readEnabled = true;
  server->activeConns[activeSlot].tcpPoller.outOffset = 0;
  server->activeConns[activeSlot].tcpPoller.outNbytes = 0;
  memset(server->activeConns[activeSlot].tcpPoller.outBuf, 0, sizeof(server->activeConns[activeSlot].tcpPoller.outBuf));
  memcpy(keySlot, key, ProtocolPskSize);
  server->activeConns[activeSlot].keyRef = keySlot;
  server->activeConns[activeSlot].keySlot = activeSlot;
  memcpy(server->activeConns[activeSlot].claim, claim, (size_t)claimNbytes);
  server->activeConns[activeSlot].claimNbytes = claimNbytes;
  server->activeConns[activeSlot].heartbeatAckPending = false;
  server->activeConns[activeSlot].active = true;
  server->activeCount++;
  return activeSlot;
}

bool serverRemoveClient(server_t *server, int slot) {
  int sourceSlot;

  if (!activeSlotIndexValid(server, slot) || !server->activeConns[slot].active) {
    return false;
  }

  if (!serverDropPendingTunToTcpByOwner(server, slot)) {
    return false;
  }
  for (sourceSlot = 0; sourceSlot < server->maxActiveSessions; sourceSlot++) {
    session_t *sourceSession;
    if (!server->activeConns[sourceSlot].active) {
      continue;
    }
    sourceSession = server->activeConns[sourceSlot].session;
    if (sourceSession == NULL) {
      continue;
    }
    if (!sessionDropOverflow(sourceSession, &server->activeConns[sourceSlot].tcpPoller, slot)) {
      return false;
    }
  }
  sessionDestroy(server->activeConns[slot].session);
  server->activeConns[slot].tcpPoller.poller.reactor = NULL;
  server->activeConns[slot].tcpPoller.poller.fd = -1;
  server->activeConns[slot].tcpPoller.poller.events = 0;
  server->activeConns[slot].tcpPoller.poller.callbacks = NULL;
  server->activeConns[slot].tcpPoller.poller.ctx = NULL;
  server->activeConns[slot].tcpPoller.poller.readEnabled = false;
  server->activeConns[slot].tcpPoller.outOffset = 0;
  server->activeConns[slot].tcpPoller.outNbytes = 0;
  memset(server->activeConns[slot].tcpPoller.outBuf, 0, sizeof(server->activeConns[slot].tcpPoller.outBuf));
  if (server->activeConns[slot].keySlot >= 0) {
    unsigned char *keySlot = serverAuthoritativeKeySlot(server, server->activeConns[slot].keySlot);
    if (keySlot != NULL) {
      sodium_memzero(keySlot, ProtocolPskSize);
    }
  }
  server->activeConns[slot].keyRef = NULL;
  server->activeConns[slot].keySlot = -1;
  memset(server->activeConns[slot].claim, 0, sizeof(server->activeConns[slot].claim));
  server->activeConns[slot].claimNbytes = 0;
  server->activeConns[slot].heartbeatAckPending = false;
  server->activeConns[slot].session = NULL;
  server->activeConns[slot].active = false;
  server->activeCount--;
  return true;
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
  if (server == NULL) {
    return false;
  }
  if (!ioTunSetReadEnabled(&server->tunPoller, enabled)) {
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
    server_t *server, activeConn_t *conn, const void *data, long nbytes) {
  long queued;
  int ownerSlot;
  ioTcpPoller_t *tcpPoller;

  if (server == NULL || conn == NULL || conn->owner != server || data == NULL || nbytes <= 0) {
    return sessionQueueResultError;
  }
  ownerSlot = serverActiveSlotFromConn(server, conn);
  if (ownerSlot < 0 || !conn->active) {
    return sessionQueueResultError;
  }
  tcpPoller = &conn->tcpPoller;
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
    activeConn_t *conn,
    const unsigned char key[ProtocolPskSize],
    const protocolMessage_t *msg) {
  protocolFrame_t frame;

  if (key == NULL || msg == NULL) {
    return sessionQueueResultError;
  }
  if (protocolEncodeSecureMsg(msg, key, &frame) != protocolStatusOk) {
    return sessionQueueResultError;
  }
  return serverQueueTcpWithBackpressure(server, conn, frame.buf, frame.nbytes);
}

static sessionQueueResult_t serverRetryHeartbeatAck(server_t *server, int slot) {
  protocolMessage_t ack = {.type = protocolMsgHeartbeatAck, .nbytes = 0, .buf = NULL};
  protocolFrame_t frame;

  if (!activeSlotIndexValid(server, slot) || !server->activeConns[slot].active) {
    return sessionQueueResultError;
  }
  if (protocolEncodeSecureMsg(&ack, serverKeyAt(server, slot), &frame) != protocolStatusOk) {
    return sessionQueueResultError;
  }
  return serverQueueTcpWithDrop(
      &server->activeConns[slot].tcpPoller,
      frame.buf,
      frame.nbytes);
}

sessionQueueResult_t serverHandleInboundMessage(
    server_t *server,
    activeConn_t *conn,
    const unsigned char key[ProtocolPskSize],
    long long *lastValidInboundMs,
    const protocolMessage_t *msg) {
  long long nowMs;
  int slot;

  if (server == NULL || conn == NULL || conn->owner != server || key == NULL || lastValidInboundMs == NULL || msg == NULL) {
    return sessionQueueResultError;
  }
  slot = serverActiveSlotFromConn(server, conn);
  if (slot < 0 || !conn->active) {
    return sessionQueueResultError;
  }
  (void)key;

  nowMs = serverNowMs(server);
  *lastValidInboundMs = nowMs;

  if (msg->type == protocolMsgData) {
    logf("unexpected data message in server inbound handler");
    return sessionQueueResultError;
  }
  if (msg->type == protocolMsgHeartbeatReq) {
    sessionQueueResult_t result;
    server->activeConns[slot].heartbeatAckPending = true;
    result = serverRetryHeartbeatAck(server, slot);
    if (result == sessionQueueResultError) {
      return result;
    }
    if (result == sessionQueueResultQueued) {
      server->activeConns[slot].heartbeatAckPending = false;
      dbgf("heartbeat request received, sent ack");
      return sessionQueueResultQueued;
    }
    return sessionQueueResultBlocked;
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

static bool serverRetryPendingTcpToTcpForDestination(server_t *server, int destSlot) {
  int i;
  int start;

  if (server == NULL || !activeSlotIndexValid(server, destSlot) || !server->activeConns[destSlot].active) {
    return false;
  }
  if (server->maxActiveSessions <= 0) {
    return true;
  }

  start = server->retryCursor % server->maxActiveSessions;
  for (i = 0; i < server->maxActiveSessions; i++) {
    int sourceSlot = (start + i) % server->maxActiveSessions;
    session_t *sourceSession;
    if (!server->activeConns[sourceSlot].active) {
      continue;
    }
    sourceSession = server->activeConns[sourceSlot].session;
    if (!sessionOverflowTargetsDestSlot(sourceSession, destSlot)) {
      continue;
    }
    if (!sessionRetryOverflowToTcp(
            sourceSession,
            &server->activeConns[sourceSlot].tcpPoller,
            &server->activeConns[destSlot].tcpPoller,
            destSlot)) {
      return false;
    }
  }
  return true;
}

bool serverServiceBackpressure(server_t *server, int slot, ioEvent_t event) {
  long queued;
  int ownerSlot;
  ioTcpPoller_t *ownerPoller;
  serverPendingRetry_t retry;

  if (server == NULL || event != ioEventTcpWrite || !activeSlotIndexValid(server, slot) || !server->activeConns[slot].active) {
    return true;
  }
  ownerPoller = &server->activeConns[slot].tcpPoller;
  queued = ioTcpQueuedBytes(ownerPoller);
  if (queued < 0) {
    return false;
  }
  if (queued > IoPollerLowWatermark) {
    return true;
  }
  if (server->activeConns[slot].heartbeatAckPending) {
    sessionQueueResult_t result = serverRetryHeartbeatAck(server, slot);
    if (result == sessionQueueResultError) {
      return false;
    }
    if (result == sessionQueueResultQueued) {
      server->activeConns[slot].heartbeatAckPending = false;
    }
    return true;
  }
  if (!serverRetryPendingTcpToTcpForDestination(server, slot)) {
    return false;
  }
  if (!serverHasPendingTunToTcp(server)) {
    return true;
  }

  ownerSlot = serverPendingTunToTcpOwner(server);
  if (slot != ownerSlot || !activeSlotIndexValid(server, ownerSlot) || !server->activeConns[ownerSlot].active) {
    return true;
  }
  ownerPoller = &server->activeConns[ownerSlot].tcpPoller;

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

const unsigned char *serverKeyAt(const server_t *server, int slot) {
  if (!activeSlotIndexValid(server, slot) || !server->activeConns[slot].active) {
    return NULL;
  }
  return server->activeConns[slot].keyRef;
}

const unsigned char *serverAuthoritativeKeyAt(const server_t *server, int slot) {
  return serverAuthoritativeKeySlotConst(server, slot);
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

int serverCreatePreAuthConn(
    server_t *server,
    int preAuthSlot,
    long long authDeadlineMs) {
  ioTcpPoller_t pollerCopy;
  preAuthConn_t *conn;

  if (server == NULL
      || server->preAuthConns == NULL
      || !preAuthSlotIndexValid(server, preAuthSlot)) {
    return -1;
  }
  conn = &server->preAuthConns[preAuthSlot];
  if (conn->active
      || conn->tcpPoller.poller.fd < 0
      || conn->tcpPoller.poller.kind != ioPollerKindTcp
      || server->preAuthCount >= server->maxPreAuthSessions) {
    return -1;
  }
  pollerCopy = conn->tcpPoller;
  memset(conn, 0, sizeof(*conn));
  conn->owner = server;
  conn->tcpPoller = pollerCopy;
  conn->tcpPoller.poller.kind = ioPollerKindTcp;
  conn->tcpPoller.poller.ctx = conn;
  conn->authDeadlineMs = authDeadlineMs;
  conn->resolvedActiveSlot = -1;
  protocolDecoderInit(&conn->decoder);
  conn->active = true;
  server->preAuthCount++;
  return preAuthSlot;
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
  memset(&conn->decoder, 0, sizeof(conn->decoder));
  memset(conn->tcpReadCarryBuf, 0, sizeof(conn->tcpReadCarryBuf));
  conn->tcpReadCarryNbytes = 0;
  memset(conn->authWriteBuf, 0, sizeof(conn->authWriteBuf));
  conn->authWriteOffset = 0;
  conn->authWriteNbytes = 0;
  conn->authState = 0;
  conn->authDeadlineMs = 0;
  conn->resolvedActiveSlot = -1;
  conn->tcpPoller.poller.reactor = NULL;
  conn->tcpPoller.poller.fd = -1;
  conn->tcpPoller.poller.events = 0;
  conn->tcpPoller.poller.callbacks = NULL;
  conn->tcpPoller.poller.ctx = NULL;
  conn->tcpPoller.poller.readEnabled = false;
  conn->tcpPoller.outOffset = 0;
  conn->tcpPoller.outNbytes = 0;
  memset(conn->tcpPoller.outBuf, 0, sizeof(conn->tcpPoller.outBuf));
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
  int activeSlot;
  session_t *session;
  unsigned char *keySlot;

  if (server == NULL) {
    return false;
  }
  preAuth = serverPreAuthAt(server, preAuthSlot);
  if (preAuth == NULL || !activeSlotIndexValid(server, preAuth->resolvedActiveSlot)) {
    return false;
  }
  activeSlot = preAuth->resolvedActiveSlot;
  if (server->activeConns[activeSlot].active) {
    return false;
  }
  keySlot = serverAuthoritativeKeySlot(server, activeSlot);
  if (keySlot == NULL) {
    return false;
  }

  session = sessionCreate(true, &server->heartbeatCfg, server->nowMsFn, server->nowCtx);
  if (session == NULL) {
    return false;
  }
  sessionAttachServer(session, server);

  memcpy(keySlot, preAuth->resolvedKey, ProtocolPskSize);
  server->activeConns[activeSlot].session = session;
  memset(&server->activeConns[activeSlot].tcpPoller, 0, sizeof(server->activeConns[activeSlot].tcpPoller));
  server->activeConns[activeSlot].owner = server;
  server->activeConns[activeSlot].tcpPoller.poller.reactor = NULL;
  server->activeConns[activeSlot].tcpPoller.poller.fd = -1;
  server->activeConns[activeSlot].tcpPoller.poller.events = 0;
  server->activeConns[activeSlot].tcpPoller.poller.kind = ioPollerKindTcp;
  server->activeConns[activeSlot].tcpPoller.poller.callbacks = NULL;
  server->activeConns[activeSlot].tcpPoller.poller.ctx = &server->activeConns[activeSlot];
  server->activeConns[activeSlot].tcpPoller.poller.readEnabled = false;
  server->activeConns[activeSlot].keyRef = keySlot;
  server->activeConns[activeSlot].keySlot = activeSlot;
  memcpy(server->activeConns[activeSlot].claim, preAuth->claim, (size_t)preAuth->claimNbytes);
  server->activeConns[activeSlot].claimNbytes = preAuth->claimNbytes;
  server->activeConns[activeSlot].heartbeatAckPending = false;
  server->activeConns[activeSlot].active = true;
  server->activeCount++;
  return true;
}

static int isValidTunClaim(const unsigned char *claim, long claimNbytes) {
  return claim != NULL && claimNbytes == 4;
}

static int isValidTapClaim(const unsigned char *claim, long claimNbytes) {
  return claim != NULL && claimNbytes == 6;
}

typedef enum {
  preAuthStateWaitClaim = 0,
  preAuthStateWaitHello,
} preAuthState_t;

static bool serverDropActiveConn(server_t *server, int activeSlot) {
  if (server == NULL || !activeSlotIndexValid(server, activeSlot) || !server->activeConns[activeSlot].active) {
    return false;
  }
  ioTcpPollerDispose(&server->activeConns[activeSlot].tcpPoller);
  return serverRemoveClient(server, activeSlot);
}

static bool serverClosePreAuthConn(server_t *server, int preAuthSlot) {
  preAuthConn_t *conn = serverPreAuthAt(server, preAuthSlot);
  if (conn == NULL) {
    return false;
  }
  serverPreAuthConnDispose(server, preAuthSlot);
  return true;
}

static bool preAuthReadIntoCarry(preAuthConn_t *conn) {
  long nbytes = 0;
  ioStatus_t status;

  if (conn->tcpReadCarryNbytes >= (long)sizeof(conn->tcpReadCarryBuf)) {
    return false;
  }
  status = ioPollerRead(
      &conn->tcpPoller.poller,
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
  if (!ioTcpWrite(&conn->tcpPoller, conn->authWriteBuf, conn->authWriteNbytes)) {
    return false;
  }
  conn->authWriteOffset = conn->authWriteNbytes;
  conn->authWriteNbytes = 0;
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
    sessionServerResolveClaimFn_t resolveClaimFn,
    void *resolveClaimCtx,
    bool *outRetargeted) {
  preAuthConn_t *conn;
  long long nowMs;

  if (outRetargeted != NULL) {
    *outRetargeted = false;
  }
  conn = serverPreAuthAt(server, preAuthSlot);
  if (conn == NULL || resolveClaimFn == NULL) {
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

    if ((server->mode == ioIfModeTun && !isValidTunClaim(conn->claim, conn->claimNbytes))
        || (server->mode == ioIfModeTap && !isValidTapClaim(conn->claim, conn->claimNbytes))) {
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
    conn->authState = preAuthStateWaitHello;
  }

  if (conn->authState == preAuthStateWaitHello && event == ioEventTcpRead) {
    bool helloReady = false;
    int activeSlot;
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
    if (!ioTcpPollerHandoff(
            &server->activeConns[activeSlot].tcpPoller,
            &conn->tcpPoller,
            &serverActiveCallbacks,
            &server->activeConns[activeSlot],
            true)) {
      (void)serverClosePreAuthConn(server, preAuthSlot);
      (void)serverDropActiveConn(server, activeSlot);
      return false;
    }
    if (!serverRemovePreAuthConn(server, preAuthSlot)) {
      (void)serverDropActiveConn(server, activeSlot);
      return false;
    }
    activeSession = serverSessionAt(server, activeSlot);
    if (activeSession == NULL
        || !sessionPromoteFromPreAuth(
            activeSession, &helloDecoder, helloCarryNbytes > 0 ? helloCarryBuf : NULL, helloCarryNbytes)) {
      (void)serverDropActiveConn(server, activeSlot);
      return false;
    }
    logf("connected with slot=%d", activeSlot);
    if (outRetargeted != NULL) {
      *outRetargeted = true;
    }
  }

  return true;
}

static bool serverDispatchClient(server_t *server, int slot, ioEvent_t event) {
  session_t *session = serverSessionAt(server, slot);
  const unsigned char *key = serverKeyAt(server, slot);
  sessionStepResult_t stepResult;

  if (session == NULL || server->activeConns[slot].tcpPoller.poller.fd < 0) {
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
    return serverDropActiveConn(server, slot);
  }
  return true;
}

static bool serverDispatchTunIngressToSlot(
    server_t *server, int slot, const void *payload, long payloadNbytes) {
  session_t *session = serverSessionAt(server, slot);
  const unsigned char *key = serverKeyAt(server, slot);
  protocolMessage_t msg;
  sessionQueueResult_t result;

  if (session == NULL || server->activeConns[slot].tcpPoller.poller.fd < 0 || key == NULL || payload == NULL || payloadNbytes <= 0) {
    return false;
  }

  msg.type = protocolMsgData;
  msg.nbytes = payloadNbytes;
  msg.buf = (const char *)payload;
  result = serverSendMessage(server, &server->activeConns[slot], key, &msg);
  if (result == sessionQueueResultError) {
    return serverDropActiveConn(server, slot);
  }
  if (sessionFinalizeStep(session, key) == sessionStepStop) {
    return serverDropActiveConn(server, slot);
  }
  return true;
}

static bool claimsEqual(
    const unsigned char *a, long aNbytes, const unsigned char *b, long bNbytes) {
  return a != NULL && b != NULL && aNbytes > 0 && aNbytes == bNbytes && memcmp(a, b, (size_t)aNbytes) == 0;
}

static bool serverDispatchTcpIngressToSlot(
    server_t *server,
    int sourceSlot,
    int destSlot,
    const void *payload,
    long payloadNbytes) {
  session_t *sourceSession;
  const unsigned char *destKey;
  protocolMessage_t msg;
  protocolFrame_t frame;
  sessionQueueResult_t result;

  if (server == NULL
      || !activeSlotIndexValid(server, sourceSlot)
      || !activeSlotIndexValid(server, destSlot)
      || !server->activeConns[sourceSlot].active
      || !server->activeConns[destSlot].active
      || payload == NULL
      || payloadNbytes <= 0) {
    return false;
  }
  sourceSession = server->activeConns[sourceSlot].session;
  destKey = serverKeyAt(server, destSlot);
  if (sourceSession == NULL || destKey == NULL) {
    return false;
  }

  msg.type = protocolMsgData;
  msg.nbytes = payloadNbytes;
  msg.buf = (const char *)payload;
  if (protocolEncodeSecureMsg(&msg, destKey, &frame) != protocolStatusOk) {
    return false;
  }

  result = sessionQueueTcpWithBackpressure(
      &server->activeConns[sourceSlot].tcpPoller,
      &server->activeConns[destSlot].tcpPoller,
      sourceSession,
      destSlot,
      frame.buf,
      frame.nbytes);
  return result != sessionQueueResultError;
}

static bool serverBroadcastTcpIngressToClients(
    server_t *server, int sourceSlot, const void *payload, long payloadNbytes) {
  int destSlot;
  session_t *sourceSession;

  if (server == NULL
      || !activeSlotIndexValid(server, sourceSlot)
      || !server->activeConns[sourceSlot].active
      || payload == NULL
      || payloadNbytes <= 0) {
    return false;
  }
  sourceSession = server->activeConns[sourceSlot].session;
  if (sourceSession == NULL) {
    return false;
  }

  for (destSlot = 0; destSlot < server->maxActiveSessions; destSlot++) {
    const unsigned char *destKey;
    protocolMessage_t msg;
    protocolFrame_t frame;
    sessionQueueResult_t result;
    if (!server->activeConns[destSlot].active || destSlot == sourceSlot) {
      continue;
    }
    destKey = serverKeyAt(server, destSlot);
    if (destKey == NULL) {
      return false;
    }
    msg.type = protocolMsgData;
    msg.nbytes = payloadNbytes;
    msg.buf = (const char *)payload;
    if (protocolEncodeSecureMsg(&msg, destKey, &frame) != protocolStatusOk) {
      return false;
    }
    result = sessionQueueTcpWithDrop(
        &server->activeConns[destSlot].tcpPoller,
        sourceSession,
        destSlot,
        frame.buf,
        frame.nbytes);
    if (result == sessionQueueResultError) {
      return false;
    }
  }
  return true;
}

static bool serverQueueTcpIngressToTun(
    server_t *server, int sourceSlot, const void *payload, long payloadNbytes, bool dropMode) {
  session_t *sourceSession;
  sessionQueueResult_t result;

  if (server == NULL
      || !activeSlotIndexValid(server, sourceSlot)
      || !server->activeConns[sourceSlot].active
      || payload == NULL
      || payloadNbytes <= 0) {
    return false;
  }
  sourceSession = server->activeConns[sourceSlot].session;
  if (sourceSession == NULL) {
    return false;
  }
  if (dropMode) {
    result = sessionQueueTunWithDropForSession(&server->tunPoller, sourceSession, payload, payloadNbytes);
  } else {
    result = sessionQueueTunWithBackpressure(
        &server->activeConns[sourceSlot].tcpPoller, &server->tunPoller, sourceSession, payload, payloadNbytes);
  }
  return result != sessionQueueResultError;
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
    const server_t *server, const packetDestination_t *destination);

bool serverRouteTcpIngressPacket(
    server_t *server, activeConn_t *sourceConn, const void *packet, long packetNbytes) {
  packetParseMode_t mode;
  packetDestination_t destination;
  packetParseStatus_t parseStatus;
  long long nowMs;
  session_t *sourceSession;
  int sourceSlot;
  int destSlot;
  bool isServerDestination;
  bool handled;

  if (server == NULL
      || sourceConn == NULL
      || sourceConn->owner != server
      || packet == NULL
      || packetNbytes <= 0) {
    return false;
  }
  sourceSlot = serverActiveSlotFromConn(server, sourceConn);
  if (!activeSlotIndexValid(server, sourceSlot) || !server->activeConns[sourceSlot].active) {
    return false;
  }
  sourceSession = server->activeConns[sourceSlot].session;
  if (sourceSession == NULL || !serverPacketParseMode(server, &mode)) {
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
    if (!serverBroadcastTcpIngressToClients(server, sourceSlot, packet, packetNbytes)) {
      return false;
    }
    handled = serverQueueTcpIngressToTun(server, sourceSlot, packet, packetNbytes, true);
    goto done;
  }
  if (mode == packetParseModeTunIpv4 && destination.classification == packetDestinationBroadcastL3Candidate) {
    if (serverTunDestinationIsLimitedBroadcast(&destination)
        || serverTunDestinationMatchesDirectedBroadcast(server, &destination)) {
      if (!serverBroadcastTcpIngressToClients(server, sourceSlot, packet, packetNbytes)) {
        return false;
      }
      handled = serverQueueTcpIngressToTun(server, sourceSlot, packet, packetNbytes, true);
      goto done;
    }
    handled = true;
    goto done;
  }

  if (destination.classification != packetDestinationOk) {
    handled = true;
    goto done;
  }

  if (mode == packetParseModeTunIpv4 && serverTunDestinationMatchesDirectedBroadcast(server, &destination)) {
    if (!serverBroadcastTcpIngressToClients(server, sourceSlot, packet, packetNbytes)) {
      return false;
    }
    handled = serverQueueTcpIngressToTun(server, sourceSlot, packet, packetNbytes, true);
    goto done;
  }

  isServerDestination = claimsEqual(
      destination.claim,
      destination.claimNbytes,
      server->serverIdentity.claim,
      server->serverIdentity.claimNbytes);
  if (isServerDestination) {
    handled = serverQueueTcpIngressToTun(server, sourceSlot, packet, packetNbytes, false);
    goto done;
  }

  destSlot = serverFindSlotByClaim(server, destination.claim, destination.claimNbytes);
  if (destSlot < 0 || destSlot == sourceSlot) {
    handled = true;
    goto done;
  }
  handled = serverDispatchTcpIngressToSlot(server, sourceSlot, destSlot, packet, packetNbytes);

done:
  if (!handled) {
    return false;
  }
  nowMs = serverNowMs(server);
  if (nowMs < 0) {
    return false;
  }
  sourceSession->lastValidInboundMs = nowMs;
  return true;
}

static bool serverTunDestinationMatchesDirectedBroadcast(
    const server_t *server, const packetDestination_t *destination) {
  return server != NULL
      && destination != NULL
      && server->serverIdentity.directedBroadcastEnabled
      && destination->claimNbytes == 4
      && memcmp(destination->claim, server->serverIdentity.directedBroadcast, 4) == 0;
}

static bool serverFanoutTunIngressToAll(
    server_t *server, const void *payload, long payloadNbytes) {
  int slot;

  if (server == NULL || payload == NULL || payloadNbytes <= 0) {
    return false;
  }

  for (slot = 0; slot < server->maxActiveSessions; slot++) {
    session_t *session;
    const unsigned char *key;
    protocolMessage_t msg;
    protocolFrame_t frame;
    sessionQueueResult_t result;

    if (!server->activeConns[slot].active) {
      continue;
    }
    session = serverSessionAt(server, slot);
    key = serverKeyAt(server, slot);
    if (session == NULL || server->activeConns[slot].tcpPoller.poller.fd < 0 || key == NULL) {
      return false;
    }

    msg.type = protocolMsgData;
    msg.nbytes = payloadNbytes;
    msg.buf = (const char *)payload;
    if (protocolEncodeSecureMsg(&msg, key, &frame) != protocolStatusOk) {
      return serverDropActiveConn(server, slot);
    }

    result = serverQueueTcpWithDrop(&server->activeConns[slot].tcpPoller, frame.buf, frame.nbytes);
    if (result == sessionQueueResultError) {
      return serverDropActiveConn(server, slot);
    }
    if (result == sessionQueueResultBlocked) {
      continue;
    }

    if (sessionFinalizeStep(session, key) == sessionStepStop) {
      return serverDropActiveConn(server, slot);
    }
  }

  return true;
}

bool serverRouteTunIngressPacket(server_t *server, const void *packet, long packetNbytes) {
  packetParseMode_t mode;
  packetDestination_t destination;
  packetParseStatus_t parseStatus;
  int slot;

  if (server == NULL || packet == NULL || packetNbytes <= 0) {
    return false;
  }
  if (!serverPacketParseMode(server, &mode)) {
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

static bool serverHandleTunRead(server_t *server) {
  char packet[ProtocolFrameSize];
  long packetNbytes = 0;
  long maxPayload = protocolMaxPlaintextSize() - ((long)sizeof(unsigned char) + ProtocolWireLengthSize);
  ioStatus_t status;

  if (server == NULL || maxPayload <= 0 || maxPayload > (long)sizeof(packet)) {
    return false;
  }

  status = ioPollerRead(&server->tunPoller.poller, packet, maxPayload, &packetNbytes);
  if (status == ioStatusWouldBlock) {
    return true;
  }
  if (status != ioStatusOk) {
    return false;
  }

  return serverRouteTunIngressPacket(server, packet, packetNbytes);
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
    sessionServerResolveClaimFn_t resolveClaimFn,
    void *resolveClaimCtx) {
  int slot;

  for (slot = 0; slot < server->maxPreAuthSessions; slot++) {
    preAuthConn_t *conn = serverPreAuthAt(server, slot);
    if (conn == NULL) {
      continue;
    }
    if (!serverDispatchPreAuth(server, slot, ioEventTimeout, resolveClaimFn, resolveClaimCtx, NULL)) {
      return false;
    }
  }
  return true;
}

typedef struct {
  server_t *server;
} serverRuntimeCtx_t;

static const ioPollerCallbacks_t serverPreAuthCallbacks;
static const ioPollerCallbacks_t serverActiveCallbacks;

static void serverActiveConnDispose(server_t *server, int slot) {
  if (!activeSlotIndexValid(server, slot) || !server->activeConns[slot].active) {
    return;
  }
  ioTcpPollerDispose(&server->activeConns[slot].tcpPoller);
  (void)serverRemoveClient(server, slot);
}

static void serverPreAuthConnDispose(server_t *server, int preAuthSlot) {
  preAuthConn_t *conn;
  if (!preAuthSlotIndexValid(server, preAuthSlot)) {
    return;
  }
  conn = &server->preAuthConns[preAuthSlot];
  if (conn->tcpPoller.poller.fd >= 0) {
    ioTcpPollerDispose(&conn->tcpPoller);
  }
  if (conn->active) {
    (void)serverRemovePreAuthConn(server, preAuthSlot);
  }
}

static void serverRuntimeDispose(server_t *server) {
  int i;
  if (server == NULL) {
    return;
  }
  for (i = 0; i < server->maxActiveSessions; i++) {
    serverActiveConnDispose(server, i);
  }
  for (i = 0; i < server->maxPreAuthSessions; i++) {
    serverPreAuthConnDispose(server, i);
  }
  ioTunPollerDispose(&server->tunPoller);
  ioListenPollerDispose(&server->listenPoller);
  ioReactorDispose(&server->reactor);
}

static ioPollerAction_t serverOnListenReadable(void *ctx, ioReactor_t *reactor, ioPoller_t *poller) {
  serverRuntimeCtx_t *runtime = ctx;
  ioListenPoller_t *listenPoller;
  server_t *server;
  (void)reactor;

  if (runtime == NULL || poller == NULL || runtime->server == NULL) {
    return ioPollerStop;
  }
  if (poller->kind != ioPollerKindListen) {
    return ioPollerStop;
  }
  listenPoller = (ioListenPoller_t *)poller;
  server = runtime->server;

  while (1) {
    char clientIp[256];
    int clientPort = 0;
    ioStatus_t status;
    long long nowMs;
    int preAuthSlot;
    preAuthConn_t *conn;

    nowMs = serverNowMs(server);
    if (nowMs < 0) {
      return ioPollerStop;
    }
    preAuthSlot = serverFindFreePreAuthSlot(server);
    if (preAuthSlot < 0) {
      break;
    }
    conn = &server->preAuthConns[preAuthSlot];
    memset(&conn->tcpPoller, 0, sizeof(conn->tcpPoller));
    conn->tcpPoller.poller.fd = -1;

    status = ioPollerAccept(
        listenPoller, &conn->tcpPoller, clientIp, sizeof(clientIp), &clientPort);
    if (status == ioStatusWouldBlock) {
      break;
    }
    if (status != ioStatusOk) {
      if (conn->tcpPoller.poller.fd >= 0) {
        ioTcpPollerDispose(&conn->tcpPoller);
      }
      memset(&conn->tcpPoller, 0, sizeof(conn->tcpPoller));
      conn->tcpPoller.poller.fd = -1;
      return ioPollerStop;
    }
    if (conn->tcpPoller.poller.fd < 0) {
      memset(&conn->tcpPoller, 0, sizeof(conn->tcpPoller));
      conn->tcpPoller.poller.fd = -1;
      continue;
    }
    conn->tcpPoller.poller.ctx = conn;
    if (!ioReactorAddPoller(
            &server->reactor,
            &conn->tcpPoller.poller,
            &serverPreAuthCallbacks,
            conn,
            true)) {
      ioTcpPollerDispose(&conn->tcpPoller);
      memset(&conn->tcpPoller, 0, sizeof(conn->tcpPoller));
      conn->tcpPoller.poller.fd = -1;
      return ioPollerStop;
    }
    if (serverCreatePreAuthConn(server, preAuthSlot, nowMs + server->authTimeoutMs) < 0) {
      ioTcpPollerDispose(&conn->tcpPoller);
      memset(&conn->tcpPoller, 0, sizeof(conn->tcpPoller));
      conn->tcpPoller.poller.fd = -1;
      return ioPollerStop;
    }
  }

  return ioPollerContinue;
}

static ioPollerAction_t serverOnTunReadable(void *ctx, ioReactor_t *reactor, ioPoller_t *poller) {
  serverRuntimeCtx_t *runtime = ctx;
  (void)reactor;
  (void)poller;
  if (runtime == NULL || runtime->server == NULL) {
    return ioPollerStop;
  }
  return serverHandleTunRead(runtime->server) ? ioPollerContinue : ioPollerStop;
}

static ioPollerAction_t serverOnTunLowWatermark(void *ctx, ioPoller_t *poller, long queuedBytes) {
  serverRuntimeCtx_t *runtime = ctx;
  (void)poller;
  if (runtime == NULL || runtime->server == NULL) {
    return ioPollerStop;
  }
  if (queuedBytes <= IoPollerLowWatermark && serverRetryBlockedTunRoundRobin(runtime->server) < 0) {
    return ioPollerStop;
  }
  return ioPollerContinue;
}

static ioPollerAction_t serverOnTunClosed(void *ctx, ioPoller_t *poller) {
  (void)ctx;
  (void)poller;
  return ioPollerStop;
}

static ioPollerAction_t serverOnActiveReadable(void *ctx, ioReactor_t *reactor, ioPoller_t *poller) {
  activeConn_t *conn = ctx;
  server_t *server;
  int slot;
  (void)reactor;
  if (conn == NULL || conn->owner == NULL || poller == NULL) {
    return ioPollerStop;
  }
  server = conn->owner;
  slot = serverActiveSlotFromConn(server, conn);
  if (slot < 0 || !conn->active || &conn->tcpPoller.poller != poller) {
    return ioPollerContinue;
  }
  if (slot < 0) {
    return ioPollerContinue;
  }
  return serverDispatchClient(server, slot, ioEventTcpRead) ? ioPollerContinue : ioPollerStop;
}

static ioPollerAction_t serverOnActiveLowWatermark(void *ctx, ioPoller_t *poller, long queuedBytes) {
  activeConn_t *conn = ctx;
  server_t *server;
  int slot;
  (void)queuedBytes;
  if (conn == NULL || conn->owner == NULL || poller == NULL) {
    return ioPollerStop;
  }
  server = conn->owner;
  slot = serverActiveSlotFromConn(server, conn);
  if (slot < 0 || !conn->active || &conn->tcpPoller.poller != poller) {
    return ioPollerContinue;
  }
  if (slot < 0) {
    return ioPollerContinue;
  }
  if (!serverServiceBackpressure(server, slot, ioEventTcpWrite)) {
    return ioPollerStop;
  }
  return serverDispatchClient(server, slot, ioEventTcpWrite) ? ioPollerContinue : ioPollerStop;
}

static ioPollerAction_t serverOnActiveClosed(void *ctx, ioPoller_t *poller) {
  activeConn_t *conn = ctx;
  server_t *server;
  int slot;
  if (conn == NULL || conn->owner == NULL || poller == NULL) {
    return ioPollerStop;
  }
  server = conn->owner;
  slot = serverActiveSlotFromConn(server, conn);
  if (slot < 0 || !conn->active || &conn->tcpPoller.poller != poller) {
    return ioPollerContinue;
  }
  if (slot < 0) {
    return ioPollerContinue;
  }
  serverActiveConnDispose(server, slot);
  return ioPollerRetargeted;
}

static ioPollerAction_t serverOnPreAuthReadable(void *ctx, ioReactor_t *reactor, ioPoller_t *poller) {
  preAuthConn_t *conn = ctx;
  server_t *server;
  int preAuthSlot;
  bool retargeted = false;
  (void)reactor;
  if (conn == NULL || conn->owner == NULL || poller == NULL) {
    return ioPollerStop;
  }
  server = conn->owner;
  preAuthSlot = serverPreAuthSlotFromConn(server, conn);
  if (preAuthSlot < 0 || !conn->active || &conn->tcpPoller.poller != poller) {
    return ioPollerContinue;
  }
  if (preAuthSlot < 0) {
    return ioPollerContinue;
  }
  if (!serverDispatchPreAuth(
          server,
          preAuthSlot,
          ioEventTcpRead,
          server->resolveClaimFn,
          server->resolveClaimCtx,
          &retargeted)) {
    return ioPollerStop;
  }
  return retargeted ? ioPollerRetargeted : ioPollerContinue;
}

static ioPollerAction_t serverOnPreAuthClosed(void *ctx, ioPoller_t *poller) {
  preAuthConn_t *conn = ctx;
  server_t *server;
  int preAuthSlot;

  if (conn == NULL || conn->owner == NULL || poller == NULL) {
    return ioPollerStop;
  }
  server = conn->owner;
  preAuthSlot = serverPreAuthSlotFromConn(server, conn);
  if (preAuthSlot < 0 || !conn->active || &conn->tcpPoller.poller != poller) {
    return ioPollerContinue;
  }
  if (preAuthSlot < 0) {
    return ioPollerContinue;
  }
  serverPreAuthConnDispose(server, preAuthSlot);
  return ioPollerRetargeted;
}

static const ioPollerCallbacks_t serverTunCallbacks = {
    .onClosed = serverOnTunClosed,
    .onLowWatermark = serverOnTunLowWatermark,
    .onReadable = serverOnTunReadable,
};

static const ioPollerCallbacks_t serverListenCallbacks = {
    .onClosed = NULL,
    .onLowWatermark = NULL,
    .onReadable = serverOnListenReadable,
};

static const ioPollerCallbacks_t serverActiveCallbacks = {
    .onClosed = serverOnActiveClosed,
    .onLowWatermark = serverOnActiveLowWatermark,
    .onReadable = serverOnActiveReadable,
};

static const ioPollerCallbacks_t serverPreAuthCallbacks = {
    .onClosed = serverOnPreAuthClosed,
    .onLowWatermark = NULL,
    .onReadable = serverOnPreAuthReadable,
};

int serverServeMultiClient(server_t *server) {
  serverRuntimeCtx_t runtimeCtx;
  if (server == NULL
      || server->resolveClaimFn == NULL
      || (server->mode != ioIfModeTun && server->mode != ioIfModeTap)
      || server->authTimeoutMs <= 0
      || server->maxActiveSessions <= 0
      || server->maxPreAuthSessions <= 0
      || server->listenPoller.poller.fd < 0
      || server->tunPoller.poller.fd < 0) {
    return -1;
  }

  if (!ioReactorInit(&server->reactor)) {
    return -1;
  }
  runtimeCtx.server = server;

  if (!ioReactorAddPoller(&server->reactor, &server->listenPoller.poller, &serverListenCallbacks, &runtimeCtx, true)) {
    ioReactorDispose(&server->reactor);
    return -1;
  }
  if (!ioReactorAddPoller(&server->reactor, &server->tunPoller.poller, &serverTunCallbacks, &runtimeCtx, true)) {
    ioReactorDispose(&server->reactor);
    return -1;
  }

  while (1) {
    ioReactorStepResult_t step = ioReactorStep(&server->reactor, 200);
    if (step == ioReactorStepError || step == ioReactorStepStop) {
      return -1;
    }
    if (!serverTickAllClients(server)) {
      return -1;
    }
    if (!serverTickPreAuth(server, server->resolveClaimFn, server->resolveClaimCtx)) {
      return -1;
    }
  }
}

int serverServeLocal(const sessionServerConfig_t *cfg) {
  server_t server;
  int rc = -1;

  if (cfg == NULL
      || cfg->ifName == NULL
      || cfg->ifName[0] == '\0'
      || (cfg->ifMode != ioIfModeTun && cfg->ifMode != ioIfModeTap)
      || cfg->listenIP == NULL
      || cfg->port <= 0
      || cfg->port > 65535
      || cfg->resolveClaimFn == NULL
      || cfg->authTimeoutMs <= 0
      || cfg->heartbeat.intervalMs <= 0
      || cfg->heartbeat.timeoutMs <= cfg->heartbeat.intervalMs
      || cfg->maxActiveSessions <= 0
      || cfg->maxPreAuthSessions <= 0) {
    return -1;
  }
  if (!serverInit(
          &server,
          cfg->maxActiveSessions,
          cfg->maxPreAuthSessions,
          &cfg->heartbeat,
          NULL,
          NULL)) {
    return -1;
  }

  server.resolveClaimFn = cfg->resolveClaimFn;
  server.resolveClaimCtx = cfg->resolveClaimCtx;
  server.authTimeoutMs = cfg->authTimeoutMs;
  server.mode = cfg->ifMode;
  if (cfg->serverIdentity != NULL) {
    server.serverIdentity = *cfg->serverIdentity;
  }

  if (!ioPollerOpenTun(&server.tunPoller, cfg->ifName, cfg->ifMode)) {
    goto cleanup;
  }
  if (!ioPollerListen(&server.listenPoller, cfg->listenIP, cfg->port)) {
    goto cleanup;
  }
  rc = serverServeMultiClient(&server);

cleanup:
  serverRuntimeDispose(&server);
  serverDeinit(&server);
  return rc;
}
