#include "sessionInternal.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sodium.h>

#include "log.h"
#include "client.h"

#define EPOLL_WAIT_MS 200

void clientResetHeartbeatState(
    client_t *client,
    int heartbeatIntervalMs,
    int heartbeatTimeoutMs,
    long long nowMs) {
  if (client == NULL || heartbeatIntervalMs <= 0 || heartbeatTimeoutMs <= heartbeatIntervalMs) {
    return;
  }
  client->heartbeatAckPending = false;
  client->heartbeatReqPending = false;
  client->heartbeatSentMs = 0;
  client->lastHeartbeatReqMs = nowMs;
  client->lastDataSentMs = nowMs;
  client->lastDataRecvMs = nowMs;
  client->reactor.epollFd = -1;
  client->session = NULL;
  client->claim = NULL;
  client->claimNbytes = 0;
  client->key = NULL;
  protocolDecoderInit(&client->rawDecoder);
  client->preAuthState = clientPreAuthSendClaim;
  client->runStop = false;
  client->runFailed = false;
  client->tunReadPaused = false;
  client->runtimeOverflowNbytes = 0;
  memset(client->runtimeOverflowBuf, 0, sizeof(client->runtimeOverflowBuf));
  client->heartbeatIntervalMs = heartbeatIntervalMs;
  client->heartbeatTimeoutMs = heartbeatTimeoutMs;
}

sessionQueueResult_t clientQueueTcpWithBackpressure(
    client_t *client,
    const void *data,
    long nbytes) {
  long queued;
  ioTcpPoller_t *tcpPoller;
  ioTunPoller_t *tunPoller;

  if (client == NULL) {
    return sessionQueueResultError;
  }
  tcpPoller = client->tcpPoller;
  tunPoller = client->tunPoller;
  if (tcpPoller == NULL || tunPoller == NULL || data == NULL || nbytes <= 0) {
    return sessionQueueResultError;
  }
  if (client->runtimeOverflowNbytes > 0) {
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
    memcpy(client->runtimeOverflowBuf, data, (size_t)nbytes);
    client->runtimeOverflowNbytes = nbytes;
    if (!client->tunReadPaused) {
      if (!ioTunSetReadEnabled(tunPoller, false)) {
        return sessionQueueResultError;
      }
      client->tunReadPaused = true;
    }
    return sessionQueueResultBlocked;
  }
  return sessionQueueResultError;
}

static sessionQueueResult_t clientQueueTcpWithDrop(
    client_t *client,
    const void *data,
    long nbytes) {
  long used;
  ioTcpPoller_t *tcpPoller;

  if (client == NULL || data == NULL || nbytes <= 0) {
    return sessionQueueResultError;
  }
  tcpPoller = client->tcpPoller;
  if (tcpPoller == NULL) {
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

static sessionQueueResult_t clientSendHeartbeatReq(
    client_t *client,
    const unsigned char key[ProtocolPskSize]) {
  protocolFrame_t frame;
  protocolMessage_t req = {
      .type = protocolMsgHeartbeatReq,
      .nbytes = 0,
      .buf = NULL,
  };

  if (client == NULL || key == NULL) {
    return sessionQueueResultError;
  }
  if (protocolEncodeSecureMsg(&req, key, &frame) != protocolStatusOk) {
    return sessionQueueResultError;
  }
  return clientQueueTcpWithDrop(client, frame.buf, frame.nbytes);
}

static void clientMarkHeartbeatReqQueued(client_t *client, long long nowMs) {
  if (client == NULL) {
    return;
  }
  client->heartbeatReqPending = false;
  client->heartbeatAckPending = true;
  client->heartbeatSentMs = nowMs;
  client->lastHeartbeatReqMs = nowMs;
  dbgf("sent heartbeat request");
}

sessionQueueResult_t clientSendMessage(
    client_t *client,
    const unsigned char key[ProtocolPskSize],
    long long nowMs,
    const protocolMessage_t *msg) {
  protocolFrame_t frame;
  sessionQueueResult_t result;

  if (client == NULL || key == NULL || msg == NULL) {
    return sessionQueueResultError;
  }
  if (protocolEncodeSecureMsg(msg, key, &frame) != protocolStatusOk) {
    return sessionQueueResultError;
  }
  result = clientQueueTcpWithBackpressure(client, frame.buf, frame.nbytes);
  if (result == sessionQueueResultQueued && msg->type == protocolMsgData) {
    client->lastDataSentMs = nowMs;
  }
  return result;
}

sessionQueueResult_t clientHandleInboundMessage(
    client_t *client,
    long long nowMs,
    long long *lastValidInboundMs,
    const protocolMessage_t *msg) {
  if (client == NULL || lastValidInboundMs == NULL || msg == NULL) {
    return sessionQueueResultError;
  }
  *lastValidInboundMs = nowMs;

  if (msg->type == protocolMsgData) {
    logf("unexpected data message in client inbound handler");
    return sessionQueueResultError;
  }
  if (msg->type == protocolMsgHeartbeatReq) {
    logf("unexpected heartbeat request on client");
    return sessionQueueResultError;
  }
  if (msg->type == protocolMsgHeartbeatAck) {
    if (!client->heartbeatAckPending) {
      logf("unexpected heartbeat ack");
      return sessionQueueResultError;
    }
    client->heartbeatAckPending = false;
    dbgf("heartbeat ack received");
    return sessionQueueResultQueued;
  }
  return sessionQueueResultError;
}

bool clientHeartbeatTick(
    client_t *client,
    long long nowMs,
    const unsigned char key[ProtocolPskSize]) {
  if (client == NULL || key == NULL || client->heartbeatIntervalMs <= 0
      || client->heartbeatTimeoutMs <= client->heartbeatIntervalMs) {
    return false;
  }

  if (!client->heartbeatAckPending) {
    bool idleSend = nowMs - client->lastDataSentMs >= client->heartbeatIntervalMs;
    bool intervalElapsed = nowMs - client->lastHeartbeatReqMs >= client->heartbeatIntervalMs;
    if (!client->heartbeatReqPending && idleSend && intervalElapsed) {
      client->heartbeatReqPending = true;
      sessionQueueResult_t result = clientSendHeartbeatReq(client, key);
      if (result == sessionQueueResultError) {
        return false;
      }
      if (result == sessionQueueResultQueued) {
        clientMarkHeartbeatReqQueued(client, nowMs);
      }
    }
  }

  if (client->heartbeatAckPending && nowMs - client->heartbeatSentMs >= client->heartbeatTimeoutMs) {
    logf("client heartbeat timeout waiting for ack");
    return false;
  }

  return true;
}

bool clientServiceBackpressure(
    client_t *client,
    session_t *session,
    ioEvent_t event,
    const unsigned char key[ProtocolPskSize]) {
  long queued;
  long long nowMs;
  ioTcpPoller_t *tcpPoller;
  ioTunPoller_t *tunPoller;

  if (client == NULL || session == NULL || key == NULL) {
    return false;
  }
  tcpPoller = client->tcpPoller;
  tunPoller = client->tunPoller;
  if (tcpPoller == NULL || tunPoller == NULL) {
    return false;
  }

  if (!sessionRetryOverflow(session, tcpPoller, tunPoller, event)) {
    return false;
  }

  if (event != ioEventTcpWrite) {
    if (event == ioEventTimeout && client->heartbeatReqPending) {
      sessionQueueResult_t result = clientSendHeartbeatReq(client, key);
      if (result == sessionQueueResultError) {
        return false;
      }
      if (result == sessionQueueResultQueued) {
        nowMs = session->nowFn(session->nowCtx);
        clientMarkHeartbeatReqQueued(client, nowMs);
      }
    }
    return true;
  }
  queued = ioTcpQueuedBytes(tcpPoller);
  if (queued < 0) {
    return false;
  }
  if (queued > IoPollerLowWatermark) {
    return true;
  }

  if (client->heartbeatReqPending) {
    sessionQueueResult_t result = clientSendHeartbeatReq(client, key);
    if (result == sessionQueueResultError) {
      return false;
    }
    if (result == sessionQueueResultQueued) {
      nowMs = session->nowFn(session->nowCtx);
      clientMarkHeartbeatReqQueued(client, nowMs);
    }
    return true;
  }

  if (client->runtimeOverflowNbytes > 0) {
    if (ioTcpWrite(tcpPoller, client->runtimeOverflowBuf, client->runtimeOverflowNbytes)) {
      client->runtimeOverflowNbytes = 0;
    } else {
      if (queued + client->runtimeOverflowNbytes <= IoPollerQueueCapacity) {
        return false;
      }
    }
  }

  if (client->tunReadPaused && client->runtimeOverflowNbytes == 0) {
    queued = ioTcpQueuedBytes(tcpPoller);
    if (queued < 0) {
      return false;
    }
    if (queued <= IoPollerLowWatermark) {
      if (!ioTunSetReadEnabled(tunPoller, true)) {
        return false;
      }
      client->tunReadPaused = false;
    }
  }

  return true;
}

static ioPollerAction_t clientMarkRunStop(client_t *client, bool failed) {
  if (client == NULL) {
    return ioPollerStop;
  }
  client->runFailed = failed;
  client->runStop = true;
  return ioPollerStop;
}

static bool clientQueueRawMsg(client_t *client, const unsigned char *buf, long nbytes) {
  protocolFrame_t frame;
  protocolRawMsg_t raw;

  if (client == NULL || client->tcpPoller == NULL || buf == NULL || nbytes <= 0) {
    return false;
  }
  raw.buf = (const char *)buf;
  raw.nbytes = nbytes;
  if (protocolEncodeRaw(&raw, &frame) != protocolStatusOk) {
    return false;
  }
  return ioTcpWrite(client->tcpPoller, frame.buf, frame.nbytes);
}

static bool clientQueueSecureMsg(client_t *client, const protocolMessage_t *msg) {
  protocolFrame_t frame;

  if (client == NULL || client->tcpPoller == NULL || msg == NULL || client->key == NULL) {
    return false;
  }
  if (protocolEncodeSecureMsg(msg, client->key, &frame) != protocolStatusOk) {
    return false;
  }
  return ioTcpWrite(client->tcpPoller, frame.buf, frame.nbytes);
}

static ioPollerAction_t clientStepSession(client_t *client, ioEvent_t event) {
  if (client == NULL || client->session == NULL || client->tcpPoller == NULL || client->tunPoller == NULL || client->key == NULL) {
    return ioPollerStop;
  }
  if (sessionStep(client->session, client->tcpPoller, client->tunPoller, event, client->key) == sessionStepStop) {
    return clientMarkRunStop(client, false);
  }
  if (!clientServiceBackpressure(client, client->session, event, client->key)) {
    return clientMarkRunStop(client, true);
  }
  return ioPollerContinue;
}

static ioPollerAction_t clientCompletePreAuth(client_t *client, const char *carryBuf, long carryNbytes) {
  ioPollerAction_t action;

  if (client == NULL || client->session == NULL || client->tunPoller == NULL || carryNbytes < 0) {
    return ioPollerStop;
  }
  client->preAuthState = clientPreAuthReady;
  if (!ioReactorSetPollerReadEnabled(&client->tunPoller->poller, true)) {
    return clientMarkRunStop(client, true);
  }
  if (carryNbytes > 0) {
    if (carryBuf == NULL || carryNbytes > ProtocolFrameSize) {
      return clientMarkRunStop(client, true);
    }
    memcpy(client->session->tcpReadCarryBuf, carryBuf, (size_t)carryNbytes);
    client->session->tcpReadCarryNbytes = carryNbytes;
    action = clientStepSession(client, ioEventTcpRead);
    if (action != ioPollerContinue) {
      return action;
    }
  }
  return ioPollerContinue;
}

static ioPollerAction_t clientHandlePreAuthTcpReadable(client_t *client) {
  char readBuf[ProtocolFrameSize];

  if (client == NULL || client->tcpPoller == NULL) {
    return ioPollerStop;
  }

  while (1) {
    ioStatus_t readStatus;
    long nbytes = 0;
    long offset = 0;

    readStatus = ioTcpRead(client->tcpPoller->poller.fd, readBuf, sizeof(readBuf), &nbytes);
    if (readStatus == ioStatusWouldBlock) {
      return ioPollerContinue;
    }
    if (readStatus != ioStatusOk) {
      return clientMarkRunStop(client, true);
    }

    while (offset < nbytes) {
      long consumed = 0;
      protocolRawMsg_t rawMsg;
      protocolStatus_t status = protocolDecodeRaw(
          &client->rawDecoder,
          readBuf + offset,
          nbytes - offset,
          &consumed,
          &rawMsg);
      if (status == protocolStatusBadFrame || consumed <= 0) {
        return clientMarkRunStop(client, true);
      }
      offset += consumed;
      if (status == protocolStatusNeedMore) {
        break;
      }
      if (rawMsg.nbytes != ProtocolNonceSize) {
        return clientMarkRunStop(client, true);
      }

      {
        unsigned char helloPayload[ProtocolNonceSize * 2];
        protocolMessage_t helloMsg;
        memcpy(helloPayload, rawMsg.buf, ProtocolNonceSize);
        randombytes_buf(helloPayload + ProtocolNonceSize, ProtocolNonceSize);
        helloMsg.type = protocolMsgClientHello;
        helloMsg.nbytes = sizeof(helloPayload);
        helloMsg.buf = (const char *)helloPayload;
        client->preAuthState = clientPreAuthSendHello;
        if (!clientQueueSecureMsg(client, &helloMsg)) {
          return clientMarkRunStop(client, true);
        }
      }

      return clientCompletePreAuth(client, readBuf + offset, nbytes - offset);
    }
  }
}

static ioPollerAction_t clientOnTcpReadable(void *ctx, ioReactor_t *reactor, ioPoller_t *poller) {
  client_t *client = (client_t *)ctx;
  (void)reactor;
  (void)poller;

  if (client == NULL) {
    return ioPollerStop;
  }
  if (client->preAuthState == clientPreAuthAwaitChallenge) {
    return clientHandlePreAuthTcpReadable(client);
  }
  if (client->preAuthState != clientPreAuthReady) {
    return clientMarkRunStop(client, true);
  }
  return clientStepSession(client, ioEventTcpRead);
}

static ioPollerAction_t clientOnTunReadable(void *ctx, ioReactor_t *reactor, ioPoller_t *poller) {
  client_t *client = (client_t *)ctx;
  (void)reactor;
  (void)poller;

  if (client == NULL) {
    return ioPollerStop;
  }
  if (client->preAuthState != clientPreAuthReady) {
    return ioPollerContinue;
  }
  return clientStepSession(client, ioEventTunRead);
}

static ioPollerAction_t clientOnTcpLowWatermark(void *ctx, ioPoller_t *poller, long queuedBytes) {
  client_t *client = (client_t *)ctx;
  (void)poller;
  (void)queuedBytes;

  if (client == NULL || client->preAuthState != clientPreAuthReady) {
    return ioPollerContinue;
  }
  if (!clientServiceBackpressure(client, client->session, ioEventTcpWrite, client->key)) {
    return clientMarkRunStop(client, true);
  }
  return ioPollerContinue;
}

static ioPollerAction_t clientOnTunLowWatermark(void *ctx, ioPoller_t *poller, long queuedBytes) {
  client_t *client = (client_t *)ctx;
  (void)poller;
  (void)queuedBytes;

  if (client == NULL || client->preAuthState != clientPreAuthReady) {
    return ioPollerContinue;
  }
  if (!clientServiceBackpressure(client, client->session, ioEventTunWrite, client->key)) {
    return clientMarkRunStop(client, true);
  }
  return ioPollerContinue;
}

int clientServeConn(
    int tunFd,
    int connFd,
    const unsigned char *claim,
    long claimNbytes,
    const unsigned char key[ProtocolPskSize],
    const sessionHeartbeatConfig_t *heartbeatCfg) {
  ioTunPoller_t tunPoller;
  ioTcpPoller_t tcpPoller;
  client_t client;
  session_t *session = NULL;
  int result = -1;
  ioPollerCallbacks_t tcpCallbacks = {
      .onClosed = NULL,
      .onLowWatermark = clientOnTcpLowWatermark,
      .onReadable = clientOnTcpReadable,
  };
  ioPollerCallbacks_t tunCallbacks = {
      .onClosed = NULL,
      .onLowWatermark = clientOnTunLowWatermark,
      .onReadable = clientOnTunReadable,
  };

  if (tunFd < 0 || connFd < 0 || claim == NULL || claimNbytes <= 0 || key == NULL || heartbeatCfg == NULL) {
    return -1;
  }

  memset(&client, 0, sizeof(client));
  clientResetHeartbeatState(&client, heartbeatCfg->intervalMs, heartbeatCfg->timeoutMs, 0);

  session = sessionCreate(false, heartbeatCfg, NULL, NULL);
  if (session == NULL) {
    errf("session setup failed");
    goto cleanup;
  }
  sessionAttachClient(session, &client);
  client.claim = claim;
  client.claimNbytes = claimNbytes;
  client.key = key;
  client.session = session;

  if (!ioReactorInit(&client.reactor)) {
    errf("setup reactor failed: %s", strerror(errno));
    goto cleanup;
  }
  if (ioTunPollerInit(&tunPoller, client.reactor.epollFd, tunFd) != 0
      || ioTcpPollerInit(&tcpPoller, client.reactor.epollFd, connFd) != 0) {
    errf("setup pollers failed: %s", strerror(errno));
    goto cleanup;
  }
  client.tunPoller = &tunPoller;
  client.tcpPoller = &tcpPoller;

  tcpPoller.poller.callbacks = &tcpCallbacks;
  tcpPoller.poller.ctx = &client;
  tunPoller.poller.callbacks = &tunCallbacks;
  tunPoller.poller.ctx = &client;
  if (!ioReactorSetPollerReadEnabled(&tcpPoller.poller, true)
      || !ioReactorSetPollerReadEnabled(&tunPoller.poller, false)) {
    errf("reactor registration failed: %s", strerror(errno));
    goto cleanup;
  }

  if (!clientQueueRawMsg(&client, claim, claimNbytes)) {
    errf("pre-auth handshake failed");
    goto cleanup;
  }
  client.preAuthState = clientPreAuthAwaitChallenge;

  while (1) {
    ioReactorStepResult_t step = ioReactorStep(&client.reactor, EPOLL_WAIT_MS);
    if (step == ioReactorStepError) {
      client.runFailed = true;
      break;
    }
    if (step == ioReactorStepStop) {
      break;
    }
    if (step == ioReactorStepTimeout && client.preAuthState == clientPreAuthReady) {
      if (clientStepSession(&client, ioEventTimeout) != ioPollerContinue) {
        break;
      }
    }
    if (client.runStop) {
      break;
    }
  }

  result = client.runFailed ? -1 : 0;
  logf("connection stopped");

cleanup:
  if (session != NULL) {
    sessionDestroy(session);
  }
  ioReactorDeinit(&client.reactor);

  return result;
}
