#include "sessionInternal.h"

#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sodium.h>

#include "log.h"
#include "client.h"

#define EPOLL_WAIT_MS 200

void clientResetHeartbeatState(
    client_t *runtime,
    int heartbeatIntervalMs,
    int heartbeatTimeoutMs,
    long long nowMs) {
  if (runtime == NULL || heartbeatIntervalMs <= 0 || heartbeatTimeoutMs <= heartbeatIntervalMs) {
    return;
  }
  runtime->heartbeatPending = false;
  runtime->heartbeatSentMs = 0;
  runtime->lastHeartbeatReqMs = nowMs;
  runtime->lastDataSentMs = nowMs;
  runtime->lastDataRecvMs = nowMs;
  runtime->tunReadPaused = false;
  runtime->tcpWritePendingNbytes = 0;
  memset(runtime->tcpWritePendingBuf, 0, sizeof(runtime->tcpWritePendingBuf));
  runtime->heartbeatIntervalMs = heartbeatIntervalMs;
  runtime->heartbeatTimeoutMs = heartbeatTimeoutMs;
}

sessionQueueResult_t clientQueueTcpWithBackpressure(
    client_t *runtime,
    const void *data,
    long nbytes) {
  long queued;
  ioTcpPoller_t *tcpPoller;
  ioTunPoller_t *tunPoller;

  if (runtime == NULL) {
    return sessionQueueResultError;
  }
  tcpPoller = runtime->tcpPoller;
  tunPoller = runtime->tunPoller;
  if (tcpPoller == NULL || tunPoller == NULL || data == NULL || nbytes <= 0) {
    return sessionQueueResultError;
  }
  if (runtime->tcpWritePendingNbytes > 0) {
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
    memcpy(runtime->tcpWritePendingBuf, data, (size_t)nbytes);
    runtime->tcpWritePendingNbytes = nbytes;
    if (!runtime->tunReadPaused) {
      if (!ioTunSetReadEnabled(tunPoller, false)) {
        return sessionQueueResultError;
      }
      runtime->tunReadPaused = true;
    }
    return sessionQueueResultBlocked;
  }
  return sessionQueueResultError;
}

sessionQueueResult_t clientQueueTunWithBackpressure(
    client_t *runtime,
    bool *tcpReadPaused,
    long *tunWritePendingNbytes,
    char tunWritePendingBuf[ProtocolFrameSize],
    const void *data,
    long nbytes) {
  long queued;
  ioTcpPoller_t *tcpPoller;
  ioTunPoller_t *tunPoller;

  if (runtime == NULL) {
    return sessionQueueResultError;
  }
  tcpPoller = runtime->tcpPoller;
  tunPoller = runtime->tunPoller;
  if (tcpPoller == NULL || tunPoller == NULL || tcpReadPaused == NULL || tunWritePendingNbytes == NULL
      || tunWritePendingBuf == NULL || data == NULL || nbytes <= 0) {
    return sessionQueueResultError;
  }
  if (*tunWritePendingNbytes > 0) {
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
    memcpy(tunWritePendingBuf, data, (size_t)nbytes);
    *tunWritePendingNbytes = nbytes;
    if (!*tcpReadPaused) {
      if (!ioTcpSetReadEnabled(tcpPoller, false)) {
        return sessionQueueResultError;
      }
      *tcpReadPaused = true;
    }
    return sessionQueueResultBlocked;
  }
  return sessionQueueResultError;
}

sessionQueueResult_t clientSendMessage(
    client_t *runtime,
    const unsigned char key[ProtocolPskSize],
    long long nowMs,
    const protocolMessage_t *msg) {
  protocolFrame_t frame;
  sessionQueueResult_t result;

  if (runtime == NULL || key == NULL || msg == NULL) {
    return sessionQueueResultError;
  }
  if (protocolEncodeSecureMsg(msg, key, &frame) != protocolStatusOk) {
    return sessionQueueResultError;
  }
  result = clientQueueTcpWithBackpressure(runtime, frame.buf, frame.nbytes);
  if (result == sessionQueueResultQueued && msg->type == protocolMsgData) {
    runtime->lastDataSentMs = nowMs;
  }
  return result;
}

sessionQueueResult_t clientHandleInboundMessage(
    client_t *runtime,
    bool *tcpReadPaused,
    long *tunWritePendingNbytes,
    char tunWritePendingBuf[ProtocolFrameSize],
    long long nowMs,
    long long *lastValidInboundMs,
    const protocolMessage_t *msg) {
  if (runtime == NULL || lastValidInboundMs == NULL || msg == NULL) {
    return sessionQueueResultError;
  }
  *lastValidInboundMs = nowMs;

  if (msg->type == protocolMsgData) {
    sessionQueueResult_t result = clientQueueTunWithBackpressure(
        runtime, tcpReadPaused, tunWritePendingNbytes, tunWritePendingBuf, msg->buf, msg->nbytes);
    if (result != sessionQueueResultQueued) {
      return result;
    }
    runtime->lastDataRecvMs = nowMs;
    dbgf("received %ld bytes of data", msg->nbytes);
    return sessionQueueResultQueued;
  }
  if (msg->type == protocolMsgHeartbeatReq) {
    logf("unexpected heartbeat request on client");
    return sessionQueueResultError;
  }
  if (msg->type == protocolMsgHeartbeatAck) {
    if (!runtime->heartbeatPending) {
      logf("unexpected heartbeat ack");
      return sessionQueueResultError;
    }
    runtime->heartbeatPending = false;
    dbgf("heartbeat ack received");
    return sessionQueueResultQueued;
  }
  return sessionQueueResultError;
}

bool clientHeartbeatTick(
    client_t *runtime,
    long long nowMs,
    const unsigned char key[ProtocolPskSize]) {
  if (runtime == NULL || key == NULL || runtime->heartbeatIntervalMs <= 0
      || runtime->heartbeatTimeoutMs <= runtime->heartbeatIntervalMs) {
    return false;
  }

  if (!runtime->heartbeatPending) {
    bool idleSend = nowMs - runtime->lastDataSentMs >= runtime->heartbeatIntervalMs;
    bool idleRecv = nowMs - runtime->lastDataRecvMs >= runtime->heartbeatIntervalMs;
    bool intervalElapsed = nowMs - runtime->lastHeartbeatReqMs >= runtime->heartbeatIntervalMs;
    if (idleSend && idleRecv && intervalElapsed) {
      protocolMessage_t req = {.type = protocolMsgHeartbeatReq, .nbytes = 0, .buf = NULL};
      sessionQueueResult_t result = clientSendMessage(
          runtime,
          key,
          nowMs,
          &req);
      if (result == sessionQueueResultError) {
        return false;
      }
      if (result == sessionQueueResultBlocked) {
        return true;
      }
      runtime->heartbeatPending = true;
      runtime->heartbeatSentMs = nowMs;
      runtime->lastHeartbeatReqMs = nowMs;
      dbgf("sent heartbeat request");
    }
  }

  if (runtime->heartbeatPending && nowMs - runtime->heartbeatSentMs >= runtime->heartbeatTimeoutMs) {
    logf("client heartbeat timeout waiting for ack");
    return false;
  }

  return true;
}

bool clientServiceBackpressure(
    client_t *runtime,
    bool *tcpReadPaused,
    long *tunWritePendingNbytes,
    char tunWritePendingBuf[ProtocolFrameSize]) {
  long queued;
  ioTcpPoller_t *tcpPoller;
  ioTunPoller_t *tunPoller;

  if (runtime == NULL) {
    return false;
  }
  tcpPoller = runtime->tcpPoller;
  tunPoller = runtime->tunPoller;
  if (tcpPoller == NULL || tunPoller == NULL || tcpReadPaused == NULL
      || tunWritePendingNbytes == NULL || tunWritePendingBuf == NULL) {
    return false;
  }

  if (runtime->tcpWritePendingNbytes > 0) {
    if (ioTcpWrite(tcpPoller, runtime->tcpWritePendingBuf, runtime->tcpWritePendingNbytes)) {
      runtime->tcpWritePendingNbytes = 0;
    } else {
      queued = ioTcpQueuedBytes(tcpPoller);
      if (queued < 0 || queued + runtime->tcpWritePendingNbytes <= IoPollerQueueCapacity) {
        return false;
      }
    }
  }

  if (*tunWritePendingNbytes > 0) {
    if (ioTunWrite(tunPoller, tunWritePendingBuf, *tunWritePendingNbytes)) {
      *tunWritePendingNbytes = 0;
    } else {
      queued = ioTunQueuedBytes(tunPoller);
      if (queued < 0 || queued + *tunWritePendingNbytes <= IoPollerQueueCapacity) {
        return false;
      }
    }
  }

  if (*tcpReadPaused && *tunWritePendingNbytes == 0) {
    queued = ioTunQueuedBytes(tunPoller);
    if (queued < 0) {
      return false;
    }
    if (queued <= IoPollerLowWatermark) {
      if (!ioTcpSetReadEnabled(tcpPoller, true)) {
        return false;
      }
      *tcpReadPaused = false;
    }
  }

  if (runtime->tunReadPaused && runtime->tcpWritePendingNbytes == 0) {
    queued = ioTcpQueuedBytes(tcpPoller);
    if (queued < 0) {
      return false;
    }
    if (queued <= IoPollerLowWatermark) {
      if (!ioTunSetReadEnabled(tunPoller, true)) {
        return false;
      }
      runtime->tunReadPaused = false;
    }
  }

  return true;
}

static int writeAll(int fd, const void *buf, long nbytes) {
  long offset = 0;
  while (offset < nbytes) {
    ssize_t n = write(fd, (const char *)buf + offset, (size_t)(nbytes - offset));
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (n == 0) {
      return -1;
    }
    offset += (long)n;
  }
  return 0;
}

int clientReadRawMsg(int fd, protocolRawMsg_t *msg) {
  char readBuf[ProtocolFrameSize];
  protocolDecoder_t decoder;
  long consumed = 0;

  if (fd < 0 || msg == NULL) {
    return -1;
  }

  protocolDecoderInit(&decoder);
  while (1) {
    ssize_t nread = read(fd, readBuf, sizeof(readBuf));
    if (nread < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (nread == 0) {
      return -1;
    }

    consumed = 0;
    protocolStatus_t status = protocolDecodeRaw(&decoder, readBuf, (long)nread, &consumed, msg);
    if (status == protocolStatusBadFrame) {
      return -1;
    }
    if (status == protocolStatusNeedMore) {
      if (consumed != (long)nread) {
        return -1;
      }
      continue;
    }
    if (consumed != (long)nread) {
      return -1;
    }
    return 0;
  }
}

int clientReadSecureMsg(int fd, const unsigned char key[ProtocolPskSize], protocolMessage_t *msg) {
  char readBuf[ProtocolFrameSize];
  protocolDecoder_t decoder;
  long consumed = 0;

  if (fd < 0 || key == NULL || msg == NULL) {
    return -1;
  }

  protocolDecoderInit(&decoder);
  while (1) {
    ssize_t nread = read(fd, readBuf, sizeof(readBuf));
    if (nread < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (nread == 0) {
      return -1;
    }

    consumed = 0;
    protocolStatus_t status = protocolDecodeSecureMsg(&decoder, key, readBuf, (long)nread, &consumed, msg);
    if (status == protocolStatusBadFrame) {
      return -1;
    }
    if (status == protocolStatusNeedMore) {
      if (consumed != (long)nread) {
        return -1;
      }
      continue;
    }
    if (consumed != (long)nread) {
      return -1;
    }
    return 0;
  }
}

static int clientRunPreAuthHandshake(
    int connFd, const unsigned char *claim, long claimNbytes, const unsigned char key[ProtocolPskSize]) {
  protocolRawMsg_t rawMsg;
  protocolMessage_t msg;
  unsigned char helloPayload[ProtocolNonceSize * 2];

  if (claim == NULL || claimNbytes <= 0 || key == NULL) {
    return -1;
  }
  rawMsg.nbytes = claimNbytes;
  rawMsg.buf = (const char *)claim;
  if (clientWriteRawMsg(connFd, &rawMsg) != 0) {
    return -1;
  }

  if (clientReadRawMsg(connFd, &rawMsg) != 0) {
    return -1;
  }
  if (rawMsg.nbytes != ProtocolNonceSize) {
    return -1;
  }

  memcpy(helloPayload, rawMsg.buf, ProtocolNonceSize);
  randombytes_buf(helloPayload + ProtocolNonceSize, ProtocolNonceSize);
  msg.type = protocolMsgClientHello;
  msg.nbytes = sizeof(helloPayload);
  msg.buf = (const char *)helloPayload;
  if (clientWriteSecureMsg(connFd, &msg, key) != 0) {
    return -1;
  }
  return 0;
}

int clientWriteRawMsg(int fd, const protocolRawMsg_t *msg) {
  protocolFrame_t frame;

  if (fd < 0 || msg == NULL || msg->buf == NULL || msg->nbytes <= 0) {
    return -1;
  }
  if (protocolEncodeRaw(msg, &frame) != protocolStatusOk) {
    return -1;
  }
  return writeAll(fd, frame.buf, frame.nbytes);
}

int clientWriteSecureMsg(
    int fd, const protocolMessage_t *msg, const unsigned char key[ProtocolPskSize]) {
  protocolFrame_t frame;

  if (fd < 0 || msg == NULL || msg->buf == NULL || msg->nbytes <= 0 || key == NULL) {
    return -1;
  }
  if (protocolEncodeSecureMsg(msg, key, &frame) != protocolStatusOk) {
    return -1;
  }
  return writeAll(fd, frame.buf, frame.nbytes);
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
  client_t runtime;
  ioEvent_t event;
  session_t *session = NULL;
  int epollFd = -1;
  int result = -1;

  if (tunFd < 0 || connFd < 0 || claim == NULL || claimNbytes <= 0 || key == NULL || heartbeatCfg == NULL) {
    return -1;
  }

  if (clientRunPreAuthHandshake(connFd, claim, claimNbytes, key) != 0) {
    errf("pre-auth handshake failed");
    return -1;
  }

  epollFd = epoll_create1(0);
  if (epollFd < 0) {
    errf("setup epoll failed: %s", strerror(errno));
    goto cleanup;
  }
  if (ioTunPollerInit(&tunPoller, epollFd, tunFd) != 0 || ioTcpPollerInit(&tcpPoller, epollFd, connFd) != 0) {
    errf("setup epoll failed: %s", strerror(errno));
    goto cleanup;
  }
  runtime.tunPoller = &tunPoller;
  runtime.tcpPoller = &tcpPoller;
  clientResetHeartbeatState(&runtime, heartbeatCfg->intervalMs, heartbeatCfg->timeoutMs, 0);

  session = sessionCreate(false, heartbeatCfg, NULL, NULL);
  if (session == NULL) {
    errf("session setup failed");
    goto cleanup;
  }
  sessionSetClient(session, &runtime);

  while (1) {
    event = ioPollersWait(&tunPoller, &tcpPoller, EPOLL_WAIT_MS);
    if (sessionStep(session, &tcpPoller, &tunPoller, event, key) == sessionStepStop) {
      break;
    }
  }

  result = 0;
  logf("connection stopped");

cleanup:
  if (session != NULL) {
    sessionDestroy(session);
  }
  if (epollFd >= 0) {
    close(epollFd);
  }

  return result;
}
