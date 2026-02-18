#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <unistd.h>
#include <arpa/inet.h>

#include "log.h"
#include "protocol.h"
#include "crypt.h"
#include "io.h"

#define EPOLL_WAIT_MS          200
#define HEARTBEAT_INTERVAL_MS  5000
#define HEARTBEAT_MISS_LIMIT   3

typedef struct {
  bool isServer;
  protocolDecoder_t tcpDecoder;
  char tcpBuf[ProtocolFrameSize];
  char tcpBufferedBuf[ProtocolFrameSize];
  long tcpBufferedNbytes;
  long long lastValidInboundMs;
  long long lastDataSentMs;
  long long lastDataRecvMs;
  bool heartbeatPending;
  long long heartbeatSentMs;
  long long lastHeartbeatReqMs;
  bool tunReadPaused;
  bool tcpReadPaused;
  long pendingTcpNbytes;
  char pendingTcpBuf[ProtocolWireLengthSize + ProtocolFrameSize];
  long pendingTunNbytes;
  char pendingTunBuf[ProtocolFrameSize];
} sessionState_t;

typedef enum {
  queueResultQueued = 0,
  queueResultBlocked,
  queueResultError,
} queueResult_t;

static long long nowMs() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long long)ts.tv_sec * 1000 + (long long)ts.tv_nsec / 1000000;
}

static long long heartbeatTimeoutMs() {
  return (long long)HEARTBEAT_INTERVAL_MS * HEARTBEAT_MISS_LIMIT;
}

static long messageHeaderSize() {
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

static queueResult_t queueTcpWithBackpressure(ioPoller_t *poller, sessionState_t *state, const void *data, long nbytes) {
  long queued;

  if (state->pendingTcpNbytes > 0) {
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
    memcpy(state->pendingTcpBuf, data, (size_t)nbytes);
    state->pendingTcpNbytes = nbytes;
    if (!pauseReadSource(poller, ioSourceTun, &state->tunReadPaused)) {
      return queueResultError;
    }
    return queueResultBlocked;
  }
  return queueResultError;
}

static queueResult_t queueTunWithBackpressure(ioPoller_t *poller, sessionState_t *state, const void *data, long nbytes) {
  long queued;

  if (state->pendingTunNbytes > 0) {
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
    memcpy(state->pendingTunBuf, data, (size_t)nbytes);
    state->pendingTunNbytes = nbytes;
    if (!pauseReadSource(poller, ioSourceTcp, &state->tcpReadPaused)) {
      return queueResultError;
    }
    return queueResultBlocked;
  }
  return queueResultError;
}

static bool serviceBackpressure(ioPoller_t *poller, sessionState_t *state) {
  long queued;

  if (state->pendingTcpNbytes > 0) {
    if (ioPollerQueueWrite(poller, ioSourceTcp, state->pendingTcpBuf, state->pendingTcpNbytes)) {
      state->pendingTcpNbytes = 0;
    } else {
      queued = ioPollerQueuedBytes(poller, ioSourceTcp);
      if (queued < 0 || queued + state->pendingTcpNbytes <= IoPollerQueueCapacity) {
        return false;
      }
    }
  }

  if (state->pendingTunNbytes > 0) {
    if (ioPollerQueueWrite(poller, ioSourceTun, state->pendingTunBuf, state->pendingTunNbytes)) {
      state->pendingTunNbytes = 0;
    } else {
      queued = ioPollerQueuedBytes(poller, ioSourceTun);
      if (queued < 0 || queued + state->pendingTunNbytes <= IoPollerQueueCapacity) {
        return false;
      }
    }
  }

  return maybeResumeReadSource(
             poller, ioSourceTun, ioSourceTcp, &state->tunReadPaused, state->pendingTcpNbytes)
      && maybeResumeReadSource(
             poller, ioSourceTcp, ioSourceTun, &state->tcpReadPaused, state->pendingTunNbytes);
}

static queueResult_t sendMessage(
    ioPoller_t *poller, const unsigned char key[ProtocolPskSize], sessionState_t *state, const protocolMessage_t *msg) {
  protocolFrame_t frame;
  char wireBuf[ProtocolWireLengthSize + ProtocolFrameSize];
  long wireNbytes;

  if (protocolSecureEncodeMessage(msg, key, &frame) != protocolStatusOk) {
    return queueResultError;
  }

  uint32_t wireLength = htonl((uint32_t)frame.nbytes);
  memcpy(wireBuf, &wireLength, ProtocolWireLengthSize);
  memcpy(wireBuf + ProtocolWireLengthSize, frame.buf, (size_t)frame.nbytes);
  wireNbytes = ProtocolWireLengthSize + frame.nbytes;
  return queueTcpWithBackpressure(poller, state, wireBuf, wireNbytes);
}

static void sessionStateInit(sessionState_t *state, bool isServer) {
  long long now = nowMs();
  memset(state, 0, sizeof(*state));
  state->isServer = isServer;
  protocolDecoderInit(&state->tcpDecoder);
  state->lastValidInboundMs = now;
  state->lastDataSentMs = now;
  state->lastDataRecvMs = now;
  state->lastHeartbeatReqMs = now;
}

static bool pipeTun(
    int tunFd,
    ioPoller_t *poller,
    const unsigned char key[ProtocolPskSize],
    sessionState_t *state) {
  char payload[ProtocolFrameSize];
  long maxPayload = protocolMaxPlaintextSize() - messageHeaderSize();
  long nbytes = 0;

  if (maxPayload <= 0) {
    return false;
  }

  ioStatus_t status = ioReadSome(tunFd, payload, maxPayload, &nbytes);
  if (status == ioStatusWouldBlock) {
    return true;
  }
  if (status != ioStatusOk) {
    return false;
  }

  protocolMessage_t msg = {
      .type = protocolMsgData,
      .nbytes = nbytes,
      .buf = payload,
  };
  queueResult_t result = sendMessage(poller, key, state, &msg);
  if (result == queueResultError) {
    return false;
  }
  if (result == queueResultBlocked) {
    return true;
  }

  if (!state->isServer) {
    state->lastDataSentMs = nowMs();
  }

  dbgf("sent %ld bytes of data", nbytes);
  return true;
}

static queueResult_t handleInboundMessage(
    ioPoller_t *poller,
    const unsigned char key[ProtocolPskSize],
    sessionState_t *state,
    const protocolMessage_t *msg) {
  long long now = nowMs();
  state->lastValidInboundMs = now;

  if (msg->type == protocolMsgData) {
    queueResult_t result = queueTunWithBackpressure(poller, state, msg->buf, msg->nbytes);
    if (result != queueResultQueued) {
      return result;
    }
    if (!state->isServer) {
      state->lastDataRecvMs = now;
    }
    dbgf("received %ld bytes of data", msg->nbytes);
    return queueResultQueued;
  }

  if (msg->type == protocolMsgHeartbeatReq) {
    if (!state->isServer) {
      logf("unexpected heartbeat request on client");
      return queueResultError;
    }

    protocolMessage_t ack = {
        .type = protocolMsgHeartbeatAck,
        .nbytes = 0,
        .buf = NULL,
    };
    queueResult_t result = sendMessage(poller, key, state, &ack);
    if (result != queueResultQueued) {
      return result;
    }
    dbgf("heartbeat request received, sent ack");
    return queueResultQueued;
  }

  if (msg->type == protocolMsgHeartbeatAck) {
    if (state->isServer || !state->heartbeatPending) {
      logf("unexpected heartbeat ack");
      return queueResultError;
    }

    state->heartbeatPending = false;
    dbgf("heartbeat ack received");
    return queueResultQueued;
  }

  return queueResultError;
}

static bool pipeTcpBytes(
    ioPoller_t *poller,
    const unsigned char key[ProtocolPskSize],
    sessionState_t *state,
    const char *buf,
    int k,
    int *outConsumed) {
  int offset = 0;
  while (offset < k) {
    long consumed = 0;
    protocolMessage_t msg;
    protocolStatus_t status = protocolSecureDecoderReadMessage(
        &state->tcpDecoder, key, buf + offset, k - offset, &consumed, &msg);
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

    queueResult_t result = handleInboundMessage(poller, key, state, &msg);
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
    sessionState_t *state) {
  long nbytes = 0;
  int consumed = 0;
  int k;

  if (state->tcpBufferedNbytes > 0) {
    if (!pipeTcpBytes(poller, key, state, state->tcpBufferedBuf, (int)state->tcpBufferedNbytes, &consumed)) {
      return false;
    }
    if (consumed < state->tcpBufferedNbytes) {
      long rem = state->tcpBufferedNbytes - consumed;
      memmove(state->tcpBufferedBuf, state->tcpBufferedBuf + consumed, (size_t)rem);
      state->tcpBufferedNbytes = rem;
      return true;
    }
    state->tcpBufferedNbytes = 0;
  }

  ioStatus_t readStatus = ioReadSome(poller->tcpFd, state->tcpBuf, sizeof(state->tcpBuf), &nbytes);
  if (readStatus == ioStatusWouldBlock) {
    return true;
  }
  if (readStatus != ioStatusOk) {
    return false;
  }
  k = (int)nbytes;
  if (!pipeTcpBytes(poller, key, state, state->tcpBuf, k, &consumed)) {
    return false;
  }
  if (consumed < k) {
    long rem = (long)(k - consumed);
    memcpy(state->tcpBufferedBuf, state->tcpBuf + consumed, (size_t)rem);
    state->tcpBufferedNbytes = rem;
  }

  return true;
}

static bool heartbeatTick(
    ioPoller_t *poller, const unsigned char key[ProtocolPskSize], sessionState_t *state) {
  long long now = nowMs();
  long long timeoutMs = heartbeatTimeoutMs();

  if (state->isServer) {
    if (now - state->lastValidInboundMs >= timeoutMs) {
      logf("server heartbeat timeout");
      return false;
    }
    return true;
  }

  if (!state->heartbeatPending) {
    bool idleSend = now - state->lastDataSentMs >= HEARTBEAT_INTERVAL_MS;
    bool idleRecv = now - state->lastDataRecvMs >= HEARTBEAT_INTERVAL_MS;
    bool intervalElapsed = now - state->lastHeartbeatReqMs >= HEARTBEAT_INTERVAL_MS;
    if (idleSend && idleRecv && intervalElapsed) {
      protocolMessage_t req = {
          .type = protocolMsgHeartbeatReq,
          .nbytes = 0,
          .buf = NULL,
      };
      queueResult_t result = sendMessage(poller, key, state, &req);
      if (result == queueResultError) {
        return false;
      }
      if (result == queueResultBlocked) {
        return true;
      }

      state->heartbeatPending = true;
      state->heartbeatSentMs = now;
      state->lastHeartbeatReqMs = now;
      dbgf("sent heartbeat request");
    }
  }

  if (state->heartbeatPending && now - state->heartbeatSentMs >= timeoutMs) {
    logf("client heartbeat timeout waiting for ack");
    return false;
  }

  return true;
}

void serveTcp(
    const char *ifName,
    int connFd,
    const unsigned char key[ProtocolPskSize],
    bool isServer) {
  logf("opening tun device %s", ifName);
  int tunFd = ioTunOpen(ifName);
  if (tunFd < 0) {
    perrf("failed to open tun device %s", ifName);
  }
  logf("successfully opened tun device %s", ifName);
  ioPoller_t poller;

  if (ioPollerInit(&poller, tunFd, connFd) != 0) {
    perrf("setup epoll failed");
  }

  sessionState_t state;
  sessionStateInit(&state, isServer);

  bool stop = false;
  while (!stop) {
    ioEvent_t event = ioPollerWait(&poller, EPOLL_WAIT_MS);
    if (event == ioEventError) {
      logf("connection error or closed");
      stop = true;
    } else if (
        event == ioEventTunRead || event == ioEventTcpRead
        || event == ioEventTunWrite || event == ioEventTcpWrite) {
      bool result;
      if (event == ioEventTunRead) {
        result = pipeTun(tunFd, &poller, key, &state);
      } else if (event == ioEventTcpRead) {
        result = pipeTcp(&poller, key, &state);
      } else {
        result = true;
      }
      if (!result) {
        logf("connection closed");
        stop = true;
      }
    }

    if (!stop && !serviceBackpressure(&poller, &state)) {
      logf("backpressure handling failure");
      stop = true;
    }

    if (!stop && !heartbeatTick(&poller, key, &state)) {
      logf("heartbeat failure");
      stop = true;
    }
  }

  ioPollerClose(&poller);
  close(connFd);
  close(tunFd);
  logf("connection stopped");
}

void listenTcp(
    const char *ifName,
    const char *listenIP,
    int port,
    const unsigned char key[ProtocolPskSize]) {
  int listenFd = ioTcpListen(listenIP, port);
  if (listenFd < 0) {
    perrf("listen setup failed");
  }
  logf("listening on %s:%d", listenIP, port);

  while (1) {
    char clientIP[256];
    int clientPort = 0;
    int connFd = ioTcpAccept(listenFd, clientIP, sizeof(clientIP), &clientPort);
    if (connFd < 0) {
      perrf("accept failed");
    }
    logf("connected with %s:%d", clientIP, clientPort);

    serveTcp(ifName, connFd, key, true);
  }

  close(listenFd);
  logf("server stopped");
}

void connTcp(
    const char *ifName,
    const char *remoteIP,
    int port,
    const unsigned char key[ProtocolPskSize]) {
  int connFd = ioTcpConnect(remoteIP, port);
  if (connFd < 0) {
    perrf("connect to %s:%d failed", remoteIP, port);
  }
  logf("connected to %s:%d", remoteIP, port);

  serveTcp(ifName, connFd, key, false);
}

int main(int argc, char **argv) {
  if (argc != 6) {
    panicf("invalid arguments: <ifName> <ip> <port> <serverFlag> <secretFile>");
  }
  const char *ifName = argv[1];
  const char *ip = argv[2];
  int port = atoi(argv[3]);
  int server = atoi(argv[4]);
  const char *secretFile = argv[5];

  unsigned char key[ProtocolPskSize];
  cryptGlobalInit();
  if (cryptLoadKeyFromFile(key, secretFile) != 0) {
    panicf("invalid secret file, expected exactly %d raw bytes", ProtocolPskSize);
  }

  if (server) {
    listenTcp(ifName, ip, port, key);
  } else {
    connTcp(ifName, ip, port, key);
  }

  return 0;
}
