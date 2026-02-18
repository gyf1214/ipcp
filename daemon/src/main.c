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
  long long lastValidInboundMs;
  long long lastDataSentMs;
  long long lastDataRecvMs;
  bool heartbeatPending;
  long long heartbeatSentMs;
  long long lastHeartbeatReqMs;
} sessionState_t;

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

static bool sendMessage(
    ioPoller_t *poller, const unsigned char key[ProtocolPskSize], const protocolMessage_t *msg) {
  protocolFrame_t frame;
  char wireBuf[ProtocolWireLengthSize + ProtocolFrameSize];
  long wireNbytes;
  if (protocolSecureEncodeMessage(msg, key, &frame) != protocolStatusOk) {
    return false;
  }

  uint32_t wireLength = htonl((uint32_t)frame.nbytes);
  memcpy(wireBuf, &wireLength, ProtocolWireLengthSize);
  memcpy(wireBuf + ProtocolWireLengthSize, frame.buf, (size_t)frame.nbytes);
  wireNbytes = ProtocolWireLengthSize + frame.nbytes;
  return ioPollerQueueWrite(poller, ioSourceTcp, wireBuf, wireNbytes);
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
  if (!sendMessage(poller, key, &msg)) {
    return false;
  }

  if (!state->isServer) {
    state->lastDataSentMs = nowMs();
  }

  dbgf("sent %ld bytes of data", nbytes);
  return true;
}

static bool handleInboundMessage(
    ioPoller_t *poller,
    const unsigned char key[ProtocolPskSize],
    sessionState_t *state,
    const protocolMessage_t *msg) {
  long long now = nowMs();
  state->lastValidInboundMs = now;

  if (msg->type == protocolMsgData) {
    if (!ioPollerQueueWrite(poller, ioSourceTun, msg->buf, msg->nbytes)) {
      return false;
    }
    if (!state->isServer) {
      state->lastDataRecvMs = now;
    }
    dbgf("received %ld bytes of data", msg->nbytes);
    return true;
  }

  if (msg->type == protocolMsgHeartbeatReq) {
    if (!state->isServer) {
      logf("unexpected heartbeat request on client");
      return false;
    }

    protocolMessage_t ack = {
        .type = protocolMsgHeartbeatAck,
        .nbytes = 0,
        .buf = NULL,
    };
    if (!sendMessage(poller, key, &ack)) {
      return false;
    }
    dbgf("heartbeat request received, sent ack");
    return true;
  }

  if (msg->type == protocolMsgHeartbeatAck) {
    if (state->isServer || !state->heartbeatPending) {
      logf("unexpected heartbeat ack");
      return false;
    }

    state->heartbeatPending = false;
    dbgf("heartbeat ack received");
    return true;
  }

  return false;
}

static bool pipeTcp(
    ioPoller_t *poller,
    const unsigned char key[ProtocolPskSize],
    sessionState_t *state) {
  long nbytes = 0;
  int offset = 0;
  int k;

  ioStatus_t readStatus = ioReadSome(poller->tcpFd, state->tcpBuf, sizeof(state->tcpBuf), &nbytes);
  if (readStatus == ioStatusWouldBlock) {
    return true;
  }
  if (readStatus != ioStatusOk) {
    return false;
  }
  k = (int)nbytes;

  while (offset < k) {
    long consumed = 0;
    protocolStatus_t status =
        protocolDecodeFeed(&state->tcpDecoder, state->tcpBuf + offset, k - offset, &consumed);
    if (status == protocolStatusBadFrame) {
      logf("bad frame");
      return false;
    }
    if (consumed <= 0) {
      break;
    }
    offset += (int)consumed;

    if (!protocolDecoderHasFrame(&state->tcpDecoder)) {
      continue;
    }

    protocolFrame_t frame;
    status = protocolDecoderTake(&state->tcpDecoder, &frame);
    if (status != protocolStatusOk) {
      return false;
    }
    protocolMessage_t msg;
    if (protocolSecureDecodeFrame(&frame, key, &msg) != protocolStatusOk) {
      logf("failed to decrypt/decode message");
      return false;
    }

    if (!handleInboundMessage(poller, key, state, &msg)) {
      return false;
    }
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
      if (!sendMessage(poller, key, &req)) {
        return false;
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
