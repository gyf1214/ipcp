#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if.h>
#include <linux/if_tun.h>

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

int tunOpen(const char *ifName) {
  struct ifreq ifr;
  int fd, err;
  logf("opening tun device %s", ifName);

  if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
    perrf("failed to open /dev/net/tun");
  }
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN;
  strncpy(ifr.ifr_name, ifName, IFNAMSIZ - 1);

  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) == -1) {
    perrf("ioctl failed on tun device");
  }

  logf("successfully opened tun device %s", ifName);
  return fd;
}

static bool sendMessage(int connFd, const cryptCtx_t *crypt, const protocolMessage_t *msg) {
  protocolFrame_t frame;
  if (protocolMessageEncodeFrame(msg, &frame) != protocolStatusOk) {
    return false;
  }
  if (protocolFrameEncrypt(&frame, crypt->key) != protocolStatusOk) {
    return false;
  }

  uint32_t wireLength = htonl((uint32_t)frame.nbytes);
  return ioWriteAll(connFd, &wireLength, ProtocolWireLengthSize)
      && ioWriteAll(connFd, frame.buf, frame.nbytes);
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

static bool pipeTun(int tunFd, int connFd, const cryptCtx_t *crypt, sessionState_t *state) {
  char payload[ProtocolFrameSize];
  long maxPayload = protocolMaxPlaintextSize() - messageHeaderSize();
  long nbytes = 0;

  if (maxPayload <= 0) {
    return false;
  }

  if (ioReadSome(tunFd, payload, maxPayload, &nbytes) != ioStatusOk) {
    return false;
  }

  protocolMessage_t msg = {
      .type = protocolMsgData,
      .nbytes = nbytes,
      .buf = payload,
  };
  if (!sendMessage(connFd, crypt, &msg)) {
    return false;
  }

  if (!state->isServer) {
    state->lastDataSentMs = nowMs();
  }

  dbgf("sent %ld bytes of data", nbytes);
  return true;
}

static bool handleInboundMessage(
    int tunFd,
    int connFd,
    const cryptCtx_t *crypt,
    sessionState_t *state,
    const protocolMessage_t *msg) {
  long long now = nowMs();
  state->lastValidInboundMs = now;

  if (msg->type == protocolMsgData) {
    if (!ioWriteAll(tunFd, msg->buf, msg->nbytes)) {
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
    if (!sendMessage(connFd, crypt, &ack)) {
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

static bool pipeTcp(int tunFd, int connFd, const cryptCtx_t *crypt, sessionState_t *state) {
  long nbytes = 0;
  int offset = 0;
  int k;

  if (ioReadSome(connFd, state->tcpBuf, sizeof(state->tcpBuf), &nbytes) != ioStatusOk) {
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
    if (protocolFrameDecrypt(&frame, crypt->key) != protocolStatusOk) {
      logf("failed to decrypt/authenticate frame");
      return false;
    }

    protocolMessage_t msg;
    if (protocolMessageDecodeFrame(&frame, &msg) != protocolStatusOk) {
      logf("failed to decode message");
      return false;
    }

    if (!handleInboundMessage(tunFd, connFd, crypt, state, &msg)) {
      return false;
    }
  }

  return true;
}

static bool heartbeatTick(int connFd, const cryptCtx_t *crypt, sessionState_t *state) {
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
      if (!sendMessage(connFd, crypt, &req)) {
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

void serveTcp(const char *ifName, int connFd, const cryptCtx_t *crypt, bool isServer) {
  int tunFd = tunOpen(ifName);
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
    } else if (event == ioEventTun || event == ioEventTcp) {
      bool result;
      if (event == ioEventTun) {
        result = pipeTun(tunFd, connFd, crypt, &state);
      } else {
        result = pipeTcp(tunFd, connFd, crypt, &state);
      }
      if (!result) {
        logf("connection closed");
        stop = true;
      }
    }

    if (!stop && !heartbeatTick(connFd, crypt, &state)) {
      logf("heartbeat failure");
      stop = true;
    }
  }

  ioPollerClose(&poller);
  close(connFd);
  close(tunFd);
  logf("connection stopped");
}

void listenTcp(const char *ifName, const char *listenIP, int port, const cryptCtx_t *crypt) {
  int listenFd = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in serverAddr;
  serverAddr.sin_family = AF_INET;
  inet_pton(AF_INET, listenIP, &serverAddr.sin_addr);
  serverAddr.sin_port = htons(port);

  if (bind(listenFd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
    perrf("bind failed");
  }
  listen(listenFd, 1);
  logf("listening on %s:%d", listenIP, port);

  while (1) {
    struct sockaddr_in clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    int connFd = accept(listenFd, (struct sockaddr *)&clientAddr, &addrLen);

    char clientIP[256];
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, sizeof(clientIP));
    int clientPort = ntohs(clientAddr.sin_port);
    logf("connected with %s:%d", clientIP, clientPort);

    serveTcp(ifName, connFd, crypt, true);
  }

  close(listenFd);
  logf("server stopped");
}

void connTcp(const char *ifName, const char *remoteIP, int port, const cryptCtx_t *crypt) {
  int connFd = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in remoteAddr;
  remoteAddr.sin_family = AF_INET;
  inet_pton(AF_INET, remoteIP, &remoteAddr.sin_addr);
  remoteAddr.sin_port = htons(port);

  if (connect(connFd, (struct sockaddr *)&remoteAddr, sizeof(remoteAddr)) < 0) {
    close(connFd);
    perrf("connect to %s:%d failed", remoteIP, port);
  }
  logf("connected to %s:%d", remoteIP, port);

  serveTcp(ifName, connFd, crypt, false);
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

  cryptCtx_t crypt;
  cryptGlobalInit();
  if (cryptInitFromFile(&crypt, secretFile) != 0) {
    panicf("invalid secret file, expected exactly %d raw bytes", ProtocolPskSize);
  }

  if (server) {
    listenTcp(ifName, ip, port, &crypt);
  } else {
    connTcp(ifName, ip, port, &crypt);
  }

  return 0;
}
