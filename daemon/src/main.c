#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "crypt.h"
#include "io.h"
#include "log.h"
#include "protocol.h"
#include "session.h"

#define EPOLL_WAIT_MS 200

static void serveTcp(
    const char *ifName,
    int connFd,
    const unsigned char key[ProtocolPskSize],
    bool isServer) {
  ioPoller_t poller;
  ioEvent_t event;

  logf("opening tun device %s", ifName);
  int tunFd = ioTunOpen(ifName);
  if (tunFd < 0) {
    perrf("failed to open tun device %s", ifName);
  }
  logf("successfully opened tun device %s", ifName);

  if (ioPollerInit(&poller, tunFd, connFd) != 0) {
    perrf("setup epoll failed");
  }

  session_t *session = sessionCreate(isServer, NULL, NULL);
  if (session == NULL) {
    panicf("session setup failed");
  }

  while (1) {
    event = ioPollerWait(&poller, EPOLL_WAIT_MS);
    if (sessionStep(session, &poller, event, key) == sessionStepStop) {
      break;
    }
  }

  sessionDestroy(session);
  ioPollerClose(&poller);
  close(connFd);
  close(tunFd);
  logf("connection stopped");
}

static void listenTcp(
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
}

static void connTcp(
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
  const char *ifName;
  const char *ip;
  int port;
  int server;
  const char *secretFile;
  unsigned char key[ProtocolPskSize];

  if (argc != 6) {
    panicf("invalid arguments: <ifName> <ip> <port> <serverFlag> <secretFile>");
  }
  ifName = argv[1];
  ip = argv[2];
  port = atoi(argv[3]);
  server = atoi(argv[4]);
  secretFile = argv[5];

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
