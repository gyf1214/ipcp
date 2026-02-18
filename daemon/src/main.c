#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sodium.h>

#include "crypt.h"
#include "io.h"
#include "log.h"
#include "protocol.h"
#include "session.h"

#define EPOLL_WAIT_MS 200

static bool parseIntStrict(const char *s, long min, long max, int *out) {
  char *end = NULL;
  long value = 0;

  if (s == NULL || out == NULL || *s == '\0') {
    return false;
  }

  errno = 0;
  value = strtol(s, &end, 10);
  if (errno != 0 || end == s || *end != '\0') {
    return false;
  }
  if (value < min || value > max) {
    return false;
  }
  if (value < INT_MIN || value > INT_MAX) {
    return false;
  }

  *out = (int)value;
  return true;
}

static int serveTcp(
    const char *ifName,
    int connFd,
    const unsigned char key[ProtocolPskSize],
    bool isServer) {
  ioPoller_t poller;
  ioEvent_t event;
  session_t *session = NULL;
  int tunFd = -1;
  int result = -1;

  logf("opening tun device %s", ifName);
  tunFd = ioTunOpen(ifName);
  if (tunFd < 0) {
    errf("failed to open tun device %s: %s", ifName, strerror(errno));
    goto cleanup;
  }
  logf("successfully opened tun device %s", ifName);

  if (ioPollerInit(&poller, tunFd, connFd) != 0) {
    errf("setup epoll failed: %s", strerror(errno));
    goto cleanup;
  }

  session = sessionCreate(isServer, NULL, NULL);
  if (session == NULL) {
    errf("session setup failed");
    ioPollerClose(&poller);
    goto cleanup;
  }

  while (1) {
    event = ioPollerWait(&poller, EPOLL_WAIT_MS);
    if (sessionStep(session, &poller, event, key) == sessionStepStop) {
      break;
    }
  }

  result = 0;
  sessionDestroy(session);
  ioPollerClose(&poller);
  logf("connection stopped");

cleanup:
  if (session != NULL && result != 0) {
    sessionDestroy(session);
  }
  if (connFd >= 0) {
    close(connFd);
  }
  if (tunFd >= 0) {
    close(tunFd);
  }

  return result;
}

static int listenTcp(
    const char *ifName,
    const char *listenIP,
    int port,
    const unsigned char key[ProtocolPskSize]) {
  int listenFd = ioTcpListen(listenIP, port);
  if (listenFd < 0) {
    errf("listen setup failed: %s", strerror(errno));
    return -1;
  }
  logf("listening on %s:%d", listenIP, port);

  while (1) {
    char clientIP[256];
    int clientPort = 0;
    int connFd = ioTcpAccept(listenFd, clientIP, sizeof(clientIP), &clientPort);
    if (connFd < 0) {
      errf("accept failed: %s", strerror(errno));
      close(listenFd);
      return -1;
    }
    logf("connected with %s:%d", clientIP, clientPort);

    if (serveTcp(ifName, connFd, key, true) != 0) {
      close(listenFd);
      return -1;
    }
  }

  close(listenFd);
  return 0;
}

static int connTcp(
    const char *ifName,
    const char *remoteIP,
    int port,
    const unsigned char key[ProtocolPskSize]) {
  int connFd = ioTcpConnect(remoteIP, port);
  if (connFd < 0) {
    errf("connect to %s:%d failed: %s", remoteIP, port, strerror(errno));
    return -1;
  }
  logf("connected to %s:%d", remoteIP, port);

  return serveTcp(ifName, connFd, key, false);
}

int main(int argc, char **argv) {
  const char *ifName;
  const char *ip;
  int port;
  int server;
  const char *secretFile;
  unsigned char key[ProtocolPskSize];
  int exitCode = 1;
  bool keyLoaded = false;

  if (argc != 6) {
    panicf("invalid arguments: <ifName> <ip> <port> <serverFlag> <secretFile>");
  }
  ifName = argv[1];
  ip = argv[2];
  if (!parseIntStrict(argv[3], 1, 65535, &port)
      || !parseIntStrict(argv[4], 0, 1, &server)) {
    panicf("invalid arguments: <ifName> <ip> <port> <serverFlag> <secretFile>");
  }
  secretFile = argv[5];

  cryptGlobalInit();
  if (cryptLoadKeyFromFile(key, secretFile) != 0) {
    panicf("invalid secret file, expected exactly %d raw bytes", ProtocolPskSize);
  }
  keyLoaded = true;

  if (server) {
    exitCode = listenTcp(ifName, ip, port, key) == 0 ? 0 : 1;
  } else {
    exitCode = connTcp(ifName, ip, port, key) == 0 ? 0 : 1;
  }

  if (keyLoaded) {
    sodium_memzero(key, sizeof(key));
  }

  return exitCode;
}
