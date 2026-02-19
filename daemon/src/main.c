#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sodium.h>

#include "config.h"
#include "crypt.h"
#include "io.h"
#include "log.h"
#include "protocol.h"
#include "session.h"

#define EPOLL_WAIT_MS 200

static ioIfMode_t toIoIfMode(configIfMode_t mode) {
  if (mode == configIfModeTap) {
    return ioIfModeTap;
  }
  return ioIfModeTun;
}

static int serveTcp(
    const char *ifName,
    configIfMode_t ifMode,
    int connFd,
    const unsigned char key[ProtocolPskSize],
    bool isServer,
    const sessionHeartbeatConfig_t *heartbeatCfg) {
  ioPoller_t poller;
  ioEvent_t event;
  session_t *session = NULL;
  int tunFd = -1;
  int result = -1;

  logf("opening tun device %s", ifName);
  tunFd = ioTunOpen(ifName, toIoIfMode(ifMode));
  if (tunFd < 0) {
    errf("failed to open tun device %s: %s", ifName, strerror(errno));
    goto cleanup;
  }
  logf("successfully opened tun device %s", ifName);

  if (ioPollerInit(&poller, tunFd, connFd) != 0) {
    errf("setup epoll failed: %s", strerror(errno));
    goto cleanup;
  }

  session = sessionCreate(isServer, heartbeatCfg, NULL, NULL);
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
    configIfMode_t ifMode,
    const char *listenIP,
    int port,
    const unsigned char key[ProtocolPskSize],
    const sessionHeartbeatConfig_t *heartbeatCfg) {
  int tunFd = -1;
  int listenFd = ioTcpListen(listenIP, port);
  if (listenFd < 0) {
    errf("listen setup failed: %s", strerror(errno));
    return -1;
  }
  logf("listening on %s:%d", listenIP, port);
  logf("opening tun device %s", ifName);
  tunFd = ioTunOpen(ifName, toIoIfMode(ifMode));
  if (tunFd < 0) {
    errf("failed to open tun device %s: %s", ifName, strerror(errno));
    close(listenFd);
    return -1;
  }
  logf("successfully opened tun device %s", ifName);

  if (sessionServeMultiClient(tunFd, listenFd, key, heartbeatCfg, 64) != 0) {
    close(tunFd);
    close(listenFd);
    return -1;
  }

  close(tunFd);
  close(listenFd);
  return 0;
}

static int connTcp(
    const char *ifName,
    configIfMode_t ifMode,
    const char *remoteIP,
    int port,
    const unsigned char key[ProtocolPskSize],
    const sessionHeartbeatConfig_t *heartbeatCfg) {
  int connFd = ioTcpConnect(remoteIP, port);
  if (connFd < 0) {
    errf("connect to %s:%d failed: %s", remoteIP, port, strerror(errno));
    return -1;
  }
  logf("connected to %s:%d", remoteIP, port);

  return serveTcp(ifName, ifMode, connFd, key, false, heartbeatCfg);
}

int main(int argc, char **argv) {
  daemonConfig_t cfg;
  sessionHeartbeatConfig_t heartbeatCfg;
  unsigned char key[ProtocolPskSize];
  int exitCode = EXIT_FAILURE;
  bool configLoaded = false;
  bool keyLoaded = false;

  configZero(&cfg);

  if (argc != 2) {
    errf("invalid arguments: <configFile>");
    goto cleanup;
  }

  cryptGlobalInit();
  if (configLoadFromFile(&cfg, argv[1]) != 0) {
    errf("invalid config file");
    goto cleanup;
  }
  configLoaded = true;

  if (cryptLoadKeyFromFile(key, cfg.keyFile) != 0) {
    errf("invalid secret file, expected exactly %d raw bytes", ProtocolPskSize);
    goto cleanup;
  }
  keyLoaded = true;
  heartbeatCfg.intervalMs = cfg.heartbeatIntervalMs;
  heartbeatCfg.timeoutMs = cfg.heartbeatTimeoutMs;

  if (cfg.mode == configModeServer) {
    exitCode =
        listenTcp(cfg.ifName, cfg.ifMode, cfg.listenIP, cfg.listenPort, key, &heartbeatCfg) == 0
            ? EXIT_SUCCESS
            : EXIT_FAILURE;
  } else {
    exitCode =
        connTcp(cfg.ifName, cfg.ifMode, cfg.serverIP, cfg.serverPort, key, &heartbeatCfg) == 0
            ? EXIT_SUCCESS
            : EXIT_FAILURE;
  }

cleanup:
  if (keyLoaded) {
    sodium_memzero(key, sizeof(key));
  }
  if (configLoaded) {
    configZero(&cfg);
  }

  return exitCode;
}
