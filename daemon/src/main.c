#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sodium.h>

#include "config.h"
#include "crypt.h"
#include "io.h"
#include "log.h"
#include "protocol.h"
#include "session.h"

static ioIfMode_t toIoIfMode(configIfMode_t mode) {
  if (mode == configIfModeTap) {
    return ioIfModeTap;
  }
  return ioIfModeTun;
}

typedef struct {
  const cryptServerKeyStore_t *store;
  configIfMode_t ifMode;
} serverKeyLookupCtx_t;

static const char *ifModeLabel(configIfMode_t mode) {
  return mode == configIfModeTap ? "tap" : "tun";
}

static int serverLookupByClaim(
    void *ctx,
    const unsigned char *claim,
    long claimNbytes,
    unsigned char key[ProtocolPskSize],
    int *outActiveSlot) {
  serverKeyLookupCtx_t *lookup = (serverKeyLookupCtx_t *)ctx;
  if (lookup == NULL || lookup->store == NULL) {
    return -1;
  }
  return cryptServerKeyStoreLookup(lookup->store, lookup->ifMode, claim, claimNbytes, key, outActiveSlot);
}

static int listenTcp(
    const char *ifName,
    configIfMode_t ifMode,
    const char *listenIP,
    int port,
    const sessionServerIdentity_t *serverIdentity,
    const cryptServerKeyStore_t *keyStore,
    int authTimeoutMs,
    int maxPreAuthSessions,
    const sessionHeartbeatConfig_t *heartbeatCfg) {
  serverKeyLookupCtx_t lookupCtx;
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

  lookupCtx.store = keyStore;
  lookupCtx.ifMode = ifMode;
  if (sessionRunServer(
          tunFd,
          listenFd,
          serverLookupByClaim,
          &lookupCtx,
          ifModeLabel(ifMode),
          serverIdentity,
          authTimeoutMs,
          heartbeatCfg,
          keyStore->count,
          maxPreAuthSessions)
      != 0) {
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
    const unsigned char *claim,
    long claimNbytes,
    const unsigned char key[ProtocolPskSize],
    const sessionHeartbeatConfig_t *heartbeatCfg) {
  int tunFd = -1;
  int connFd = -1;
  int status = -1;

  logf("opening tun device %s", ifName);
  tunFd = ioTunOpen(ifName, toIoIfMode(ifMode));
  if (tunFd < 0) {
    errf("failed to open tun device %s: %s", ifName, strerror(errno));
    goto cleanup;
  }
  logf("successfully opened tun device %s", ifName);

  connFd = ioTcpConnect(remoteIP, port);
  if (connFd < 0) {
    errf("connect to %s:%d failed: %s", remoteIP, port, strerror(errno));
    goto cleanup;
  }
  logf("connected to %s:%d", remoteIP, port);

  if (sessionRunClient(tunFd, connFd, claim, claimNbytes, key, heartbeatCfg) != 0) {
    errf("client session failed");
    goto cleanup;
  }

  status = 0;

cleanup:
  if (connFd >= 0) {
    close(connFd);
  }
  if (tunFd >= 0) {
    close(tunFd);
  }
  return status;
}

int main(int argc, char **argv) {
  daemonConfig_t cfg;
  sessionHeartbeatConfig_t heartbeatCfg;
  unsigned char key[ProtocolPskSize];
  cryptServerKeyStore_t keyStore;
  int exitCode = EXIT_FAILURE;
  bool configLoaded = false;
  bool keyLoaded = false;
  bool keyStoreLoaded = false;

  configZero(&cfg);
  cryptServerKeyStoreZero(&keyStore);

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

  if (cfg.mode == configModeServer) {
    if (cryptServerKeyStoreLoadFromConfig(&keyStore, &cfg) != 0) {
      errf("invalid secret file, expected exactly %d raw bytes", ProtocolPskSize);
      goto cleanup;
    }
    keyStoreLoaded = true;
  } else {
    if (cryptLoadKeyFromFile(key, cfg.keyFile) != 0) {
      errf("invalid secret file, expected exactly %d raw bytes", ProtocolPskSize);
      goto cleanup;
    }
    keyLoaded = true;
  }
  heartbeatCfg.intervalMs = cfg.heartbeatIntervalMs;
  heartbeatCfg.timeoutMs = cfg.heartbeatTimeoutMs;

  if (cfg.mode == configModeServer) {
    exitCode =
        listenTcp(
            cfg.ifName,
            cfg.ifMode,
            cfg.listenIP,
            cfg.listenPort,
            &cfg.serverIdentity,
            &keyStore,
            cfg.authTimeoutMs,
            cfg.maxPreAuthSessions,
            &heartbeatCfg)
            == 0
            ? EXIT_SUCCESS
            : EXIT_FAILURE;
  } else {
    const unsigned char *claim = cfg.claim;
    exitCode =
        connTcp(cfg.ifName, cfg.ifMode, cfg.serverIP, cfg.serverPort, claim, cfg.claimNbytes, key, &heartbeatCfg) == 0
            ? EXIT_SUCCESS
            : EXIT_FAILURE;
  }

cleanup:
  if (keyLoaded) {
    sodium_memzero(key, sizeof(key));
  }
  if (keyStoreLoaded) {
    cryptServerKeyStoreZero(&keyStore);
  }
  if (configLoaded) {
    configZero(&cfg);
  }

  return exitCode;
}
