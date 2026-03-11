#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sodium.h>

#include "config.h"
#include "crypt.h"
#include "io.h"
#include "log.h"
#include "protocol.h"
#include "session.h"

typedef struct {
  const cryptServerKeyStore_t *store;
  ioIfMode_t ifMode;
} serverKeyLookupCtx_t;

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
    ioIfMode_t ifMode,
    const char *listenIP,
    int port,
    const daemonServerIdentity_t *serverIdentity,
    const cryptServerKeyStore_t *keyStore,
    int authTimeoutMs,
    int maxPreAuthSessions,
    const sessionHeartbeatConfig_t *heartbeatCfg) {
  serverKeyLookupCtx_t lookupCtx;
  sessionServerIdentity_t sessionIdentity;

  lookupCtx.store = keyStore;
  lookupCtx.ifMode = ifMode;
  memcpy(&sessionIdentity, serverIdentity, sizeof(sessionIdentity));
  sessionServerConfig_t sessionCfg = {
      .ifName = ifName,
      .ifMode = ifMode,
      .listenIP = listenIP,
      .port = port,
      .resolveClaimFn = serverLookupByClaim,
      .resolveClaimCtx = &lookupCtx,
      .serverIdentity = &sessionIdentity,
      .authTimeoutMs = authTimeoutMs,
      .heartbeat = *heartbeatCfg,
      .maxActiveSessions = keyStore->count,
      .maxPreAuthSessions = maxPreAuthSessions,
  };
  if (sessionRunServer(&sessionCfg) != 0) {
    errf("server session failed: %s", strerror(errno));
    return -1;
  }

  return 0;
}

static int connTcp(
    const char *ifName,
    ioIfMode_t ifMode,
    const char *remoteIP,
    int port,
    const unsigned char *claim,
    long claimNbytes,
    const unsigned char key[ProtocolPskSize],
    const sessionHeartbeatConfig_t *heartbeatCfg) {
  sessionClientConfig_t sessionCfg = {
      .ifName = ifName,
      .ifMode = ifMode,
      .remoteIP = remoteIP,
      .port = port,
      .claim = claim,
      .claimNbytes = claimNbytes,
      .key = key,
      .heartbeat = *heartbeatCfg,
  };
  if (sessionRunClient(&sessionCfg) != 0) {
    errf("client session failed");
    return -1;
  }
  return 0;
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
