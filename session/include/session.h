#pragma once

#include <stdbool.h>

#include "protocol.h"

#define SessionClaimSize 16

typedef int (*sessionServerResolveClaimFn_t)(
    void *ctx,
    const unsigned char *claim,
    long claimNbytes,
    unsigned char key[ProtocolPskSize],
    int *outActiveSlot);

typedef struct {
  int intervalMs;
  int timeoutMs;
} sessionHeartbeatConfig_t;

typedef struct {
  unsigned char claim[SessionClaimSize];
  long claimNbytes;
  bool directedBroadcastEnabled;
  unsigned char directedBroadcast[4];
} sessionServerIdentity_t;

typedef enum {
  sessionIfModeTun = 0,
  sessionIfModeTap,
} sessionIfMode_t;

int sessionRunServer(
    int tunFd,
    int listenFd,
    sessionServerResolveClaimFn_t resolveClaimFn,
    void *resolveClaimCtx,
    sessionIfMode_t mode,
    const sessionServerIdentity_t *serverIdentity,
    int authTimeoutMs,
    const sessionHeartbeatConfig_t *heartbeatCfg,
    int maxActiveSessions,
    int maxPreAuthSessions);
int sessionRunClient(
    int tunFd,
    int connFd,
    const unsigned char *claim,
    long claimNbytes,
    const unsigned char key[ProtocolPskSize],
    const sessionHeartbeatConfig_t *heartbeatCfg);
