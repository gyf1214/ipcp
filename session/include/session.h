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
  bool enabled;
  unsigned char network[4];
  int prefix;
  unsigned char broadcast[4];
} sessionTunSubnet_t;

int sessionRunServer(
    int tunFd,
    int listenFd,
    sessionServerResolveClaimFn_t resolveClaimFn,
    void *resolveClaimCtx,
    const char *ifModeLabel,
    const sessionTunSubnet_t *tunSubnet,
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
