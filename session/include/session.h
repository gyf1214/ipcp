#pragma once

#include <stdbool.h>

#include "io.h"
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

typedef struct {
  const char *ifName;
  ioIfMode_t ifMode;
  const char *listenIP;
  int port;
  sessionServerResolveClaimFn_t resolveClaimFn;
  void *resolveClaimCtx;
  const sessionServerIdentity_t *serverIdentity;
  int authTimeoutMs;
  sessionHeartbeatConfig_t heartbeat;
  int maxActiveSessions;
  int maxPreAuthSessions;
} sessionServerConfig_t;

typedef struct {
  const char *ifName;
  ioIfMode_t ifMode;
  const char *remoteIP;
  int port;
  const unsigned char *claim;
  long claimNbytes;
  const unsigned char *key;
  sessionHeartbeatConfig_t heartbeat;
} sessionClientConfig_t;

int sessionRunServer(const sessionServerConfig_t *cfg);
int sessionRunClient(const sessionClientConfig_t *cfg);
