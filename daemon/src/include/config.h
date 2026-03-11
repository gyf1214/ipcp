#pragma once

#include <stdbool.h>

#include "io.h"
#include "protocol.h"

#define ConfigTextSize 512
#define ConfigDefaultHeartbeatIntervalMs 5000
#define ConfigDefaultHeartbeatTimeoutMs  15000
#define ConfigMaxServerCredentials 128
#define DaemonClaimSize 16

typedef enum {
  configModeServer = 0,
  configModeClient,
} configMode_t;

typedef struct {
  unsigned char claim[DaemonClaimSize];
  long claimNbytes;
  bool directedBroadcastEnabled;
  unsigned char directedBroadcast[4];
} daemonServerIdentity_t;

typedef struct {
  char tunIP[ConfigTextSize];
  char tapMac[ConfigTextSize];
  unsigned char claim[DaemonClaimSize];
  long claimNbytes;
  char keyFile[ConfigTextSize];
} daemonServerCredential_t;

typedef struct {
  configMode_t mode;
  ioIfMode_t ifMode;
  char ifName[ConfigTextSize];
  char keyFile[ConfigTextSize];
  char listenIP[ConfigTextSize];
  int listenPort;
  char serverIP[ConfigTextSize];
  int serverPort;
  char tunIP[ConfigTextSize];
  char tapMac[ConfigTextSize];
  unsigned char claim[DaemonClaimSize];
  long claimNbytes;
  int heartbeatIntervalMs;
  int heartbeatTimeoutMs;
  int authTimeoutMs;
  int maxPreAuthSessions;
  daemonServerIdentity_t serverIdentity;
  daemonServerCredential_t serverCredentials[ConfigMaxServerCredentials];
  int serverCredentialCount;
} daemonConfig_t;

void configZero(daemonConfig_t *cfg);
int configLoadFromFile(daemonConfig_t *out, const char *path);
