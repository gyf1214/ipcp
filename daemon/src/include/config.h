#pragma once

#include "protocol.h"

#define ConfigTextSize 512
#define ConfigDefaultHeartbeatIntervalMs 5000
#define ConfigDefaultHeartbeatTimeoutMs  15000
#define ConfigMaxServerCredentials 128

typedef enum {
  configModeServer = 0,
  configModeClient,
} configMode_t;

typedef enum {
  configIfModeTun = 0,
  configIfModeTap,
} configIfMode_t;

typedef struct {
  char tunIP[ConfigTextSize];
  char tapMac[ConfigTextSize];
  char keyFile[ConfigTextSize];
} daemonServerCredential_t;

typedef struct {
  configMode_t mode;
  configIfMode_t ifMode;
  char ifName[ConfigTextSize];
  char keyFile[ConfigTextSize];
  char listenIP[ConfigTextSize];
  int listenPort;
  char serverIP[ConfigTextSize];
  int serverPort;
  char tunIP[ConfigTextSize];
  char tapMac[ConfigTextSize];
  int heartbeatIntervalMs;
  int heartbeatTimeoutMs;
  int authTimeoutMs;
  daemonServerCredential_t serverCredentials[ConfigMaxServerCredentials];
  int serverCredentialCount;
} daemonConfig_t;

void configZero(daemonConfig_t *cfg);
int configLoadFromFile(daemonConfig_t *out, const char *path);
