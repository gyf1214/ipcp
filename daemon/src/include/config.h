#pragma once

#include "protocol.h"

#define ConfigTextSize 512
#define ConfigDefaultHeartbeatIntervalMs 5000
#define ConfigDefaultHeartbeatTimeoutMs  15000

typedef enum {
  configModeServer = 0,
  configModeClient,
} configMode_t;

typedef enum {
  configIfModeTun = 0,
  configIfModeTap,
} configIfMode_t;

typedef struct {
  configMode_t mode;
  configIfMode_t ifMode;
  char ifName[ConfigTextSize];
  char keyFile[ConfigTextSize];
  char listenIP[ConfigTextSize];
  int listenPort;
  char serverIP[ConfigTextSize];
  int serverPort;
  int heartbeatIntervalMs;
  int heartbeatTimeoutMs;
} daemonConfig_t;

void configZero(daemonConfig_t *cfg);
int configLoadFromFile(daemonConfig_t *out, const char *path);
