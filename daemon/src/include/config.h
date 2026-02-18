#pragma once

#include "protocol.h"

#define ConfigTextSize 512

typedef enum {
  configModeServer = 0,
  configModeClient,
} configMode_t;

typedef struct {
  configMode_t mode;
  char ifName[ConfigTextSize];
  char keyFile[ConfigTextSize];
  char listenIP[ConfigTextSize];
  int listenPort;
  char serverIP[ConfigTextSize];
  int serverPort;
} daemonConfig_t;

void configZero(daemonConfig_t *cfg);
int configLoadFromFile(daemonConfig_t *out, const char *path);
