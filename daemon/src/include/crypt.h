#pragma once

#include "config.h"
#include "protocol.h"

typedef struct {
  configIfMode_t ifMode;
  char claim[ConfigTextSize];
  unsigned char key[ProtocolPskSize];
} cryptServerKeyEntry_t;

typedef struct {
  cryptServerKeyEntry_t entries[ConfigMaxServerCredentials];
  int count;
} cryptServerKeyStore_t;

void cryptGlobalInit();
int cryptLoadKeyFromFile(unsigned char key[ProtocolPskSize], const char *filePath);
void cryptServerKeyStoreZero(cryptServerKeyStore_t *store);
int cryptServerKeyStoreLoadFromConfig(cryptServerKeyStore_t *store, const daemonConfig_t *cfg);
int cryptServerKeyStoreLookup(
    const cryptServerKeyStore_t *store,
    configIfMode_t ifMode,
    const char *claim,
    unsigned char key[ProtocolPskSize]);
