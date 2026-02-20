#include <sodium.h>
#include <string.h>
#include <stdio.h>

#include "crypt.h"
#include "log.h"

void cryptGlobalInit() {
  if (sodium_init() < 0) {
    panicf("sodium init failed");
  }
}

int cryptLoadKeyFromFile(unsigned char key[ProtocolPskSize], const char *filePath) {
  FILE *fin = fopen(filePath, "rb");
  if (fin == NULL) {
    return -1;
  }

  size_t nread = fread(key, 1, ProtocolPskSize, fin);
  if (nread != ProtocolPskSize) {
    fclose(fin);
    return -1;
  }

  unsigned char extra = 0;
  if (fread(&extra, 1, 1, fin) != 0) {
    fclose(fin);
    return -1;
  }
  if (ferror(fin)) {
    fclose(fin);
    return -1;
  }

  fclose(fin);
  return 0;
}

void cryptServerKeyStoreZero(cryptServerKeyStore_t *store) {
  if (store == NULL) {
    return;
  }
  sodium_memzero(store, sizeof(*store));
}

int cryptServerKeyStoreLoadFromConfig(cryptServerKeyStore_t *store, const daemonConfig_t *cfg) {
  int i;
  if (store == NULL || cfg == NULL || cfg->mode != configModeServer) {
    return -1;
  }
  cryptServerKeyStoreZero(store);
  if (cfg->serverCredentialCount <= 0 || cfg->serverCredentialCount > ConfigMaxServerCredentials) {
    return -1;
  }

  for (i = 0; i < cfg->serverCredentialCount; i++) {
    const daemonServerCredential_t *cred = &cfg->serverCredentials[i];
    cryptServerKeyEntry_t *entry = &store->entries[i];
    if (cryptLoadKeyFromFile(entry->key, cred->keyFile) != 0) {
      cryptServerKeyStoreZero(store);
      return -1;
    }
    entry->ifMode = cfg->ifMode;
    if (cfg->ifMode == configIfModeTun) {
      strncpy(entry->claim, cred->tunIP, sizeof(entry->claim) - 1);
      entry->claim[sizeof(entry->claim) - 1] = '\0';
    } else {
      strncpy(entry->claim, cred->tapMac, sizeof(entry->claim) - 1);
      entry->claim[sizeof(entry->claim) - 1] = '\0';
    }
  }

  store->count = cfg->serverCredentialCount;
  return 0;
}

int cryptServerKeyStoreLookup(
    const cryptServerKeyStore_t *store,
    configIfMode_t ifMode,
    const char *claim,
    unsigned char key[ProtocolPskSize]) {
  int i;
  if (store == NULL || claim == NULL || key == NULL) {
    return -1;
  }
  for (i = 0; i < store->count; i++) {
    if (store->entries[i].ifMode != ifMode) {
      continue;
    }
    if (strcmp(store->entries[i].claim, claim) != 0) {
      continue;
    }
    memcpy(key, store->entries[i].key, ProtocolPskSize);
    return 0;
  }
  return -1;
}
