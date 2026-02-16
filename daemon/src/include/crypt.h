#pragma once

#include "protocol.h"

typedef struct {
  unsigned char key[ProtocolPskSize];
} cryptCtx_t;

void cryptGlobalInit();
int cryptInitFromFile(cryptCtx_t *ctx, const char *filePath);
