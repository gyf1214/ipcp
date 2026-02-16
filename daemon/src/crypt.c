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

int cryptInitFromFile(cryptCtx_t *ctx, const char *filePath) {
  FILE *fin = fopen(filePath, "rb");
  if (fin == NULL) {
    return -1;
  }

  size_t nread = fread(ctx->key, 1, sizeof(ctx->key), fin);
  if (nread != sizeof(ctx->key)) {
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
