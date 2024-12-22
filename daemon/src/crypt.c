#include <sodium.h>

#include "crypt.h"
#include "log.h"

void cryptGlobalInit() {
  if (sodium_init() < 0) {
    panicf("sodium init failed");
  }
}
