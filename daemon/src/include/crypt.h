#pragma once

#include "protocol.h"

void cryptGlobalInit();
int cryptLoadKeyFromFile(unsigned char key[ProtocolPskSize], const char *filePath);
