#pragma once

#include <stdbool.h>

#include "session.h"

typedef struct serverRuntime_t serverRuntime_t;

typedef struct {
  int connFd;
  session_t *session;
  ioPoller_t poller;
  bool active;
} serverRuntimeSlot_t;

struct serverRuntime_t {
  int tunFd;
  int listenFd;
  int epollFd;
  unsigned int tunEvents;
  long tunOutOffset;
  long tunOutNbytes;
  unsigned char tunOutBuf[IoPollerQueueCapacity];
  int retryCursor;
  int maxSessions;
  int clientCount;
  serverRuntimeSlot_t *slots;
  sessionHeartbeatConfig_t heartbeatCfg;
};

bool serverRuntimeInit(
    serverRuntime_t *runtime,
    int tunFd,
    int listenFd,
    int maxSessions,
    const sessionHeartbeatConfig_t *heartbeatCfg);
void serverRuntimeDeinit(serverRuntime_t *runtime);

int serverRuntimeAddClient(serverRuntime_t *runtime, int connFd);
bool serverRuntimeRemoveClient(serverRuntime_t *runtime, int slot);

int serverRuntimeFindSlotByFd(const serverRuntime_t *runtime, int connFd);
int serverRuntimePickEgressClient(const serverRuntime_t *runtime);
int serverRuntimeClientCount(const serverRuntime_t *runtime);
long serverRuntimeQueuedTunBytes(const serverRuntime_t *runtime);

bool serverRuntimeSyncTunWriteInterest(serverRuntime_t *runtime);
bool serverRuntimeQueueTunWrite(serverRuntime_t *runtime, const void *data, long nbytes);
bool serverRuntimeServiceTunWriteEvent(serverRuntime_t *runtime);
int serverRuntimeRetryBlockedTunRoundRobin(serverRuntime_t *runtime);

session_t *serverRuntimeSessionAt(serverRuntime_t *runtime, int slot);
int serverRuntimeConnFdAt(const serverRuntime_t *runtime, int slot);
