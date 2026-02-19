#include "serverRuntime.h"

#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>

static bool slotIndexValid(const serverRuntime_t *runtime, int slot) {
  return runtime != NULL && runtime->slots != NULL && slot >= 0 && slot < runtime->maxSessions;
}

bool serverRuntimeInit(
    serverRuntime_t *runtime,
    int tunFd,
    int listenFd,
    int maxSessions,
    const sessionHeartbeatConfig_t *heartbeatCfg) {
  if (runtime == NULL || heartbeatCfg == NULL || maxSessions <= 0 || tunFd < 0 || listenFd < 0) {
    return false;
  }

  memset(runtime, 0, sizeof(*runtime));
  runtime->slots = calloc((size_t)maxSessions, sizeof(*runtime->slots));
  if (runtime->slots == NULL) {
    return false;
  }

  runtime->tunFd = tunFd;
  runtime->listenFd = listenFd;
  runtime->maxSessions = maxSessions;
  runtime->heartbeatCfg = *heartbeatCfg;
  return true;
}

void serverRuntimeDeinit(serverRuntime_t *runtime) {
  int i;

  if (runtime == NULL || runtime->slots == NULL) {
    return;
  }

  for (i = 0; i < runtime->maxSessions; i++) {
    if (runtime->slots[i].session != NULL) {
      sessionDestroy(runtime->slots[i].session);
    }
  }

  free(runtime->slots);
  memset(runtime, 0, sizeof(*runtime));
}

int serverRuntimeAddClient(serverRuntime_t *runtime, int connFd) {
  int i;
  session_t *session;

  if (runtime == NULL || runtime->slots == NULL || connFd < 0) {
    return -1;
  }
  if (runtime->clientCount >= runtime->maxSessions) {
    return -1;
  }

  for (i = 0; i < runtime->maxSessions; i++) {
    if (runtime->slots[i].active) {
      continue;
    }

    session = sessionCreate(true, &runtime->heartbeatCfg, NULL, NULL);
    if (session == NULL) {
      return -1;
    }

    runtime->slots[i].connFd = connFd;
    runtime->slots[i].session = session;
    runtime->slots[i].poller.epollFd = runtime->epollFd;
    runtime->slots[i].poller.tunFd = runtime->tunFd;
    runtime->slots[i].poller.tcpFd = connFd;
    runtime->slots[i].poller.tunEvents = EPOLLIN | EPOLLRDHUP;
    runtime->slots[i].poller.tcpEvents = EPOLLIN | EPOLLRDHUP;
    runtime->slots[i].poller.tunOutOffset = 0;
    runtime->slots[i].poller.tunOutNbytes = 0;
    runtime->slots[i].poller.tcpOutOffset = 0;
    runtime->slots[i].poller.tcpOutNbytes = 0;
    runtime->slots[i].active = true;
    runtime->clientCount++;
    return i;
  }

  return -1;
}

bool serverRuntimeRemoveClient(serverRuntime_t *runtime, int slot) {
  if (!slotIndexValid(runtime, slot) || !runtime->slots[slot].active) {
    return false;
  }

  sessionDestroy(runtime->slots[slot].session);
  runtime->slots[slot].connFd = -1;
  runtime->slots[slot].session = NULL;
  runtime->slots[slot].active = false;
  runtime->clientCount--;
  return true;
}

int serverRuntimeFindSlotByFd(const serverRuntime_t *runtime, int connFd) {
  int i;

  if (runtime == NULL || runtime->slots == NULL || connFd < 0) {
    return -1;
  }

  for (i = 0; i < runtime->maxSessions; i++) {
    if (runtime->slots[i].active && runtime->slots[i].connFd == connFd) {
      return i;
    }
  }

  return -1;
}

int serverRuntimePickEgressClient(const serverRuntime_t *runtime) {
  int i;

  if (runtime == NULL || runtime->slots == NULL) {
    return -1;
  }

  for (i = 0; i < runtime->maxSessions; i++) {
    if (runtime->slots[i].active) {
      return runtime->slots[i].connFd;
    }
  }

  return -1;
}

int serverRuntimeClientCount(const serverRuntime_t *runtime) {
  if (runtime == NULL || runtime->slots == NULL) {
    return -1;
  }
  return runtime->clientCount;
}

session_t *serverRuntimeSessionAt(serverRuntime_t *runtime, int slot) {
  if (!slotIndexValid(runtime, slot) || !runtime->slots[slot].active) {
    return NULL;
  }
  return runtime->slots[slot].session;
}

int serverRuntimeConnFdAt(const serverRuntime_t *runtime, int slot) {
  if (!slotIndexValid(runtime, slot) || !runtime->slots[slot].active) {
    return -1;
  }
  return runtime->slots[slot].connFd;
}
