#include "serverRuntime.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

static bool slotIndexValid(const serverRuntime_t *runtime, int slot) {
  return runtime != NULL && runtime->slots != NULL && slot >= 0 && slot < runtime->maxSessions;
}

static bool runtimeTunEpollCtl(serverRuntime_t *runtime, unsigned int events) {
  struct epoll_event event;

  if (runtime == NULL || runtime->epollFd < 0 || runtime->tunFd < 0) {
    return false;
  }

  memset(&event, 0, sizeof(event));
  event.events = events;
  event.data.fd = runtime->tunFd;
  if (epoll_ctl(runtime->epollFd, EPOLL_CTL_MOD, runtime->tunFd, &event) < 0) {
    return false;
  }
  runtime->tunEvents = events;
  return true;
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
  runtime->epollFd = -1;
  runtime->tunEvents = EPOLLIN | EPOLLRDHUP;
  runtime->tunOutOffset = 0;
  runtime->tunOutNbytes = 0;
  runtime->retryCursor = 0;
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
    sessionSetServerRuntime(session, runtime);
    runtime->slots[i].poller.epollFd = runtime->epollFd;
    runtime->slots[i].poller.tunFd = runtime->tunFd;
    runtime->slots[i].poller.tcpFd = connFd;
    runtime->slots[i].poller.tunEvents = runtime->tunEvents;
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
  runtime->slots[slot].poller.tcpOutOffset = 0;
  runtime->slots[slot].poller.tcpOutNbytes = 0;
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

long serverRuntimeQueuedTunBytes(const serverRuntime_t *runtime) {
  if (runtime == NULL) {
    return -1;
  }
  return runtime->tunOutNbytes;
}

bool serverRuntimeSyncTunWriteInterest(serverRuntime_t *runtime) {
  unsigned int nextEvents;
  bool needWrite;

  if (runtime == NULL) {
    return false;
  }
  if (runtime->epollFd < 0) {
    return true;
  }

  needWrite = runtime->tunOutNbytes > 0;
  nextEvents = runtime->tunEvents;
  if (needWrite) {
    nextEvents |= EPOLLOUT;
  } else {
    nextEvents &= ~EPOLLOUT;
  }
  if (nextEvents == runtime->tunEvents) {
    return true;
  }
  return runtimeTunEpollCtl(runtime, nextEvents);
}

bool serverRuntimeQueueTunWrite(serverRuntime_t *runtime, const void *data, long nbytes) {
  long used;

  if (runtime == NULL || data == NULL || nbytes <= 0 || nbytes > IoPollerQueueCapacity) {
    return false;
  }

  used = runtime->tunOutOffset + runtime->tunOutNbytes;
  if (used + nbytes > IoPollerQueueCapacity && runtime->tunOutOffset > 0) {
    memmove(runtime->tunOutBuf, runtime->tunOutBuf + runtime->tunOutOffset, (size_t)runtime->tunOutNbytes);
    runtime->tunOutOffset = 0;
    used = runtime->tunOutNbytes;
  }

  if (used + nbytes > IoPollerQueueCapacity) {
    return false;
  }

  memcpy(runtime->tunOutBuf + used, data, (size_t)nbytes);
  runtime->tunOutNbytes += nbytes;
  return serverRuntimeSyncTunWriteInterest(runtime);
}

bool serverRuntimeServiceTunWriteEvent(serverRuntime_t *runtime) {
  while (runtime != NULL && runtime->tunOutNbytes > 0) {
    long wrote = (long)write(runtime->tunFd, runtime->tunOutBuf + runtime->tunOutOffset, (size_t)runtime->tunOutNbytes);
    if (wrote > 0) {
      runtime->tunOutOffset += wrote;
      runtime->tunOutNbytes -= wrote;
      continue;
    }
    if (wrote == 0) {
      return false;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return serverRuntimeSyncTunWriteInterest(runtime);
    }
    return false;
  }

  if (runtime == NULL) {
    return false;
  }
  runtime->tunOutOffset = 0;
  return serverRuntimeSyncTunWriteInterest(runtime);
}

int serverRuntimeRetryBlockedTunRoundRobin(serverRuntime_t *runtime) {
  int i;
  int start;
  int nextCursor = -1;

  if (runtime == NULL || runtime->slots == NULL || runtime->maxSessions <= 0) {
    return -1;
  }

  start = runtime->retryCursor % runtime->maxSessions;
  for (i = 0; i < runtime->maxSessions; i++) {
    int slot = (start + i) % runtime->maxSessions;
    session_t *session;
    if (!runtime->slots[slot].active) {
      continue;
    }
    session = runtime->slots[slot].session;
    if (session == NULL) {
      continue;
    }
    if (!sessionHasPendingTunEgress(session)) {
      continue;
    }
    if (!sessionServiceBackpressure(session, &runtime->slots[slot].poller)) {
      return -1;
    }
  }

  for (i = 1; i <= runtime->maxSessions; i++) {
    int slot = (start + i) % runtime->maxSessions;
    if (runtime->slots[slot].active) {
      nextCursor = slot;
      break;
    }
  }
  if (nextCursor < 0) {
    nextCursor = 0;
  }
  runtime->retryCursor = nextCursor;
  return runtime->retryCursor;
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
