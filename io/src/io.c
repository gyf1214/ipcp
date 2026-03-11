#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "io.h"

#define ioContainerOf(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))

static ioTcpPoller_t *tcpFromPoller(ioPoller_t *poller) {
  if (poller == NULL || poller->kind != ioPollerKindTcp) {
    return NULL;
  }
  return ioContainerOf(poller, ioTcpPoller_t, poller);
}

static ioTunPoller_t *tunFromPoller(ioPoller_t *poller) {
  if (poller == NULL || poller->kind != ioPollerKindTun) {
    return NULL;
  }
  return ioContainerOf(poller, ioTunPoller_t, poller);
}

static int pollerSetNonBlocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }
  if ((flags & O_NONBLOCK) != 0) {
    return 0;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int pollerCtlPoller(int epollFd, int op, ioPoller_t *poller, unsigned int events) {
  struct epoll_event event;
  event.events = events;
  event.data.ptr = poller;
  return epoll_ctl(epollFd, op, poller->fd, &event);
}

static int pollerMod(ioTcpPoller_t *poller, unsigned int events) {
  if (poller == NULL) {
    return -1;
  }
  if (poller->poller.reactor != NULL
      && poller->poller.reactor->epollFd >= 0
      && pollerCtlPoller(poller->poller.reactor->epollFd, EPOLL_CTL_MOD, &poller->poller, events) < 0) {
    return -1;
  }
  poller->poller.events = events;
  poller->poller.readEnabled = (events & EPOLLIN) != 0;
  return 0;
}

static int pollerEnsureWriteInterest(ioTcpPoller_t *poller) {
  if ((poller->poller.events & EPOLLOUT) != 0) {
    return 0;
  }
  return pollerMod(poller, poller->poller.events | EPOLLOUT);
}

static int pollerDisableWriteInterest(ioTcpPoller_t *poller) {
  if ((poller->poller.events & EPOLLOUT) == 0) {
    return 0;
  }
  return pollerMod(poller, poller->poller.events & ~EPOLLOUT);
}

static int pollerFlushQueue(ioTcpPoller_t *poller) {
  while (poller->outNbytes > 0) {
    long wrote = (long)write(poller->poller.fd, poller->outBuf + poller->outOffset, (size_t)poller->outNbytes);
    if (wrote > 0) {
      poller->outOffset += wrote;
      poller->outNbytes -= wrote;
      continue;
    }

    if (wrote == 0) {
      return -1;
    }

    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0;
    }
    return -1;
  }

  poller->outOffset = 0;
  if (pollerDisableWriteInterest(poller) < 0) {
    return -1;
  }

  return 0;
}

static bool pollerQueueWrite(ioTcpPoller_t *poller, const void *data, long nbytes) {
  long used;
  bool needsCompact;
  long compactedUsed;

  if (poller == NULL || data == NULL || nbytes <= 0 || nbytes > IoPollerQueueCapacity) {
    return false;
  }

  used = poller->outOffset + poller->outNbytes;
  needsCompact = used + nbytes > IoPollerQueueCapacity && poller->outOffset > 0;
  compactedUsed = needsCompact ? poller->outNbytes : used;
  if (compactedUsed + nbytes > IoPollerQueueCapacity) {
    return false;
  }
  if (poller->poller.reactor != NULL && pollerEnsureWriteInterest(poller) < 0) {
    return false;
  }
  if (needsCompact) {
    memmove(poller->outBuf, poller->outBuf + poller->outOffset, (size_t)poller->outNbytes);
    poller->outOffset = 0;
  }
  memcpy(poller->outBuf + compactedUsed, data, (size_t)nbytes);
  poller->outNbytes += nbytes;
  return true;
}

static bool pollerSetReadEnabled(ioTcpPoller_t *poller, bool enabled) {
  unsigned int nextEvents = poller->poller.events;

  if (enabled) {
    nextEvents |= EPOLLIN;
  } else {
    nextEvents &= ~EPOLLIN;
  }
  return pollerMod(poller, nextEvents) == 0;
}

static int tunFrameNext(int index) {
  return (index + 1) % IoTunQueueFrameCapacity;
}

static void pollerDispose(ioPoller_t *poller) {
  if (poller == NULL) {
    return;
  }
  if (poller->fd >= 0) {
    if (poller->reactor != NULL && poller->reactor->epollFd >= 0) {
      (void)epoll_ctl(poller->reactor->epollFd, EPOLL_CTL_DEL, poller->fd, NULL);
    }
    (void)close(poller->fd);
  }
  poller->reactor = NULL;
  poller->fd = -1;
  poller->events = 0;
  poller->callbacks = NULL;
  poller->ctx = NULL;
  poller->readEnabled = false;
}

static bool tunQueueWrite(ioTunPoller_t *poller, const void *data, long nbytes) {
  long start = -1;
  long tailSpace;

  if (poller == NULL || data == NULL || nbytes <= 0 || nbytes > IoPollerQueueCapacity) {
    return false;
  }
  if (poller->frameCount >= IoTunQueueFrameCapacity) {
    return false;
  }

  if (poller->frameCount == 0) {
    poller->readPos = 0;
    poller->writePos = 0;
    start = 0;
  } else if (poller->writePos < poller->readPos) {
    if (nbytes <= (poller->readPos - poller->writePos)) {
      start = poller->writePos;
    }
  } else {
    tailSpace = IoPollerQueueCapacity - poller->writePos;
    if (nbytes <= tailSpace) {
      start = poller->writePos;
    } else if (nbytes <= poller->readPos) {
      start = 0;
    }
  }

  if (start < 0 || start + nbytes > IoPollerQueueCapacity) {
    return false;
  }

  memcpy(poller->outBuf + start, data, (size_t)nbytes);
  poller->frames[poller->frameTail].start = start;
  poller->frames[poller->frameTail].nbytes = nbytes;
  poller->frameTail = tunFrameNext(poller->frameTail);
  poller->frameCount++;
  poller->queuedBytes += nbytes;
  poller->writePos = start + nbytes;
  if (poller->writePos == IoPollerQueueCapacity) {
    poller->writePos = 0;
  }
  return true;
}

static bool tunQueueCanWrite(const ioTunPoller_t *poller, long nbytes) {
  long start = -1;
  long tailSpace;

  if (poller == NULL || nbytes <= 0 || nbytes > IoPollerQueueCapacity) {
    return false;
  }
  if (poller->frameCount >= IoTunQueueFrameCapacity) {
    return false;
  }

  if (poller->frameCount == 0) {
    start = 0;
  } else if (poller->writePos < poller->readPos) {
    if (nbytes <= (poller->readPos - poller->writePos)) {
      start = poller->writePos;
    }
  } else {
    tailSpace = IoPollerQueueCapacity - poller->writePos;
    if (nbytes <= tailSpace) {
      start = poller->writePos;
    } else if (nbytes <= poller->readPos) {
      start = 0;
    }
  }

  return start >= 0 && start + nbytes <= IoPollerQueueCapacity;
}

static int tunQueueFlush(ioTunPoller_t *poller) {
  while (poller->frameCount > 0) {
    const long start = poller->frames[poller->frameHead].start;
    const long nbytes = poller->frames[poller->frameHead].nbytes;
    long wrote;

    if (start < 0 || nbytes <= 0 || start + nbytes > IoPollerQueueCapacity) {
      return -1;
    }

    wrote = (long)write(poller->poller.fd, poller->outBuf + start, (size_t)nbytes);
    if (wrote == nbytes) {
      poller->queuedBytes -= nbytes;
      poller->frameHead = tunFrameNext(poller->frameHead);
      poller->frameCount--;
      if (poller->frameCount == 0) {
        poller->readPos = 0;
        poller->writePos = 0;
      } else {
        poller->readPos = poller->frames[poller->frameHead].start;
      }
      continue;
    }
    if (wrote < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
      return 0;
    }
    return -1;
  }

  if ((poller->poller.events & EPOLLOUT) != 0) {
    if (poller->poller.reactor != NULL
        && poller->poller.reactor->epollFd >= 0
        && pollerCtlPoller(
               poller->poller.reactor->epollFd,
               EPOLL_CTL_MOD,
               &poller->poller,
               poller->poller.events & ~EPOLLOUT) < 0) {
      return -1;
    }
  }
  poller->poller.events &= ~EPOLLOUT;
  poller->poller.readEnabled = (poller->poller.events & EPOLLIN) != 0;
  return 0;
}

static bool tunSetReadEnabled(ioTunPoller_t *poller, bool enabled) {
  unsigned int nextEvents;

  if (poller == NULL) {
    return false;
  }
  nextEvents = poller->poller.events;
  if (enabled) {
    nextEvents |= EPOLLIN;
  } else {
    nextEvents &= ~EPOLLIN;
  }
  if (nextEvents == poller->poller.events) {
    return true;
  }
  if (poller->poller.reactor != NULL
      && poller->poller.reactor->epollFd >= 0
      && pollerCtlPoller(poller->poller.reactor->epollFd, EPOLL_CTL_MOD, &poller->poller, nextEvents) < 0) {
    return false;
  }
  poller->poller.events = nextEvents;
  poller->poller.readEnabled = (poller->poller.events & EPOLLIN) != 0;
  return true;
}

bool ioReactorInit(ioReactor_t *reactor) {
  if (reactor == NULL) {
    return false;
  }
  reactor->epollFd = epoll_create1(0);
  return reactor->epollFd >= 0;
}

void ioReactorDispose(ioReactor_t *reactor) {
  if (reactor == NULL) {
    return;
  }
  if (reactor->epollFd >= 0) {
    close(reactor->epollFd);
  }
  reactor->epollFd = -1;
}

bool ioReactorAddPoller(
    ioReactor_t *reactor,
    ioPoller_t *poller,
    const ioPollerCallbacks_t *callbacks,
    void *ctx,
    bool readEnabled) {
  unsigned int events;

  if (reactor == NULL || poller == NULL || callbacks == NULL || reactor->epollFd < 0 || poller->fd < 0) {
    return false;
  }

  events = EPOLLRDHUP;
  if ((poller->events & EPOLLOUT) != 0) {
    events |= EPOLLOUT;
  }
  if (readEnabled) {
    events |= EPOLLIN;
  }

  poller->reactor = reactor;
  poller->callbacks = callbacks;
  poller->ctx = ctx;
  poller->readEnabled = readEnabled;
  poller->events = events;

  return pollerCtlPoller(reactor->epollFd, EPOLL_CTL_ADD, poller, events) == 0;
}

bool ioReactorSetPollerReadEnabled(ioPoller_t *poller, bool enabled) {
  unsigned int events;

  if (poller == NULL || poller->reactor == NULL || poller->reactor->epollFd < 0 || poller->fd < 0) {
    return false;
  }

  events = poller->events;
  if (enabled) {
    events |= EPOLLIN;
  } else {
    events &= ~EPOLLIN;
  }
  if (pollerCtlPoller(poller->reactor->epollFd, EPOLL_CTL_MOD, poller, events) < 0) {
    return false;
  }

  poller->events = events;
  poller->readEnabled = enabled;
  return true;
}

static ioReactorStepResult_t ioReactorApplyAction(
    ioPoller_t *poller,
    ioPollerAction_t action,
    bool *removed,
    bool *stopChain) {
  if (action == ioPollerContinue) {
    return ioReactorStepReady;
  }
  if (action == ioPollerStop) {
    return ioReactorStepStop;
  }
  if (action == ioPollerRemove) {
    if (poller->reactor == NULL
        || poller->reactor->epollFd < 0
        || epoll_ctl(poller->reactor->epollFd, EPOLL_CTL_DEL, poller->fd, NULL) < 0) {
      return ioReactorStepError;
    }
    poller->reactor = NULL;
    poller->events = 0;
    *removed = true;
    *stopChain = true;
    return ioReactorStepReady;
  }
  if (action == ioPollerRetargeted) {
    *stopChain = true;
    return ioReactorStepReady;
  }
  return ioReactorStepError;
}

static bool pollerServiceWritable(ioPoller_t *poller, long *outBefore, long *outAfter) {
  ioTcpPoller_t *tcp = tcpFromPoller(poller);
  ioTunPoller_t *tun = tunFromPoller(poller);

  if (outBefore == NULL || outAfter == NULL) {
    return false;
  }

  if (tcp != NULL) {
    *outBefore = tcp->outNbytes;
    if (pollerFlushQueue(tcp) < 0) {
      return false;
    }
    *outAfter = tcp->outNbytes;
    return true;
  }

  if (tun != NULL) {
    *outBefore = tun->queuedBytes;
    if (tunQueueFlush(tun) < 0) {
      return false;
    }
    *outAfter = tun->queuedBytes;
    return true;
  }

  *outBefore = -1;
  *outAfter = -1;
  return true;
}

ioReactorStepResult_t ioReactorStep(ioReactor_t *reactor, int timeoutMs) {
  struct epoll_event events[8];
  int n;
  int i;

  if (reactor == NULL || reactor->epollFd < 0) {
    return ioReactorStepError;
  }

  n = epoll_wait(reactor->epollFd, events, (int)(sizeof(events) / sizeof(events[0])), timeoutMs);
  if (n < 0) {
    return ioReactorStepError;
  }
  if (n == 0) {
    return ioReactorStepTimeout;
  }

  for (i = 0; i < n; i++) {
    ioPoller_t *poller = (ioPoller_t *)events[i].data.ptr;
    ioReactorStepResult_t result;
    long queuedBefore = -1;
    long queuedAfter = -1;
    bool removed = false;
    bool stopChain = false;

    if (poller == NULL || poller->callbacks == NULL) {
      return ioReactorStepError;
    }

    if ((events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0 && poller->callbacks->onClosed != NULL) {
      result = ioReactorApplyAction(poller, poller->callbacks->onClosed(poller->ctx, poller), &removed, &stopChain);
      if (result == ioReactorStepStop || result == ioReactorStepError) {
        return result;
      }
      if (stopChain || removed) {
        continue;
      }
    }

    if ((events[i].events & EPOLLOUT) != 0) {
      if (!pollerServiceWritable(poller, &queuedBefore, &queuedAfter)) {
        if (poller->callbacks->onClosed != NULL) {
          result = ioReactorApplyAction(poller, poller->callbacks->onClosed(poller->ctx, poller), &removed, &stopChain);
          if (result == ioReactorStepStop || result == ioReactorStepError) {
            return result;
          }
          continue;
        }
        return ioReactorStepError;
      }
      if (poller->callbacks->onLowWatermark != NULL
          && queuedBefore > IoPollerLowWatermark
          && queuedAfter <= IoPollerLowWatermark) {
        result = ioReactorApplyAction(
            poller,
            poller->callbacks->onLowWatermark(poller->ctx, poller, queuedAfter),
            &removed,
            &stopChain);
        if (result == ioReactorStepStop || result == ioReactorStepError) {
          return result;
        }
        if (stopChain || removed) {
          continue;
        }
      }
    }

    if ((events[i].events & EPOLLIN) != 0 && poller->callbacks->onReadable != NULL) {
      result = ioReactorApplyAction(
          poller,
          poller->callbacks->onReadable(poller->ctx, reactor, poller),
          &removed,
          &stopChain);
      if (result == ioReactorStepStop || result == ioReactorStepError) {
        return result;
      }
      if (stopChain || removed) {
        continue;
      }
    }
  }

  return ioReactorStepReady;
}

static ioStatus_t ioReadSome(int fd, void *buf, long capacity, long *outNbytes) {
  long nbytes;

  if (outNbytes == NULL || buf == NULL || capacity <= 0) {
    return ioStatusError;
  }

  nbytes = (long)read(fd, buf, (size_t)capacity);
  if (nbytes > 0) {
    *outNbytes = nbytes;
    return ioStatusOk;
  }

  *outNbytes = 0;
  if (nbytes == 0) {
    return ioStatusClosed;
  }
  if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
    return ioStatusWouldBlock;
  }
  return ioStatusError;
}

ioStatus_t ioPollerRead(ioPoller_t *poller, void *buf, long capacity, long *outNbytes) {
  if (poller == NULL || poller->fd < 0) {
    if (outNbytes != NULL) {
      *outNbytes = 0;
    }
    return ioStatusError;
  }
  return ioReadSome(poller->fd, buf, capacity, outNbytes);
}

int ioTunOpen(const char *ifName, ioIfMode_t mode) {
  struct ifreq ifr;
  int fd;
  short ifFlags = 0;

  if (ifName == NULL || ifName[0] == '\0') {
    return -1;
  }
  if (mode == ioIfModeTun) {
    ifFlags = IFF_TUN;
  } else if (mode == ioIfModeTap) {
    ifFlags = IFF_TAP;
  } else {
    return -1;
  }

  fd = open("/dev/net/tun", O_RDWR);
  if (fd < 0) {
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = ifFlags;
  strncpy(ifr.ifr_name, ifName, IFNAMSIZ - 1);
  ifr.ifr_name[IFNAMSIZ - 1] = '\0';
  if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
    close(fd);
    return -1;
  }

  return fd;
}

static int ioPortValid(int port) {
  return port > 0 && port <= 65535;
}

static int fillPeerInfo(const struct sockaddr_in *clientAddr, char *peerIp, long peerIpSize, int *peerPort) {
  if (peerIp != NULL) {
    if (peerIpSize <= 0) {
      return -1;
    }
    if (inet_ntop(AF_INET, &clientAddr->sin_addr, peerIp, (socklen_t)peerIpSize) == NULL) {
      return -1;
    }
  }
  if (peerPort != NULL) {
    *peerPort = (int)ntohs(clientAddr->sin_port);
  }
  return 0;
}

int ioTcpListen(const char *listenIP, int port) {
  int listenFd;
  struct sockaddr_in serverAddr;

  if (listenIP == NULL || !ioPortValid(port)) {
    return -1;
  }

  listenFd = socket(AF_INET, SOCK_STREAM, 0);
  if (listenFd < 0) {
    return -1;
  }

  memset(&serverAddr, 0, sizeof(serverAddr));
  serverAddr.sin_family = AF_INET;
  if (inet_pton(AF_INET, listenIP, &serverAddr.sin_addr) != 1) {
    close(listenFd);
    return -1;
  }
  serverAddr.sin_port = htons((unsigned short)port);

  if (bind(listenFd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0
      || listen(listenFd, IoTcpListenBacklog) < 0) {
    close(listenFd);
    return -1;
  }

  return listenFd;
}

ioStatus_t ioTcpAcceptNonBlocking(int listenFd, int *outConnFd, char *peerIp, long peerIpSize, int *peerPort) {
  struct sockaddr_in clientAddr;
  socklen_t addrLen = sizeof(clientAddr);
  int listenFlags;
  bool restoreListenFlags = false;
  int connFd;

  if (outConnFd == NULL) {
    return ioStatusError;
  }
  *outConnFd = -1;

  listenFlags = fcntl(listenFd, F_GETFL, 0);
  if (listenFlags < 0) {
    return ioStatusError;
  }
  if ((listenFlags & O_NONBLOCK) == 0) {
    if (fcntl(listenFd, F_SETFL, listenFlags | O_NONBLOCK) < 0) {
      return ioStatusError;
    }
    restoreListenFlags = true;
  }

  connFd = accept(listenFd, (struct sockaddr *)&clientAddr, &addrLen);
  if (restoreListenFlags) {
    (void)fcntl(listenFd, F_SETFL, listenFlags);
  }
  if (connFd < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
      return ioStatusWouldBlock;
    }
    return ioStatusError;
  }
  if (pollerSetNonBlocking(connFd) < 0) {
    close(connFd);
    return ioStatusError;
  }

  if (fillPeerInfo(&clientAddr, peerIp, peerIpSize, peerPort) != 0) {
    close(connFd);
    return ioStatusError;
  }

  *outConnFd = connFd;
  return ioStatusOk;
}

int ioTcpConnect(const char *remoteIP, int port) {
  int connFd;
  struct sockaddr_in remoteAddr;

  if (remoteIP == NULL || !ioPortValid(port)) {
    return -1;
  }

  connFd = socket(AF_INET, SOCK_STREAM, 0);
  if (connFd < 0) {
    return -1;
  }

  memset(&remoteAddr, 0, sizeof(remoteAddr));
  remoteAddr.sin_family = AF_INET;
  if (inet_pton(AF_INET, remoteIP, &remoteAddr.sin_addr) != 1) {
    close(connFd);
    return -1;
  }
  remoteAddr.sin_port = htons((unsigned short)port);

  if (connect(connFd, (struct sockaddr *)&remoteAddr, sizeof(remoteAddr)) < 0) {
    close(connFd);
    return -1;
  }

  return connFd;
}

bool ioPollerListen(ioListenPoller_t *poller, const char *listenIP, int port) {
  int listenFd;

  if (poller == NULL) {
    return false;
  }

  listenFd = ioTcpListen(listenIP, port);
  if (listenFd < 0) {
    return false;
  }
  if (pollerSetNonBlocking(listenFd) < 0) {
    close(listenFd);
    return false;
  }

  memset(poller, 0, sizeof(*poller));
  poller->poller.reactor = NULL;
  poller->poller.fd = listenFd;
  poller->poller.events = EPOLLIN | EPOLLRDHUP;
  poller->poller.kind = ioPollerKindListen;
  poller->poller.readEnabled = true;
  return true;
}

ioStatus_t ioPollerAccept(
    ioListenPoller_t *listenPoller,
    ioTcpPoller_t *outTcpPoller,
    char *peerIp,
    long peerIpSize,
    int *peerPort) {
  ioStatus_t status;
  int connFd = -1;

  if (listenPoller == NULL || outTcpPoller == NULL || listenPoller->poller.fd < 0) {
    return ioStatusError;
  }

  status = ioTcpAcceptNonBlocking(listenPoller->poller.fd, &connFd, peerIp, peerIpSize, peerPort);
  if (status != ioStatusOk) {
    return status;
  }

  memset(outTcpPoller, 0, sizeof(*outTcpPoller));
  outTcpPoller->poller.reactor = NULL;
  outTcpPoller->poller.fd = connFd;
  outTcpPoller->poller.events = EPOLLIN | EPOLLRDHUP;
  outTcpPoller->poller.kind = ioPollerKindTcp;
  outTcpPoller->poller.readEnabled = true;
  return ioStatusOk;
}

bool ioPollerConnect(ioTcpPoller_t *poller, const char *remoteIP, int port) {
  int connFd;

  if (poller == NULL) {
    return false;
  }

  connFd = ioTcpConnect(remoteIP, port);
  if (connFd < 0) {
    return false;
  }
  if (pollerSetNonBlocking(connFd) < 0) {
    close(connFd);
    return false;
  }

  memset(poller, 0, sizeof(*poller));
  poller->poller.reactor = NULL;
  poller->poller.fd = connFd;
  poller->poller.events = EPOLLIN | EPOLLRDHUP;
  poller->poller.kind = ioPollerKindTcp;
  poller->poller.readEnabled = true;
  return true;
}

bool ioTcpPollerHandoff(
    ioTcpPoller_t *dst,
    ioTcpPoller_t *src,
    const ioPollerCallbacks_t *callbacks,
    void *ctx,
    bool readEnabled) {
  ioTcpPoller_t dstBefore;
  ioTcpPoller_t srcBefore;
  unsigned int nextEvents;

  if (dst == NULL || src == NULL || callbacks == NULL || dst == src) {
    return false;
  }
  if (src->poller.reactor == NULL
      || src->poller.reactor->epollFd < 0
      || src->poller.fd < 0
      || src->poller.kind != ioPollerKindTcp) {
    return false;
  }
  if (dst->poller.reactor != NULL || dst->poller.fd > 0 || dst->outNbytes != 0 || dst->outOffset != 0) {
    return false;
  }

  dstBefore = *dst;
  srcBefore = *src;
  *dst = *src;
  dst->poller.kind = ioPollerKindTcp;
  dst->poller.callbacks = callbacks;
  dst->poller.ctx = ctx;

  nextEvents = dst->poller.events;
  if (readEnabled) {
    nextEvents |= EPOLLIN;
  } else {
    nextEvents &= ~EPOLLIN;
  }
  dst->poller.events = nextEvents;
  dst->poller.readEnabled = readEnabled;

  if (pollerCtlPoller(src->poller.reactor->epollFd, EPOLL_CTL_MOD, &dst->poller, dst->poller.events) < 0) {
    *dst = dstBefore;
    *src = srcBefore;
    return false;
  }

  memset(src, 0, sizeof(*src));
  src->poller.fd = -1;
  src->poller.kind = ioPollerKindTcp;
  return true;
}

void ioListenPollerDispose(ioListenPoller_t *poller) {
  if (poller == NULL) {
    return;
  }
  pollerDispose(&poller->poller);
}

void ioTcpPollerDispose(ioTcpPoller_t *poller) {
  if (poller == NULL) {
    return;
  }
  pollerDispose(&poller->poller);
  poller->outOffset = 0;
  poller->outNbytes = 0;
  memset(poller->outBuf, 0, sizeof(poller->outBuf));
}

bool ioPollerOpenTun(ioTunPoller_t *poller, const char *ifName, ioIfMode_t mode) {
  int tunFd;

  if (poller == NULL) {
    return false;
  }

  tunFd = ioTunOpen(ifName, mode);
  if (tunFd < 0) {
    return false;
  }
  if (pollerSetNonBlocking(tunFd) < 0) {
    close(tunFd);
    return false;
  }

  memset(poller, 0, sizeof(*poller));
  poller->poller.reactor = NULL;
  poller->poller.fd = tunFd;
  poller->poller.events = EPOLLIN | EPOLLRDHUP;
  poller->poller.kind = ioPollerKindTun;
  poller->poller.readEnabled = true;
  return true;
}

void ioTunPollerDispose(ioTunPoller_t *poller) {
  if (poller == NULL) {
    return;
  }
  pollerDispose(&poller->poller);
  poller->readPos = 0;
  poller->writePos = 0;
  poller->queuedBytes = 0;
  poller->frameHead = 0;
  poller->frameTail = 0;
  poller->frameCount = 0;
  memset(poller->frames, 0, sizeof(poller->frames));
  memset(poller->outBuf, 0, sizeof(poller->outBuf));
}

bool ioTcpWrite(ioTcpPoller_t *poller, const void *data, long nbytes) {
  bool ok;
  if (poller == NULL) {
    return false;
  }
  ok = pollerQueueWrite(poller, data, nbytes);
  return ok;
}

bool ioTunWrite(ioTunPoller_t *poller, const void *data, long nbytes) {
  bool needWriteInterest;
  if (poller == NULL) {
    return false;
  }
  if (!tunQueueCanWrite(poller, nbytes)) {
    return false;
  }
  needWriteInterest = poller->poller.reactor != NULL
      && poller->poller.reactor->epollFd >= 0
      && (poller->poller.events & EPOLLOUT) == 0;
  if (needWriteInterest
      && pollerCtlPoller(
             poller->poller.reactor->epollFd,
             EPOLL_CTL_MOD,
             &poller->poller,
             poller->poller.events | EPOLLOUT) < 0) {
    return false;
  }
  if (needWriteInterest) {
    poller->poller.events |= EPOLLOUT;
    poller->poller.readEnabled = (poller->poller.events & EPOLLIN) != 0;
  }
  if (!tunQueueWrite(poller, data, nbytes)) {
    return false;
  }
  return true;
}

bool ioTcpSetReadEnabled(ioTcpPoller_t *poller, bool enabled) {
  bool ok;
  if (poller == NULL) {
    return false;
  }
  ok = pollerSetReadEnabled(poller, enabled);
  return ok;
}

bool ioTunSetReadEnabled(ioTunPoller_t *poller, bool enabled) {
  bool ok;
  if (poller == NULL) {
    return false;
  }
  ok = tunSetReadEnabled(poller, enabled);
  return ok;
}

long ioTcpQueuedBytes(const ioTcpPoller_t *poller) {
  if (poller == NULL) {
    return -1;
  }
  return poller->outNbytes;
}

long ioTunQueuedBytes(const ioTunPoller_t *poller) {
  if (poller == NULL) {
    return -1;
  }
  return poller->queuedBytes;
}
