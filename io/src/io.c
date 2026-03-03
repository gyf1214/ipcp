#include <errno.h>
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

typedef struct {
  int epollFd;
  int fd;
  unsigned int *events;
  long *outOffset;
  long *outNbytes;
  unsigned char *outBuf;
} ioQueueState_t;

static ioQueueState_t tcpQueueState(ioTcpPoller_t *poller) {
  ioQueueState_t state = {
    .epollFd = poller->epollFd,
    .fd = poller->tcpFd,
    .events = &poller->events,
    .outOffset = &poller->outOffset,
    .outNbytes = &poller->outNbytes,
    .outBuf = poller->outBuf,
  };
  return state;
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

static int pollerCtl(int epollFd, int op, int fd, unsigned int events) {
  struct epoll_event event;
  event.events = events;
  event.data.fd = fd;
  return epoll_ctl(epollFd, op, fd, &event);
}

static int pollerAdd(int epollFd, int fd, unsigned int events) {
  return pollerCtl(epollFd, EPOLL_CTL_ADD, fd, events);
}

static int pollerMod(ioQueueState_t state, unsigned int events) {
  if (pollerCtl(state.epollFd, EPOLL_CTL_MOD, state.fd, events) < 0) {
    return -1;
  }
  *state.events = events;
  return 0;
}

static int pollerEnsureWriteInterest(ioQueueState_t state) {
  if ((*state.events & EPOLLOUT) != 0) {
    return 0;
  }
  return pollerMod(state, *state.events | EPOLLOUT);
}

static int pollerDisableWriteInterest(ioQueueState_t state) {
  if ((*state.events & EPOLLOUT) == 0) {
    return 0;
  }
  return pollerMod(state, *state.events & ~EPOLLOUT);
}

static int pollerFlushQueue(ioQueueState_t state) {
  while (*state.outNbytes > 0) {
    long wrote = (long)write(state.fd, state.outBuf + *state.outOffset, (size_t)*state.outNbytes);
    if (wrote > 0) {
      *state.outOffset += wrote;
      *state.outNbytes -= wrote;
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

  *state.outOffset = 0;
  if (pollerDisableWriteInterest(state) < 0) {
    return -1;
  }

  return 0;
}

static bool pollerQueueWrite(ioQueueState_t state, const void *data, long nbytes) {
  long used;

  if (data == NULL || nbytes <= 0 || nbytes > IoPollerQueueCapacity) {
    return false;
  }

  used = *state.outOffset + *state.outNbytes;
  if (used + nbytes > IoPollerQueueCapacity && *state.outOffset > 0) {
    memmove(state.outBuf, state.outBuf + *state.outOffset, (size_t)*state.outNbytes);
    *state.outOffset = 0;
    used = *state.outNbytes;
  }
  if (used + nbytes > IoPollerQueueCapacity) {
    return false;
  }

  memcpy(state.outBuf + used, data, (size_t)nbytes);
  *state.outNbytes += nbytes;
  if (state.epollFd < 0) {
    return true;
  }
  return pollerEnsureWriteInterest(state) == 0;
}

static bool pollerSetReadEnabled(ioQueueState_t state, bool enabled) {
  unsigned int nextEvents = *state.events;

  if (state.epollFd < 0) {
    return false;
  }
  if (enabled) {
    nextEvents |= EPOLLIN;
  } else {
    nextEvents &= ~EPOLLIN;
  }
  return pollerMod(state, nextEvents) == 0;
}

static int tunFrameNext(int index) {
  return (index + 1) % IoTunQueueFrameCapacity;
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

static int tunQueueFlush(ioTunPoller_t *poller) {
  while (poller->frameCount > 0) {
    const long start = poller->frames[poller->frameHead].start;
    const long nbytes = poller->frames[poller->frameHead].nbytes;
    long wrote;

    if (start < 0 || nbytes <= 0 || start + nbytes > IoPollerQueueCapacity) {
      return -1;
    }

    wrote = (long)write(poller->tunFd, poller->outBuf + start, (size_t)nbytes);
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

  if ((poller->events & EPOLLOUT) != 0 && pollerCtl(poller->epollFd, EPOLL_CTL_MOD, poller->tunFd, poller->events & ~EPOLLOUT) < 0) {
    return -1;
  }
  poller->events &= ~EPOLLOUT;
  return 0;
}

static bool tunSetReadEnabled(ioTunPoller_t *poller, bool enabled) {
  unsigned int nextEvents;

  if (poller == NULL || poller->epollFd < 0) {
    return false;
  }

  nextEvents = poller->events;
  if (enabled) {
    nextEvents |= EPOLLIN;
  } else {
    nextEvents &= ~EPOLLIN;
  }
  if (nextEvents == poller->events) {
    return true;
  }
  if (pollerCtl(poller->epollFd, EPOLL_CTL_MOD, poller->tunFd, nextEvents) < 0) {
    return false;
  }
  poller->events = nextEvents;
  return true;
}

ioStatus_t ioReadSome(int fd, void *buf, long capacity, long *outNbytes) {
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

ioStatus_t ioTcpRead(int tcpFd, void *buf, long capacity, long *outNbytes) {
  return ioReadSome(tcpFd, buf, capacity, outNbytes);
}

ioStatus_t ioTunRead(int tunFd, void *buf, long capacity, long *outNbytes) {
  return ioReadSome(tunFd, buf, capacity, outNbytes);
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

static int fillPeerInfo(int connFd, const struct sockaddr_in *clientAddr, char *peerIp, long peerIpSize, int *peerPort) {
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
  (void)connFd;
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

int ioTcpAccept(int listenFd, char *peerIp, long peerIpSize, int *peerPort) {
  struct sockaddr_in clientAddr;
  socklen_t addrLen = sizeof(clientAddr);
  int connFd = accept(listenFd, (struct sockaddr *)&clientAddr, &addrLen);
  if (connFd < 0) {
    return -1;
  }

  if (fillPeerInfo(connFd, &clientAddr, peerIp, peerIpSize, peerPort) != 0) {
    close(connFd);
    return -1;
  }

  return connFd;
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

  if (fillPeerInfo(connFd, &clientAddr, peerIp, peerIpSize, peerPort) != 0) {
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

int ioTcpPollerInit(ioTcpPoller_t *poller, int epollFd, int tcpFd) {
  if (poller == NULL || tcpFd < 0 || epollFd < 0) {
    return -1;
  }
  if (pollerSetNonBlocking(tcpFd) < 0) {
    return -1;
  }

  memset(poller, 0, sizeof(*poller));
  poller->epollFd = epollFd;
  poller->tcpFd = tcpFd;
  poller->events = EPOLLIN | EPOLLRDHUP;
  poller->outOffset = 0;
  poller->outNbytes = 0;

  if (pollerAdd(epollFd, tcpFd, poller->events) < 0) {
    return -1;
  }
  return 0;
}

void ioTcpPollerClose(ioTcpPoller_t *poller) {
  (void)poller;
}

int ioTunPollerInit(ioTunPoller_t *poller, int epollFd, int tunFd) {
  if (poller == NULL || tunFd < 0 || epollFd < 0) {
    return -1;
  }
  if (pollerSetNonBlocking(tunFd) < 0) {
    return -1;
  }

  memset(poller, 0, sizeof(*poller));
  poller->epollFd = epollFd;
  poller->tunFd = tunFd;
  poller->events = EPOLLIN | EPOLLRDHUP;
  poller->readPos = 0;
  poller->writePos = 0;
  poller->queuedBytes = 0;
  poller->frameHead = 0;
  poller->frameTail = 0;
  poller->frameCount = 0;

  if (pollerAdd(epollFd, tunFd, poller->events) < 0) {
    return -1;
  }
  return 0;
}

void ioTunPollerClose(ioTunPoller_t *poller) {
  (void)poller;
}

bool ioTcpWrite(ioTcpPoller_t *poller, const void *data, long nbytes) {
  if (poller == NULL) {
    return false;
  }
  return pollerQueueWrite(tcpQueueState(poller), data, nbytes);
}

bool ioTunWrite(ioTunPoller_t *poller, const void *data, long nbytes) {
  if (poller == NULL) {
    return false;
  }
  if (!tunQueueWrite(poller, data, nbytes)) {
    return false;
  }
  if (poller->epollFd < 0 || (poller->events & EPOLLOUT) != 0) {
    return true;
  }
  if (pollerCtl(poller->epollFd, EPOLL_CTL_MOD, poller->tunFd, poller->events | EPOLLOUT) < 0) {
    return false;
  }
  poller->events |= EPOLLOUT;
  return true;
}

bool ioTcpServiceWriteEvent(ioTcpPoller_t *poller) {
  if (poller == NULL || poller->epollFd < 0) {
    return false;
  }
  return pollerFlushQueue(tcpQueueState(poller)) == 0;
}

bool ioTunServiceWriteEvent(ioTunPoller_t *poller) {
  if (poller == NULL || poller->epollFd < 0) {
    return false;
  }
  return tunQueueFlush(poller) == 0;
}

bool ioTcpSetReadEnabled(ioTcpPoller_t *poller, bool enabled) {
  if (poller == NULL) {
    return false;
  }
  return pollerSetReadEnabled(tcpQueueState(poller), enabled);
}

bool ioTunSetReadEnabled(ioTunPoller_t *poller, bool enabled) {
  if (poller == NULL) {
    return false;
  }
  return tunSetReadEnabled(poller, enabled);
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

ioEvent_t ioPollersWait(ioTunPoller_t *tunPoller, ioTcpPoller_t *tcpPoller, int timeoutMs) {
  struct epoll_event event;
  int n;

  if (tunPoller == NULL || tcpPoller == NULL || tunPoller->epollFd < 0 || tcpPoller->epollFd != tunPoller->epollFd) {
    return ioEventError;
  }

  n = epoll_wait(tunPoller->epollFd, &event, 1, timeoutMs);
  if (n < 0) {
    return ioEventError;
  }
  if (n == 0) {
    return ioEventTimeout;
  }

  if (event.events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) {
    return ioEventError;
  }

  if (event.events & EPOLLOUT) {
    if (event.data.fd == tunPoller->tunFd) {
      if (tunQueueFlush(tunPoller) < 0) {
        return ioEventError;
      }
      return ioEventTunWrite;
    }
    if (event.data.fd == tcpPoller->tcpFd) {
      if (pollerFlushQueue(tcpQueueState(tcpPoller)) < 0) {
        return ioEventError;
      }
      return ioEventTcpWrite;
    }
    return ioEventError;
  }

  if (event.events & EPOLLIN) {
    if (event.data.fd == tunPoller->tunFd) {
      return ioEventTunRead;
    }
    if (event.data.fd == tcpPoller->tcpFd) {
      return ioEventTcpRead;
    }
  }

  return ioEventError;
}
