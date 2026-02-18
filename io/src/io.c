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
  int fd;
  unsigned int *events;
  long *outOffset;
  long *outNbytes;
  unsigned char *outBuf;
} ioQueueState_t;

static ioQueueState_t queueState(ioPoller_t *poller, ioSource_t source) {
  if (source == ioSourceTun) {
    ioQueueState_t state = {
      .fd = poller->tunFd,
      .events = &poller->tunEvents,
      .outOffset = &poller->tunOutOffset,
      .outNbytes = &poller->tunOutNbytes,
      .outBuf = poller->tunOutBuf,
    };
    return state;
  }

  ioQueueState_t state = {
    .fd = poller->tcpFd,
    .events = &poller->tcpEvents,
    .outOffset = &poller->tcpOutOffset,
    .outNbytes = &poller->tcpOutNbytes,
    .outBuf = poller->tcpOutBuf,
  };
  return state;
}

static int sourceValid(ioSource_t source) {
  return source == ioSourceTun || source == ioSourceTcp;
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

static int pollerMod(ioPoller_t *poller, ioSource_t source, unsigned int events) {
  ioQueueState_t state = queueState(poller, source);
  if (pollerCtl(poller->epollFd, EPOLL_CTL_MOD, state.fd, events) < 0) {
    return -1;
  }
  *state.events = events;
  return 0;
}

static int pollerEnsureWriteInterest(ioPoller_t *poller, ioSource_t source) {
  ioQueueState_t state = queueState(poller, source);
  if ((*state.events & EPOLLOUT) != 0) {
    return 0;
  }
  return pollerMod(poller, source, *state.events | EPOLLOUT);
}

static int pollerDisableWriteInterest(ioPoller_t *poller, ioSource_t source) {
  ioQueueState_t state = queueState(poller, source);
  if ((*state.events & EPOLLOUT) == 0) {
    return 0;
  }
  return pollerMod(poller, source, *state.events & ~EPOLLOUT);
}

static int pollerFlushQueue(ioPoller_t *poller, ioSource_t source) {
  ioQueueState_t state = queueState(poller, source);

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
  if (pollerDisableWriteInterest(poller, source) < 0) {
    return -1;
  }

  return 0;
}

bool ioWriteAll(int fd, const void *data, long nbytes) {
  long i = 0;
  const char *buf = (const char *)data;

  while (i < nbytes) {
    long wrote = (long)write(fd, buf + i, (size_t)(nbytes - i));
    if (wrote <= 0) {
      return false;
    }
    i += wrote;
  }
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

int ioTunOpen(const char *ifName) {
  struct ifreq ifr;
  int fd;

  if (ifName == NULL || ifName[0] == '\0') {
    return -1;
  }

  fd = open("/dev/net/tun", O_RDWR);
  if (fd < 0) {
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN;
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

  if (bind(listenFd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0 || listen(listenFd, 1) < 0) {
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

  if (peerIp != NULL) {
    if (peerIpSize <= 0) {
      close(connFd);
      return -1;
    }
    if (inet_ntop(AF_INET, &clientAddr.sin_addr, peerIp, (socklen_t)peerIpSize) == NULL) {
      close(connFd);
      return -1;
    }
  }
  if (peerPort != NULL) {
    *peerPort = (int)ntohs(clientAddr.sin_port);
  }

  return connFd;
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

int ioPollerInit(ioPoller_t *poller, int tunFd, int tcpFd) {
  int epollFd;

  if (poller == NULL) {
    return -1;
  }

  if (pollerSetNonBlocking(tunFd) < 0 || pollerSetNonBlocking(tcpFd) < 0) {
    return -1;
  }

  epollFd = epoll_create1(0);
  if (epollFd < 0) {
    return -1;
  }

  poller->epollFd = epollFd;
  poller->tunFd = tunFd;
  poller->tcpFd = tcpFd;
  poller->tunEvents = EPOLLIN | EPOLLRDHUP;
  poller->tcpEvents = EPOLLIN | EPOLLRDHUP;
  poller->tunOutOffset = 0;
  poller->tunOutNbytes = 0;
  poller->tcpOutOffset = 0;
  poller->tcpOutNbytes = 0;

  if (pollerAdd(epollFd, tunFd, poller->tunEvents) < 0 || pollerAdd(epollFd, tcpFd, poller->tcpEvents) < 0) {
    ioPollerClose(poller);
    return -1;
  }

  return 0;
}

void ioPollerClose(ioPoller_t *poller) {
  if (poller == NULL) {
    return;
  }
  if (poller->epollFd >= 0) {
    close(poller->epollFd);
    poller->epollFd = -1;
  }
}

bool ioPollerQueueWrite(ioPoller_t *poller, ioSource_t source, const void *data, long nbytes) {
  ioQueueState_t state;
  long used;

  if (poller == NULL || data == NULL || nbytes <= 0 || nbytes > IoPollerQueueCapacity) {
    return false;
  }

  state = queueState(poller, source);
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

  if (pollerEnsureWriteInterest(poller, source) < 0) {
    return false;
  }

  return true;
}

bool ioPollerSetReadEnabled(ioPoller_t *poller, ioSource_t source, bool enabled) {
  ioQueueState_t state;
  unsigned int nextEvents;

  if (poller == NULL || poller->epollFd < 0 || !sourceValid(source)) {
    return false;
  }

  state = queueState(poller, source);
  nextEvents = *state.events;
  if (enabled) {
    nextEvents |= EPOLLIN;
  } else {
    nextEvents &= ~EPOLLIN;
  }

  return pollerMod(poller, source, nextEvents) == 0;
}

long ioPollerQueuedBytes(const ioPoller_t *poller, ioSource_t source) {
  if (poller == NULL || !sourceValid(source)) {
    return -1;
  }
  if (source == ioSourceTun) {
    return poller->tunOutNbytes;
  }
  return poller->tcpOutNbytes;
}

ioEvent_t ioPollerWait(ioPoller_t *poller, int timeoutMs) {
  struct epoll_event event;
  int n;

  if (poller == NULL || poller->epollFd < 0) {
    return ioEventError;
  }

  n = epoll_wait(poller->epollFd, &event, 1, timeoutMs);
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
    if (event.data.fd == poller->tunFd) {
      if (pollerFlushQueue(poller, ioSourceTun) < 0) {
        return ioEventError;
      }
      return ioEventTunWrite;
    }
    if (event.data.fd == poller->tcpFd) {
      if (pollerFlushQueue(poller, ioSourceTcp) < 0) {
        return ioEventError;
      }
      return ioEventTcpWrite;
    }
    return ioEventError;
  }

  if (event.events & EPOLLIN) {
    if (event.data.fd == poller->tunFd) {
      return ioEventTunRead;
    }
    if (event.data.fd == poller->tcpFd) {
      return ioEventTcpRead;
    }
  }

  return ioEventError;
}
