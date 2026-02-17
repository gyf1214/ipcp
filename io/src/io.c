#include <unistd.h>
#include <sys/epoll.h>

#include "io.h"

static int pollerAdd(int epollFd, int fd) {
  struct epoll_event event;
  event.events = EPOLLIN | EPOLLRDHUP;
  event.data.fd = fd;
  return epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &event);
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
  return ioStatusError;
}

int ioPollerInit(ioPoller_t *poller, int tunFd, int tcpFd) {
  int epollFd;

  if (poller == NULL) {
    return -1;
  }

  epollFd = epoll_create1(0);
  if (epollFd < 0) {
    return -1;
  }

  poller->epollFd = epollFd;
  poller->tunFd = tunFd;
  poller->tcpFd = tcpFd;

  if (pollerAdd(epollFd, tunFd) < 0 || pollerAdd(epollFd, tcpFd) < 0) {
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
  if (event.events & EPOLLIN) {
    if (event.data.fd == poller->tunFd) {
      return ioEventTun;
    }
    if (event.data.fd == poller->tcpFd) {
      return ioEventTcp;
    }
  }

  return ioEventError;
}
