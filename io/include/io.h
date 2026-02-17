#pragma once

#include <stdbool.h>

typedef enum {
  ioStatusOk = 0,
  ioStatusClosed,
  ioStatusError,
} ioStatus_t;

typedef enum {
  ioEventTun = 0,
  ioEventTcp,
  ioEventTimeout,
  ioEventError,
} ioEvent_t;

typedef struct {
  int epollFd;
  int tunFd;
  int tcpFd;
} ioPoller_t;

bool ioWriteAll(int fd, const void *data, long nbytes);
ioStatus_t ioReadSome(int fd, void *buf, long capacity, long *outNbytes);
int ioTunOpen(const char *ifName);
int ioTcpListen(const char *listenIP, int port);
int ioTcpAccept(int listenFd, char *peerIp, long peerIpSize, int *peerPort);
int ioTcpConnect(const char *remoteIP, int port);

int ioPollerInit(ioPoller_t *poller, int tunFd, int tcpFd);
void ioPollerClose(ioPoller_t *poller);
ioEvent_t ioPollerWait(ioPoller_t *poller, int timeoutMs);
