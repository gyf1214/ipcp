#pragma once

#include <stdbool.h>

typedef enum {
  ioStatusOk = 0,
  ioStatusWouldBlock,
  ioStatusClosed,
  ioStatusError,
} ioStatus_t;

typedef enum {
  ioEventTunRead = 0,
  ioEventTcpRead,
  ioEventTunWrite,
  ioEventTcpWrite,
  ioEventTimeout,
  ioEventError,
} ioEvent_t;

#define IoPollerQueueCapacity 65536

typedef enum {
  ioSourceTun = 0,
  ioSourceTcp,
} ioSource_t;

typedef struct {
  int epollFd;
  int tunFd;
  int tcpFd;
  unsigned int tunEvents;
  unsigned int tcpEvents;
  long tunOutOffset;
  long tunOutNbytes;
  long tcpOutOffset;
  long tcpOutNbytes;
  unsigned char tunOutBuf[IoPollerQueueCapacity];
  unsigned char tcpOutBuf[IoPollerQueueCapacity];
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
bool ioPollerQueueWrite(ioPoller_t *poller, ioSource_t source, const void *data, long nbytes);
