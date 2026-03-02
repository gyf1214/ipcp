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
#define IoPollerLowWatermark 49152
#define IoTcpListenBacklog 16

typedef enum {
  ioIfModeTun = 0,
  ioIfModeTap,
} ioIfMode_t;

typedef struct {
  int epollFd;
  int tcpFd;
  unsigned int events;
  long outOffset;
  long outNbytes;
  unsigned char outBuf[IoPollerQueueCapacity];
} ioTcpPoller_t;

typedef struct {
  int epollFd;
  int tunFd;
  unsigned int events;
  long outOffset;
  long outNbytes;
  unsigned char outBuf[IoPollerQueueCapacity];
} ioTunPoller_t;

typedef enum {
  ioSourceTun = 0,
  ioSourceTcp,
} ioSource_t;

ioStatus_t ioReadSome(int fd, void *buf, long capacity, long *outNbytes);
ioStatus_t ioTcpRead(int tcpFd, void *buf, long capacity, long *outNbytes);
ioStatus_t ioTunRead(int tunFd, void *buf, long capacity, long *outNbytes);
int ioTunOpen(const char *ifName, ioIfMode_t mode);
int ioTcpListen(const char *listenIP, int port);
int ioTcpAccept(int listenFd, char *peerIp, long peerIpSize, int *peerPort);
ioStatus_t ioTcpAcceptNonBlocking(int listenFd, int *outConnFd, char *peerIp, long peerIpSize, int *peerPort);
int ioTcpConnect(const char *remoteIP, int port);

int ioTcpPollerInit(ioTcpPoller_t *poller, int epollFd, int tcpFd);
void ioTcpPollerClose(ioTcpPoller_t *poller);
int ioTunPollerInit(ioTunPoller_t *poller, int epollFd, int tunFd);
void ioTunPollerClose(ioTunPoller_t *poller);
bool ioTcpWrite(ioTcpPoller_t *poller, const void *data, long nbytes);
bool ioTunWrite(ioTunPoller_t *poller, const void *data, long nbytes);
bool ioTcpServiceWriteEvent(ioTcpPoller_t *poller);
bool ioTunServiceWriteEvent(ioTunPoller_t *poller);
bool ioTcpSetReadEnabled(ioTcpPoller_t *poller, bool enabled);
bool ioTunSetReadEnabled(ioTunPoller_t *poller, bool enabled);
long ioTcpQueuedBytes(const ioTcpPoller_t *poller);
long ioTunQueuedBytes(const ioTunPoller_t *poller);
ioEvent_t ioPollersWait(ioTunPoller_t *tunPoller, ioTcpPoller_t *tcpPoller, int timeoutMs);
