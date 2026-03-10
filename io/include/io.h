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
#define IoTunQueueFrameCapacity 256

typedef enum {
  ioIfModeTun = 0,
  ioIfModeTap,
} ioIfMode_t;

typedef struct ioReactor_t ioReactor_t;
typedef struct ioPoller_t ioPoller_t;
typedef struct ioListenPoller_t ioListenPoller_t;
typedef struct ioTcpPoller_t ioTcpPoller_t;
typedef struct ioTunPoller_t ioTunPoller_t;

typedef enum {
  ioPollerContinue = 0,
  ioPollerRemove,
  ioPollerStop,
} ioPollerAction_t;

typedef enum {
  ioReactorStepReady = 0,
  ioReactorStepTimeout,
  ioReactorStepStop,
  ioReactorStepError,
} ioReactorStepResult_t;

typedef enum {
  ioPollerListen = 0,
  ioPollerTcp,
  ioPollerTun,
} ioPollerKind_t;

typedef ioPollerAction_t (*ioClosedFn_t)(void *ctx, ioPoller_t *poller);
typedef ioPollerAction_t (*ioLowWatermarkFn_t)(void *ctx, ioPoller_t *poller, long queuedBytes);
typedef ioPollerAction_t (*ioReadableFn_t)(void *ctx, ioReactor_t *reactor, ioPoller_t *poller);
typedef ioPollerAction_t (*ioListenReadableFn_t)(void *ctx, ioReactor_t *reactor, ioListenPoller_t *listenPoller);

typedef struct {
  ioClosedFn_t onClosed;
  ioLowWatermarkFn_t onLowWatermark;
  ioReadableFn_t onReadable;
} ioPollerCallbacks_t;

struct ioReactor_t {
  int epollFd;
};

struct ioPoller_t {
  int epollFd;
  int fd;
  unsigned int events;
  ioPollerKind_t kind;
  const ioPollerCallbacks_t *callbacks;
  void *ctx;
  bool readEnabled;
};

struct ioListenPoller_t {
  ioPoller_t poller;
};

struct ioTcpPoller_t {
  ioPoller_t poller;
  long outOffset;
  long outNbytes;
  unsigned char outBuf[IoPollerQueueCapacity];
};

struct ioTunPoller_t {
  ioPoller_t poller;
  long readPos;
  long writePos;
  long queuedBytes;
  int frameHead;
  int frameTail;
  int frameCount;
  struct {
    long start;
    long nbytes;
  } frames[IoTunQueueFrameCapacity];
  unsigned char outBuf[IoPollerQueueCapacity];
};

typedef enum {
  ioSourceTun = 0,
  ioSourceTcp,
} ioSource_t;

ioStatus_t ioReadSome(int fd, void *buf, long capacity, long *outNbytes);
ioStatus_t ioTcpRead(int tcpFd, void *buf, long capacity, long *outNbytes);
ioStatus_t ioTunRead(int tunFd, void *buf, long capacity, long *outNbytes);

bool ioReactorInit(ioReactor_t *reactor);
void ioReactorDeinit(ioReactor_t *reactor);
bool ioReactorAddPoller(
    ioReactor_t *reactor,
    ioPoller_t *poller,
    const ioPollerCallbacks_t *callbacks,
    void *ctx,
    bool readEnabled);
bool ioReactorSetPollerReadEnabled(ioPoller_t *poller, bool enabled);
ioReactorStepResult_t ioReactorStep(ioReactor_t *reactor, int timeoutMs);

int ioTunOpen(const char *ifName, ioIfMode_t mode);
int ioTcpListen(const char *listenIP, int port);
int ioTcpAccept(int listenFd, char *peerIp, long peerIpSize, int *peerPort);
ioStatus_t ioTcpAcceptNonBlocking(int listenFd, int *outConnFd, char *peerIp, long peerIpSize, int *peerPort);
int ioTcpConnect(const char *remoteIP, int port);
bool ioListenPollerListen(ioListenPoller_t *poller, const char *listenIP, int port);
ioStatus_t ioListenPollerAcceptNonBlocking(
    ioListenPoller_t *listenPoller,
    ioTcpPoller_t *outTcpPoller,
    char *peerIp,
    long peerIpSize,
    int *peerPort);
bool ioTcpPollerConnect(ioTcpPoller_t *poller, const char *remoteIP, int port);
bool ioTunPollerOpen(ioTunPoller_t *poller, const char *ifName, ioIfMode_t mode);

int ioTcpPollerInit(ioTcpPoller_t *poller, int epollFd, int tcpFd);
int ioTunPollerInit(ioTunPoller_t *poller, int epollFd, int tunFd);
bool ioTcpWrite(ioTcpPoller_t *poller, const void *data, long nbytes);
bool ioTunWrite(ioTunPoller_t *poller, const void *data, long nbytes);
bool ioTcpServiceWriteEvent(ioTcpPoller_t *poller);
bool ioTunServiceWriteEvent(ioTunPoller_t *poller);
bool ioTcpSetReadEnabled(ioTcpPoller_t *poller, bool enabled);
bool ioTunSetReadEnabled(ioTunPoller_t *poller, bool enabled);
long ioTcpQueuedBytes(const ioTcpPoller_t *poller);
long ioTunQueuedBytes(const ioTunPoller_t *poller);
ioEvent_t ioPollersWait(ioTunPoller_t *tunPoller, ioTcpPoller_t *tcpPoller, int timeoutMs);
