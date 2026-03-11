#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "ioTest.h"
#include "io.h"
#include "testAssert.h"


static void testIoReadSomeOk(void) {
  int fds[2];
  char buf[64];
  long outNbytes = -1;
  const char *payload = "io-write-all";
  ioStatus_t status;

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair should succeed");
  testAssertTrue(write(fds[0], payload, strlen(payload)) == (long)strlen(payload), "test setup write should succeed");

  status = ioReadSome(fds[1], buf, sizeof(buf), &outNbytes);
  testAssertTrue(status == ioStatusOk, "ioReadSome should report ioStatusOk");
  testAssertTrue(outNbytes == (long)strlen(payload), "ioReadSome should report bytes read");
  testAssertTrue(memcmp(buf, payload, (size_t)outNbytes) == 0, "ioReadSome bytes should match written payload");

  close(fds[0]);
  close(fds[1]);
}

static void testIoReadSomeClosed(void) {
  int fds[2];
  char buf[16];
  long outNbytes = -1;
  ioStatus_t status;

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair should succeed");
  close(fds[0]);
  status = ioReadSome(fds[1], buf, sizeof(buf), &outNbytes);

  testAssertTrue(status == ioStatusClosed, "ioReadSome should report ioStatusClosed on EOF");
  testAssertTrue(outNbytes == 0, "ioReadSome closed should return outNbytes=0");
  close(fds[1]);
}

static void testIoReadSomeError(void) {
  char buf[16];
  long outNbytes = -1;
  ioStatus_t status = ioReadSome(-1, buf, sizeof(buf), &outNbytes);

  testAssertTrue(status == ioStatusError, "ioReadSome should report ioStatusError on invalid fd");
  testAssertTrue(outNbytes == 0, "ioReadSome error should return outNbytes=0");
}

static void testIoTunOpenRejectNullName(void) {
  testAssertTrue(ioTunOpen(NULL, ioIfModeTun) < 0, "ioTunOpen should reject NULL interface name");
}

static void testIoTunOpenRejectInvalidMode(void) {
  testAssertTrue(ioTunOpen("tun0", (ioIfMode_t)99) < 0, "ioTunOpen should reject invalid interface mode");
}

static void testIoTcpListenRejectInvalidIp(void) {
  testAssertTrue(ioTcpListen("not-an-ip", 5000) < 0, "ioTcpListen should reject invalid listen IP");
}

static void testIoTcpConnectRejectInvalidIp(void) {
  testAssertTrue(ioTcpConnect("not-an-ip", 5000) < 0, "ioTcpConnect should reject invalid remote IP");
}

static void testIoTcpListenBacklogIsGreaterThanOne(void) {
  testAssertTrue(IoTcpListenBacklog > 1, "listen backlog should allow more than one pending client");
}

static void testIoTcpAcceptNonBlockingWouldBlockWhenQueueEmpty(void) {
  int listenFd = ioTcpListen("127.0.0.1", 46110);
  int connFd = -1;
  ioStatus_t status;

  testAssertTrue(listenFd >= 0, "ioTcpListen should succeed");
  status = ioTcpAcceptNonBlocking(listenFd, &connFd, NULL, 0, NULL);
  testAssertTrue(status == ioStatusWouldBlock, "ioTcpAcceptNonBlocking should report empty queue");
  testAssertTrue(connFd == -1, "ioTcpAcceptNonBlocking should leave conn fd unset on would-block");

  close(listenFd);
}

static void testIoListenPollerListenRejectNullPoller(void) {
  testAssertTrue(!ioListenPollerListen(NULL, "127.0.0.1", 46112), "listen poller listen should reject null poller");
}

static void testIoListenPollerAcceptNonBlockingRejectInvalidArgs(void) {
  ioListenPoller_t listenPoller;
  ioTcpPoller_t tcpPoller;
  ioStatus_t status;

  memset(&listenPoller, 0, sizeof(listenPoller));
  memset(&tcpPoller, 0, sizeof(tcpPoller));

  status = ioListenPollerAcceptNonBlocking(NULL, &tcpPoller, NULL, 0, NULL);
  testAssertTrue(status == ioStatusError, "accept non-blocking should reject null listen poller");
  status = ioListenPollerAcceptNonBlocking(&listenPoller, NULL, NULL, 0, NULL);
  testAssertTrue(status == ioStatusError, "accept non-blocking should reject null output poller");

  listenPoller.poller.fd = -1;
  status = ioListenPollerAcceptNonBlocking(&listenPoller, &tcpPoller, NULL, 0, NULL);
  testAssertTrue(status == ioStatusError, "accept non-blocking should reject negative listen fd");
}

static void testIoTcpPollerConnectRejectInvalidArgs(void) {
  ioTcpPoller_t poller;

  memset(&poller, 0, sizeof(poller));
  testAssertTrue(!ioTcpPollerConnect(NULL, "127.0.0.1", 5000), "tcp poller connect should reject null poller");
  testAssertTrue(!ioTcpPollerConnect(&poller, NULL, 5000), "tcp poller connect should reject null remote ip");
  testAssertTrue(!ioTcpPollerConnect(&poller, "127.0.0.1", 0), "tcp poller connect should reject invalid remote port");
  testAssertTrue(
      !ioTcpPollerConnect(&poller, "not-an-ip", 5000),
      "tcp poller connect should reject invalid remote ip format");
}

static void testIoTcpPollerConnectInitializesPoller(void) {
  ioTcpPoller_t tcpPoller;
  int listenFd;
  int acceptedFd = -1;
  int attempts;
  ioStatus_t status;

  memset(&tcpPoller, 0, sizeof(tcpPoller));
  listenFd = ioTcpListen("127.0.0.1", 46113);
  testAssertTrue(listenFd >= 0, "listen setup should succeed");
  testAssertTrue(
      ioTcpPollerConnect(&tcpPoller, "127.0.0.1", 46113),
      "tcp poller connect should succeed against local listener");

  status = ioTcpAcceptNonBlocking(listenFd, &acceptedFd, NULL, 0, NULL);
  if (status == ioStatusWouldBlock) {
    for (attempts = 0; attempts < 10 && status == ioStatusWouldBlock; attempts++) {
      usleep(1000);
      status = ioTcpAcceptNonBlocking(listenFd, &acceptedFd, NULL, 0, NULL);
    }
  }

  testAssertTrue(status == ioStatusOk, "accept should observe connected client");
  testAssertTrue(tcpPoller.poller.fd >= 0, "connected tcp poller should carry fd");
  testAssertTrue(tcpPoller.poller.reactor == NULL, "connected tcp poller should be detached");
  testAssertTrue(tcpPoller.poller.kind == ioPollerTcp, "connected tcp poller kind should be tcp");
  testAssertTrue((tcpPoller.poller.events & EPOLLIN) != 0, "connected tcp poller should enable EPOLLIN");
  testAssertTrue((tcpPoller.poller.events & EPOLLRDHUP) != 0, "connected tcp poller should enable EPOLLRDHUP");

  close(acceptedFd);
  close(tcpPoller.poller.fd);
  close(listenFd);
}

static void testIoTunPollerOpenRejectInvalidArgs(void) {
  ioTunPoller_t poller;

  memset(&poller, 0, sizeof(poller));
  testAssertTrue(!ioTunPollerOpen(NULL, "tun0", ioIfModeTun), "tun poller open should reject null poller");
  testAssertTrue(!ioTunPollerOpen(&poller, NULL, ioIfModeTun), "tun poller open should reject null interface name");
  testAssertTrue(
      !ioTunPollerOpen(&poller, "tun0", (ioIfMode_t)99),
      "tun poller open should reject invalid interface mode");
}

static void testIoReactorPublicContracts(void) {
  ioReactor_t reactor;
  ioPoller_t poller;

  testAssertTrue(sizeof(reactor) > 0, "reactor type should be defined");
  testAssertTrue(sizeof(poller) > 0, "poller type should be defined");
  testAssertTrue(ioPollerStop != ioPollerContinue, "poller actions should be distinct");
  testAssertTrue(ioPollerRemove != ioPollerContinue, "poller remove action should be distinct");
  testAssertTrue(ioReactorStepReady != ioReactorStepTimeout, "reactor step results should be distinct");
  testAssertTrue(ioPollerListen != ioPollerTcp, "poller kinds should be distinct");
}

static void testIoReactorInitAndAddPoller(void) {
  ioReactor_t reactor;
  ioPoller_t poller;
  ioPollerCallbacks_t callbacks = {0};
  int pipeFds[2];

  memset(&reactor, 0, sizeof(reactor));
  memset(&poller, 0, sizeof(poller));
  testAssertTrue(pipe(pipeFds) == 0, "pipe should be created");

  testAssertTrue(ioReactorInit(&reactor), "ioReactorInit should succeed");
  poller.fd = pipeFds[0];
  poller.kind = ioPollerTcp;
  testAssertTrue(
      ioReactorAddPoller(&reactor, &poller, &callbacks, &poller, true),
      "ioReactorAddPoller should register poller");
  testAssertTrue(poller.reactor == &reactor, "poller should bind reactor");
  testAssertTrue(poller.callbacks == &callbacks, "poller should store callback table");
  testAssertTrue(poller.ctx == &poller, "poller should store callback context");
  testAssertTrue((poller.events & EPOLLIN) != 0, "add should register read interest");

  testAssertTrue(ioReactorSetPollerReadEnabled(&poller, false), "read disable should succeed");
  testAssertTrue((poller.events & EPOLLIN) == 0, "read disable should clear EPOLLIN bit");
  testAssertTrue(ioReactorSetPollerReadEnabled(&poller, true), "read enable should succeed");
  testAssertTrue((poller.events & EPOLLIN) != 0, "read enable should set EPOLLIN bit");

  ioReactorDeinit(&reactor);
  testAssertTrue(reactor.epollFd == -1, "ioReactorDeinit should reset epoll fd");
  close(pipeFds[0]);
  close(pipeFds[1]);
}

typedef struct {
  int closedCalls;
  int readableCalls;
  int lowWatermarkCalls;
  char order[16];
  int orderLen;
} reactorCallbackCounts_t;

static ioPollerAction_t reactorReadableStop(void *ctx, ioReactor_t *reactor, ioPoller_t *poller) {
  reactorCallbackCounts_t *counts = ctx;
  (void)reactor;
  (void)poller;
  counts->readableCalls++;
  return ioPollerStop;
}

static ioPollerAction_t reactorClosedRemove(void *ctx, ioPoller_t *poller) {
  reactorCallbackCounts_t *counts = ctx;
  (void)poller;
  counts->closedCalls++;
  return ioPollerRemove;
}

static ioPollerAction_t reactorReadableCount(void *ctx, ioReactor_t *reactor, ioPoller_t *poller) {
  reactorCallbackCounts_t *counts = ctx;
  (void)reactor;
  (void)poller;
  counts->readableCalls++;
  if (counts->orderLen < (int)sizeof(counts->order) - 1) {
    counts->order[counts->orderLen++] = 'R';
    counts->order[counts->orderLen] = '\0';
  }
  return ioPollerContinue;
}

static ioPollerAction_t reactorLowWatermarkCount(void *ctx, ioPoller_t *poller, long queuedBytes) {
  reactorCallbackCounts_t *counts = ctx;
  (void)poller;
  (void)queuedBytes;
  counts->lowWatermarkCalls++;
  if (counts->orderLen < (int)sizeof(counts->order) - 1) {
    counts->order[counts->orderLen++] = 'L';
    counts->order[counts->orderLen] = '\0';
  }
  return ioPollerContinue;
}

static void testIoReactorStepTimeoutAndStop(void) {
  ioReactor_t reactor;
  ioPoller_t poller;
  ioPollerCallbacks_t callbacks = {0};
  reactorCallbackCounts_t counts = {0};
  int pipeFds[2];

  testAssertTrue(pipe(pipeFds) == 0, "pipe should be created");
  testAssertTrue(ioReactorInit(&reactor), "ioReactorInit should succeed");

  callbacks.onReadable = reactorReadableStop;
  memset(&poller, 0, sizeof(poller));
  poller.fd = pipeFds[0];
  poller.kind = ioPollerListen;
  testAssertTrue(ioReactorAddPoller(&reactor, &poller, &callbacks, &counts, true), "poller add should succeed");
  testAssertTrue(ioReactorStep(&reactor, 5) == ioReactorStepTimeout, "idle step should timeout");

  testAssertTrue(write(pipeFds[1], "x", 1) == 1, "test producer write should succeed");
  testAssertTrue(ioReactorStep(&reactor, 50) == ioReactorStepStop, "readable stop action should stop reactor step");
  testAssertTrue(counts.readableCalls == 1, "readable callback should run once");

  ioReactorDeinit(&reactor);
  close(pipeFds[0]);
  close(pipeFds[1]);
}

static void testIoReactorStepRemoveStopsCallbackChain(void) {
  ioReactor_t reactor;
  ioPoller_t poller;
  ioPollerCallbacks_t callbacks = {0};
  reactorCallbackCounts_t counts = {0};
  int socketFds[2];

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, socketFds) == 0, "socketpair should be created");
  testAssertTrue(ioReactorInit(&reactor), "ioReactorInit should succeed");

  callbacks.onClosed = reactorClosedRemove;
  callbacks.onReadable = reactorReadableCount;
  memset(&poller, 0, sizeof(poller));
  poller.fd = socketFds[0];
  poller.kind = ioPollerListen;
  testAssertTrue(ioReactorAddPoller(&reactor, &poller, &callbacks, &counts, true), "poller add should succeed");

  close(socketFds[1]);
  testAssertTrue(ioReactorStep(&reactor, 100) == ioReactorStepReady, "closed-remove path should return ready");
  testAssertTrue(counts.closedCalls == 1, "closed callback should run once");
  testAssertTrue(counts.readableCalls == 0, "remove action should stop callback chain");
  testAssertTrue(!ioReactorSetPollerReadEnabled(&poller, false), "removed poller should no longer support epoll mod");

  ioReactorDeinit(&reactor);
  close(socketFds[0]);
}

static void testIoPollerHeadersAndLowWatermarkEdge(void) {
  ioReactor_t reactor;
  ioTcpPoller_t tcpPoller;
  ioPollerCallbacks_t callbacks = {0};
  reactorCallbackCounts_t counts = {0};
  int socketFds[2];
  static char payload[IoPollerLowWatermark + 1];
  char peerBuf[sizeof(payload)];
  int attempts;

  testAssertTrue(offsetof(ioListenPoller_t, poller) == 0, "listen poller should embed shared poller header first");
  testAssertTrue(offsetof(ioTcpPoller_t, poller) == 0, "tcp poller should embed shared poller header first");
  testAssertTrue(offsetof(ioTunPoller_t, poller) == 0, "tun poller should embed shared poller header first");

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, socketFds) == 0, "socketpair should be created");
  testAssertTrue(ioReactorInit(&reactor), "ioReactorInit should succeed");

  memset(&tcpPoller, 0, sizeof(tcpPoller));
  tcpPoller.poller.reactor = NULL;
  tcpPoller.poller.fd = socketFds[0];
  tcpPoller.poller.events = EPOLLRDHUP;
  tcpPoller.poller.kind = ioPollerTcp;

  callbacks.onLowWatermark = reactorLowWatermarkCount;
  testAssertTrue(
      ioReactorAddPoller(&reactor, &tcpPoller.poller, &callbacks, &counts, true),
      "tcp poller add should succeed");

  memset(payload, 'p', sizeof(payload));
  testAssertTrue(ioTcpWrite(&tcpPoller, payload, sizeof(payload)), "tcp queue write should succeed");
  for (attempts = 0; attempts < 5 && counts.lowWatermarkCalls == 0; attempts++) {
    testAssertTrue(ioReactorStep(&reactor, 50) == ioReactorStepReady, "reactor step should process writable events");
  }
  testAssertTrue(counts.lowWatermarkCalls == 1, "low-watermark callback should fire once on crossing edge");
  testAssertTrue(strcmp(counts.order, "L") == 0, "low-watermark callback should run first in writable flow");
  testAssertTrue(read(socketFds[1], peerBuf, sizeof(peerBuf)) == (long)sizeof(payload), "peer should receive queued payload");
  testAssertTrue(ioReactorStep(&reactor, 20) == ioReactorStepTimeout, "no repeated low-watermark callback when already below threshold");
  testAssertTrue(counts.lowWatermarkCalls == 1, "low-watermark callback should be edge-triggered");

  ioReactorDeinit(&reactor);
  close(socketFds[0]);
  close(socketFds[1]);
}

static void testIoReactorTcpWritableRearmsAfterFlush(void) {
  ioReactor_t reactor;
  ioTcpPoller_t tcpPoller;
  ioPollerCallbacks_t callbacks = {0};
  int socketFds[2];
  char payload[] = "rearm-gap";
  char peerBuf[32];
  int flags;
  int attempts;
  ssize_t nread;

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, socketFds) == 0, "socketpair should be created");
  testAssertTrue(ioReactorInit(&reactor), "ioReactorInit should succeed");

  memset(&tcpPoller, 0, sizeof(tcpPoller));
  tcpPoller.poller.reactor = NULL;
  tcpPoller.poller.fd = socketFds[0];
  tcpPoller.poller.events = EPOLLRDHUP;
  tcpPoller.poller.kind = ioPollerTcp;

  testAssertTrue(
      ioReactorAddPoller(&reactor, &tcpPoller.poller, &callbacks, NULL, true),
      "tcp poller add should succeed");

  testAssertTrue(ioTcpWrite(&tcpPoller, payload, (long)sizeof(payload)), "first queue write should succeed");
  for (attempts = 0; attempts < 5 && ioTcpQueuedBytes(&tcpPoller) > 0; attempts++) {
    testAssertTrue(ioReactorStep(&reactor, 50) == ioReactorStepReady, "first writable drain should progress");
  }
  testAssertTrue(ioTcpQueuedBytes(&tcpPoller) == 0, "first write should fully flush");
  testAssertTrue(
      (tcpPoller.poller.events & EPOLLOUT) == 0,
      "reactor callback header should clear writable interest after flush");
  testAssertTrue(read(socketFds[1], peerBuf, sizeof(payload)) == (long)sizeof(payload), "peer should read first payload");

  testAssertTrue(ioTcpWrite(&tcpPoller, payload, (long)sizeof(payload)), "second queue write should succeed");
  for (attempts = 0; attempts < 5 && ioTcpQueuedBytes(&tcpPoller) > 0; attempts++) {
    testAssertTrue(ioReactorStep(&reactor, 50) == ioReactorStepReady, "second writable drain should progress");
  }
  testAssertTrue(ioTcpQueuedBytes(&tcpPoller) == 0, "second write should fully flush via reactor");

  flags = fcntl(socketFds[1], F_GETFL, 0);
  testAssertTrue(flags >= 0, "peer flags fetch should succeed");
  testAssertTrue(fcntl(socketFds[1], F_SETFL, flags | O_NONBLOCK) == 0, "peer should become nonblocking");
  nread = read(socketFds[1], peerBuf, sizeof(payload));
  testAssertTrue(nread == (long)sizeof(payload), "second payload should reach peer");

  ioReactorDeinit(&reactor);
  close(socketFds[0]);
  close(socketFds[1]);
}

static void testIoListenPollerAcceptNonBlockingInitializesTcpPoller(void) {
  ioListenPoller_t listenPoller;
  ioTcpPoller_t acceptedPoller;
  int clientFd = -1;
  ioStatus_t status;

  testAssertTrue(ioListenPollerListen(&listenPoller, "127.0.0.1", 46111), "listen poller listen should succeed");
  clientFd = ioTcpConnect("127.0.0.1", 46111);
  testAssertTrue(clientFd >= 0, "client connect should succeed");

  status = ioListenPollerAcceptNonBlocking(&listenPoller, &acceptedPoller, NULL, 0, NULL);
  if (status == ioStatusWouldBlock) {
    usleep(1000);
    status = ioListenPollerAcceptNonBlocking(&listenPoller, &acceptedPoller, NULL, 0, NULL);
  }

  testAssertTrue(status == ioStatusOk, "listen accept non-blocking should accept pending connection");
  testAssertTrue(acceptedPoller.poller.fd >= 0, "accepted tcp poller should contain accepted fd");
  testAssertTrue(acceptedPoller.poller.reactor == NULL, "accepted tcp poller should start detached from epoll");
  testAssertTrue(acceptedPoller.poller.kind == ioPollerTcp, "accepted poller kind should be tcp");

  close(clientFd);
  close(acceptedPoller.poller.fd);
  close(listenPoller.poller.fd);
}

static void testIoDetachedPollerSkipsEpollCtl(void) {
  ioTcpPoller_t tcpPoller;

  memset(&tcpPoller, 0, sizeof(tcpPoller));
  tcpPoller.poller.reactor = NULL;
  tcpPoller.poller.fd = -1;
  tcpPoller.poller.events = EPOLLIN | EPOLLRDHUP;
  tcpPoller.poller.kind = ioPollerTcp;
  tcpPoller.poller.readEnabled = true;

  testAssertTrue(ioTcpSetReadEnabled(&tcpPoller, false), "detached poller read-disable should not require epoll");
  testAssertTrue((tcpPoller.poller.events & EPOLLIN) == 0, "detached read-disable should clear EPOLLIN bit");
  testAssertTrue(ioTcpSetReadEnabled(&tcpPoller, true), "detached poller read-enable should not require epoll");
  testAssertTrue((tcpPoller.poller.events & EPOLLIN) != 0, "detached read-enable should set EPOLLIN bit");
  testAssertTrue(ioTcpWrite(&tcpPoller, "q", 1), "detached poller queue write should skip epoll ctl");
  testAssertTrue(ioTcpQueuedBytes(&tcpPoller) == 1, "detached queue write should still buffer bytes");
}

void runIoTests(void) {
  testIoReadSomeOk();
  testIoReadSomeClosed();
  testIoReadSomeError();
  testIoTunOpenRejectNullName();
  testIoTunOpenRejectInvalidMode();
  testIoTcpListenRejectInvalidIp();
  testIoTcpConnectRejectInvalidIp();
  testIoTcpListenBacklogIsGreaterThanOne();
  testIoTcpAcceptNonBlockingWouldBlockWhenQueueEmpty();
  testIoListenPollerListenRejectNullPoller();
  testIoListenPollerAcceptNonBlockingRejectInvalidArgs();
  testIoTcpPollerConnectRejectInvalidArgs();
  testIoTcpPollerConnectInitializesPoller();
  testIoTunPollerOpenRejectInvalidArgs();
  testIoReactorPublicContracts();
  testIoReactorInitAndAddPoller();
  testIoReactorStepTimeoutAndStop();
  testIoReactorStepRemoveStopsCallbackChain();
  testIoPollerHeadersAndLowWatermarkEdge();
  testIoReactorTcpWritableRearmsAfterFlush();
  testIoListenPollerAcceptNonBlockingInitializesTcpPoller();
  testIoDetachedPollerSkipsEpollCtl();
}
