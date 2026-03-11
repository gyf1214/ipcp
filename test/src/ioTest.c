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


static void testIoPollerReadOk(void) {
  int fds[2];
  ioPoller_t poller;
  char buf[64];
  long outNbytes = -1;
  const char *payload = "io-write-all";
  ioStatus_t status;

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair should succeed");
  testAssertTrue(write(fds[0], payload, strlen(payload)) == (long)strlen(payload), "test setup write should succeed");

  memset(&poller, 0, sizeof(poller));
  poller.fd = fds[1];
  status = ioPollerRead(&poller, buf, sizeof(buf), &outNbytes);
  testAssertTrue(status == ioStatusOk, "ioPollerRead should report ioStatusOk");
  testAssertTrue(outNbytes == (long)strlen(payload), "ioPollerRead should report bytes read");
  testAssertTrue(memcmp(buf, payload, (size_t)outNbytes) == 0, "ioPollerRead bytes should match written payload");

  close(fds[0]);
  close(fds[1]);
}

static void testIoPollerReadClosed(void) {
  int fds[2];
  ioPoller_t poller;
  char buf[16];
  long outNbytes = -1;
  ioStatus_t status;

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair should succeed");
  close(fds[0]);
  memset(&poller, 0, sizeof(poller));
  poller.fd = fds[1];
  status = ioPollerRead(&poller, buf, sizeof(buf), &outNbytes);

  testAssertTrue(status == ioStatusClosed, "ioPollerRead should report ioStatusClosed on EOF");
  testAssertTrue(outNbytes == 0, "ioPollerRead closed should return outNbytes=0");
  close(fds[1]);
}

static void testIoPollerReadError(void) {
  ioPoller_t poller;
  char buf[16];
  long outNbytes = -1;
  ioStatus_t status;

  memset(&poller, 0, sizeof(poller));
  poller.fd = -1;
  status = ioPollerRead(&poller, buf, sizeof(buf), &outNbytes);
  testAssertTrue(status == ioStatusError, "ioPollerRead should report ioStatusError on invalid fd");
  testAssertTrue(outNbytes == 0, "ioPollerRead error should return outNbytes=0");
  status = ioPollerRead(NULL, buf, sizeof(buf), &outNbytes);
  testAssertTrue(status == ioStatusError, "ioPollerRead should reject null poller");
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
  testAssertTrue(!ioPollerListen(NULL, "127.0.0.1", 46112), "listen poller listen should reject null poller");
}

static void testIoListenPollerAcceptNonBlockingRejectInvalidArgs(void) {
  ioListenPoller_t listenPoller;
  ioTcpPoller_t tcpPoller;
  ioStatus_t status;

  memset(&listenPoller, 0, sizeof(listenPoller));
  memset(&tcpPoller, 0, sizeof(tcpPoller));

  status = ioPollerAccept(NULL, &tcpPoller, NULL, 0, NULL);
  testAssertTrue(status == ioStatusError, "accept non-blocking should reject null listen poller");
  status = ioPollerAccept(&listenPoller, NULL, NULL, 0, NULL);
  testAssertTrue(status == ioStatusError, "accept non-blocking should reject null output poller");

  listenPoller.poller.fd = -1;
  status = ioPollerAccept(&listenPoller, &tcpPoller, NULL, 0, NULL);
  testAssertTrue(status == ioStatusError, "accept non-blocking should reject negative listen fd");
}

static void testIoTcpPollerConnectRejectInvalidArgs(void) {
  ioTcpPoller_t poller;

  memset(&poller, 0, sizeof(poller));
  testAssertTrue(!ioPollerConnect(NULL, "127.0.0.1", 5000), "tcp poller connect should reject null poller");
  testAssertTrue(!ioPollerConnect(&poller, NULL, 5000), "tcp poller connect should reject null remote ip");
  testAssertTrue(!ioPollerConnect(&poller, "127.0.0.1", 0), "tcp poller connect should reject invalid remote port");
  testAssertTrue(
      !ioPollerConnect(&poller, "not-an-ip", 5000),
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
      ioPollerConnect(&tcpPoller, "127.0.0.1", 46113),
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
  testAssertTrue(tcpPoller.poller.kind == ioPollerKindTcp, "connected tcp poller kind should be tcp");
  testAssertTrue((tcpPoller.poller.events & EPOLLIN) != 0, "connected tcp poller should enable EPOLLIN");
  testAssertTrue((tcpPoller.poller.events & EPOLLRDHUP) != 0, "connected tcp poller should enable EPOLLRDHUP");

  close(acceptedFd);
  ioTcpPollerDispose(&tcpPoller);
  close(listenFd);
}

static void testIoTunPollerOpenRejectInvalidArgs(void) {
  ioTunPoller_t poller;

  memset(&poller, 0, sizeof(poller));
  testAssertTrue(!ioPollerOpenTun(NULL, "tun0", ioIfModeTun), "tun poller open should reject null poller");
  testAssertTrue(!ioPollerOpenTun(&poller, NULL, ioIfModeTun), "tun poller open should reject null interface name");
  testAssertTrue(
      !ioPollerOpenTun(&poller, "tun0", (ioIfMode_t)99),
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
  testAssertTrue(ioPollerKindListen != ioPollerKindTcp, "poller kinds should be distinct");
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
  poller.kind = ioPollerKindTcp;
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

  ioReactorDispose(&reactor);
  testAssertTrue(reactor.epollFd == -1, "ioReactorDispose should reset epoll fd");
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

typedef struct {
  int readableCalls;
} handoffReadableCounts_t;

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

static ioPollerAction_t reactorClosedRetarget(void *ctx, ioPoller_t *poller) {
  reactorCallbackCounts_t *counts = ctx;
  (void)poller;
  counts->closedCalls++;
  return ioPollerRetargeted;
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

static ioPollerAction_t reactorReadableHandoffCount(void *ctx, ioReactor_t *reactor, ioPoller_t *poller) {
  handoffReadableCounts_t *counts = ctx;
  (void)reactor;
  (void)poller;
  counts->readableCalls++;
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
  poller.kind = ioPollerKindListen;
  testAssertTrue(ioReactorAddPoller(&reactor, &poller, &callbacks, &counts, true), "poller add should succeed");
  testAssertTrue(ioReactorStep(&reactor, 5) == ioReactorStepTimeout, "idle step should timeout");

  testAssertTrue(write(pipeFds[1], "x", 1) == 1, "test producer write should succeed");
  testAssertTrue(ioReactorStep(&reactor, 50) == ioReactorStepStop, "readable stop action should stop reactor step");
  testAssertTrue(counts.readableCalls == 1, "readable callback should run once");

  ioReactorDispose(&reactor);
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
  poller.kind = ioPollerKindListen;
  testAssertTrue(ioReactorAddPoller(&reactor, &poller, &callbacks, &counts, true), "poller add should succeed");

  close(socketFds[1]);
  testAssertTrue(ioReactorStep(&reactor, 100) == ioReactorStepReady, "closed-remove path should return ready");
  testAssertTrue(counts.closedCalls == 1, "closed callback should run once");
  testAssertTrue(counts.readableCalls == 0, "remove action should stop callback chain");
  testAssertTrue(!ioReactorSetPollerReadEnabled(&poller, false), "removed poller should no longer support epoll mod");

  ioReactorDispose(&reactor);
  close(socketFds[0]);
}

static void testIoReactorStepRetargetStopsCallbackChainWithoutRemoval(void) {
  ioReactor_t reactor;
  ioPoller_t poller;
  ioPollerCallbacks_t callbacks = {0};
  reactorCallbackCounts_t counts = {0};
  int socketFds[2];

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, socketFds) == 0, "socketpair should be created");
  testAssertTrue(ioReactorInit(&reactor), "ioReactorInit should succeed");

  callbacks.onClosed = reactorClosedRetarget;
  callbacks.onReadable = reactorReadableCount;
  memset(&poller, 0, sizeof(poller));
  poller.fd = socketFds[0];
  poller.kind = ioPollerKindListen;
  testAssertTrue(ioReactorAddPoller(&reactor, &poller, &callbacks, &counts, true), "poller add should succeed");

  close(socketFds[1]);
  testAssertTrue(ioReactorStep(&reactor, 100) == ioReactorStepReady, "closed-retarget path should return ready");
  testAssertTrue(counts.closedCalls == 1, "closed callback should run once");
  testAssertTrue(counts.readableCalls == 0, "retarget action should stop callback chain");
  testAssertTrue(
      ioReactorSetPollerReadEnabled(&poller, false),
      "retarget action should keep poller attached for future read toggles");

  ioReactorDispose(&reactor);
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
  tcpPoller.poller.kind = ioPollerKindTcp;

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

  ioReactorDispose(&reactor);
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
  tcpPoller.poller.kind = ioPollerKindTcp;

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

  ioReactorDispose(&reactor);
  close(socketFds[0]);
  close(socketFds[1]);
}

static void testIoReactorWritableFailureInvokesClosedCallback(void) {
  ioReactor_t reactor;
  ioTcpPoller_t tcpPoller;
  ioPollerCallbacks_t callbacks = {0};
  reactorCallbackCounts_t counts = {0};
  int socketFds[2];
  char payload[] = "wfail";

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, socketFds) == 0, "socketpair should be created");
  testAssertTrue(ioReactorInit(&reactor), "ioReactorInit should succeed");

  memset(&tcpPoller, 0, sizeof(tcpPoller));
  tcpPoller.poller.reactor = NULL;
  tcpPoller.poller.fd = socketFds[0];
  tcpPoller.poller.events = EPOLLRDHUP;
  tcpPoller.poller.kind = ioPollerKindTcp;

  callbacks.onClosed = reactorClosedRetarget;
  callbacks.onReadable = reactorReadableCount;
  callbacks.onLowWatermark = reactorLowWatermarkCount;
  testAssertTrue(
      ioReactorAddPoller(&reactor, &tcpPoller.poller, &callbacks, &counts, true),
      "tcp poller add should succeed");
  testAssertTrue(ioTcpWrite(&tcpPoller, payload, (long)sizeof(payload)), "queue write should succeed");

  /* Force writable flush failure while preserving an EPOLLOUT-ready registration in epoll. */
  tcpPoller.poller.fd = -1;
  testAssertTrue(
      ioReactorStep(&reactor, 100) == ioReactorStepReady,
      "writable failure should be handled via closed callback, not reactor error");
  testAssertTrue(counts.closedCalls == 1, "writable failure should trigger closed callback once");
  testAssertTrue(counts.lowWatermarkCalls == 0, "closed handling should stop writable callback chain");
  testAssertTrue(counts.readableCalls == 0, "closed handling should stop readable callback chain");

  ioReactorDispose(&reactor);
  close(socketFds[0]);
  close(socketFds[1]);
}

static void testIoListenPollerAcceptNonBlockingInitializesTcpPoller(void) {
  ioListenPoller_t listenPoller;
  ioTcpPoller_t acceptedPoller;
  int clientFd = -1;
  ioStatus_t status;

  testAssertTrue(ioPollerListen(&listenPoller, "127.0.0.1", 46111), "listen poller listen should succeed");
  clientFd = ioTcpConnect("127.0.0.1", 46111);
  testAssertTrue(clientFd >= 0, "client connect should succeed");

  status = ioPollerAccept(&listenPoller, &acceptedPoller, NULL, 0, NULL);
  if (status == ioStatusWouldBlock) {
    usleep(1000);
    status = ioPollerAccept(&listenPoller, &acceptedPoller, NULL, 0, NULL);
  }

  testAssertTrue(status == ioStatusOk, "listen accept non-blocking should accept pending connection");
  testAssertTrue(acceptedPoller.poller.fd >= 0, "accepted tcp poller should contain accepted fd");
  testAssertTrue(acceptedPoller.poller.reactor == NULL, "accepted tcp poller should start detached from epoll");
  testAssertTrue(acceptedPoller.poller.kind == ioPollerKindTcp, "accepted poller kind should be tcp");

  close(clientFd);
  ioTcpPollerDispose(&acceptedPoller);
  ioListenPollerDispose(&listenPoller);
}

static void testIoDetachedPollerSkipsEpollCtl(void) {
  ioTcpPoller_t tcpPoller;

  memset(&tcpPoller, 0, sizeof(tcpPoller));
  tcpPoller.poller.reactor = NULL;
  tcpPoller.poller.fd = -1;
  tcpPoller.poller.events = EPOLLIN | EPOLLRDHUP;
  tcpPoller.poller.kind = ioPollerKindTcp;
  tcpPoller.poller.readEnabled = true;

  testAssertTrue(ioTcpSetReadEnabled(&tcpPoller, false), "detached poller read-disable should not require epoll");
  testAssertTrue((tcpPoller.poller.events & EPOLLIN) == 0, "detached read-disable should clear EPOLLIN bit");
  testAssertTrue(ioTcpSetReadEnabled(&tcpPoller, true), "detached poller read-enable should not require epoll");
  testAssertTrue((tcpPoller.poller.events & EPOLLIN) != 0, "detached read-enable should set EPOLLIN bit");
  testAssertTrue(ioTcpWrite(&tcpPoller, "q", 1), "detached poller queue write should skip epoll ctl");
  testAssertTrue(ioTcpQueuedBytes(&tcpPoller) == 1, "detached queue write should still buffer bytes");
}

static void testIoTcpWriteEpollCtlFailureDoesNotQueue(void) {
  ioReactor_t reactor;
  ioTcpPoller_t tcpPoller;
  ioPollerCallbacks_t callbacks = {0};
  int socketFds[2];

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, socketFds) == 0, "socketpair should be created");
  testAssertTrue(ioReactorInit(&reactor), "ioReactorInit should succeed");

  memset(&tcpPoller, 0, sizeof(tcpPoller));
  tcpPoller.poller.reactor = NULL;
  tcpPoller.poller.fd = socketFds[0];
  tcpPoller.poller.events = EPOLLRDHUP;
  tcpPoller.poller.kind = ioPollerKindTcp;
  testAssertTrue(
      ioReactorAddPoller(&reactor, &tcpPoller.poller, &callbacks, NULL, true),
      "tcp poller add should succeed");
  testAssertTrue(close(reactor.epollFd) == 0, "closing epoll fd should succeed");

  testAssertTrue(!ioTcpWrite(&tcpPoller, "x", 1), "tcp write should fail when epoll ctl mod fails");
  testAssertTrue(ioTcpQueuedBytes(&tcpPoller) == 0, "failed tcp write should not leave queued bytes");
  testAssertTrue((tcpPoller.poller.events & EPOLLOUT) == 0, "failed tcp write should keep EPOLLOUT disabled");

  reactor.epollFd = -1;
  ioReactorDispose(&reactor);
  close(socketFds[0]);
  close(socketFds[1]);
}

static void testIoTunWriteEpollCtlFailureDoesNotQueue(void) {
  ioReactor_t reactor;
  ioTunPoller_t tunPoller;
  ioPollerCallbacks_t callbacks = {0};
  int socketFds[2];

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, socketFds) == 0, "socketpair should be created");
  testAssertTrue(ioReactorInit(&reactor), "ioReactorInit should succeed");

  memset(&tunPoller, 0, sizeof(tunPoller));
  tunPoller.poller.reactor = NULL;
  tunPoller.poller.fd = socketFds[0];
  tunPoller.poller.events = EPOLLRDHUP;
  tunPoller.poller.kind = ioPollerKindTun;
  testAssertTrue(
      ioReactorAddPoller(&reactor, &tunPoller.poller, &callbacks, NULL, true),
      "tun poller add should succeed");
  testAssertTrue(close(reactor.epollFd) == 0, "closing epoll fd should succeed");

  testAssertTrue(!ioTunWrite(&tunPoller, "x", 1), "tun write should fail when epoll ctl mod fails");
  testAssertTrue(ioTunQueuedBytes(&tunPoller) == 0, "failed tun write should not leave queued bytes");
  testAssertTrue(tunPoller.frameCount == 0, "failed tun write should not enqueue frame metadata");
  testAssertTrue((tunPoller.poller.events & EPOLLOUT) == 0, "failed tun write should keep EPOLLOUT disabled");

  reactor.epollFd = -1;
  ioReactorDispose(&reactor);
  close(socketFds[0]);
  close(socketFds[1]);
}

static void testIoTcpPollerDisposeDetachesClosesAndResetsState(void) {
  ioReactor_t reactor;
  ioTcpPoller_t tcpPoller;
  ioPollerCallbacks_t callbacks = {0};
  int socketFds[2];
  int disposedFd;

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, socketFds) == 0, "socketpair should be created");
  testAssertTrue(ioReactorInit(&reactor), "ioReactorInit should succeed");

  memset(&tcpPoller, 0, sizeof(tcpPoller));
  tcpPoller.poller.reactor = NULL;
  tcpPoller.poller.fd = socketFds[0];
  tcpPoller.poller.events = EPOLLRDHUP;
  tcpPoller.poller.kind = ioPollerKindTcp;
  testAssertTrue(
      ioReactorAddPoller(&reactor, &tcpPoller.poller, &callbacks, NULL, true),
      "tcp poller add should succeed");
  testAssertTrue(ioTcpWrite(&tcpPoller, "abc", 3), "tcp write should queue");
  testAssertTrue(ioTcpQueuedBytes(&tcpPoller) == 3, "tcp queue should contain bytes before dispose");

  disposedFd = tcpPoller.poller.fd;
  ioTcpPollerDispose(&tcpPoller);

  testAssertTrue(tcpPoller.poller.fd == -1, "tcp dispose should reset fd");
  testAssertTrue(tcpPoller.poller.reactor == NULL, "tcp dispose should detach reactor");
  testAssertTrue(tcpPoller.poller.events == 0, "tcp dispose should reset event mask");
  testAssertTrue(ioTcpQueuedBytes(&tcpPoller) == 0, "tcp dispose should clear queue");
  testAssertTrue(fcntl(disposedFd, F_GETFD) < 0 && errno == EBADF, "tcp dispose should close fd");
  testAssertTrue(
      !ioReactorSetPollerReadEnabled(&tcpPoller.poller, false),
      "disposed tcp poller should no longer support read toggles");

  close(socketFds[1]);
  ioReactorDispose(&reactor);
}

static void testIoTunPollerDisposeDetachesClosesAndResetsState(void) {
  ioReactor_t reactor;
  ioTunPoller_t tunPoller;
  ioPollerCallbacks_t callbacks = {0};
  int socketFds[2];
  int disposedFd;

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, socketFds) == 0, "socketpair should be created");
  testAssertTrue(ioReactorInit(&reactor), "ioReactorInit should succeed");

  memset(&tunPoller, 0, sizeof(tunPoller));
  tunPoller.poller.reactor = NULL;
  tunPoller.poller.fd = socketFds[0];
  tunPoller.poller.events = EPOLLRDHUP;
  tunPoller.poller.kind = ioPollerKindTun;
  testAssertTrue(
      ioReactorAddPoller(&reactor, &tunPoller.poller, &callbacks, NULL, true),
      "tun poller add should succeed");
  testAssertTrue(ioTunWrite(&tunPoller, "abc", 3), "tun write should queue");
  testAssertTrue(ioTunQueuedBytes(&tunPoller) == 3, "tun queue should contain bytes before dispose");
  testAssertTrue(tunPoller.frameCount == 1, "tun queue metadata should include one frame before dispose");

  disposedFd = tunPoller.poller.fd;
  ioTunPollerDispose(&tunPoller);

  testAssertTrue(tunPoller.poller.fd == -1, "tun dispose should reset fd");
  testAssertTrue(tunPoller.poller.reactor == NULL, "tun dispose should detach reactor");
  testAssertTrue(tunPoller.poller.events == 0, "tun dispose should reset event mask");
  testAssertTrue(ioTunQueuedBytes(&tunPoller) == 0, "tun dispose should clear queued bytes");
  testAssertTrue(tunPoller.frameCount == 0, "tun dispose should clear frame queue");
  testAssertTrue(tunPoller.readPos == 0 && tunPoller.writePos == 0, "tun dispose should reset queue cursors");
  testAssertTrue(fcntl(disposedFd, F_GETFD) < 0 && errno == EBADF, "tun dispose should close fd");
  testAssertTrue(
      !ioReactorSetPollerReadEnabled(&tunPoller.poller, false),
      "disposed tun poller should no longer support read toggles");

  close(socketFds[1]);
  ioReactorDispose(&reactor);
}

static void testIoTcpPollerHandoffRejectsInvalidArgs(void) {
  ioTcpPoller_t src;
  ioTcpPoller_t dst;
  ioPollerCallbacks_t callbacks = {0};

  memset(&src, 0, sizeof(src));
  memset(&dst, 0, sizeof(dst));

  testAssertTrue(
      !ioTcpPollerHandoff(NULL, &src, &callbacks, NULL, true),
      "handoff should reject null destination");
  testAssertTrue(
      !ioTcpPollerHandoff(&dst, NULL, &callbacks, NULL, true),
      "handoff should reject null source");
  testAssertTrue(
      !ioTcpPollerHandoff(&dst, &src, NULL, NULL, true),
      "handoff should reject null callbacks");
}

static void testIoTcpPollerHandoffTransfersAttachmentAndQueue(void) {
  ioReactor_t reactor;
  ioTcpPoller_t src;
  ioTcpPoller_t dst;
  ioPollerCallbacks_t srcCallbacks = {0};
  ioPollerCallbacks_t dstCallbacks = {0};
  handoffReadableCounts_t srcCounts = {0};
  handoffReadableCounts_t dstCounts = {0};
  int socketFds[2];
  long queuedBefore;
  int srcFdBefore;

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, socketFds) == 0, "socketpair should be created");
  testAssertTrue(ioReactorInit(&reactor), "ioReactorInit should succeed");

  memset(&src, 0, sizeof(src));
  memset(&dst, 0, sizeof(dst));
  src.poller.fd = socketFds[0];
  src.poller.kind = ioPollerKindTcp;
  src.poller.events = EPOLLRDHUP;

  srcCallbacks.onReadable = reactorReadableHandoffCount;
  dstCallbacks.onReadable = reactorReadableHandoffCount;
  testAssertTrue(
      ioReactorAddPoller(&reactor, &src.poller, &srcCallbacks, &srcCounts, true),
      "source poller should be registered");
  testAssertTrue(ioTcpWrite(&src, "queued", 6), "queue write should succeed before handoff");
  queuedBefore = ioTcpQueuedBytes(&src);
  srcFdBefore = src.poller.fd;

  testAssertTrue(
      ioTcpPollerHandoff(&dst, &src, &dstCallbacks, &dstCounts, false),
      "handoff should transfer source fd and runtime state");

  testAssertTrue(dst.poller.fd == srcFdBefore, "destination should own source fd after handoff");
  testAssertTrue(dst.poller.reactor == &reactor, "destination should stay attached to reactor");
  testAssertTrue(dst.poller.callbacks == &dstCallbacks, "destination should receive new callback table");
  testAssertTrue(dst.poller.ctx == &dstCounts, "destination should receive new callback context");
  testAssertTrue((dst.poller.events & EPOLLIN) == 0, "destination should apply requested read-disabled state");
  testAssertTrue((dst.poller.events & EPOLLRDHUP) != 0, "destination should keep close detection flags");
  testAssertTrue(ioTcpQueuedBytes(&dst) == queuedBefore, "destination should inherit queued bytes");

  testAssertTrue(src.poller.reactor == NULL, "source should be detached after handoff");
  testAssertTrue(src.poller.fd == -1, "source fd should be cleared after handoff");
  testAssertTrue(src.poller.events == 0, "source event mask should be cleared after handoff");
  testAssertTrue(src.poller.callbacks == NULL, "source callbacks should be cleared after handoff");
  testAssertTrue(src.poller.ctx == NULL, "source ctx should be cleared after handoff");
  testAssertTrue(ioTcpQueuedBytes(&src) == 0, "source queue should be cleared after handoff");

  testAssertTrue(write(socketFds[1], "r", 1) == 1, "peer should write readable byte");
  testAssertTrue(ioReactorSetPollerReadEnabled(&dst.poller, true), "destination read-enable should succeed");
  testAssertTrue(ioReactorStep(&reactor, 100) == ioReactorStepReady, "reactor step should dispatch handoff destination");
  testAssertTrue(dstCounts.readableCalls > 0, "destination readable callback should run");
  testAssertTrue(srcCounts.readableCalls == 0, "source readable callback should not run after handoff");

  ioReactorDispose(&reactor);
  close(socketFds[0]);
  close(socketFds[1]);
}

static void testIoTcpPollerHandoffPreservesSourceOnModFailure(void) {
  ioReactor_t reactor;
  ioTcpPoller_t src;
  ioTcpPoller_t dst;
  ioPollerCallbacks_t srcCallbacks = {0};
  ioPollerCallbacks_t dstCallbacks = {0};
  handoffReadableCounts_t srcCounts = {0};
  int socketFds[2];
  int srcFdBefore;
  long srcQueuedBefore;
  unsigned int srcEventsBefore;

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, socketFds) == 0, "socketpair should be created");
  testAssertTrue(ioReactorInit(&reactor), "ioReactorInit should succeed");

  memset(&src, 0, sizeof(src));
  memset(&dst, 0, sizeof(dst));
  src.poller.fd = socketFds[0];
  src.poller.kind = ioPollerKindTcp;
  src.poller.events = EPOLLRDHUP;
  srcCallbacks.onReadable = reactorReadableHandoffCount;
  testAssertTrue(
      ioReactorAddPoller(&reactor, &src.poller, &srcCallbacks, &srcCounts, true),
      "source poller should be registered");
  testAssertTrue(ioTcpWrite(&src, "queued", 6), "queue write should succeed before failure path");

  srcFdBefore = src.poller.fd;
  srcQueuedBefore = ioTcpQueuedBytes(&src);
  srcEventsBefore = src.poller.events;
  testAssertTrue(close(reactor.epollFd) == 0, "closing reactor epoll fd should succeed");

  testAssertTrue(
      !ioTcpPollerHandoff(&dst, &src, &dstCallbacks, &srcCounts, true),
      "handoff should fail when epoll mod fails");
  testAssertTrue(src.poller.fd == srcFdBefore, "source fd should remain unchanged on handoff failure");
  testAssertTrue(src.poller.reactor == &reactor, "source reactor should remain unchanged on handoff failure");
  testAssertTrue(src.poller.events == srcEventsBefore, "source events should remain unchanged on handoff failure");
  testAssertTrue(ioTcpQueuedBytes(&src) == srcQueuedBefore, "source queue should remain unchanged on handoff failure");
  testAssertTrue(dst.poller.fd == 0, "destination should remain untouched on handoff failure");
  testAssertTrue(ioTcpQueuedBytes(&dst) == 0, "destination queue should remain empty on handoff failure");

  reactor.epollFd = -1;
  ioReactorDispose(&reactor);
  close(socketFds[0]);
  close(socketFds[1]);
}

void runIoTests(void) {
  testIoPollerReadOk();
  testIoPollerReadClosed();
  testIoPollerReadError();
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
  testIoReactorStepRetargetStopsCallbackChainWithoutRemoval();
  testIoPollerHeadersAndLowWatermarkEdge();
  testIoReactorTcpWritableRearmsAfterFlush();
  testIoReactorWritableFailureInvokesClosedCallback();
  testIoListenPollerAcceptNonBlockingInitializesTcpPoller();
  testIoDetachedPollerSkipsEpollCtl();
  testIoTcpWriteEpollCtlFailureDoesNotQueue();
  testIoTunWriteEpollCtlFailureDoesNotQueue();
  testIoTcpPollerDisposeDetachesClosesAndResetsState();
  testIoTunPollerDisposeDetachesClosesAndResetsState();
  testIoTcpPollerHandoffRejectsInvalidArgs();
  testIoTcpPollerHandoffTransfersAttachmentAndQueue();
  testIoTcpPollerHandoffPreservesSourceOnModFailure();
}
