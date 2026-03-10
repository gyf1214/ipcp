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

typedef struct {
  int epollFd;
  ioTunPoller_t tunPoller;
  ioTcpPoller_t tcpPoller;
} splitPollersFixture_t;

static int setupSplitPollers(splitPollersFixture_t *fixture, int tunFd, int tcpFd) {
  if (fixture == NULL) {
    return -1;
  }
  fixture->epollFd = epoll_create1(0);
  if (fixture->epollFd < 0) {
    return -1;
  }
  if (ioTunPollerInit(&fixture->tunPoller, fixture->epollFd, tunFd) < 0
      || ioTcpPollerInit(&fixture->tcpPoller, fixture->epollFd, tcpFd) < 0) {
    close(fixture->epollFd);
    fixture->epollFd = -1;
    return -1;
  }
  return 0;
}

static void teardownSplitPollers(splitPollersFixture_t *fixture) {
  if (fixture != NULL && fixture->epollFd >= 0) {
    close(fixture->epollFd);
    fixture->epollFd = -1;
  }
}

static ioEvent_t waitSplitPollers(splitPollersFixture_t *fixture, int timeoutMs) {
  return ioPollersWait(&fixture->tunPoller, &fixture->tcpPoller, timeoutMs);
}

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

static void testIoPollerTimeout(void) {
  int tunPipe[2];
  int tcpPipe[2];
  splitPollersFixture_t pollers;
  ioEvent_t event;

  testAssertTrue(pipe(tunPipe) == 0, "tun pipe should be created");
  testAssertTrue(pipe(tcpPipe) == 0, "tcp pipe should be created");
  testAssertTrue(setupSplitPollers(&pollers, tunPipe[0], tcpPipe[0]) == 0, "setupSplitPollers should succeed");

  event = waitSplitPollers(&pollers, 10);
  testAssertTrue(event == ioEventTimeout, "waitSplitPollers should return timeout when idle");

  teardownSplitPollers(&pollers);
  close(tunPipe[0]);
  close(tunPipe[1]);
  close(tcpPipe[0]);
  close(tcpPipe[1]);
}

static void testIoPollerSourceReadable(void) {
  int tunPipe[2];
  int tcpPipe[2];
  splitPollersFixture_t pollers;
  ioEvent_t event;

  testAssertTrue(pipe(tunPipe) == 0, "tun pipe should be created");
  testAssertTrue(pipe(tcpPipe) == 0, "tcp pipe should be created");
  testAssertTrue(setupSplitPollers(&pollers, tunPipe[0], tcpPipe[0]) == 0, "setupSplitPollers should succeed");

  testAssertTrue(write(tunPipe[1], "a", 1) == 1, "write tun pipe should succeed");
  event = waitSplitPollers(&pollers, 100);
  testAssertTrue(event == ioEventTunRead, "waitSplitPollers should tag tun source");
  testAssertTrue(read(tunPipe[0], (char[2]){0}, 1) == 1, "tun byte should drain");

  testAssertTrue(write(tcpPipe[1], "b", 1) == 1, "write tcp pipe should succeed");
  event = waitSplitPollers(&pollers, 100);
  testAssertTrue(event == ioEventTcpRead, "waitSplitPollers should tag tcp source");
  testAssertTrue(read(tcpPipe[0], (char[2]){0}, 1) == 1, "tcp byte should drain");

  teardownSplitPollers(&pollers);
  close(tunPipe[0]);
  close(tunPipe[1]);
  close(tcpPipe[0]);
  close(tcpPipe[1]);
}

static void testIoPollerError(void) {
  int tunSock[2];
  int tcpPipe[2];
  splitPollersFixture_t pollers;
  ioEvent_t event;

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunSock) == 0, "tun socketpair should be created");
  testAssertTrue(pipe(tcpPipe) == 0, "tcp pipe should be created");
  testAssertTrue(setupSplitPollers(&pollers, tunSock[0], tcpPipe[0]) == 0, "setupSplitPollers should succeed");

  close(tunSock[1]);
  event = waitSplitPollers(&pollers, 100);
  testAssertTrue(event == ioEventError, "waitSplitPollers should map closed peer to ioEventError");

  teardownSplitPollers(&pollers);
  close(tunSock[0]);
  close(tcpPipe[0]);
  close(tcpPipe[1]);
}

static void testIoPollerQueueWriteFlushesOnWritable(void) {
  int tunPair[2];
  int tcpPair[2];
  splitPollersFixture_t pollers;
  ioEvent_t event;
  char buf[128];
  const char *payload = "queued-nonblocking-write";

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "tcp socketpair should be created");
  testAssertTrue(setupSplitPollers(&pollers, tunPair[0], tcpPair[0]) == 0, "setupSplitPollers should succeed");

  testAssertTrue(
      ioTcpWrite(&pollers.tcpPoller, payload, (long)strlen(payload)),
      "queue write should succeed when space is available");

  event = waitSplitPollers(&pollers, 100);
  testAssertTrue(event == ioEventTcpWrite, "poller should surface writable tcp event");

  testAssertTrue(read(tcpPair[1], buf, sizeof(buf)) == (long)strlen(payload), "peer should read queued payload");
  testAssertTrue(memcmp(buf, payload, strlen(payload)) == 0, "queued payload should match");

  event = waitSplitPollers(&pollers, 20);
  testAssertTrue(event == ioEventTimeout, "epollout should be disabled after queue drain");

  teardownSplitPollers(&pollers);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testIoPollerQueueWriteRejectsOverflow(void) {
  int tunPair[2];
  int tcpPair[2];
  splitPollersFixture_t pollers;
  static char payload[IoPollerQueueCapacity];

  memset(payload, 'x', sizeof(payload));
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "tcp socketpair should be created");
  testAssertTrue(setupSplitPollers(&pollers, tunPair[0], tcpPair[0]) == 0, "setupSplitPollers should succeed");

  testAssertTrue(
      ioTcpWrite(&pollers.tcpPoller, payload, IoPollerQueueCapacity - 8),
      "first queue write should fill almost all capacity");
  testAssertTrue(
      !ioTcpWrite(&pollers.tcpPoller, payload, 16),
      "second queue write should fail when full frame does not fit");

  teardownSplitPollers(&pollers);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testIoPollerReadMaskAndQueueBytes(void) {
  int tunPipe[2];
  int tcpPair[2];
  splitPollersFixture_t pollers;
  ioEvent_t event;
  char buf[32];
  const char *payload = "queued";

  testAssertTrue(IoPollerLowWatermark == 49152, "low watermark should be 75% of queue capacity");
  testAssertTrue(pipe(tunPipe) == 0, "tun pipe should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "tcp socketpair should be created");
  testAssertTrue(setupSplitPollers(&pollers, tunPipe[0], tcpPair[0]) == 0, "setupSplitPollers should succeed");

  testAssertTrue(ioTunSetReadEnabled(&pollers.tunPoller, false), "should disable tun read interest");
  testAssertTrue(write(tunPipe[1], "z", 1) == 1, "tun producer write should succeed");
  event = waitSplitPollers(&pollers, 20);
  testAssertTrue(event == ioEventTimeout, "masked tun read should not trigger event");

  testAssertTrue(ioTunSetReadEnabled(&pollers.tunPoller, true), "should re-enable tun read interest");
  event = waitSplitPollers(&pollers, 100);
  testAssertTrue(event == ioEventTunRead, "unmasked tun read should trigger event");
  testAssertTrue(read(tunPipe[0], (char[2]){0}, 1) == 1, "tun byte should drain");

  testAssertTrue(ioTcpQueuedBytes(&pollers.tcpPoller) == 0, "tcp queue should start empty");
  testAssertTrue(
      ioTcpWrite(&pollers.tcpPoller, payload, (long)strlen(payload)),
      "queue write should succeed");
  testAssertTrue(
      ioTcpQueuedBytes(&pollers.tcpPoller) == (long)strlen(payload),
      "queue bytes should reflect enqueued payload");
  event = waitSplitPollers(&pollers, 100);
  testAssertTrue(event == ioEventTcpWrite, "queue flush should surface tcp write event");
  testAssertTrue(read(tcpPair[1], buf, sizeof(buf)) == (long)strlen(payload), "peer should read queued payload");
  testAssertTrue(ioTcpQueuedBytes(&pollers.tcpPoller) == 0, "queue bytes should be zero after flush");

  teardownSplitPollers(&pollers);
  close(tunPipe[0]);
  close(tunPipe[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testIoTunWriteFlushesAtFrameBoundary(void) {
  int tunPair[2];
  int tcpPipe[2];
  splitPollersFixture_t pollers;
  ioEvent_t event;
  char frameA[64];
  char frameB[96];
  char recvBuf[128];
  long nread;

  memset(frameA, 'A', sizeof(frameA));
  memset(frameB, 'B', sizeof(frameB));
  testAssertTrue(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, tunPair) == 0, "tun seqpacket pair should be created");
  testAssertTrue(pipe(tcpPipe) == 0, "tcp pipe should be created");
  testAssertTrue(setupSplitPollers(&pollers, tunPair[0], tcpPipe[0]) == 0, "setupSplitPollers should succeed");

  testAssertTrue(ioTunWrite(&pollers.tunPoller, frameA, sizeof(frameA)), "first tun frame enqueue should succeed");
  testAssertTrue(ioTunWrite(&pollers.tunPoller, frameB, sizeof(frameB)), "second tun frame enqueue should succeed");

  event = waitSplitPollers(&pollers, 100);
  testAssertTrue(event == ioEventTunWrite, "tun write event should surface");
  nread = (long)read(tunPair[1], recvBuf, sizeof(recvBuf));
  testAssertTrue(nread == (long)sizeof(frameA), "first packet read should match first frame size");
  testAssertTrue(memcmp(recvBuf, frameA, sizeof(frameA)) == 0, "first packet payload should match first frame");

  nread = (long)read(tunPair[1], recvBuf, sizeof(recvBuf));
  testAssertTrue(nread == (long)sizeof(frameB), "second packet read should match second frame size");
  testAssertTrue(memcmp(recvBuf, frameB, sizeof(frameB)) == 0, "second packet payload should match second frame");

  teardownSplitPollers(&pollers);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPipe[0]);
  close(tcpPipe[1]);
}

static void testIoTunQueueWrapKeepsFrameBoundary(void) {
  int tunPair[2];
  int tcpPipe[2];
  splitPollersFixture_t pollers;
  ioEvent_t event;
  char frameA[464];
  char frameB[256];
  char recvBuf[1024];
  long nread;

  memset(frameA, 'X', sizeof(frameA));
  memset(frameB, 'Y', sizeof(frameB));
  testAssertTrue(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, tunPair) == 0, "tun seqpacket pair should be created");
  testAssertTrue(pipe(tcpPipe) == 0, "tcp pipe should be created");
  testAssertTrue(setupSplitPollers(&pollers, tunPair[0], tcpPipe[0]) == 0, "setupSplitPollers should succeed");

  memset(pollers.tunPoller.outBuf + (IoPollerQueueCapacity - (long)sizeof(frameA)), frameA[0], sizeof(frameA));
  pollers.tunPoller.readPos = IoPollerQueueCapacity - (long)sizeof(frameA);
  pollers.tunPoller.writePos = IoPollerQueueCapacity - 36;
  pollers.tunPoller.queuedBytes = sizeof(frameA);
  pollers.tunPoller.frameHead = 0;
  pollers.tunPoller.frameTail = 1;
  pollers.tunPoller.frameCount = 1;
  pollers.tunPoller.frames[0].start = pollers.tunPoller.readPos;
  pollers.tunPoller.frames[0].nbytes = sizeof(frameA);

  testAssertTrue(
      ioTunWrite(&pollers.tunPoller, frameB, sizeof(frameB)),
      "tun enqueue should wrap to buffer start when tail cannot fit full frame");

  event = waitSplitPollers(&pollers, 100);
  testAssertTrue(event == ioEventTunWrite, "first tun write event should surface");
  nread = (long)read(tunPair[1], recvBuf, sizeof(recvBuf));
  testAssertTrue(nread == (long)sizeof(frameA), "first wrapped-sequence packet should preserve first frame size");
  testAssertTrue(memcmp(recvBuf, frameA, sizeof(frameA)) == 0, "first wrapped-sequence payload should match");

  nread = (long)read(tunPair[1], recvBuf, sizeof(recvBuf));
  testAssertTrue(nread == (long)sizeof(frameB), "second wrapped-sequence packet should preserve second frame size");
  testAssertTrue(memcmp(recvBuf, frameB, sizeof(frameB)) == 0, "second wrapped-sequence payload should match");

  teardownSplitPollers(&pollers);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPipe[0]);
  close(tcpPipe[1]);
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
  testAssertTrue(poller.epollFd == reactor.epollFd, "poller should bind reactor epoll fd");
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
  tcpPoller.poller.epollFd = -1;
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
  tcpPoller.poller.epollFd = -1;
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
  testAssertTrue(acceptedPoller.poller.epollFd == -1, "accepted tcp poller should start detached from epoll");
  testAssertTrue(acceptedPoller.poller.kind == ioPollerTcp, "accepted poller kind should be tcp");

  close(clientFd);
  close(acceptedPoller.poller.fd);
  close(listenPoller.poller.fd);
}

void runIoTests(void) {
  testIoReadSomeOk();
  testIoReadSomeClosed();
  testIoReadSomeError();
  testIoPollerTimeout();
  testIoPollerSourceReadable();
  testIoPollerError();
  testIoPollerQueueWriteFlushesOnWritable();
  testIoPollerQueueWriteRejectsOverflow();
  testIoPollerReadMaskAndQueueBytes();
  testIoTunWriteFlushesAtFrameBoundary();
  testIoTunQueueWrapKeepsFrameBoundary();
  testIoTunOpenRejectNullName();
  testIoTunOpenRejectInvalidMode();
  testIoTcpListenRejectInvalidIp();
  testIoTcpConnectRejectInvalidIp();
  testIoTcpListenBacklogIsGreaterThanOne();
  testIoTcpAcceptNonBlockingWouldBlockWhenQueueEmpty();
  testIoReactorPublicContracts();
  testIoReactorInitAndAddPoller();
  testIoReactorStepTimeoutAndStop();
  testIoReactorStepRemoveStopsCallbackChain();
  testIoPollerHeadersAndLowWatermarkEdge();
  testIoReactorTcpWritableRearmsAfterFlush();
  testIoListenPollerAcceptNonBlockingInitializesTcpPoller();
}
