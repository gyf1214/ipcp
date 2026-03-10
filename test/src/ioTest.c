#include <stdlib.h>
#include <stdio.h>
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
}
