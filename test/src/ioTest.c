#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "ioTest.h"
#include "io.h"
#include "testAssert.h"

static void testIoWriteAllAndReadSomeOk(void) {
  int fds[2];
  char buf[64];
  long outNbytes = -1;
  const char *payload = "io-write-all";
  ioStatus_t status;

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair should succeed");
  testAssertTrue(ioWriteAll(fds[0], payload, (long)strlen(payload)), "ioWriteAll should succeed");

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
  ioPoller_t poller;
  ioEvent_t event;

  testAssertTrue(pipe(tunPipe) == 0, "tun pipe should be created");
  testAssertTrue(pipe(tcpPipe) == 0, "tcp pipe should be created");
  testAssertTrue(ioPollerInit(&poller, tunPipe[0], tcpPipe[0]) == 0, "ioPollerInit should succeed");

  event = ioPollerWait(&poller, 10);
  testAssertTrue(event == ioEventTimeout, "ioPollerWait should return timeout when idle");

  ioPollerClose(&poller);
  close(tunPipe[0]);
  close(tunPipe[1]);
  close(tcpPipe[0]);
  close(tcpPipe[1]);
}

static void testIoPollerSourceReadable(void) {
  int tunPipe[2];
  int tcpPipe[2];
  ioPoller_t poller;
  ioEvent_t event;

  testAssertTrue(pipe(tunPipe) == 0, "tun pipe should be created");
  testAssertTrue(pipe(tcpPipe) == 0, "tcp pipe should be created");
  testAssertTrue(ioPollerInit(&poller, tunPipe[0], tcpPipe[0]) == 0, "ioPollerInit should succeed");

  testAssertTrue(write(tunPipe[1], "a", 1) == 1, "write tun pipe should succeed");
  event = ioPollerWait(&poller, 100);
  testAssertTrue(event == ioEventTunRead, "ioPollerWait should tag tun source");
  testAssertTrue(read(tunPipe[0], (char[2]){0}, 1) == 1, "tun byte should drain");

  testAssertTrue(write(tcpPipe[1], "b", 1) == 1, "write tcp pipe should succeed");
  event = ioPollerWait(&poller, 100);
  testAssertTrue(event == ioEventTcpRead, "ioPollerWait should tag tcp source");
  testAssertTrue(read(tcpPipe[0], (char[2]){0}, 1) == 1, "tcp byte should drain");

  ioPollerClose(&poller);
  close(tunPipe[0]);
  close(tunPipe[1]);
  close(tcpPipe[0]);
  close(tcpPipe[1]);
}

static void testIoPollerError(void) {
  int tunSock[2];
  int tcpPipe[2];
  ioPoller_t poller;
  ioEvent_t event;

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunSock) == 0, "tun socketpair should be created");
  testAssertTrue(pipe(tcpPipe) == 0, "tcp pipe should be created");
  testAssertTrue(ioPollerInit(&poller, tunSock[0], tcpPipe[0]) == 0, "ioPollerInit should succeed");

  close(tunSock[1]);
  event = ioPollerWait(&poller, 100);
  testAssertTrue(event == ioEventError, "ioPollerWait should map closed peer to ioEventError");

  ioPollerClose(&poller);
  close(tunSock[0]);
  close(tcpPipe[0]);
  close(tcpPipe[1]);
}

static void testIoPollerQueueWriteFlushesOnWritable(void) {
  int tunPair[2];
  int tcpPair[2];
  ioPoller_t poller;
  ioEvent_t event;
  char buf[128];
  const char *payload = "queued-nonblocking-write";

  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "tcp socketpair should be created");
  testAssertTrue(ioPollerInit(&poller, tunPair[0], tcpPair[0]) == 0, "ioPollerInit should succeed");

  testAssertTrue(
      ioPollerQueueWrite(&poller, ioSourceTcp, payload, (long)strlen(payload)),
      "queue write should succeed when space is available");

  event = ioPollerWait(&poller, 100);
  testAssertTrue(event == ioEventTcpWrite, "poller should surface writable tcp event");

  testAssertTrue(read(tcpPair[1], buf, sizeof(buf)) == (long)strlen(payload), "peer should read queued payload");
  testAssertTrue(memcmp(buf, payload, strlen(payload)) == 0, "queued payload should match");

  event = ioPollerWait(&poller, 20);
  testAssertTrue(event == ioEventTimeout, "epollout should be disabled after queue drain");

  ioPollerClose(&poller);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testIoPollerQueueWriteRejectsOverflow(void) {
  int tunPair[2];
  int tcpPair[2];
  ioPoller_t poller;
  static char payload[IoPollerQueueCapacity];

  memset(payload, 'x', sizeof(payload));
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunPair) == 0, "tun socketpair should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "tcp socketpair should be created");
  testAssertTrue(ioPollerInit(&poller, tunPair[0], tcpPair[0]) == 0, "ioPollerInit should succeed");

  testAssertTrue(
      ioPollerQueueWrite(&poller, ioSourceTcp, payload, IoPollerQueueCapacity - 8),
      "first queue write should fill almost all capacity");
  testAssertTrue(
      !ioPollerQueueWrite(&poller, ioSourceTcp, payload, 16),
      "second queue write should fail when full frame does not fit");

  ioPollerClose(&poller);
  close(tunPair[0]);
  close(tunPair[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testIoPollerReadMaskAndQueueBytes(void) {
  int tunPipe[2];
  int tcpPair[2];
  ioPoller_t poller;
  ioEvent_t event;
  char buf[32];
  const char *payload = "queued";

  testAssertTrue(IoPollerLowWatermark == 49152, "low watermark should be 75% of queue capacity");
  testAssertTrue(pipe(tunPipe) == 0, "tun pipe should be created");
  testAssertTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tcpPair) == 0, "tcp socketpair should be created");
  testAssertTrue(ioPollerInit(&poller, tunPipe[0], tcpPair[0]) == 0, "ioPollerInit should succeed");

  testAssertTrue(ioPollerSetReadEnabled(&poller, ioSourceTun, false), "should disable tun read interest");
  testAssertTrue(write(tunPipe[1], "z", 1) == 1, "tun producer write should succeed");
  event = ioPollerWait(&poller, 20);
  testAssertTrue(event == ioEventTimeout, "masked tun read should not trigger event");

  testAssertTrue(ioPollerSetReadEnabled(&poller, ioSourceTun, true), "should re-enable tun read interest");
  event = ioPollerWait(&poller, 100);
  testAssertTrue(event == ioEventTunRead, "unmasked tun read should trigger event");
  testAssertTrue(read(tunPipe[0], (char[2]){0}, 1) == 1, "tun byte should drain");

  testAssertTrue(ioPollerQueuedBytes(&poller, ioSourceTcp) == 0, "tcp queue should start empty");
  testAssertTrue(
      ioPollerQueueWrite(&poller, ioSourceTcp, payload, (long)strlen(payload)),
      "queue write should succeed");
  testAssertTrue(
      ioPollerQueuedBytes(&poller, ioSourceTcp) == (long)strlen(payload),
      "queue bytes should reflect enqueued payload");
  event = ioPollerWait(&poller, 100);
  testAssertTrue(event == ioEventTcpWrite, "queue flush should surface tcp write event");
  testAssertTrue(read(tcpPair[1], buf, sizeof(buf)) == (long)strlen(payload), "peer should read queued payload");
  testAssertTrue(ioPollerQueuedBytes(&poller, ioSourceTcp) == 0, "queue bytes should be zero after flush");

  ioPollerClose(&poller);
  close(tunPipe[0]);
  close(tunPipe[1]);
  close(tcpPair[0]);
  close(tcpPair[1]);
}

static void testIoTunOpenRejectNullName(void) {
  testAssertTrue(ioTunOpen(NULL) < 0, "ioTunOpen should reject NULL interface name");
}

static void testIoTcpListenRejectInvalidIp(void) {
  testAssertTrue(ioTcpListen("not-an-ip", 5000) < 0, "ioTcpListen should reject invalid listen IP");
}

static void testIoTcpConnectRejectInvalidIp(void) {
  testAssertTrue(ioTcpConnect("not-an-ip", 5000) < 0, "ioTcpConnect should reject invalid remote IP");
}

void runIoTests(void) {
  testIoWriteAllAndReadSomeOk();
  testIoReadSomeClosed();
  testIoReadSomeError();
  testIoPollerTimeout();
  testIoPollerSourceReadable();
  testIoPollerError();
  testIoPollerQueueWriteFlushesOnWritable();
  testIoPollerQueueWriteRejectsOverflow();
  testIoPollerReadMaskAndQueueBytes();
  testIoTunOpenRejectNullName();
  testIoTcpListenRejectInvalidIp();
  testIoTcpConnectRejectInvalidIp();
}
