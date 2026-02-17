#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "ioTest.h"
#include "io.h"

static void assertIoTrue(int cond, const char *msg) {
  if (!cond) {
    fprintf(stderr, "FAIL: %s\n", msg);
    exit(1);
  }
}

static void testIoWriteAllAndReadSomeOk(void) {
  int fds[2];
  char buf[64];
  long outNbytes = -1;
  const char *payload = "io-write-all";
  ioStatus_t status;

  assertIoTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair should succeed");
  assertIoTrue(ioWriteAll(fds[0], payload, (long)strlen(payload)), "ioWriteAll should succeed");

  status = ioReadSome(fds[1], buf, sizeof(buf), &outNbytes);
  assertIoTrue(status == ioStatusOk, "ioReadSome should report ioStatusOk");
  assertIoTrue(outNbytes == (long)strlen(payload), "ioReadSome should report bytes read");
  assertIoTrue(memcmp(buf, payload, (size_t)outNbytes) == 0, "ioReadSome bytes should match written payload");

  close(fds[0]);
  close(fds[1]);
}

static void testIoReadSomeClosed(void) {
  int fds[2];
  char buf[16];
  long outNbytes = -1;
  ioStatus_t status;

  assertIoTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair should succeed");
  close(fds[0]);
  status = ioReadSome(fds[1], buf, sizeof(buf), &outNbytes);

  assertIoTrue(status == ioStatusClosed, "ioReadSome should report ioStatusClosed on EOF");
  assertIoTrue(outNbytes == 0, "ioReadSome closed should return outNbytes=0");
  close(fds[1]);
}

static void testIoReadSomeError(void) {
  char buf[16];
  long outNbytes = -1;
  ioStatus_t status = ioReadSome(-1, buf, sizeof(buf), &outNbytes);

  assertIoTrue(status == ioStatusError, "ioReadSome should report ioStatusError on invalid fd");
  assertIoTrue(outNbytes == 0, "ioReadSome error should return outNbytes=0");
}

static void testIoPollerTimeout(void) {
  int tunPipe[2];
  int tcpPipe[2];
  ioPoller_t poller;
  ioEvent_t event;

  assertIoTrue(pipe(tunPipe) == 0, "tun pipe should be created");
  assertIoTrue(pipe(tcpPipe) == 0, "tcp pipe should be created");
  assertIoTrue(ioPollerInit(&poller, tunPipe[0], tcpPipe[0]) == 0, "ioPollerInit should succeed");

  event = ioPollerWait(&poller, 10);
  assertIoTrue(event == ioEventTimeout, "ioPollerWait should return timeout when idle");

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

  assertIoTrue(pipe(tunPipe) == 0, "tun pipe should be created");
  assertIoTrue(pipe(tcpPipe) == 0, "tcp pipe should be created");
  assertIoTrue(ioPollerInit(&poller, tunPipe[0], tcpPipe[0]) == 0, "ioPollerInit should succeed");

  assertIoTrue(write(tunPipe[1], "a", 1) == 1, "write tun pipe should succeed");
  event = ioPollerWait(&poller, 100);
  assertIoTrue(event == ioEventTun, "ioPollerWait should tag tun source");
  assertIoTrue(read(tunPipe[0], (char[2]){0}, 1) == 1, "tun byte should drain");

  assertIoTrue(write(tcpPipe[1], "b", 1) == 1, "write tcp pipe should succeed");
  event = ioPollerWait(&poller, 100);
  assertIoTrue(event == ioEventTcp, "ioPollerWait should tag tcp source");
  assertIoTrue(read(tcpPipe[0], (char[2]){0}, 1) == 1, "tcp byte should drain");

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

  assertIoTrue(socketpair(AF_UNIX, SOCK_STREAM, 0, tunSock) == 0, "tun socketpair should be created");
  assertIoTrue(pipe(tcpPipe) == 0, "tcp pipe should be created");
  assertIoTrue(ioPollerInit(&poller, tunSock[0], tcpPipe[0]) == 0, "ioPollerInit should succeed");

  close(tunSock[1]);
  event = ioPollerWait(&poller, 100);
  assertIoTrue(event == ioEventError, "ioPollerWait should map closed peer to ioEventError");

  ioPollerClose(&poller);
  close(tunSock[0]);
  close(tcpPipe[0]);
  close(tcpPipe[1]);
}

void runIoTests(void) {
  testIoWriteAllAndReadSomeOk();
  testIoReadSomeClosed();
  testIoReadSomeError();
  testIoPollerTimeout();
  testIoPollerSourceReadable();
  testIoPollerError();
}
