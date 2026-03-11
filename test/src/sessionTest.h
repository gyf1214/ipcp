#pragma once

#include <stdbool.h>
#include <string.h>
#include <sys/epoll.h>

#include "client.h"
#include "io.h"

typedef struct {
  client_t client;
  ioEvent_t capturedEvents[32];
  int capturedHead;
  int capturedTail;
  int capturedCount;
} runtimeEventFixture_t;

static inline void runtimeEventFixtureCaptureEvent(runtimeEventFixture_t *fixture, ioEvent_t event) {
  int capacity = (int)(sizeof(fixture->capturedEvents) / sizeof(fixture->capturedEvents[0]));
  if (fixture == NULL || fixture->capturedCount >= capacity) {
    return;
  }
  fixture->capturedEvents[fixture->capturedTail] = event;
  fixture->capturedTail = (fixture->capturedTail + 1) % capacity;
  fixture->capturedCount++;
}

static inline bool runtimeEventFixturePopEvent(runtimeEventFixture_t *fixture, ioEvent_t *outEvent) {
  int capacity = (int)(sizeof(fixture->capturedEvents) / sizeof(fixture->capturedEvents[0]));
  if (fixture == NULL || outEvent == NULL || fixture->capturedCount <= 0) {
    return false;
  }
  *outEvent = fixture->capturedEvents[fixture->capturedHead];
  fixture->capturedHead = (fixture->capturedHead + 1) % capacity;
  fixture->capturedCount--;
  return true;
}

extern const ioPollerCallbacks_t runtimeEventFixtureCallbacks;

static inline int runtimeEventFixtureSetup(
    runtimeEventFixture_t *fixture,
    int tunFd,
    int tcpFd,
    long heartbeatIntervalMs,
    long heartbeatTimeoutMs) {
  if (fixture == NULL) {
    return -1;
  }

  memset(&fixture->client, 0, sizeof(fixture->client));
  clientResetHeartbeatState(&fixture->client, heartbeatIntervalMs, heartbeatTimeoutMs, 0);
  if (!ioReactorInit(&fixture->client.reactor)) {
    return -1;
  }
  fixture->capturedHead = 0;
  fixture->capturedTail = 0;
  fixture->capturedCount = 0;

  memset(&fixture->client.tunPoller, 0, sizeof(fixture->client.tunPoller));
  fixture->client.tunPoller.poller.reactor = NULL;
  fixture->client.tunPoller.poller.fd = tunFd;
  fixture->client.tunPoller.poller.events = EPOLLRDHUP;
  fixture->client.tunPoller.poller.kind = ioPollerTun;
  if (!ioReactorAddPoller(
          &fixture->client.reactor,
          &fixture->client.tunPoller.poller,
          &runtimeEventFixtureCallbacks,
          fixture,
          true)) {
    ioReactorDispose(&fixture->client.reactor);
    return -1;
  }

  memset(&fixture->client.tcpPoller, 0, sizeof(fixture->client.tcpPoller));
  fixture->client.tcpPoller.poller.reactor = NULL;
  fixture->client.tcpPoller.poller.fd = tcpFd;
  fixture->client.tcpPoller.poller.events = EPOLLRDHUP;
  fixture->client.tcpPoller.poller.kind = ioPollerTcp;
  if (!ioReactorAddPoller(
          &fixture->client.reactor,
          &fixture->client.tcpPoller.poller,
          &runtimeEventFixtureCallbacks,
          fixture,
          true)) {
    ioReactorDispose(&fixture->client.reactor);
    return -1;
  }

  return 0;
}

static inline void runtimeEventFixtureTeardown(runtimeEventFixture_t *fixture) {
  if (fixture != NULL) {
    ioReactorDispose(&fixture->client.reactor);
  }
}

static inline bool runtimeEventFixtureWaitEvent(runtimeEventFixture_t *fixture, int timeoutMs, ioEvent_t *outEvent) {
  int attempts;
  if (fixture == NULL || outEvent == NULL) {
    return false;
  }
  for (attempts = 0; attempts < 6; attempts++) {
    ioReactorStepResult_t step;
    if (runtimeEventFixturePopEvent(fixture, outEvent)) {
      return true;
    }
    step = ioReactorStep(&fixture->client.reactor, timeoutMs);
    if (step == ioReactorStepError || step == ioReactorStepStop) {
      return false;
    }
    if (runtimeEventFixturePopEvent(fixture, outEvent)) {
      return true;
    }
  }
  return false;
}

static inline bool runtimeEventFixtureWaitEventOfKind(runtimeEventFixture_t *fixture, int timeoutMs, ioEvent_t expected) {
  int attempts;
  ioEvent_t event;
  for (attempts = 0; attempts < 8; attempts++) {
    if (!runtimeEventFixtureWaitEvent(fixture, timeoutMs, &event)) {
      return false;
    }
    if (event == expected) {
      return true;
    }
  }
  return false;
}

void runClientTests(void);
void runServerTests(void);
void runSessionTests(void);
