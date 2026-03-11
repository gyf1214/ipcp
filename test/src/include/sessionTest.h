#pragma once

#include <stdbool.h>
#include <string.h>

#include "io.h"

typedef struct {
  ioEvent_t capturedEvents[32];
  int capturedHead;
  int capturedTail;
  int capturedCount;
} sessionEventFixture_t;

static inline void sessionEventFixtureCaptureEvent(sessionEventFixture_t *fixture, ioEvent_t event) {
  int capacity = (int)(sizeof(fixture->capturedEvents) / sizeof(fixture->capturedEvents[0]));
  if (fixture == NULL || fixture->capturedCount >= capacity) {
    return;
  }
  fixture->capturedEvents[fixture->capturedTail] = event;
  fixture->capturedTail = (fixture->capturedTail + 1) % capacity;
  fixture->capturedCount++;
}

static inline bool sessionEventFixturePopEvent(sessionEventFixture_t *fixture, ioEvent_t *outEvent) {
  int capacity = (int)(sizeof(fixture->capturedEvents) / sizeof(fixture->capturedEvents[0]));
  if (fixture == NULL || outEvent == NULL || fixture->capturedCount <= 0) {
    return false;
  }
  *outEvent = fixture->capturedEvents[fixture->capturedHead];
  fixture->capturedHead = (fixture->capturedHead + 1) % capacity;
  fixture->capturedCount--;
  return true;
}

extern const ioPollerCallbacks_t sessionEventFixtureCallbacks;
bool sessionTestInitTcpPollerFromFd(ioTcpPoller_t *poller, int tcpFd);
bool sessionTestSocketPairOpen(int sockType, int pair[2]);
void sessionTestSocketPairClose(int pair[2]);
bool sessionTestTcpPairOpen(int pair[2]);
void sessionTestTcpPairClose(int pair[2]);
bool sessionTestTunPairOpen(int pair[2]);
void sessionTestTunPairClose(int pair[2]);
/* TODO(test-harness-cleanup): add a shared tun-poller-from-fd helper to mirror TCP setup. */

static inline void sessionEventFixtureReset(sessionEventFixture_t *fixture) {
  if (fixture == NULL) {
    return;
  }
  fixture->capturedHead = 0;
  fixture->capturedTail = 0;
  fixture->capturedCount = 0;
}

static inline bool sessionEventFixtureWaitEvent(
    sessionEventFixture_t *fixture,
    ioReactor_t *reactor,
    int timeoutMs,
    ioEvent_t *outEvent) {
  int attempts;
  if (fixture == NULL || reactor == NULL || outEvent == NULL) {
    return false;
  }
  for (attempts = 0; attempts < 6; attempts++) {
    ioReactorStepResult_t step;
    if (sessionEventFixturePopEvent(fixture, outEvent)) {
      return true;
    }
    step = ioReactorStep(reactor, timeoutMs);
    if (step == ioReactorStepError || step == ioReactorStepStop) {
      return false;
    }
    if (sessionEventFixturePopEvent(fixture, outEvent)) {
      return true;
    }
  }
  return false;
}

static inline bool sessionEventFixtureWaitEventOfKind(
    sessionEventFixture_t *fixture,
    ioReactor_t *reactor,
    int timeoutMs,
    ioEvent_t expected) {
  int attempts;
  ioEvent_t event;
  for (attempts = 0; attempts < 8; attempts++) {
    if (!sessionEventFixtureWaitEvent(fixture, reactor, timeoutMs, &event)) {
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
