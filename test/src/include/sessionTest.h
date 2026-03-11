#pragma once

#include <stdbool.h>
#include <string.h>

#include "io.h"

typedef struct {
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
bool sessionTestInitTcpPollerFromFd(ioTcpPoller_t *poller, int tcpFd);
/* TODO(test-harness-cleanup): add a shared tun-poller-from-fd helper to mirror TCP setup. */

static inline void runtimeEventFixtureReset(runtimeEventFixture_t *fixture) {
  if (fixture == NULL) {
    return;
  }
  fixture->capturedHead = 0;
  fixture->capturedTail = 0;
  fixture->capturedCount = 0;
}

static inline bool runtimeEventFixtureWaitEvent(
    runtimeEventFixture_t *fixture,
    ioReactor_t *reactor,
    int timeoutMs,
    ioEvent_t *outEvent) {
  int attempts;
  if (fixture == NULL || reactor == NULL || outEvent == NULL) {
    return false;
  }
  for (attempts = 0; attempts < 6; attempts++) {
    ioReactorStepResult_t step;
    if (runtimeEventFixturePopEvent(fixture, outEvent)) {
      return true;
    }
    step = ioReactorStep(reactor, timeoutMs);
    if (step == ioReactorStepError || step == ioReactorStepStop) {
      return false;
    }
    if (runtimeEventFixturePopEvent(fixture, outEvent)) {
      return true;
    }
  }
  return false;
}

static inline bool runtimeEventFixtureWaitEventOfKind(
    runtimeEventFixture_t *fixture,
    ioReactor_t *reactor,
    int timeoutMs,
    ioEvent_t expected) {
  int attempts;
  ioEvent_t event;
  for (attempts = 0; attempts < 8; attempts++) {
    if (!runtimeEventFixtureWaitEvent(fixture, reactor, timeoutMs, &event)) {
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
