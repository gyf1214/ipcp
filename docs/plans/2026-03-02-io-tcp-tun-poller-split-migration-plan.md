# IO TCP/TUN Poller Split Migration Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Split monolithic `ioPoller_t` into explicit `ioTcpPoller_t` and `ioTunPoller_t`, migrate session/server runtime to IO APIs only (no direct `read`/`write` in session layer), and remove deprecated poller APIs.

**Architecture:** Introduce endpoint-specific pollers and endpoint-specific IO APIs while preserving current backpressure semantics (single pending frame + pause/resume) and existing TCP behavior. Server runtime owns one shared `ioTunPoller_t`; each active connection owns one `ioTcpPoller_t`. TUN ingress client selection behavior remains unchanged in this plan (current first-available-session behavior).

**Tech Stack:** C17, Linux `epoll`, `TUN/TAP`, existing `mkmake` build and C test harness.

---

### Task 1: Lock API Contract With Failing Tests

**Files:**
- Modify: `io/include/io.h`
- Modify: `test/src/ioTest.c`
- Test: `test/src/ioTest.c`

**Step 1: Write the failing tests**

Add tests that compile against the target API surface:

```c
typedef struct { /* ... */ } ioTcpPoller_t;
typedef struct { /* ... */ } ioTunPoller_t;

int ioTcpPollerInit(ioTcpPoller_t *poller, int epollFd, int tcpFd);
int ioTunPollerInit(ioTunPoller_t *poller, int epollFd, int tunFd);
ioStatus_t ioTcpRead(int tcpFd, void *buf, long capacity, long *outNbytes);
ioStatus_t ioTunRead(int tunFd, void *buf, long capacity, long *outNbytes);
bool ioTcpWrite(ioTcpPoller_t *poller, const void *data, long nbytes);
bool ioTunWrite(ioTunPoller_t *poller, const void *data, long nbytes);
```

Add compile-time and runtime tests for:
- TCP queue/write/flush event path via `ioTcp*` APIs.
- TUN queue/write/flush event path via `ioTun*` APIs.
- Read-enable toggling per endpoint.

**Step 2: Run test to verify it fails**

Run: `podman run --rm -v "$PWD:/work" -w /work localhost/ipcp-integration:local bash -lc "make test"`
Expected: FAIL with undefined type/function errors for new `ioTcp*`/`ioTun*` symbols.

**Step 3: Write minimal header declarations only**

Declare new types/functions in `io/include/io.h` without removing old APIs yet.

**Step 4: Run test to verify partial progress**

Run: `podman run --rm -v "$PWD:/work" -w /work localhost/ipcp-integration:local bash -lc "make test"`
Expected: FAIL at link stage for missing implementations.

**Step 5: Commit**

```bash
git add io/include/io.h test/src/ioTest.c
git commit -m "test: add split poller API contract coverage"
```

### Task 2: Implement `ioTcpPoller_t` and `ioTunPoller_t` in IO Layer

**Files:**
- Modify: `io/include/io.h`
- Modify: `io/src/io.c`
- Test: `test/src/ioTest.c`

**Step 1: Write failing behavior tests**

Add tests for queue capacity, flush behavior, and read-interest toggles for both new pollers.

**Step 2: Run test to verify it fails**

Run: `podman run --rm -v "$PWD:/work" -w /work localhost/ipcp-integration:local bash -lc "make test"`
Expected: FAIL in `ioTest` for unimplemented behavior.

**Step 3: Write minimal implementation**

Implement endpoint-specific structs and APIs in `io/src/io.c`:

```c
struct ioTcpPoller_t {
  int epollFd;
  int tcpFd;
  unsigned int tcpEvents;
  long outOffset;
  long outNbytes;
  unsigned char outBuf[IoPollerQueueCapacity];
};

struct ioTunPoller_t {
  int epollFd;
  int tunFd;
  unsigned int tunEvents;
  long outOffset;
  long outNbytes;
  unsigned char outBuf[IoPollerQueueCapacity];
};
```

Implement `ioTcpRead/ioTunRead` as wrappers over the existing nonblocking read helper behavior. Keep queue semantics identical to current implementation.

**Step 4: Run test to verify it passes**

Run: `podman run --rm -v "$PWD:/work" -w /work localhost/ipcp-integration:local bash -lc "make test"`
Expected: PASS `io tests` and no regressions in other suites.

**Step 5: Commit**

```bash
git add io/include/io.h io/src/io.c test/src/ioTest.c
git commit -m "feat: add endpoint-specific io tcp/tun pollers"
```

### Task 3: Refactor Session API to Endpoint-Specific Pollers

**Files:**
- Modify: `session/include/session.h`
- Modify: `session/src/session.c`
- Modify: `test/src/sessionTest.c`
- Test: `test/src/sessionTest.c`

**Step 1: Write failing tests for session signatures**

Update tests to call session APIs with split pollers:

```c
sessionStep(session, &tcpPoller, &tunPoller, event, key);
sessionServiceBackpressure(session, &tcpPoller, &tunPoller);
```

**Step 2: Run test to verify it fails**

Run: `podman run --rm -v "$PWD:/work" -w /work localhost/ipcp-integration:local bash -lc "make test"`
Expected: FAIL with signature mismatch/undefined references.

**Step 3: Write minimal implementation**

Refactor session internals:
- Replace `ioPoller_t *poller` arguments with `ioTcpPoller_t *tcpPoller` and `ioTunPoller_t *tunPoller`.
- Replace all `ioReadSome(poller->fd,...)` with `ioTcpRead(...)` / `ioTunRead(...)`.
- Replace `ioPollerQueueWrite`/`ioPollerQueuedBytes`/`ioPollerSetReadEnabled`/`ioPollerServiceWriteEvent` calls with endpoint-specific APIs.
- Keep existing pause/backpressure decisions unchanged.

**Step 4: Run test to verify it passes**

Run: `podman run --rm -v "$PWD:/work" -w /work localhost/ipcp-integration:local bash -lc "make test"`
Expected: PASS `session tests` and `serverRuntime tests`.

**Step 5: Commit**

```bash
git add session/include/session.h session/src/session.c test/src/sessionTest.c
git commit -m "refactor: use split tcp/tun pollers in session layer"
```

### Task 4: Refactor Server Runtime Ownership Model

**Files:**
- Modify: `session/src/include/serverRuntime.h`
- Modify: `session/src/serverRuntime.c`
- Modify: `session/src/session.c`
- Modify: `test/src/serverRuntimeTest.c`
- Test: `test/src/serverRuntimeTest.c`

**Step 1: Write failing tests for runtime ownership and APIs**

Add/adjust tests to assert:
- Runtime has one shared `ioTunPoller_t`.
- Each active connection owns `ioTcpPoller_t`.
- Pending owner-slot behavior is unchanged.

**Step 2: Run test to verify it fails**

Run: `podman run --rm -v "$PWD:/work" -w /work localhost/ipcp-integration:local bash -lc "make test"`
Expected: FAIL in runtime/session compilation and test assertions.

**Step 3: Write minimal implementation**

- Move server shared TUN queue state into runtime-owned `ioTunPoller_t`.
- Replace `activeConn_t.poller` with `activeConn_t.tcpPoller`.
- Keep runtime-level pending TUN->TCP single-frame storage and owner-slot retry behavior.
- Keep shared epoll registration behavior intact.

**Step 4: Run test to verify it passes**

Run: `podman run --rm -v "$PWD:/work" -w /work localhost/ipcp-integration:local bash -lc "make test"`
Expected: PASS `serverRuntime tests` plus all existing unit suites.

**Step 5: Commit**

```bash
git add session/src/include/serverRuntime.h session/src/serverRuntime.c session/src/session.c test/src/serverRuntimeTest.c
git commit -m "refactor: split server runtime tun and per-client tcp pollers"
```

### Task 5: Preserve Existing TUN Ingress Selection During Poller Split

**Files:**
- Modify: `session/src/include/serverRuntime.h`
- Modify: `session/src/serverRuntime.c`
- Modify: `session/src/session.c`
- Modify: `test/src/serverRuntimeTest.c`
- Modify: `test/src/sessionTest.c`
- Test: `test/src/serverRuntimeTest.c`
- Test: `test/src/sessionTest.c`

**Step 1: Write failing compatibility/backpressure tests**

Add tests for server TUN ingress:
- Existing selection behavior remains unchanged (first available active session).
- Backpressure behavior remains unchanged (single pending + pause/resume).
- No claim-based destination routing is introduced in this task.

**Step 2: Run test to verify it fails**

Run: `podman run --rm -v "$PWD:/work" -w /work localhost/ipcp-integration:local bash -lc "make test"`
Expected: FAIL on compatibility assertions until wiring is complete.

**Step 3: Write minimal implementation**

- Keep existing active-session selection logic when handling shared TUN `EPOLLIN`.
- Route selected frame into the selected session TCP path through split poller APIs.
- Preserve overflow handling: runtime pending-owner behavior and TUN read pause/resume.

**Step 4: Run test to verify it passes**

Run: `podman run --rm -v "$PWD:/work" -w /work localhost/ipcp-integration:local bash -lc "make test"`
Expected: PASS compatibility coverage with no behavior regression.

**Step 5: Commit**

```bash
git add session/src/include/serverRuntime.h session/src/serverRuntime.c session/src/session.c test/src/serverRuntimeTest.c test/src/sessionTest.c
git commit -m "refactor: preserve tun ingress behavior during poller split"
```

### Task 6: Remove Deprecated `ioPoller`/`ioSource` APIs Completely

**Files:**
- Modify: `io/include/io.h`
- Modify: `io/src/io.c`
- Modify: `daemon/src/main.c`
- Modify: `session/include/session.h`
- Modify: `session/src/session.c`
- Modify: `session/src/serverRuntime.c`
- Modify: `test/src/ioTest.c`
- Modify: `test/src/sessionTest.c`
- Modify: `test/src/serverRuntimeTest.c`

**Step 1: Write failing compile guard test**

Add a compile-time assertion pattern in tests/code that old APIs are no longer referenced:
- `ioPoller_t`
- `ioSource_t`
- `ioPoller*` functions
- direct `ioReadSome(...)` from session/runtime code

**Step 2: Run test/build to verify it fails before cleanup**

Run: `podman run --rm -v "$PWD:/work" -w /work localhost/ipcp-integration:local bash -lc "make all"`
Expected: FAIL where deprecated symbols are still referenced.

**Step 3: Remove deprecated APIs and callers**

- Delete old symbols from `io/include/io.h` and `io/src/io.c`.
- Update daemon client loop to split pollers.
- Update all tests and call sites.
- Ensure session layer does not call `read`/`write` directly.

**Step 4: Run full unit verification**

Run: `podman run --rm -v "$PWD:/work" -w /work localhost/ipcp-integration:local bash -lc "make test"`
Expected: PASS all unit suites.

**Step 5: Commit**

```bash
git add io/include/io.h io/src/io.c daemon/src/main.c session/include/session.h session/src/session.c session/src/serverRuntime.c test/src/ioTest.c test/src/sessionTest.c test/src/serverRuntimeTest.c
git commit -m "refactor: remove deprecated unified poller APIs"
```

### Task 7: End-to-End Verification and Documentation Update

**Files:**
- Modify: `README.md`
- Create: `scratch/notes/2026-03-02-io-poller-split-verification.md`

**Step 1: Document API and ownership model changes**

Update README architecture section:
- Server: shared `ioTunPoller_t` in runtime, per-connection `ioTcpPoller_t`.
- Client: one `ioTunPoller_t` + one `ioTcpPoller_t`.
- Session boundary: IO only via `ioTcp*`/`ioTun*` APIs.

**Step 2: Run full verification matrix**

Run:
- `podman run --rm -v "$PWD:/work" -w /work localhost/ipcp-integration:local bash -lc "make all"`
- `podman run --rm -v "$PWD:/work" -w /work localhost/ipcp-integration:local bash -lc "make test"`
- `bash scripts/run_in_container.sh`

Expected: all commands exit 0.

**Step 3: Record evidence**

Capture command outputs and key pass lines in `scratch/notes/2026-03-02-io-poller-split-verification.md`.

**Step 4: Final commit**

```bash
git add README.md
git commit -m "docs: describe split tcp/tun poller architecture"
```

**Step 5: Final status check**

Run: `git status --short`
Expected: clean tree except intentionally untracked ignored note files.
