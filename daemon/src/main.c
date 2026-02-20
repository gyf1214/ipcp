#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sodium.h>
#include <arpa/inet.h>

#include "config.h"
#include "crypt.h"
#include "io.h"
#include "log.h"
#include "protocol.h"
#include "session.h"

#define EPOLL_WAIT_MS 200

static ioIfMode_t toIoIfMode(configIfMode_t mode) {
  if (mode == configIfModeTap) {
    return ioIfModeTap;
  }
  return ioIfModeTun;
}

typedef struct {
  const cryptServerKeyStore_t *store;
  configIfMode_t ifMode;
} serverKeyLookupCtx_t;

static const char *ifModeLabel(configIfMode_t mode) {
  return mode == configIfModeTap ? "tap" : "tun";
}

static int serverLookupByClaim(void *ctx, const char *claim, unsigned char key[ProtocolPskSize]) {
  serverKeyLookupCtx_t *lookup = (serverKeyLookupCtx_t *)ctx;
  if (lookup == NULL || lookup->store == NULL) {
    return -1;
  }
  return cryptServerKeyStoreLookup(lookup->store, lookup->ifMode, claim, key);
}

static int writeAll(int fd, const void *buf, long nbytes) {
  long offset = 0;
  while (offset < nbytes) {
    ssize_t n = write(fd, (const char *)buf + offset, (size_t)(nbytes - offset));
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (n == 0) {
      return -1;
    }
    offset += (long)n;
  }
  return 0;
}

static int readAll(int fd, void *buf, long nbytes) {
  long offset = 0;
  while (offset < nbytes) {
    ssize_t n = read(fd, (char *)buf + offset, (size_t)(nbytes - offset));
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (n == 0) {
      return -1;
    }
    offset += (long)n;
  }
  return 0;
}

static int writeWireFrame(int fd, const protocolFrame_t *frame) {
  uint32_t wire = 0;
  if (frame == NULL || frame->nbytes <= 0 || frame->nbytes > ProtocolFrameSize) {
    return -1;
  }
  wire = htonl((uint32_t)frame->nbytes);
  if (writeAll(fd, &wire, ProtocolWireLengthSize) != 0) {
    return -1;
  }
  return writeAll(fd, frame->buf, frame->nbytes);
}

static int readWireFrame(int fd, protocolFrame_t *frame) {
  uint32_t wire = 0;
  if (frame == NULL) {
    return -1;
  }
  if (readAll(fd, &wire, ProtocolWireLengthSize) != 0) {
    return -1;
  }
  frame->nbytes = (long)ntohl(wire);
  if (frame->nbytes <= 0 || frame->nbytes > ProtocolFrameSize) {
    return -1;
  }
  return readAll(fd, frame->buf, frame->nbytes);
}

static int clientRunPreAuthHandshake(
    int connFd, const char *claim, const unsigned char key[ProtocolPskSize]) {
  protocolFrame_t frame;
  protocolMessage_t msg;
  unsigned char helloPayload[ProtocolNonceSize * 2];

  if (claim == NULL || claim[0] == '\0' || key == NULL) {
    return -1;
  }
  if (protocolEncode(claim, (long)strlen(claim), &frame) != protocolStatusOk) {
    return -1;
  }
  if (writeWireFrame(connFd, &frame) != 0) {
    return -1;
  }

  if (readWireFrame(connFd, &frame) != 0) {
    return -1;
  }
  if (protocolMessageDecodeFrame(&frame, &msg) != protocolStatusOk) {
    return -1;
  }
  if (msg.type != protocolMsgAuthChallenge || msg.nbytes != ProtocolNonceSize) {
    return -1;
  }

  memcpy(helloPayload, msg.buf, ProtocolNonceSize);
  randombytes_buf(helloPayload + ProtocolNonceSize, ProtocolNonceSize);
  msg.type = protocolMsgClientHello;
  msg.nbytes = sizeof(helloPayload);
  msg.buf = (const char *)helloPayload;
  if (protocolSecureEncodeMessage(&msg, key, &frame) != protocolStatusOk) {
    return -1;
  }
  if (writeWireFrame(connFd, &frame) != 0) {
    return -1;
  }
  return 0;
}

static int serveTcp(
    const char *ifName,
    configIfMode_t ifMode,
    int connFd,
    const unsigned char key[ProtocolPskSize],
    bool isServer,
    const sessionHeartbeatConfig_t *heartbeatCfg) {
  ioPoller_t poller;
  ioEvent_t event;
  session_t *session = NULL;
  int tunFd = -1;
  int result = -1;

  logf("opening tun device %s", ifName);
  tunFd = ioTunOpen(ifName, toIoIfMode(ifMode));
  if (tunFd < 0) {
    errf("failed to open tun device %s: %s", ifName, strerror(errno));
    goto cleanup;
  }
  logf("successfully opened tun device %s", ifName);

  if (ioPollerInit(&poller, tunFd, connFd) != 0) {
    errf("setup epoll failed: %s", strerror(errno));
    goto cleanup;
  }

  session = sessionCreate(isServer, heartbeatCfg, NULL, NULL);
  if (session == NULL) {
    errf("session setup failed");
    ioPollerClose(&poller);
    goto cleanup;
  }

  while (1) {
    event = ioPollerWait(&poller, EPOLL_WAIT_MS);
    if (sessionStep(session, &poller, event, key) == sessionStepStop) {
      break;
    }
  }

  result = 0;
  sessionDestroy(session);
  ioPollerClose(&poller);
  logf("connection stopped");

cleanup:
  if (session != NULL && result != 0) {
    sessionDestroy(session);
  }
  if (connFd >= 0) {
    close(connFd);
  }
  if (tunFd >= 0) {
    close(tunFd);
  }

  return result;
}

static int listenTcp(
    const char *ifName,
    configIfMode_t ifMode,
    const char *listenIP,
    int port,
    const cryptServerKeyStore_t *keyStore,
    int authTimeoutMs,
    const sessionHeartbeatConfig_t *heartbeatCfg) {
  serverKeyLookupCtx_t lookupCtx;
  int tunFd = -1;
  int listenFd = ioTcpListen(listenIP, port);
  if (listenFd < 0) {
    errf("listen setup failed: %s", strerror(errno));
    return -1;
  }
  logf("listening on %s:%d", listenIP, port);
  logf("opening tun device %s", ifName);
  tunFd = ioTunOpen(ifName, toIoIfMode(ifMode));
  if (tunFd < 0) {
    errf("failed to open tun device %s: %s", ifName, strerror(errno));
    close(listenFd);
    return -1;
  }
  logf("successfully opened tun device %s", ifName);

  lookupCtx.store = keyStore;
  lookupCtx.ifMode = ifMode;
  if (sessionServeMultiClient(
          tunFd,
          listenFd,
          serverLookupByClaim,
          &lookupCtx,
          ifModeLabel(ifMode),
          authTimeoutMs,
          heartbeatCfg,
          64)
      != 0) {
    close(tunFd);
    close(listenFd);
    return -1;
  }

  close(tunFd);
  close(listenFd);
  return 0;
}

static int connTcp(
    const char *ifName,
    configIfMode_t ifMode,
    const char *remoteIP,
    int port,
    const char *claim,
    const unsigned char key[ProtocolPskSize],
    const sessionHeartbeatConfig_t *heartbeatCfg) {
  int connFd = ioTcpConnect(remoteIP, port);
  if (connFd < 0) {
    errf("connect to %s:%d failed: %s", remoteIP, port, strerror(errno));
    return -1;
  }
  logf("connected to %s:%d", remoteIP, port);
  if (clientRunPreAuthHandshake(connFd, claim, key) != 0) {
    errf("pre-auth handshake failed");
    close(connFd);
    return -1;
  }

  return serveTcp(ifName, ifMode, connFd, key, false, heartbeatCfg);
}

int main(int argc, char **argv) {
  daemonConfig_t cfg;
  sessionHeartbeatConfig_t heartbeatCfg;
  unsigned char key[ProtocolPskSize];
  cryptServerKeyStore_t keyStore;
  int exitCode = EXIT_FAILURE;
  bool configLoaded = false;
  bool keyLoaded = false;
  bool keyStoreLoaded = false;

  configZero(&cfg);
  cryptServerKeyStoreZero(&keyStore);

  if (argc != 2) {
    errf("invalid arguments: <configFile>");
    goto cleanup;
  }

  cryptGlobalInit();
  if (configLoadFromFile(&cfg, argv[1]) != 0) {
    errf("invalid config file");
    goto cleanup;
  }
  configLoaded = true;

  if (cfg.mode == configModeServer) {
    if (cryptServerKeyStoreLoadFromConfig(&keyStore, &cfg) != 0) {
      errf("invalid secret file, expected exactly %d raw bytes", ProtocolPskSize);
      goto cleanup;
    }
    keyStoreLoaded = true;
  } else {
    if (cryptLoadKeyFromFile(key, cfg.keyFile) != 0) {
      errf("invalid secret file, expected exactly %d raw bytes", ProtocolPskSize);
      goto cleanup;
    }
    keyLoaded = true;
  }
  heartbeatCfg.intervalMs = cfg.heartbeatIntervalMs;
  heartbeatCfg.timeoutMs = cfg.heartbeatTimeoutMs;

  if (cfg.mode == configModeServer) {
    exitCode =
        listenTcp(
            cfg.ifName,
            cfg.ifMode,
            cfg.listenIP,
            cfg.listenPort,
            &keyStore,
            cfg.authTimeoutMs,
            &heartbeatCfg)
            == 0
            ? EXIT_SUCCESS
            : EXIT_FAILURE;
  } else {
    const char *claim = cfg.ifMode == configIfModeTap ? cfg.tapMac : cfg.tunIP;
    exitCode =
        connTcp(cfg.ifName, cfg.ifMode, cfg.serverIP, cfg.serverPort, claim, key, &heartbeatCfg) == 0
            ? EXIT_SUCCESS
            : EXIT_FAILURE;
  }

cleanup:
  if (keyLoaded) {
    sodium_memzero(key, sizeof(key));
  }
  if (keyStoreLoaded) {
    cryptServerKeyStoreZero(&keyStore);
  }
  if (configLoaded) {
    configZero(&cfg);
  }

  return exitCode;
}
