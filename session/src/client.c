#include "session.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sodium.h>

#include "log.h"

#define EPOLL_WAIT_MS 200

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

static int decodeRawWireFrame(const protocolFrame_t *frame, protocolRawMsg_t *msg) {
  protocolDecoder_t decoder;
  unsigned char wire[ProtocolWireLengthSize + ProtocolFrameSize];
  uint32_t wireLen = 0;
  long consumed = 0;

  if (frame == NULL || msg == NULL || frame->nbytes <= 0 || frame->nbytes > ProtocolFrameSize) {
    return -1;
  }

  wireLen = htonl((uint32_t)frame->nbytes);
  memcpy(wire, &wireLen, ProtocolWireLengthSize);
  memcpy(wire + ProtocolWireLengthSize, frame->buf, (size_t)frame->nbytes);

  protocolDecoderInit(&decoder);
  if (protocolDecodeRaw(
          &decoder,
          wire,
          ProtocolWireLengthSize + frame->nbytes,
          &consumed,
          msg)
      != protocolStatusOk) {
    return -1;
  }
  return consumed == ProtocolWireLengthSize + frame->nbytes ? 0 : -1;
}

static int clientRunPreAuthHandshake(
    int connFd, const unsigned char *claim, long claimNbytes, const unsigned char key[ProtocolPskSize]) {
  protocolFrame_t frame;
  protocolRawMsg_t rawMsg;
  protocolMessage_t msg;
  unsigned char helloPayload[ProtocolNonceSize * 2];

  if (claim == NULL || claimNbytes <= 0 || key == NULL) {
    return -1;
  }
  rawMsg.nbytes = claimNbytes;
  rawMsg.buf = (const char *)claim;
  if (protocolEncodeRaw(&rawMsg, &frame) != protocolStatusOk) {
    return -1;
  }
  if (writeWireFrame(connFd, &frame) != 0) {
    return -1;
  }

  if (readWireFrame(connFd, &frame) != 0) {
    return -1;
  }
  if (decodeRawWireFrame(&frame, &rawMsg) != 0) {
    return -1;
  }
  if (rawMsg.nbytes != ProtocolNonceSize) {
    return -1;
  }

  memcpy(helloPayload, rawMsg.buf, ProtocolNonceSize);
  randombytes_buf(helloPayload + ProtocolNonceSize, ProtocolNonceSize);
  msg.type = protocolMsgClientHello;
  msg.nbytes = sizeof(helloPayload);
  msg.buf = (const char *)helloPayload;
  if (protocolEncodeSecureMsg(&msg, key, &frame) != protocolStatusOk) {
    return -1;
  }
  if (writeWireFrame(connFd, &frame) != 0) {
    return -1;
  }
  return 0;
}

int sessionServeClient(
    int tunFd,
    int connFd,
    const unsigned char *claim,
    long claimNbytes,
    const unsigned char key[ProtocolPskSize],
    const sessionHeartbeatConfig_t *heartbeatCfg) {
  ioTunPoller_t tunPoller;
  ioTcpPoller_t tcpPoller;
  ioEvent_t event;
  session_t *session = NULL;
  int epollFd = -1;
  int result = -1;

  if (tunFd < 0 || connFd < 0 || claim == NULL || claimNbytes <= 0 || key == NULL || heartbeatCfg == NULL) {
    return -1;
  }

  if (clientRunPreAuthHandshake(connFd, claim, claimNbytes, key) != 0) {
    errf("pre-auth handshake failed");
    return -1;
  }

  epollFd = epoll_create1(0);
  if (epollFd < 0) {
    errf("setup epoll failed: %s", strerror(errno));
    goto cleanup;
  }
  if (ioTunPollerInit(&tunPoller, epollFd, tunFd) != 0 || ioTcpPollerInit(&tcpPoller, epollFd, connFd) != 0) {
    errf("setup epoll failed: %s", strerror(errno));
    goto cleanup;
  }

  session = sessionCreate(false, heartbeatCfg, NULL, NULL);
  if (session == NULL) {
    errf("session setup failed");
    goto cleanup;
  }

  while (1) {
    event = ioPollersWait(&tunPoller, &tcpPoller, EPOLL_WAIT_MS);
    if (sessionStep(session, &tcpPoller, &tunPoller, event, key) == sessionStepStop) {
      break;
    }
  }

  result = 0;
  logf("connection stopped");

cleanup:
  if (session != NULL) {
    sessionDestroy(session);
  }
  if (epollFd >= 0) {
    close(epollFd);
  }

  return result;
}
