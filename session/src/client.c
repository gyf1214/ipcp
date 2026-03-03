#include "sessionInternal.h"

#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sodium.h>

#include "log.h"
#include "client.h"

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

static int readWireFrame(int fd, protocolFrame_t *frame) {
  long contentNbytes = 0;
  if (frame == NULL) {
    return -1;
  }
  if (readAll(fd, frame->buf, ProtocolWireLengthSize) != 0) {
    return -1;
  }
  contentNbytes = ((long)(unsigned char)frame->buf[0] << 24)
      | ((long)(unsigned char)frame->buf[1] << 16)
      | ((long)(unsigned char)frame->buf[2] << 8)
      | (long)(unsigned char)frame->buf[3];
  if (contentNbytes <= 0 || contentNbytes > (ProtocolFrameSize - ProtocolWireLengthSize)) {
    return -1;
  }
  frame->nbytes = ProtocolWireLengthSize + contentNbytes;
  return readAll(fd, frame->buf + ProtocolWireLengthSize, contentNbytes);
}

static int decodeRawWireFrame(const protocolFrame_t *frame, protocolRawMsg_t *msg) {
  protocolDecoder_t decoder;
  long consumed = 0;

  if (frame == NULL || msg == NULL || frame->nbytes <= 0 || frame->nbytes > ProtocolFrameSize) {
    return -1;
  }

  protocolDecoderInit(&decoder);
  if (protocolDecodeRaw(&decoder, frame->buf, frame->nbytes, &consumed, msg) != protocolStatusOk) {
    return -1;
  }
  return consumed == frame->nbytes ? 0 : -1;
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
  if (clientWriteRawMsg(connFd, &rawMsg) != 0) {
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
  if (clientWriteSecureMsg(connFd, &msg, key) != 0) {
    return -1;
  }
  return 0;
}

int clientWriteRawMsg(int fd, const protocolRawMsg_t *msg) {
  protocolFrame_t frame;

  if (fd < 0 || msg == NULL || msg->buf == NULL || msg->nbytes <= 0) {
    return -1;
  }
  if (protocolEncodeRaw(msg, &frame) != protocolStatusOk) {
    return -1;
  }
  return writeAll(fd, frame.buf, frame.nbytes);
}

int clientWriteSecureMsg(
    int fd, const protocolMessage_t *msg, const unsigned char key[ProtocolPskSize]) {
  protocolFrame_t frame;

  if (fd < 0 || msg == NULL || msg->buf == NULL || msg->nbytes <= 0 || key == NULL) {
    return -1;
  }
  if (protocolEncodeSecureMsg(msg, key, &frame) != protocolStatusOk) {
    return -1;
  }
  return writeAll(fd, frame.buf, frame.nbytes);
}

int clientServeConn(
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
