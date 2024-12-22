#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "log.h"

int tunOpen(const char *ifName) {
  struct ifreq ifr;
  int fd, err;
  logf("opening tun device %s", ifName);

  if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
    perrf("failed to open /dev/net/tun");
  }
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN;
  strncpy(ifr.ifr_name, ifName, IFNAMSIZ - 1);

  /* ioctl will use ifr.if_name as the name of TUN
   * interface to open: "tun0", etc. */
  if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) == -1) {
    perrf("ioctl failed on tun device");
  }

  /* After the ioctl call the fd is "connected" to tun device specified
   * by devname ("tun0", "tun1", etc)*/
  logf("successfully opened tun device %s", ifName);
  return fd;
}

#define PACKET_SIZE 4096
#define TIMEOUT     2000

typedef struct packet_t {
  long nbytes;
  char buf[PACKET_SIZE];
} packet_t;

bool pipeTun(int tunFd, int connFd) {
  static packet_t packet;

  packet.nbytes = read(tunFd, packet.buf, sizeof(packet.buf));
  if (packet.nbytes <= 0) {
    return false;
  }

  dbgf("read %ld bytes from tun", packet.nbytes);

  int i = 0;
  int nbytes = sizeof(packet.nbytes) + packet.nbytes;
  while (i < nbytes) {
    int k = write(connFd, (char *)&packet + i, nbytes - i);
    if (k <= 0) {
      return false;
    }
    i += k;
  }
  return true;
}

packet_t tcpPacket;
int tcpPacketOffset;

bool pipeTcp(int tunFd, int connFd) {
  if (tcpPacketOffset < sizeof(tcpPacket.nbytes)) {
    int k = read(connFd, (char *)&tcpPacket + tcpPacketOffset, sizeof(tcpPacket.nbytes) - tcpPacketOffset);
    if (k <= 0) {
      return false;
    }
    tcpPacketOffset += k;
    if (tcpPacketOffset < sizeof(tcpPacket.nbytes)) {
      return true;
    }
    if (tcpPacket.nbytes <= 0 || tcpPacket.nbytes > PACKET_SIZE) {
      logf("bad packet");
      return false;
    }
    return true;
  }

  int nbytes = sizeof(tcpPacket.nbytes) + tcpPacket.nbytes;
  if (tcpPacketOffset < nbytes) {
    int k = read(connFd, (char *)&tcpPacket + tcpPacketOffset, nbytes - tcpPacketOffset);
    if (k <= 0) {
      return false;
    }
    tcpPacketOffset += k;
  }
  if (tcpPacketOffset < nbytes) {
    return true;
  }

  dbgf("read %ld bytes from remote", tcpPacket.nbytes);

  nbytes = tcpPacket.nbytes;
  int i = 0;
  while (i < nbytes) {
    int k = write(tunFd, tcpPacket.buf + i, nbytes - i);
    if (k <= 0) {
      return false;
    }
    i += k;
  }
  tcpPacketOffset = 0;
  return true;
}

void epollAdd(int epollFd, int fd) {
  struct epoll_event event;
  event.events = EPOLLIN | EPOLLRDHUP;
  event.data.fd = fd;

  if (epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &event) < 0) {
    perrf("setup epoll failed");
  }
}

void serveTcp(const char *ifName, int connFd) {
  int tunFd = tunOpen(ifName);

  int epollFd = epoll_create(1);
  if (epollFd < 0) {
    perrf("setup epoll failed");
  }
  epollAdd(epollFd, tunFd);
  epollAdd(epollFd, connFd);
  memset(&tcpPacket, 0, sizeof(tcpPacket));
  tcpPacketOffset = 0;

  bool stop = false;
  while (!stop) {
    struct epoll_event event;
    int n = epoll_wait(epollFd, &event, 1, TIMEOUT);
    int i;
    if (n < 0) {
      perrf("epoll wait failed");
    } else if (n == 0) {
      dbgf("no event");
      continue;
    }
    for (i = 0; i < n; i++) {
      if (event.events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) {
        logf("connection error or closed");
        stop = true;
        break;
      } else if (event.events & EPOLLIN) {
        bool result;
        if (event.data.fd == tunFd) {
          result = pipeTun(tunFd, connFd);
        } else {
          result = pipeTcp(tunFd, connFd);
        }
        if (!result) {
          logf("connection closed");
          stop = true;
        }
        break;
      }
    }
  }

  close(connFd);
  close(tunFd);
  logf("connection stopped");
}

void listenTcp(const char *ifName, const char *listenIP, int port) {
  int listenFd = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in serverAddr;
  serverAddr.sin_family = AF_INET;
  inet_pton(AF_INET, listenIP, &serverAddr.sin_addr);
  serverAddr.sin_port = htons(port);

  if (bind(listenFd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
    perrf("bind failed");
  }
  listen(listenFd, 1);
  logf("listening on %s:%d", listenIP, port);

  while (1) {
    struct sockaddr_in clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    int connFd = accept(listenFd, (struct sockaddr *)&clientAddr, &addrLen);

    char clientIP[256];
    inet_ntop(AF_INET, &clientAddr, clientIP, sizeof(clientIP));
    int clientPort = ntohs(clientAddr.sin_port);
    logf("connected with %s:%d", clientIP, clientPort);

    serveTcp(ifName, connFd);
  }

  close(listenFd);
  logf("server stopped");
}

void connTcp(const char *ifName, const char *remoteIP, int port) {
  int connFd = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in remoteAddr;
  remoteAddr.sin_family = AF_INET;
  inet_pton(AF_INET, remoteIP, &remoteAddr.sin_addr);
  remoteAddr.sin_port = htons(port);

  connect(connFd, (struct sockaddr *)&remoteAddr, sizeof(remoteAddr));
  logf("connected to %s:%d", remoteIP, port);

  serveTcp(ifName, connFd);
}

int main(int argc, char **argv) {
  if (argc != 5) {
    panicf("invalid arguments");
  }
  const char *ifName = argv[1];
  const char *ip = argv[2];
  int port = atoi(argv[3]);
  int server = atoi(argv[4]);

  if (server) {
    listenTcp(ifName, ip, port);
  } else {
    connTcp(ifName, ip, port);
  }

  return 0;
}
