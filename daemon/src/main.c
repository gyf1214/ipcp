#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <pthread.h>

#ifdef NDEBUG
#define dbgf(...)           do {} while (0)
#define logf(fmt, ...)      fprintf(stderr, fmt"\n", ##__VA_ARGS__)
#else
#define dbgf(fmt, ...)      fprintf(stderr, "[DEBUG] (%s:%d) "fmt"\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define logf(fmt, ...)      fprintf(stderr, "[ INFO] (%s:%d) "fmt"\n", __FILE__, __LINE__, ##__VA_ARGS__)
#endif

int tunOpen(const char *ifName) {
  struct ifreq ifr;
  int fd, err;
  logf("opening tun device %s", ifName);

  if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
    perror("open /dev/net/tun");
    exit(1);
  }
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN;
  strncpy(ifr.ifr_name, ifName, IFNAMSIZ - 1);

  /* ioctl will use ifr.if_name as the name of TUN
   * interface to open: "tun0", etc. */
  if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) == -1) {
    perror("ioctl TUNSETIFF");
    close(fd);
    exit(1);
  }

  /* After the ioctl call the fd is "connected" to tun device specified
   * by devname ("tun0", "tun1", etc)*/
  logf("successfully opened tun device %s", ifName);
  return fd;
}

volatile bool stop;

#define PACKET_SIZE 4096

typedef struct packet_t {
  long nbytes;
  char buf[PACKET_SIZE];
} packet_t;

void serveTun(int connFd, int tunFd) {
  packet_t packet;
  logf("start serve tun device");
  while (1) {
    packet.nbytes = read(tunFd, packet.buf, sizeof(packet.buf));
    if (stop || packet.nbytes <= 0) {
      break;
    }
    dbgf("read %ld bytes from tun", packet.nbytes);

    int i = 0;
    int nbytes = sizeof(packet.nbytes) + packet.nbytes;
    while (i < nbytes) {
      i += write(connFd, (char *)&packet + i, nbytes - i);
    }
  }
  logf("serve tun device stopped");
}

typedef struct arg_t {
  int connFd;
  int tunFd;
} arg_t;

void *serveTunFunc(void *arg) {
  arg_t *arg1 = (arg_t *)arg;
  int connFd = arg1->connFd;
  int tunFd = arg1->tunFd;
  free(arg);

  serveTun(connFd, tunFd);

  return NULL;
}

void serveTcp(const char *ifName, int connFd) {
  int tunFd = tunOpen(ifName);

  stop = false;
  arg_t *arg = malloc(sizeof(arg_t));
  arg->connFd = connFd;
  arg->tunFd = tunFd;
  pthread_t threadId;
  pthread_create(&threadId, NULL, serveTunFunc, arg);

  packet_t packet;
  while (1) {
    if (read(connFd, &packet.nbytes, sizeof(packet.nbytes)) <= 0) {
      logf("connection closed by remote");
      break;
    }
    if (packet.nbytes > 0 && packet.nbytes < sizeof(packet.buf)) {
      int i = 0;
      while (i < packet.nbytes) {
        i += read(connFd, packet.buf + i, packet.nbytes - i);
      }
      dbgf("read %ld bytes from remote", packet.nbytes);

      write(tunFd, packet.buf, packet.nbytes);
    } else {
      dbgf("discard bad packet");
    }
  }

  stop = true;
  close(tunFd);
  void *nothing;
  pthread_join(threadId, &nothing);
  close(connFd);
  logf("connection stopped");
}

void listenTcp(const char *ifName, const char *listenIP, int port) {
  int listenFd = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in serverAddr;
  serverAddr.sin_family = AF_INET;
  inet_pton(AF_INET, listenIP, &serverAddr.sin_addr);
  serverAddr.sin_port = htons(port);

  if (bind(listenFd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
    perror("bind");
    close(listenFd);
    exit(1);
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
    fprintf(stderr, "invalid arguments\n");
    exit(1);
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
