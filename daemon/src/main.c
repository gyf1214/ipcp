#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if.h>
#include <linux/if_tun.h>

int tun_open(const char *ifname) {
  struct ifreq ifr;
  int fd, err;

  if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
    perror("open /dev/net/tun");
    exit(1);
  }
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN;
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

  /* ioctl will use ifr.if_name as the name of TUN
   * interface to open: "tun0", etc. */
  if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) == -1) {
    perror("ioctl TUNSETIFF");
    close(fd);
    exit(1);
  }

  /* After the ioctl call the fd is "connected" to tun device specified
   * by devname ("tun0", "tun1", etc)*/
  return fd;
}

int main() {
  int fd, nbytes;
  char buf[2560];

  fd = tun_open("tun0");
  printf("listen on tun0\n");
  while (1) {
    nbytes = read(fd, buf, sizeof(buf));
    printf("read %d bytes from tun0\n", nbytes);
  }

  return 0;
}
