#include <time.h>

#include "log.h"

#define TIME_BUF_SIZE 128

const char *logTimeStr() {
  static char buffer[TIME_BUF_SIZE];

  time_t nowTime = time(NULL);
  struct tm *now = localtime(&nowTime);
  strftime(buffer, TIME_BUF_SIZE, "%Y-%m-%d %H:%M:%S", now);
  return buffer;
}
