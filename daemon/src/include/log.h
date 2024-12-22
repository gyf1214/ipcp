#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef NDEBUG
#define doLogF(level, fmt, ...)   fprintf(stderr, "[%s] "fmt"\n", logTimeStr(), ##__VA_ARGS__)
#define doDbgF(level, fmt, ...)   do {} while (0)
#else
#define doLogF(level, fmt, ...)   fprintf(stderr, "[%s][%5s] (%s:%d) "fmt"\n", logTimeStr(), level, __FILE__, __LINE__, ##__VA_ARGS__)
#define doDbgF(level, fmt, ...)   doLogF(level, fmt, ##__VA_ARGS__)
#endif

#define dbgf(fmt, ...)      doDbgF("DEBUG", fmt, ##__VA_ARGS__)
#define logf(fmt, ...)      doLogF("INFO", fmt, ##__VA_ARGS__)
#define warnf(fmt, ...)     doLogF("WARN", fmt, ##__VA_ARGS__)
#define errf(fmt, ...)      doLogF("ERROR", fmt, ##__VA_ARGS__)
#define panicf(fmt, ...)    do { errf(fmt, ##__VA_ARGS__); abort(); } while (0)
#define perrf(fmt, ...)     panicf(fmt": %s", ##__VA_ARGS__, strerror(errno))

const char *logTimeStr();
