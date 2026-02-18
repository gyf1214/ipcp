#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#include <cjson/cJSON.h>

#include "config.h"

static int parseMode(const cJSON *root, daemonConfig_t *cfg) {
  const cJSON *mode = cJSON_GetObjectItemCaseSensitive(root, "mode");
  if (!cJSON_IsString(mode) || mode->valuestring == NULL) {
    return -1;
  }
  if (strcmp(mode->valuestring, "server") == 0) {
    cfg->mode = configModeServer;
    return 0;
  }
  if (strcmp(mode->valuestring, "client") == 0) {
    cfg->mode = configModeClient;
    return 0;
  }
  return -1;
}

static int copyRequiredString(const cJSON *root, const char *name, char out[ConfigTextSize]) {
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(root, name);
  size_t nbytes = 0;

  if (!cJSON_IsString(value) || value->valuestring == NULL) {
    return -1;
  }
  nbytes = strlen(value->valuestring);
  if (nbytes == 0 || nbytes >= ConfigTextSize) {
    return -1;
  }
  memcpy(out, value->valuestring, nbytes + 1);
  return 0;
}

static int copyRequiredPort(const cJSON *root, const char *name, int *out) {
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(root, name);
  if (!cJSON_IsNumber(value) || value->valuedouble != (double)value->valueint) {
    return -1;
  }
  if (value->valueint < 1 || value->valueint > 65535) {
    return -1;
  }
  *out = value->valueint;
  return 0;
}

static int copyOptionalPositiveInt(const cJSON *root, const char *name, int *out) {
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(root, name);
  if (value == NULL) {
    return 0;
  }
  if (!cJSON_IsNumber(value) || value->valuedouble != (double)value->valueint || value->valueint <= 0) {
    return -1;
  }
  *out = value->valueint;
  return 0;
}

static int parseHeartbeatConfig(const cJSON *root, daemonConfig_t *cfg) {
  if (copyOptionalPositiveInt(root, "heartbeat_interval_ms", &cfg->heartbeatIntervalMs) != 0) {
    return -1;
  }
  if (copyOptionalPositiveInt(root, "heartbeat_timeout_ms", &cfg->heartbeatTimeoutMs) != 0) {
    return -1;
  }
  if (cfg->heartbeatTimeoutMs <= cfg->heartbeatIntervalMs) {
    return -1;
  }
  return 0;
}

static int parseServerConfig(const cJSON *root, daemonConfig_t *cfg) {
  if (copyRequiredString(root, "if_name", cfg->ifName) != 0) {
    return -1;
  }
  if (copyRequiredString(root, "key_file", cfg->keyFile) != 0) {
    return -1;
  }
  if (copyRequiredString(root, "listen_ip", cfg->listenIP) != 0) {
    return -1;
  }
  if (copyRequiredPort(root, "listen_port", &cfg->listenPort) != 0) {
    return -1;
  }
  return 0;
}

static int parseClientConfig(const cJSON *root, daemonConfig_t *cfg) {
  if (copyRequiredString(root, "if_name", cfg->ifName) != 0) {
    return -1;
  }
  if (copyRequiredString(root, "key_file", cfg->keyFile) != 0) {
    return -1;
  }
  if (copyRequiredString(root, "server_ip", cfg->serverIP) != 0) {
    return -1;
  }
  if (copyRequiredPort(root, "server_port", &cfg->serverPort) != 0) {
    return -1;
  }
  return 0;
}

void configZero(daemonConfig_t *cfg) {
  if (cfg == NULL) {
    return;
  }
  sodium_memzero(cfg, sizeof(*cfg));
  cfg->heartbeatIntervalMs = ConfigDefaultHeartbeatIntervalMs;
  cfg->heartbeatTimeoutMs = ConfigDefaultHeartbeatTimeoutMs;
}

int configLoadFromFile(daemonConfig_t *out, const char *path) {
  FILE *fin = NULL;
  char *buf = NULL;
  cJSON *root = NULL;
  int result = -1;
  long fileSize = 0;
  size_t nread = 0;

  if (out == NULL || path == NULL) {
    return -1;
  }

  configZero(out);

  fin = fopen(path, "rb");
  if (fin == NULL) {
    goto cleanup;
  }
  if (fseek(fin, 0, SEEK_END) != 0) {
    goto cleanup;
  }
  fileSize = ftell(fin);
  if (fileSize < 0) {
    goto cleanup;
  }
  if (fseek(fin, 0, SEEK_SET) != 0) {
    goto cleanup;
  }
  buf = malloc((size_t)fileSize + 1);
  if (buf == NULL) {
    goto cleanup;
  }
  nread = fread(buf, 1, (size_t)fileSize, fin);
  if (nread != (size_t)fileSize || ferror(fin)) {
    goto cleanup;
  }
  buf[fileSize] = '\0';

  root = cJSON_Parse(buf);
  if (!cJSON_IsObject(root)) {
    goto cleanup;
  }
  if (parseMode(root, out) != 0) {
    goto cleanup;
  }
  if (out->mode == configModeServer) {
    if (parseServerConfig(root, out) != 0) {
      goto cleanup;
    }
  } else if (out->mode == configModeClient) {
    if (parseClientConfig(root, out) != 0) {
      goto cleanup;
    }
  } else {
    goto cleanup;
  }
  if (parseHeartbeatConfig(root, out) != 0) {
    goto cleanup;
  }

  result = 0;

cleanup:
  if (root != NULL) {
    cJSON_Delete(root);
  }
  if (buf != NULL) {
    sodium_memzero(buf, (size_t)fileSize + 1);
    free(buf);
  }
  if (fin != NULL) {
    fclose(fin);
  }
  if (result != 0) {
    configZero(out);
  }

  return result;
}
