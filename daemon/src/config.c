#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <arpa/inet.h>
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

static int parseIfMode(const cJSON *root, daemonConfig_t *cfg) {
  const cJSON *ifMode = cJSON_GetObjectItemCaseSensitive(root, "if_mode");
  if (ifMode == NULL) {
    return 0;
  }
  if (!cJSON_IsString(ifMode) || ifMode->valuestring == NULL) {
    return -1;
  }
  if (strcmp(ifMode->valuestring, "tun") == 0) {
    cfg->ifMode = configIfModeTun;
    return 0;
  }
  if (strcmp(ifMode->valuestring, "tap") == 0) {
    cfg->ifMode = configIfModeTap;
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

static int parseRequiredPositiveInt(const cJSON *root, const char *name, int *out) {
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(root, name);
  if (!cJSON_IsNumber(value) || value->valuedouble != (double)value->valueint || value->valueint <= 0) {
    return -1;
  }
  *out = value->valueint;
  return 0;
}

static int parseIPv4String(const char *s) {
  struct in_addr addr;
  if (s == NULL) {
    return 0;
  }
  return inet_pton(AF_INET, s, &addr) == 1;
}

static int parseIPv4Claim(const char *s, unsigned char out[SessionClaimSize], long *outNbytes) {
  struct in_addr addr;
  if (s == NULL || out == NULL || outNbytes == NULL) {
    return -1;
  }
  if (inet_pton(AF_INET, s, &addr) != 1) {
    return -1;
  }
  memcpy(out, &addr, 4);
  *outNbytes = 4;
  return 0;
}

static int parseMacString(const char *s) {
  int i;
  if (s == NULL || strlen(s) != 17) {
    return 0;
  }
  for (i = 0; i < 17; i++) {
    if ((i % 3) == 2) {
      if (s[i] != ':') {
        return 0;
      }
      continue;
    }
    if (!isxdigit((unsigned char)s[i])) {
      return 0;
    }
  }
  return 1;
}

static int hexNibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return 10 + c - 'a';
  }
  if (c >= 'A' && c <= 'F') {
    return 10 + c - 'A';
  }
  return -1;
}

static int parseMacClaim(const char *s, unsigned char out[SessionClaimSize], long *outNbytes) {
  int i;
  if (s == NULL || out == NULL || outNbytes == NULL || !parseMacString(s)) {
    return -1;
  }
  for (i = 0; i < 6; i++) {
    int hi = hexNibble(s[i * 3]);
    int lo = hexNibble(s[i * 3 + 1]);
    if (hi < 0 || lo < 0) {
      return -1;
    }
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  *outNbytes = 6;
  return 0;
}

static int parseTunSubnet(const cJSON *root, daemonConfig_t *cfg) {
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(root, "tun_subnet");
  char subnet[ConfigTextSize];
  char *slash = NULL;
  char *end = NULL;
  long prefix = 0;
  struct in_addr networkAddr;
  uint32_t networkHost = 0;
  uint32_t maskHost = 0;
  uint32_t broadcastHost = 0;
  uint32_t networkNet = 0;
  uint32_t broadcastNet = 0;

  if (!cJSON_IsString(value) || value->valuestring == NULL) {
    return -1;
  }
  if (strlen(value->valuestring) >= sizeof(subnet)) {
    return -1;
  }
  memcpy(subnet, value->valuestring, strlen(value->valuestring) + 1);
  slash = strchr(subnet, '/');
  if (slash == NULL) {
    return -1;
  }
  *slash = '\0';
  if (inet_pton(AF_INET, subnet, &networkAddr) != 1) {
    return -1;
  }
  prefix = strtol(slash + 1, &end, 10);
  if (slash[1] == '\0' || end == NULL || *end != '\0' || prefix < 0 || prefix > 32) {
    return -1;
  }

  networkHost = ntohl(networkAddr.s_addr);
  if (prefix == 0) {
    maskHost = 0;
  } else {
    maskHost = 0xffffffffu << (32 - (unsigned int)prefix);
  }
  if ((networkHost & ~maskHost) != 0) {
    return -1;
  }

  broadcastHost = networkHost | ~maskHost;
  networkNet = htonl(networkHost & maskHost);
  broadcastNet = htonl(broadcastHost);

  cfg->tunSubnet.enabled = true;
  cfg->tunSubnet.prefix = (int)prefix;
  memcpy(cfg->tunSubnet.network, &networkNet, sizeof(cfg->tunSubnet.network));
  memcpy(cfg->tunSubnet.broadcast, &broadcastNet, sizeof(cfg->tunSubnet.broadcast));
  return 0;
}

static int parseServerCredentials(const cJSON *root, daemonConfig_t *cfg) {
  const cJSON *list = cJSON_GetObjectItemCaseSensitive(root, "credentials");
  int count = 0;
  int i = 0;

  if (!cJSON_IsArray(list)) {
    return -1;
  }
  count = cJSON_GetArraySize(list);
  if (count <= 0 || count > ConfigMaxServerCredentials) {
    return -1;
  }

  for (i = 0; i < count; i++) {
    const cJSON *entry = cJSON_GetArrayItem(list, i);
    daemonServerCredential_t *cred = &cfg->serverCredentials[i];
    if (!cJSON_IsObject(entry)) {
      return -1;
    }
    if (copyRequiredString(entry, "key_file", cred->keyFile) != 0) {
      return -1;
    }
    if (cfg->ifMode == configIfModeTun) {
      if (copyRequiredString(entry, "tun_ip", cred->tunIP) != 0 || !parseIPv4String(cred->tunIP)) {
        return -1;
      }
      if (parseIPv4Claim(cred->tunIP, cred->claim, &cred->claimNbytes) != 0) {
        return -1;
      }
      if (cJSON_GetObjectItemCaseSensitive(entry, "tap_mac") != NULL) {
        return -1;
      }
    } else if (cfg->ifMode == configIfModeTap) {
      if (copyRequiredString(entry, "tap_mac", cred->tapMac) != 0 || !parseMacString(cred->tapMac)) {
        return -1;
      }
      if (parseMacClaim(cred->tapMac, cred->claim, &cred->claimNbytes) != 0) {
        return -1;
      }
      if (cJSON_GetObjectItemCaseSensitive(entry, "tun_ip") != NULL) {
        return -1;
      }
    } else {
      return -1;
    }
  }

  cfg->serverCredentialCount = count;
  return 0;
}

static int parseServerConfig(const cJSON *root, daemonConfig_t *cfg) {
  if (copyRequiredString(root, "if_name", cfg->ifName) != 0) {
    return -1;
  }
  if (cJSON_GetObjectItemCaseSensitive(root, "key_file") != NULL) {
    return -1;
  }
  if (parseRequiredPositiveInt(root, "auth_timeout_ms", &cfg->authTimeoutMs) != 0) {
    return -1;
  }
  if (parseRequiredPositiveInt(root, "max_pre_auth_sessions", &cfg->maxPreAuthSessions) != 0) {
    return -1;
  }
  if (copyRequiredString(root, "listen_ip", cfg->listenIP) != 0) {
    return -1;
  }
  if (copyRequiredPort(root, "listen_port", &cfg->listenPort) != 0) {
    return -1;
  }
  if (parseServerCredentials(root, cfg) != 0) {
    return -1;
  }
  if (cfg->ifMode == configIfModeTun) {
    if (parseTunSubnet(root, cfg) != 0) {
      return -1;
    }
  } else if (cfg->ifMode == configIfModeTap) {
    if (cJSON_GetObjectItemCaseSensitive(root, "tun_subnet") != NULL) {
      return -1;
    }
  } else {
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
  if (cfg->ifMode == configIfModeTun) {
    if (copyRequiredString(root, "tun_ip", cfg->tunIP) != 0 || !parseIPv4String(cfg->tunIP)) {
      return -1;
    }
    if (parseIPv4Claim(cfg->tunIP, cfg->claim, &cfg->claimNbytes) != 0) {
      return -1;
    }
  } else if (cfg->ifMode == configIfModeTap) {
    if (copyRequiredString(root, "tap_mac", cfg->tapMac) != 0 || !parseMacString(cfg->tapMac)) {
      return -1;
    }
    if (parseMacClaim(cfg->tapMac, cfg->claim, &cfg->claimNbytes) != 0) {
      return -1;
    }
  } else {
    return -1;
  }
  return 0;
}

void configZero(daemonConfig_t *cfg) {
  if (cfg == NULL) {
    return;
  }
  sodium_memzero(cfg, sizeof(*cfg));
  cfg->ifMode = configIfModeTun;
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
  if (parseIfMode(root, out) != 0) {
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
