#pragma once

#define PacketMaxClaimNbytes 16

typedef enum {
  packetParseModeTunIpv4 = 0,
  packetParseModeTapEthernet,
} packetParseMode_t;

typedef enum {
  packetDestinationOk = 0,
  packetDestinationBroadcastL2,
  packetDestinationBroadcastL3Candidate,
  packetDestinationDropMulticast,
  packetDestinationDropMalformed,
} packetDestinationClass_t;

typedef enum {
  packetParseStatusOk = 0,
  packetParseStatusBadArgs,
} packetParseStatus_t;

typedef struct {
  packetDestinationClass_t classification;
  unsigned char claim[PacketMaxClaimNbytes];
  long claimNbytes;
} packetDestination_t;

packetParseStatus_t packetParseDestination(
    packetParseMode_t mode,
    const void *packet,
    long packetNbytes,
    packetDestination_t *outDestination);
