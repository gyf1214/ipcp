#include "packet.h"

#include <string.h>

static packetParseStatus_t parseTunIpv4(
    const unsigned char *packet,
    long packetNbytes,
    packetDestination_t *outDestination) {
  long headerOffset = 0;
  unsigned int version;
  unsigned int ihlWords;
  long headerNbytes;
  const unsigned char *destination;

  if (packetNbytes < 20) {
    outDestination->classification = packetDestinationDropMalformed;
    return packetParseStatusOk;
  }
  if (((unsigned int)packet[0] >> 4) != 4) {
    if (packetNbytes >= 24 && ((unsigned int)packet[4] >> 4) == 4) {
      headerOffset = 4;
    } else {
      outDestination->classification = packetDestinationDropMalformed;
      return packetParseStatusOk;
    }
  }

  version = (unsigned int)packet[headerOffset] >> 4;
  ihlWords = (unsigned int)packet[headerOffset] & 0x0f;
  headerNbytes = (long)ihlWords * 4;
  if (version != 4 || ihlWords < 5 || headerOffset + headerNbytes > packetNbytes) {
    outDestination->classification = packetDestinationDropMalformed;
    return packetParseStatusOk;
  }

  destination = packet + headerOffset + 16;
  if ((destination[0] & 0xf0) == 0xe0) {
    outDestination->classification = packetDestinationDropMulticast;
    return packetParseStatusOk;
  }
  if (destination[0] == 0xff && destination[1] == 0xff && destination[2] == 0xff && destination[3] == 0xff) {
    memcpy(outDestination->claim, destination, 4);
    outDestination->claimNbytes = 4;
    outDestination->classification = packetDestinationBroadcastL3Candidate;
    return packetParseStatusOk;
  }

  memcpy(outDestination->claim, destination, 4);
  outDestination->claimNbytes = 4;
  outDestination->classification = packetDestinationOk;
  return packetParseStatusOk;
}

static packetParseStatus_t parseTapEthernet(
    const unsigned char *packet,
    long packetNbytes,
    packetDestination_t *outDestination) {
  long headerOffset = 0;
  const unsigned char *destination;

  if (packetNbytes < 14) {
    outDestination->classification = packetDestinationDropMalformed;
    return packetParseStatusOk;
  }
  if (packetNbytes >= 18 && packet[0] == 0x00 && packet[1] == 0x00) {
    headerOffset = 4;
  }

  if (headerOffset + 14 > packetNbytes) {
    outDestination->classification = packetDestinationDropMalformed;
    return packetParseStatusOk;
  }

  destination = packet + headerOffset;
  if (destination[0] == 0xff
      && destination[1] == 0xff
      && destination[2] == 0xff
      && destination[3] == 0xff
      && destination[4] == 0xff
      && destination[5] == 0xff) {
    outDestination->classification = packetDestinationBroadcastL2;
    return packetParseStatusOk;
  }
  if ((destination[0] & 0x01) != 0) {
    outDestination->classification = packetDestinationDropMulticast;
    return packetParseStatusOk;
  }

  memcpy(outDestination->claim, destination, 6);
  outDestination->claimNbytes = 6;
  outDestination->classification = packetDestinationOk;
  return packetParseStatusOk;
}

packetParseStatus_t packetParseDestination(
    packetParseMode_t mode,
    const void *packet,
    long packetNbytes,
    packetDestination_t *outDestination) {
  const unsigned char *packetBytes;

  if (packet == NULL || outDestination == NULL || packetNbytes <= 0) {
    return packetParseStatusBadArgs;
  }

  memset(outDestination, 0, sizeof(*outDestination));
  packetBytes = (const unsigned char *)packet;
  if (mode == packetParseModeTunIpv4) {
    return parseTunIpv4(packetBytes, packetNbytes, outDestination);
  }
  if (mode == packetParseModeTapEthernet) {
    return parseTapEthernet(packetBytes, packetNbytes, outDestination);
  }

  return packetParseStatusBadArgs;
}
