#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

typedef struct {
    FILE *file;
    int little_endian;
    int nanosecond;
    uint32_t snaplen;
} PcapReader;

int pcapOpen(PcapReader *reader, const char *filename);

int pcapNext(
    PcapReader *reader,
    uint8_t **data,
    size_t *length,
    double *timestamp
);

void pcapClose(PcapReader *reader);

#endif
