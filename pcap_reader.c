#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "pcap_reader.h"

#define MAX_PACKET_SIZE (1024u * 1024u)

// PCAP 바이트 순서에 따라 16비트 읽기
static uint16_t get16(const uint8_t *p, int le) {
    if (le)
        return (uint16_t)p[0] | ((uint16_t)p[1] << 8);

    return ((uint16_t)p[0] << 8) | p[1];
}

// PCAP 바이트 순서에 따라 32비트 읽기
static uint32_t get32(const uint8_t *p, int le) {
    if (le)
        return (uint32_t)p[0] |
               ((uint32_t)p[1] << 8) |
               ((uint32_t)p[2] << 16) |
               ((uint32_t)p[3] << 24);

    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
            (uint32_t)p[3];
}

int pcapOpen(PcapReader *reader, const char *filename) {
    if (!reader || !filename)
        return 0;

    memset(reader, 0, sizeof(*reader));

    FILE *fp = fopen(filename, "rb");
    if (!fp)
        return 0;

    uint8_t header[24];

    if (fread(header, 1, 24, fp) != 24) {
        fclose(fp);
        return 0;
    }

    // Magic Number로 바이트 순서 및 시간 단위 판정
    if (memcmp(header, "\xd4\xc3\xb2\xa1", 4) == 0) {
        reader->little_endian = 1;
        reader->nanosecond = 0;
    }
    else if (memcmp(header, "\xa1\xb2\xc3\xd4", 4) == 0) {
        reader->little_endian = 0;
        reader->nanosecond = 0;
    }
    else if (memcmp(header, "\x4d\x3c\xb2\xa1", 4) == 0) {
        reader->little_endian = 1;
        reader->nanosecond = 1;
    }
    else if (memcmp(header, "\xa1\xb2\x3c\x4d", 4) == 0) {
        reader->little_endian = 0;
        reader->nanosecond = 1;
    }
    else {
        fclose(fp);
        return 0;
    }

    int le = reader->little_endian;

    uint16_t major = get16(header + 4, le);
    uint16_t minor = get16(header + 6, le);

    reader->snaplen = get32(header + 16, le);

    uint32_t linktype = get32(header + 20, le);

    // classic PCAP 2.4 + Ethernet만 지원
    if (major != 2 || minor != 4 ||
        linktype != 1 ||
        reader->snaplen == 0 ||
        reader->snaplen > MAX_PACKET_SIZE) {
        fclose(fp);
        return 0;
    }

    reader->file = fp;
    return 1;
}

int pcapNext(
    PcapReader *reader,
    uint8_t **data,
    size_t *length,
    double *timestamp
) {
    if (!reader || !reader->file ||
        !data || !length || !timestamp)
        return -1;

    *data = NULL;
    *length = 0;

    uint8_t header[16];
    size_t n = fread(header, 1, 16, reader->file);

    if (n == 0 && feof(reader->file))
        return 0;

    if (n != 16)
        return -1;

    int le = reader->little_endian;

    uint32_t seconds = get32(header, le);
    uint32_t fraction = get32(header + 4, le);
    uint32_t captured = get32(header + 8, le);
    uint32_t original = get32(header + 12, le);

    uint32_t units = reader->nanosecond
                   ? 1000000000u
                   : 1000000u;

    if (captured > reader->snaplen ||
        captured > original ||
        fraction >= units)
        return -1;

    uint8_t *buffer = malloc(captured ? captured : 1);
    if (!buffer)
        return -1;

    if (fread(buffer, 1, captured, reader->file) != captured) {
        free(buffer);
        return -1;
    }

    *data = buffer;
    *length = captured;
    *timestamp = (double)seconds +
                 (double)fraction / units;

    return 1;
}

void pcapClose(PcapReader *reader) {
    if (reader && reader->file) {
        fclose(reader->file);
        reader->file = NULL;
    }
}
