#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

typedef struct Packet {
    double timestamp;

    uint32_t src_ip;
    uint32_t dst_ip;

    uint16_t src_port;
    uint16_t dst_port;

    uint8_t protocol;
    uint32_t length;

    uint8_t tcp_flags;
} Packet;

#endif
