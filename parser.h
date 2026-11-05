#ifndef PARSER_H
#define PARSER_H

#include <stddef.h>
#include <stdint.h>
#include "packet.h"

typedef enum {
    PARSE_INVALID = -1,
    PARSE_UNSUPPORTED = 0,
    PARSE_OK = 1
} ParseResult;

ParseResult parsePacket(
    const uint8_t *frame,
    size_t frame_length,
    Packet *packet
);

#endif
