#include <stdint.h>
#include <stddef.h>
#include "parser.h"

// 네트워크 바이트 순서(Big Endian) 해석
static uint16_t read16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t read32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
            (uint32_t)p[3];
}

ParseResult parsePacket(
    const uint8_t *frame,
    size_t frame_length,
    Packet *packet
) {
    if (frame == NULL || packet == NULL)
        return PARSE_INVALID;

    // Ethernet II 헤더 크기
    if (frame_length < 14)
        return PARSE_INVALID;

    // EtherType: IPv4 = 0x0800
    if (read16(frame + 12) != 0x0800)
        return PARSE_UNSUPPORTED;

    const uint8_t *ip = frame + 14;
    size_t available = frame_length - 14;

    if (available < 20)
        return PARSE_INVALID;

    // IPv4 버전과 헤더 길이
    uint8_t version = ip[0] >> 4;
    size_t ip_header_len = (ip[0] & 0x0F) * 4;

    if (version != 4)
        return PARSE_INVALID;

    if (ip_header_len < 20 ||
        ip_header_len > available)
        return PARSE_INVALID;

    uint16_t total_len = read16(ip + 2);

    if (total_len < ip_header_len ||
        total_len > available)
        return PARSE_INVALID;

    // 단편화된 IPv4 패킷은 일단 제외
    uint16_t fragment = read16(ip + 6);

    if ((fragment & 0x3FFF) != 0)
        return PARSE_UNSUPPORTED;

    // IP 헤더에서 정보 추출
    Packet parsed = {0};

    parsed.src_ip = read32(ip + 12);
    parsed.dst_ip = read32(ip + 16);
    parsed.protocol = ip[9];
    parsed.length = total_len;

    const uint8_t *transport = ip + ip_header_len;
    size_t remaining = total_len - ip_header_len;

    if (parsed.protocol == 6) {
        // TCP 최소 헤더: 20 bytes
        if (remaining < 20)
            return PARSE_INVALID;

        size_t tcp_header_len =
            (transport[12] >> 4) * 4;

        if (tcp_header_len < 20 ||
            tcp_header_len > remaining)
            return PARSE_INVALID;
    }
    else if (parsed.protocol == 17) {
        // UDP 헤더: 8 bytes
        if (remaining < 8)
            return PARSE_INVALID;

        uint16_t udp_len = read16(transport + 4);

        if (udp_len < 8 || udp_len > remaining)
            return PARSE_INVALID;
    }
    else {
        return PARSE_UNSUPPORTED;
    }

    parsed.src_port = read16(transport);
    parsed.dst_port = read16(transport + 2);

    *packet = parsed;

    return PARSE_OK;
}
