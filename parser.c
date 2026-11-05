#include "parser.h"

static uint16_t read16(const uint8_t *p) {
    return (uint16_t)(
        ((uint16_t)p[0] << 8) | p[1]
    );
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
    if (!frame || !packet || frame_length < 14)
        return PARSE_INVALID;

    // Ethernet II에서 IPv4만 지원
    if (read16(frame + 12) != 0x0800)
        return PARSE_UNSUPPORTED;

    const uint8_t *ip = frame + 14;
    size_t available = frame_length - 14;

    if (available < 20)
        return PARSE_INVALID;

    if ((ip[0] >> 4) != 4)
        return PARSE_INVALID;

    size_t ihl = (size_t)(ip[0] & 15u) * 4u;

    if (ihl < 20 || ihl > available)
        return PARSE_INVALID;

    uint16_t ip_len = read16(ip + 2);

    if (ip_len < ihl || ip_len > available)
        return PARSE_INVALID;

    // IPv4 단편화 패킷은 지원하지 않음
    if ((read16(ip + 6) & 0x3fffu) != 0)
        return PARSE_UNSUPPORTED;

    Packet out = {0};

    out.src_ip = read32(ip + 12);
    out.dst_ip = read32(ip + 16);
    out.protocol = ip[9];
    out.length = ip_len;

    const uint8_t *transport = ip + ihl;
    size_t remaining = (size_t)ip_len - ihl;

    if (out.protocol == 6) {
        // TCP 최소 헤더 길이 검증
        if (remaining < 20)
            return PARSE_INVALID;

        size_t tcp_hlen =
            (size_t)(transport[12] >> 4) * 4u;

        if (tcp_hlen < 20 || tcp_hlen > remaining)
            return PARSE_INVALID;

        // TCP Flags 추출
        out.tcp_flags = transport[13];

    } else if (out.protocol == 17) {
        // UDP 헤더 길이 검증
        if (remaining < 8)
            return PARSE_INVALID;

        uint16_t udp_len = read16(transport + 4);

        if (udp_len < 8 || udp_len > remaining)
            return PARSE_INVALID;

    } else {
        return PARSE_UNSUPPORTED;
    }

    out.src_port = read16(transport);
    out.dst_port = read16(transport + 2);

    *packet = out;

    return PARSE_OK;
}
