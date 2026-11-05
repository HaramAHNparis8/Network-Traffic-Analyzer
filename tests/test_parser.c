#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "test_framework.h"
#include "parser.h"

// Ethernet II + IPv4 + TCP (54 bytes)
static const uint8_t tcp_frame[54] = {
    [12] = 0x08, [13] = 0x00,  // EtherType: IPv4
    [14] = 0x45,              // IPv4, IHL = 5
    [16] = 0x00, [17] = 40,   // IP Total Length
    [22] = 64,                // TTL
    [23] = 6,                 // TCP

    // Source IP: 192.168.0.10
    [26] = 192, [27] = 168,
    [28] = 0,   [29] = 10,

    // Destination IP: 10.0.0.5
    [30] = 10, [31] = 0,
    [32] = 0,  [33] = 5,

    // Source Port: 50000
    [34] = 0xC3, [35] = 0x50,

    // Destination Port: 443
    [36] = 0x01, [37] = 0xBB,

    [46] = 0x50  // TCP Data Offset = 5
};

// Ethernet II + IPv4 + UDP (42 bytes)
static const uint8_t udp_frame[42] = {
    [12] = 0x08, [13] = 0x00,
    [14] = 0x45,
    [16] = 0x00, [17] = 28,
    [22] = 64,
    [23] = 17,  // UDP

    // Source IP: 192.168.0.20
    [26] = 192, [27] = 168,
    [28] = 0,   [29] = 20,

    // Destination IP: 8.8.8.8
    [30] = 8, [31] = 8,
    [32] = 8, [33] = 8,

    // Source Port: 53000
    [34] = 0xCF, [35] = 0x08,

    // Destination Port: 53
    [36] = 0x00, [37] = 0x35,

    // UDP Length: 8
    [38] = 0x00, [39] = 0x08
};

static void testTCP(void) {
    printf("\n[1] IPv4/TCP Parser Test\n");

    Packet packet = {0};

    ParseResult result = parsePacket(
        tcp_frame, sizeof(tcp_frame), &packet
    );

    CHECK_EQ(result, PARSE_OK, "TCP 파싱 성공");

    if (result != PARSE_OK)
        return;

    CHECK_EQ(packet.src_ip, 0xC0A8000A,
             "출발지 IP 확인");

    CHECK_EQ(packet.dst_ip, 0x0A000005,
             "목적지 IP 확인");

    CHECK_EQ(packet.src_port, 50000,
             "출발지 Port 확인");

    CHECK_EQ(packet.dst_port, 443,
             "목적지 Port 확인");

    CHECK_EQ(packet.protocol, 6,
             "TCP 프로토콜 확인");

    CHECK_EQ(packet.length, 40,
             "IPv4 전체 길이 확인");
}

static void testUDP(void) {
    printf("\n[2] IPv4/UDP Parser Test\n");

    Packet packet = {0};

    ParseResult result = parsePacket(
        udp_frame, sizeof(udp_frame), &packet
    );

    CHECK_EQ(result, PARSE_OK, "UDP 파싱 성공");

    if (result != PARSE_OK)
        return;

    CHECK_EQ(packet.src_ip, 0xC0A80014,
             "출발지 IP 확인");

    CHECK_EQ(packet.dst_ip, 0x08080808,
             "목적지 IP 확인");

    CHECK_EQ(packet.src_port, 53000,
             "출발지 Port 확인");

    CHECK_EQ(packet.dst_port, 53,
             "목적지 Port 확인");

    CHECK_EQ(packet.protocol, 17,
             "UDP 프로토콜 확인");

    CHECK_EQ(packet.length, 28,
             "IPv4 전체 길이 확인");
}

static void testInvalidPackets(void) {
    printf("\n[3] Invalid Packet Tests\n");

    Packet packet = {0};
    uint8_t frame[sizeof(tcp_frame)];

    // 1. Ethernet 헤더 부족
    CHECK_EQ(
        parsePacket(tcp_frame, 10, &packet),
        PARSE_INVALID,
        "Ethernet 헤더 부족 탐지"
    );

    // 2. IPv4 헤더 부족
    CHECK_EQ(
        parsePacket(tcp_frame, 20, &packet),
        PARSE_INVALID,
        "IPv4 헤더 부족 탐지"
    );

    // 3. TCP 헤더 부족
    CHECK_EQ(
        parsePacket(tcp_frame, 40, &packet),
        PARSE_INVALID,
        "TCP 헤더 부족 탐지"
    );

    // 4. 잘못된 IPv4 IHL
    memcpy(frame, tcp_frame, sizeof(frame));
    frame[14] = 0x44;

    CHECK_EQ(
        parsePacket(frame, sizeof(frame), &packet),
        PARSE_INVALID,
        "잘못된 IPv4 헤더 길이 탐지"
    );

    // 5. 잘못된 TCP Data Offset
    memcpy(frame, tcp_frame, sizeof(frame));
    frame[46] = 0x40;

    CHECK_EQ(
        parsePacket(frame, sizeof(frame), &packet),
        PARSE_INVALID,
        "잘못된 TCP 헤더 길이 탐지"
    );

    // 6. NULL 포인터
    CHECK_EQ(
        parsePacket(NULL, 0, &packet),
        PARSE_INVALID,
        "NULL 입력 탐지"
    );
}

static void testUnsupportedPackets(void) {
    printf("\n[4] Unsupported Packet Tests\n");

    Packet packet = {0};
    uint8_t frame[sizeof(tcp_frame)];

    // 1. IPv6 EtherType
    memcpy(frame, tcp_frame, sizeof(frame));
    frame[12] = 0x86;
    frame[13] = 0xDD;

    CHECK_EQ(
        parsePacket(frame, sizeof(frame), &packet),
        PARSE_UNSUPPORTED,
        "지원하지 않는 EtherType"
    );

    // 2. IPv4 단편화
    memcpy(frame, tcp_frame, sizeof(frame));
    frame[20] = 0x20; // MF flag 설정

    CHECK_EQ(
        parsePacket(frame, sizeof(frame), &packet),
        PARSE_UNSUPPORTED,
        "IPv4 단편화 패킷 탐지"
    );
}

int main(void) {
    initTestFramework();

    printf("\n");
    printf("========== Packet Parser Test ==========\n");

    testTCP();
    testUDP();
    testInvalidPackets();
    testUnsupportedPackets();

    TEST_SUMMARY();

    return tests_failed == 0 ? 0 : 1;
}
