#include <stdio.h>
#include <stdint.h>

#include "test_framework.h"
#include "security.h"
#include "parser.h"

/*
 * 테스트용 TCP SYN 패킷 생성
 */
static Packet makeTCP(
    uint32_t src,
    uint32_t dst,
    uint16_t port,
    double timestamp
) {
    Packet p = {0};

    p.src_ip = src;
    p.dst_ip = dst;
    p.src_port = 50000;
    p.dst_port = port;

    p.protocol = 6;
    p.length = 40;
    p.timestamp = timestamp;
    p.tcp_flags = TCP_SYN;

    return p;
}

/*
 * [1] TCP Flags 추출 테스트
 */
static void testTCPFlags(void) {
    printf("\n[1] TCP Flags Test\n");

    // Ethernet II + IPv4 + TCP
    uint8_t frame[54] = {0};

    frame[12] = 0x08;
    frame[13] = 0x00;

    frame[14] = 0x45;
    frame[17] = 40;
    frame[23] = 6;

    frame[46] = 0x50; // TCP Header Length

    Packet p = {0};

    frame[47] = TCP_SYN;

    CHECK(
        parsePacket(frame, sizeof(frame), &p) == PARSE_OK &&
        p.tcp_flags == TCP_SYN,
        "SYN Flag 추출"
    );

    frame[47] = TCP_ACK;

    CHECK(
        parsePacket(frame, sizeof(frame), &p) == PARSE_OK &&
        p.tcp_flags == TCP_ACK,
        "ACK Flag 추출"
    );

    frame[47] = TCP_FIN;

    CHECK(
        parsePacket(frame, sizeof(frame), &p) == PARSE_OK &&
        p.tcp_flags == TCP_FIN,
        "FIN Flag 추출"
    );

    frame[47] = TCP_RST;

    CHECK(
        parsePacket(frame, sizeof(frame), &p) == PARSE_OK &&
        p.tcp_flags == TCP_RST,
        "RST Flag 추출"
    );

    frame[47] = TCP_SYN | TCP_ACK;

    CHECK(
        parsePacket(frame, sizeof(frame), &p) == PARSE_OK &&
        p.tcp_flags == (TCP_SYN | TCP_ACK),
        "SYN + ACK 복합 Flag 추출"
    );
}

/*
 * [2] Port Scan 탐지 테스트
 */
static void testPortScan(void) {
    printf("\n[2] Port Scan Detection Test\n");

    SecurityAnalyzer s;
    securityInit(&s);

    int ok = 1;

    // 서로 다른 포트 19개 접근
    for (int i = 0; i < 19; ++i) {
        Packet p = makeTCP(
            0x0A000001,
            0x0A000002,
            (uint16_t)(1000 + i),
            1.0 + i * 0.01
        );

        if (!securityProcess(&s, &p, NULL))
            ok = 0;
    }

    CHECK(ok, "19개 SYN 패킷 처리 성공");

    CHECK(
        s.scans == 0,
        "19개 포트에서는 경고 없음"
    );

    Packet p = makeTCP(
        0x0A000001,
        0x0A000002,
        1019,
        1.20
    );

    CHECK(
        securityProcess(&s, &p, NULL),
        "20번째 SYN 패킷 처리 성공"
    );

    CHECK(
        s.scans == 1,
        "20개 고유 목적지 포트에서 경고 발생"
    );

    securityFree(&s);
}

/*
 * [3] SYN Flood 의심 탐지 테스트
 */
static void testSYNFlood(void) {
    printf("\n[3] SYN Flood Detection Test\n");

    SecurityAnalyzer s;
    securityInit(&s);

    int ok = 1;

    // 동일 목적지, 동일 포트로 SYN 99개
    for (int i = 0; i < 99; ++i) {
        Packet p = makeTCP(
            0x0A000001,
            0x0A000002,
            443,
            2.0 + i * 0.001
        );

        if (!securityProcess(&s, &p, NULL))
            ok = 0;
    }

    CHECK(ok, "99개 SYN 패킷 처리 성공");

    CHECK(
        s.floods == 0,
        "99개에서는 Flood 경고 없음"
    );

    Packet p = makeTCP(
        0x0A000001,
        0x0A000002,
        443,
        2.10
    );

    CHECK(
        securityProcess(&s, &p, NULL),
        "100번째 SYN 패킷 처리 성공"
    );

    CHECK(
        s.floods == 1,
        "SYN 100개에서 Flood 의심 경고 발생"
    );

    CHECK(
        s.scans == 0,
        "단일 포트 접근은 Port Scan으로 분류하지 않음"
    );

    // 쿨다운 이내 추가 SYN 패킷
    p.timestamp = 2.11;

    CHECK(
        securityProcess(&s, &p, NULL),
        "쿨다운 중 SYN 패킷 처리 성공"
    );

    CHECK(
        s.floods == 1,
        "쿨다운 동안 중복 경고 억제"
    );

    securityFree(&s);
}

/*
 * [4] 시간 구간 검증
 */
static void testTimeWindow(void) {
    printf("\n[4] Time Window Test\n");

    SecurityAnalyzer s;
    securityInit(&s);

    int ok = 1;

    // 처음 19개 포트 접근
    for (int i = 0; i < 19; ++i) {
        Packet p = makeTCP(
            0x0A000001,
            0x0A000002,
            (uint16_t)(2000 + i),
            i * 0.01
        );

        if (!securityProcess(&s, &p, NULL))
            ok = 0;
    }

    CHECK(ok, "초기 SYN 이벤트 처리 성공");

    // 10초가 지난 뒤 20번째 포트 접근
    Packet p = makeTCP(
        0x0A000001,
        0x0A000002,
        2019,
        11.0
    );

    CHECK(
        securityProcess(&s, &p, NULL),
        "시간 초과 후 SYN 패킷 처리 성공"
    );

    CHECK(
        s.scans == 0,
        "10초를 초과한 이전 포트 접근 제외"
    );

    CHECK(
        s.flows != NULL &&
        s.flows->syn_count == 1,
        "오래된 SYN 이벤트 삭제 확인"
    );

    securityFree(&s);
}

/*
 * [5] 트래픽 통계 검증
 */
static void testStatistics(void) {
    printf("\n[5] Traffic Statistics Test\n");

    SecurityAnalyzer s;
    securityInit(&s);

    Packet tcp = makeTCP(
        0xC0A80001,
        0x08080808,
        443,
        1.0
    );

    Packet udp = {0};

    udp.src_ip = 0xC0A80001;
    udp.dst_ip = 0x08080808;
    udp.protocol = 17;
    udp.length = 100;
    udp.timestamp = 2.0;

    int ok = securityProcess(&s, &tcp, NULL);

    ok = securityProcess(&s, &udp, NULL) && ok;

    CHECK(
        ok,
        "TCP 및 UDP 통계 처리 성공"
    );

    CHECK(
        s.total_packets == 2,
        "전체 패킷 수 2개"
    );

    CHECK(
        s.total_bytes == 140,
        "전체 IP 데이터 길이 140바이트"
    );

    CHECK(
        s.tcp_packets == 1 &&
        s.udp_packets == 1,
        "TCP 및 UDP 개수 정확성"
    );

    CHECK(
        s.sources_count == 1,
        "동일 출발지 IP를 하나로 집계"
    );

    if (s.sources_count == 1) {
        CHECK(
            s.sources[0].packets == 2 &&
            s.sources[0].bytes == 140,
            "출발지별 패킷 및 바이트 집계"
        );
    }

    securityFree(&s);
}

/*
 * 테스트 실행
 */
int main(void) {
    initTestFramework();

    printf(
        "\n========== Security Analyzer Test ==========\n"
    );

    testTCPFlags();
    testPortScan();
    testSYNFlood();
    testTimeWindow();
    testStatistics();

    TEST_SUMMARY();

    return tests_failed == 0 ? 0 : 1;
}
