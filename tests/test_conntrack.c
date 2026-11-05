#include <stdio.h>
#include <stdint.h>

#include "conntrack.h"
#include "security.h"

static int passed = 0;
static int failed = 0;

#define CHECK(x, label) do {                     \
    if (x) {                                     \
        ++passed;                                \
        printf("[PASS] %s\n", label);             \
    } else {                                     \
        ++failed;                                \
        printf("[FAIL] %s (line %d)\n",           \
               label, __LINE__);                 \
    }                                            \
} while (0)

// 테스트용 TCP 패킷 생성
static Packet pkt(
    double t,
    uint32_t src,
    uint16_t sport,
    uint32_t dst,
    uint16_t dport,
    uint8_t flags
) {
    Packet p = {0};

    p.timestamp = t;
    p.src_ip = src;
    p.src_port = sport;
    p.dst_ip = dst;
    p.dst_port = dport;

    p.protocol = 6;
    p.tcp_flags = flags;
    p.length = 40;

    return p;
}

// 정상 3-way handshake
static void test_handshake(void) {
    ConnTracker c;
    conntrackInit(&c);

    Packet a = pkt(
        1, 1, 50000, 2, 443, TCP_SYN
    );

    Packet b = pkt(
        1.1, 2, 443, 1, 50000,
        TCP_SYN | TCP_ACK
    );

    Packet d = pkt(
        1.2, 1, 50000, 2, 443, TCP_ACK
    );

    conntrackProcess(&c, &a);

    CHECK(
        c.active == 1 && c.syn_seen == 1,
        "SYN creates state"
    );

    conntrackProcess(&c, &b);

    CHECK(
        c.syn_ack_seen == 1 &&
        c.head->state == CT_SYN_ACK_SEEN,
        "reverse SYN/ACK recognized"
    );

    conntrackProcess(&c, &d);

    CHECK(
        c.completed == 1 &&
        c.head->state == CT_ESTABLISHED,
        "final ACK completes handshake"
    );

    conntrackFinish(&c);

    CHECK(
        c.incomplete == 0 && c.active == 0,
        "complete connection not marked incomplete"
    );

    conntrackFree(&c);
}

// 연결 미완료 및 타임아웃
static void test_incomplete_and_timeout(void) {
    ConnTracker c;
    conntrackInit(&c);

    Packet a = pkt(
        1, 1, 50000, 2, 443, TCP_SYN
    );

    Packet b = pkt(
        32.1, 3, 50000, 4, 443, TCP_SYN
    );

    conntrackProcess(&c, &a);
    conntrackProcess(&c, &b);

    CHECK(
        c.incomplete == 1 && c.active == 1,
        "expired SYN counted incomplete"
    );

    conntrackFinish(&c);

    CHECK(
        c.incomplete == 2 && c.active == 0,
        "remaining SYN incomplete at end"
    );

    conntrackFree(&c);
}

// SYN 반복 및 RST 종료
static void test_retransmission_and_reset(void) {
    ConnTracker c;
    conntrackInit(&c);

    Packet a = pkt(
        1, 1, 50000, 2, 443, TCP_SYN
    );

    Packet b = pkt(
        1.2, 1, 50000, 2, 443, TCP_SYN
    );

    Packet d = pkt(
        1.3, 2, 443, 1, 50000, TCP_RST
    );

    conntrackProcess(&c, &a);
    conntrackProcess(&c, &b);

    CHECK(
        c.active == 1 &&
        c.retransmitted_syn == 1,
        "repeated SYN not double state"
    );

    conntrackProcess(&c, &d);

    CHECK(
        c.incomplete == 1 &&
        c.reset_connections == 1 &&
        c.active == 0,
        "RST ends pending handshake"
    );

    conntrackFree(&c);
}

// 포트가 다른 패킷은 연결 성립으로 취급하지 않음
static void test_wrong_tuple_direction(void) {
    ConnTracker c;
    conntrackInit(&c);

    Packet a = pkt(
        1, 1, 50000, 2, 443, TCP_SYN
    );

    Packet b = pkt(
        2, 2, 444, 1, 50000,
        TCP_SYN | TCP_ACK
    );

    Packet d = pkt(
        3, 1, 50000, 2, 443, TCP_ACK
    );

    conntrackProcess(&c, &a);
    conntrackProcess(&c, &b);
    conntrackProcess(&c, &d);

    CHECK(
        c.completed == 0 &&
        c.syn_ack_seen == 0,
        "wrong port does not complete connection"
    );

    conntrackFree(&c);
}

int main(void) {
    printf("=== TCP Connection Tracking Test ===\n");

    test_handshake();
    test_incomplete_and_timeout();
    test_retransmission_and_reset();
    test_wrong_tuple_direction();

    printf("\nPassed: %d, Failed: %d\n",
           passed, failed);

    return failed ? 1 : 0;
}
