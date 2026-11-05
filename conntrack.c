#include "conntrack.h"
#include "security.h"

#include <stdlib.h>
#include <string.h>

void conntrackInit(ConnTracker *ct) {
    if (ct)
        memset(ct, 0, sizeof(*ct));
}

// 클라이언트 -> 서버 방향 확인
static int forward(
    const CtConnection *c,
    const Packet *p
) {
    return c->client_ip == p->src_ip &&
           c->server_ip == p->dst_ip &&
           c->client_port == p->src_port &&
           c->server_port == p->dst_port;
}

// 서버 -> 클라이언트 방향 확인
static int reverse(
    const CtConnection *c,
    const Packet *p
) {
    return c->client_ip == p->dst_ip &&
           c->server_ip == p->src_ip &&
           c->client_port == p->dst_port &&
           c->server_port == p->src_port;
}

// 오래되었거나 종료된 연결 삭제
static void expire(
    ConnTracker *ct,
    double now,
    int final
) {
    CtConnection **cursor = &ct->head;

    while (*cursor) {
        CtConnection *c = *cursor;

        double max_age =
            c->state == CT_ESTABLISHED
            ? CT_ESTABLISHED_TIMEOUT
            : CT_HANDSHAKE_TIMEOUT;

        if (final ||
            now - c->last_seen > max_age) {

            if (c->state != CT_ESTABLISHED)
                ++ct->incomplete;

            *cursor = c->next;

            free(c);
            --ct->active;

        } else {
            cursor = &c->next;
        }
    }
}

void conntrackProcess(
    ConnTracker *ct,
    const Packet *p
) {
    if (!ct || !p || p->protocol != 6)
        return;

    // 시간 역순 패킷 제외
    if (ct->has_timestamp &&
        p->timestamp < ct->last_timestamp) {

        ++ct->out_of_order;
        return;
    }

    ct->last_timestamp = p->timestamp;
    ct->has_timestamp = 1;

    expire(ct, p->timestamp, 0);

    int syn = (p->tcp_flags & TCP_SYN) != 0;
    int ack = (p->tcp_flags & TCP_ACK) != 0;
    int rst = (p->tcp_flags & TCP_RST) != 0;

    // 동일한 4-tuple 검색
    CtConnection **cursor = &ct->head;

    while (*cursor &&
           !forward(*cursor, p) &&
           !reverse(*cursor, p)) {

        cursor = &(*cursor)->next;
    }

    CtConnection *c = *cursor;

    // RST 수신 시 연결 제거
    if (rst && c) {
        if (c->state != CT_ESTABLISHED)
            ++ct->incomplete;

        ++ct->reset_connections;

        *cursor = c->next;
        free(c);

        --ct->active;
        return;
    }

    // 추적되지 않은 새로운 SYN
    if (!c) {
        if (!syn || ack || rst)
            return;

        ++ct->syn_seen;

        if (ct->active >= CT_MAX_CONNECTIONS) {
            ++ct->ignored_due_to_limit;
            return;
        }

        c = calloc(1, sizeof(*c));

        if (!c) {
            ++ct->ignored_due_to_limit;
            return;
        }

        c->client_ip = p->src_ip;
        c->server_ip = p->dst_ip;

        c->client_port = p->src_port;
        c->server_port = p->dst_port;

        c->started = p->timestamp;
        c->last_seen = p->timestamp;

        c->state = CT_SYN_SENT;

        c->next = ct->head;
        ct->head = c;

        ++ct->active;
        return;
    }

    c->last_seen = p->timestamp;

    // 동일한 연결에서 SYN 반복
    if (forward(c, p) &&
        syn && !ack && !rst) {

        ++ct->syn_seen;
        ++ct->retransmitted_syn;

        if (c->state == CT_ESTABLISHED) {
            c->state = CT_SYN_SENT;
            c->started = p->timestamp;
        }

        return;
    }

    // SYN -> SYN/ACK
    if (c->state == CT_SYN_SENT &&
        reverse(c, p) &&
        syn && ack) {

        c->state = CT_SYN_ACK_SEEN;
        ++ct->syn_ack_seen;
        return;
    }

    // SYN/ACK -> ACK
    if (c->state == CT_SYN_ACK_SEEN &&
        forward(c, p) &&
        ack && !syn) {

        c->state = CT_ESTABLISHED;
        ++ct->completed;
    }
}

void conntrackFinish(ConnTracker *ct) {
    if (ct)
        expire(ct, 0, 1);
}

void conntrackSummary(
    const ConnTracker *ct,
    FILE *out
) {
    if (!ct || !out)
        return;

    fprintf(
        out,
        "\n=== TCP Connection Tracking ===\n"
        "SYN packets: %llu\n"
        "SYN/ACK responses: %llu\n"
        "Completed handshakes: %llu\n"
        "Incomplete handshakes: %llu\n"
        "Repeated SYN: %llu\n"
        "RST-terminated tracked connections: %llu\n"
        "Out-of-order TCP packets skipped: %llu\n"
        "SYN not tracked (capacity/allocation): %llu\n",
        (unsigned long long)ct->syn_seen,
        (unsigned long long)ct->syn_ack_seen,
        (unsigned long long)ct->completed,
        (unsigned long long)ct->incomplete,
        (unsigned long long)ct->retransmitted_syn,
        (unsigned long long)ct->reset_connections,
        (unsigned long long)ct->out_of_order,
        (unsigned long long)ct->ignored_due_to_limit
    );
}

void conntrackFree(ConnTracker *ct) {
    if (!ct)
        return;

    conntrackFinish(ct);
    memset(ct, 0, sizeof(*ct));
}
