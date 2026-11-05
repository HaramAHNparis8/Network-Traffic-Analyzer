
#include "security.h"

#include <stdlib.h>
#include <string.h>

// IPv4 주소 출력
void printIPv4(FILE *out, uint32_t ip) {
    fprintf(
        out, "%u.%u.%u.%u",
        (unsigned)((ip >> 24) & 255u),
        (unsigned)((ip >> 16) & 255u),
        (unsigned)((ip >> 8) & 255u),
        (unsigned)(ip & 255u)
    );
}

// TCP Flags 출력
void printTcpFlags(FILE *out, uint8_t flags) {
    const struct {
        uint8_t bit;
        const char *name;
    } names[] = {
        {TCP_SYN, "SYN"},
        {TCP_ACK, "ACK"},
        {TCP_FIN, "FIN"},
        {TCP_RST, "RST"},
        {TCP_PSH, "PSH"},
        {TCP_URG, "URG"},
        {TCP_ECE, "ECE"},
        {TCP_CWR, "CWR"}
    };

    int first = 1;

    for (size_t i = 0;
         i < sizeof(names) / sizeof(names[0]);
         ++i) {

        if (flags & names[i].bit) {
            fprintf(
                out, "%s%s",
                first ? "" : ",",
                names[i].name
            );

            first = 0;
        }
    }

    if (first)
        fputs("NONE", out);
}

// 분석기 초기화
void securityInit(SecurityAnalyzer *s) {
    memset(s, 0, sizeof(*s));
}

// 출발지 IP별 통계 검색 또는 생성
static SourceStat *sourceFor(
    SecurityAnalyzer *s,
    uint32_t src
) {
    for (size_t i = 0; i < s->sources_count; ++i) {
        if (s->sources[i].src_ip == src)
            return &s->sources[i];
    }

    if (s->sources_count == s->sources_capacity) {
        size_t n = s->sources_capacity
                 ? s->sources_capacity * 2
                 : 16;

        if (n < s->sources_capacity ||
            n > SIZE_MAX / sizeof(*s->sources))
            return NULL;

        void *tmp = realloc(
            s->sources,
            n * sizeof(*s->sources)
        );

        if (!tmp)
            return NULL;

        s->sources = tmp;
        s->sources_capacity = n;
    }

    SourceStat *stat =
        &s->sources[s->sources_count++];

    *stat = (SourceStat){0};
    stat->src_ip = src;

    return stat;
}

// 출발지-목적지 IP별 탐지 상태 검색 또는 생성
static FlowState *flowFor(
    SecurityAnalyzer *s,
    uint32_t src,
    uint32_t dst
) {
    for (FlowState *f = s->flows;
         f;
         f = f->next) {

        if (f->src_ip == src && f->dst_ip == dst)
            return f;
    }

    FlowState *f = calloc(1, sizeof(*f));

    if (!f)
        return NULL;

    f->src_ip = src;
    f->dst_ip = dst;

    f->next = s->flows;
    s->flows = f;

    return f;
}

// 10초 탐지 구간에서 벗어난 SYN 이벤트 삭제
static void discardExpired(
    FlowState *f,
    double time
) {
    while (f->head &&
           time - f->head->time > DETECT_WINDOW_SEC) {

        SynEvent *old = f->head;

        f->head = old->next;
        free(old);

        --f->syn_count;
    }

    if (!f->head)
        f->tail = NULL;
}

// 서로 다른 목적지 포트 개수 계산
static size_t distinctPorts(const FlowState *f) {
    size_t count = 0;

    for (const SynEvent *e = f->head;
         e;
         e = e->next) {

        int seen = 0;

        for (const SynEvent *prev = f->head;
             prev != e;
             prev = prev->next) {

            if (prev->dst_port == e->dst_port) {
                seen = 1;
                break;
            }
        }

        if (!seen)
            ++count;
    }

    return count;
}

// 보안 경고 출력
static void alert(
    FILE *out,
    const char *kind,
    const FlowState *f,
    double time,
    const char *metric,
    size_t value
) {
    if (!out)
        return;

    fprintf(
        out,
        "[ALERT] %s (suspicious, not confirmed) at %.3f\n",
        kind,
        time
    );

    fputs("  Source: ", out);
    printIPv4(out, f->src_ip);

    fputs("  Target: ", out);
    printIPv4(out, f->dst_ip);

    fprintf(
        out,
        "  %s: %zu in %.0fs\n",
        metric,
        value,
        DETECT_WINDOW_SEC
    );
}

// 패킷 분석 및 탐지
int securityProcess(
    SecurityAnalyzer *s,
    const Packet *p,
    FILE *alerts
) {
    if (!s || !p)
        return 0;

    // 1. 출발지별 트래픽 통계 업데이트
    SourceStat *stat = sourceFor(s, p->src_ip);

    if (!stat)
        return 0;

    stat->packets++;
    stat->bytes += p->length;

    s->total_packets++;
    s->total_bytes += p->length;

    if (p->protocol == 6) {
        stat->tcp_packets++;
        s->tcp_packets++;
    }

    if (p->protocol == 17) {
        stat->udp_packets++;
        s->udp_packets++;
    }

    // 2. SYN 연결 시도만 탐지 대상으로 선정
    // SYN+ACK는 제외
    if (p->protocol != 6 ||
        !(p->tcp_flags & TCP_SYN) ||
        (p->tcp_flags & TCP_ACK))
        return 1;

    FlowState *f = flowFor(
        s,
        p->src_ip,
        p->dst_ip
    );

    if (!f)
        return 0;

    // 시간순으로 정렬되지 않은 SYN 이벤트는
    // 탐지 계산에서 제외
    if (f->syn_count &&
        p->timestamp < f->last_timestamp) {

        ++s->skipped_out_of_order;
        return 1;
    }

    f->last_timestamp = p->timestamp;

    // 오래된 SYN 이벤트 삭제
    discardExpired(f, p->timestamp);

    // 새로운 SYN 이벤트 등록
    SynEvent *e = malloc(sizeof(*e));

    if (!e)
        return 0;

    *e = (SynEvent){
        p->timestamp,
        p->dst_port,
        NULL
    };

    if (f->tail)
        f->tail->next = e;
    else
        f->head = e;

    f->tail = e;
    ++f->syn_count;

    // 3. 포트 스캔 의심 탐지
    if (f->syn_count >= PORT_SCAN_PORT_THRESHOLD) {

        size_t unique = distinctPorts(f);

        if (unique >= PORT_SCAN_PORT_THRESHOLD &&
            (!f->scan_alerted ||
             p->timestamp - f->last_scan_alert
                >= ALERT_COOLDOWN_SEC)) {

            alert(
                alerts,
                "PORT SCAN",
                f,
                p->timestamp,
                "Unique destination ports",
                unique
            );

            f->last_scan_alert = p->timestamp;
            f->scan_alerted = 1;

            s->scans++;
        }
    }

    // 4. SYN Flood 의심 탐지
    if (f->syn_count >= SYN_FLOOD_SYN_THRESHOLD &&
        (!f->flood_alerted ||
         p->timestamp - f->last_flood_alert
            >= ALERT_COOLDOWN_SEC)) {

        alert(
            alerts,
            "SYN RATE SPIKE / POSSIBLE SYN FLOOD",
            f,
            p->timestamp,
            "SYN-without-ACK packets",
            f->syn_count
        );

        f->last_flood_alert = p->timestamp;
        f->flood_alerted = 1;

        s->floods++;
    }

    return 1;
}

// 패킷 수 기준 내림차순 정렬
static int byPackets(
    const void *a,
    const void *b
) {
    const SourceStat *x = a;
    const SourceStat *y = b;

    if (x->packets < y->packets)
        return 1;

    if (x->packets > y->packets)
        return -1;

    return 0;
}

// 트래픽 통계 출력
void securityPrintSummary(
    SecurityAnalyzer *s,
    FILE *out
) {
    fprintf(out, "\n=== Traffic Summary ===\n");

    fprintf(
        out,
        "Parsed TCP/UDP: %llu (TCP %llu, UDP %llu)\n",
        (unsigned long long)s->total_packets,
        (unsigned long long)s->tcp_packets,
        (unsigned long long)s->udp_packets
    );

    fprintf(
        out,
        "IPv4 bytes: %llu\n",
        (unsigned long long)s->total_bytes
    );

    fprintf(
        out,
        "Port scan alerts: %llu\n"
        "SYN spike alerts: %llu\n",
        (unsigned long long)s->scans,
        (unsigned long long)s->floods
    );

    fprintf(
        out,
        "Out-of-order SYN ignored for detection: %llu\n",
        (unsigned long long)s->skipped_out_of_order
    );

    qsort(
        s->sources,
        s->sources_count,
        sizeof(*s->sources),
        byPackets
    );

    fprintf(out, "\nTop source IPs (by packets):\n");

    size_t top = s->sources_count < 10
               ? s->sources_count
               : 10;

    for (size_t i = 0; i < top; ++i) {
        SourceStat *v = &s->sources[i];

        fputs("  ", out);
        printIPv4(out, v->src_ip);

        fprintf(
            out,
            "  packets=%llu bytes=%llu tcp=%llu udp=%llu\n",
            (unsigned long long)v->packets,
            (unsigned long long)v->bytes,
            (unsigned long long)v->tcp_packets,
            (unsigned long long)v->udp_packets
        );
    }
}

// 할당한 메모리 해제
void securityFree(SecurityAnalyzer *s) {
    if (!s)
        return;

    free(s->sources);

    FlowState *f = s->flows;

    while (f) {
        SynEvent *e = f->head;

        while (e) {
            SynEvent *next = e->next;
            free(e);
            e = next;
        }

        FlowState *next = f->next;
        free(f);
        f = next;
    }

    securityInit(s);
}
