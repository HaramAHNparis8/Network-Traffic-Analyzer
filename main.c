#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "pcap_reader.h"
#include "parser.h"
#include "queue.h"
#include "security.h"
#include "conntrack.h"

/*
 * 패킷 정보 출력
 * --verbose 옵션에서 사용
 */
static void printPacket(
    const Packet *p,
    unsigned long long n
) {
    printf(
        "\n[Packet #%llu] time=%.6f\n",
        n,
        p->timestamp
    );

    fputs("  ", stdout);

    printIPv4(stdout, p->src_ip);

    printf(
        ":%u -> ",
        (unsigned)p->src_port
    );

    printIPv4(stdout, p->dst_ip);

    printf(
        ":%u  %s  IP bytes=%u",
        (unsigned)p->dst_port,
        p->protocol == 6 ? "TCP" : "UDP",
        (unsigned)p->length
    );

    if (p->protocol == 6) {
        fputs("  flags=", stdout);
        printTcpFlags(stdout, p->tcp_flags);
    }

    fputc('\n', stdout);
}

/*
 * 메인 분석 프로그램
 */
int main(int argc, char **argv) {

    /*
     * 명령행 인자 검사
     */
    if (
        argc < 2 ||
        argc > 3 ||
        (
            argc == 3 &&
            strcmp(argv[2], "--verbose") != 0
        )
    ) {
        fprintf(
            stderr,
            "Usage: %s <file.pcap> [--verbose]\n",
            argv[0]
        );

        return 1;
    }

    int verbose = (argc == 3);

    /*
     * PCAP Reader 초기화
     */
    PcapReader reader;

    if (!pcapOpen(&reader, argv[1])) {
        fprintf(
            stderr,
            "Cannot open PCAP: %s\n",
            argv[1]
        );

        return 1;
    }

    /*
     * Queue 초기화
     */
    Queue q;
    initQueue(&q);

    /*
     * Security Analyzer 초기화
     */
    SecurityAnalyzer sec;
    securityInit(&sec);

    /*
     * TCP Connection Tracker 초기화
     */
    ConnTracker ct;
    conntrackInit(&ct);

    /*
     * 분석 통계
     */
    unsigned long long unsupported = 0;
    unsigned long long invalid = 0;

    int error = 0;
    int reached_eof = 0;

    puts("=== Network Traffic Analyzer ===");

    /*
     * PCAP 패킷 처리 반복문
     */
    for (;;) {

        uint8_t *raw = NULL;
        size_t len = 0;
        double ts = 0;

        /*
         * PCAP에서 패킷 읽기
         */
        int state = pcapNext(
            &reader,
            &raw,
            &len,
            &ts
        );

        /*
         * 정상 EOF
         */
        if (state == 0) {
            reached_eof = 1;
            break;
        }

        /*
         * PCAP 읽기 실패
         */
        if (state < 0) {
            fputs(
                "PCAP read error\n",
                stderr
            );

            error = 1;
            break;
        }

        /*
         * TCP/IP 헤더 파싱
         */
        Packet p = {0};

        ParseResult result = parsePacket(
            raw,
            len,
            &p
        );

        /*
         * 원본 패킷 버퍼 해제
         */
        free(raw);

        /*
         * 지원하지 않는 프로토콜
         */
        if (result == PARSE_UNSUPPORTED) {
            ++unsupported;
            continue;
        }

        /*
         * 잘못된 패킷
         */
        if (result != PARSE_OK) {
            ++invalid;
            continue;
        }

        /*
         * PCAP 타임스탬프 설정
         */
        p.timestamp = ts;

        /*
         * Queue에 패킷 추가
         */
        if (!enqueue(&q, p)) {
            fputs(
                "Queue allocation failure\n",
                stderr
            );

            error = 1;
            break;
        }

        /*
         * Queue에서 패킷 추출
         */
        Packet item;

        if (!dequeue(&q, &item)) {
            fputs(
                "Queue dequeue failure\n",
                stderr
            );

            error = 1;
            break;
        }

        /*
         * 상세 패킷 출력
         */
        if (verbose) {
            printPacket(
                &item,
                (unsigned long long)
                    sec.total_packets + 1
            );
        }

        /*
         * 출발지 IP별 트래픽 통계
         * Port Scan / SYN Flood 탐지
         */
        if (!securityProcess(
                &sec,
                &item,
                stdout
            )) {

            fputs(
                "Security analyzer failure\n",
                stderr
            );

            error = 1;
            break;
        }

        /*
         * TCP 3-way Handshake 상태 추적
         */
        conntrackProcess(
            &ct,
            &item
        );
    }

    /*
     * 전체 PCAP 파일을 정상적으로 읽은 경우,
     * 아직 추적 중인 연결을 마무리한다.
     *
     * 주의:
     * 이때 집계되는 incomplete는
     * '캡처 안에서 미완료'라는 의미다.
     */
    if (!error && reached_eof) {
        conntrackFinish(&ct);
    }

    /*
     * Traffic Summary 출력
     */
    securityPrintSummary(
        &sec,
        stdout
    );

    printf(
        "Unsupported: %llu\n"
        "Invalid: %llu\n",
        unsupported,
        invalid
    );

    /*
     * Connection Tracking Summary 출력
     */
    conntrackSummary(
        &ct,
        stdout
    );

    /*
     * 비정상 종료 안내
     */
    if (error || !reached_eof) {
        fputs(
            "\n[WARNING] Analysis incomplete: "
            "processing stopped before EOF.\n",
            stderr
        );
    }

    /*
     * 메모리 및 파일 정리
     */
    conntrackFree(&ct);

    securityFree(&sec);

    freeQueue(&q);

    pcapClose(&reader);

    /*
     * 프로그램 종료 코드
     */
    return (error || !reached_eof) ? 1 : 0;
}
