#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "pcap_reader.h"
#include "parser.h"
#include "queue.h"

// IPv4 주소 출력
static void printIP(unsigned int ip) {
    printf("%u.%u.%u.%u",
           (ip >> 24) & 255u,
           (ip >> 16) & 255u,
           (ip >> 8) & 255u,
           ip & 255u);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file.pcap>\n", argv[0]);
        return 1;
    }

    PcapReader reader;

    if (!pcapOpen(&reader, argv[1])) {
        fprintf(stderr, "PCAP 파일을 열 수 없습니다.\n");
        return 1;
    }

    Queue queue;
    initQueue(&queue);

    unsigned long count = 0;
    unsigned long unsupported = 0;
    unsigned long invalid = 0;
    int error = 0;

    printf("=== Network Traffic Analyzer ===\n");

    for (;;) {
        uint8_t *raw = NULL;
        size_t length = 0;
        double timestamp = 0;

        int status = pcapNext(
            &reader, &raw, &length, &timestamp
        );

        if (status == 0)
            break;

        if (status < 0) {
            fprintf(stderr, "PCAP 읽기 오류\n");
            error = 1;
            break;
        }

        Packet packet = {0};

        ParseResult result =
            parsePacket(raw, length, &packet);

        free(raw);

        if (result == PARSE_UNSUPPORTED) {
            unsupported++;
            continue;
        }

        if (result != PARSE_OK) {
            invalid++;
            continue;
        }

        packet.timestamp = timestamp;

        if (!enqueue(&queue, packet)) {
            fprintf(stderr, "Queue 메모리 할당 실패\n");
            error = 1;
            break;
        }

        Packet current;

        if (!dequeue(&queue, &current)) {
            fprintf(stderr, "Queue 처리 오류\n");
            error = 1;
            break;
        }

        count++;

        printf("\n[Packet #%lu]\n", count);
        printf("Timestamp : %.6f\n", current.timestamp);

        printf("Source IP : ");
        printIP(current.src_ip);
        printf("\n");

        printf("Dest IP   : ");
        printIP(current.dst_ip);
        printf("\n");

        printf("Protocol  : %s\n",
               current.protocol == 6 ? "TCP" : "UDP");

        printf("Src Port  : %u\n", current.src_port);
        printf("Dst Port  : %u\n", current.dst_port);
        printf("IP Length : %u bytes\n", current.length);
    }

    printf("\n=== Summary ===\n");
    printf("Parsed      : %lu\n", count);
    printf("Unsupported : %lu\n", unsupported);
    printf("Invalid     : %lu\n", invalid);

    freeQueue(&queue);
    pcapClose(&reader);

    return error ? 1 : 0;
}
