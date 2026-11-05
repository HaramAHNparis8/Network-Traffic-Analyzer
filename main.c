#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcap_reader.h"
#include "parser.h"
#include "queue.h"
#include "security.h"

static void printPacket(
    const Packet *p,
    unsigned long long n
) {
    printf(
        "\n[Packet #%llu] time=%.6f\n",
        n, p->timestamp
    );

    fputs("  ", stdout);
    printIPv4(stdout, p->src_ip);

    printf(":%u -> ", (unsigned)p->src_port);

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

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3 ||
        (argc == 3 &&
         strcmp(argv[2], "--verbose"))) {

        fprintf(
            stderr,
            "Usage: %s <file.pcap> [--verbose]\n",
            argv[0]
        );

        return 1;
    }

    int verbose = argc == 3;

    PcapReader reader;

    if (!pcapOpen(&reader, argv[1])) {
        fprintf(
            stderr,
            "Cannot open PCAP "
            "(classic Ethernet pcap required): %s\n",
            argv[1]
        );

        return 1;
    }

    Queue q;
    initQueue(&q);

    SecurityAnalyzer sec;
    securityInit(&sec);

    unsigned long long unsupported = 0;
    unsigned long long invalid = 0;

    int error = 0;

    puts("=== Network Traffic Analyzer ===");

    for (;;) {
        uint8_t *raw = NULL;
        size_t len = 0;
        double ts = 0;

        int state = pcapNext(
            &reader,
            &raw,
            &len,
            &ts
        );

        if (state == 0)
            break;

        if (state < 0) {
            fputs("PCAP read error\n", stderr);
            error = 1;
            break;
        }

        Packet p = {0};

        ParseResult result = parsePacket(
            raw,
            len,
            &p
        );

        free(raw);

        if (result == PARSE_UNSUPPORTED) {
            ++unsupported;
            continue;
        }

        if (result != PARSE_OK) {
            ++invalid;
            continue;
        }

        p.timestamp = ts;

        if (!enqueue(&q, p)) {
            fputs("Queue allocation failure\n", stderr);
            error = 1;
            break;
        }

        Packet item;

        if (!dequeue(&q, &item)) {
            fputs("Queue dequeue failure\n", stderr);
            error = 1;
            break;
        }

        if (verbose) {
            printPacket(
                &item,
                sec.total_packets + 1
            );
        }

        if (!securityProcess(
                &sec,
                &item,
                stdout
            )) {

            fputs(
                "Security analyzer allocation failure\n",
                stderr
            );

            error = 1;
            break;
        }
    }

    securityPrintSummary(&sec, stdout);

    printf(
        "Unsupported: %llu\nInvalid: %llu\n",
        unsupported,
        invalid
    );

    if (error)
        fputs(
            "INCOMPLETE: processing stopped due to error\n",
            stderr
        );

    securityFree(&sec);
    freeQueue(&q);
    pcapClose(&reader);

    return error ? 1 : 0;
}
