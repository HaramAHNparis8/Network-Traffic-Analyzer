#ifndef SECURITY_H
#define SECURITY_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "packet.h"

// TCP Flags 비트 마스크
#define TCP_FIN 0x01u
#define TCP_SYN 0x02u
#define TCP_RST 0x04u
#define TCP_PSH 0x08u
#define TCP_ACK 0x10u
#define TCP_URG 0x20u
#define TCP_ECE 0x40u
#define TCP_CWR 0x80u

// 탐지 임계값 (실습용)
#define DETECT_WINDOW_SEC 10.0
#define PORT_SCAN_PORT_THRESHOLD 20u
#define SYN_FLOOD_SYN_THRESHOLD 100u
#define ALERT_COOLDOWN_SEC 10.0

// 출발지 IP별 통계
typedef struct {
    uint32_t src_ip;

    uint64_t packets;
    uint64_t bytes;
    uint64_t tcp_packets;
    uint64_t udp_packets;
} SourceStat;

// TCP SYN 이벤트
typedef struct SynEvent {
    double time;
    uint16_t dst_port;

    struct SynEvent *next;
} SynEvent;

// 출발지-목적지 IP별 탐지 상태
typedef struct FlowState {
    uint32_t src_ip;
    uint32_t dst_ip;

    SynEvent *head;
    SynEvent *tail;

    size_t syn_count;

    double last_timestamp;
    double last_scan_alert;
    double last_flood_alert;

    int scan_alerted;
    int flood_alerted;

    struct FlowState *next;
} FlowState;

// 전체 보안 분석기
typedef struct {
    SourceStat *sources;

    size_t sources_count;
    size_t sources_capacity;

    FlowState *flows;

    uint64_t total_packets;
    uint64_t total_bytes;

    uint64_t tcp_packets;
    uint64_t udp_packets;

    uint64_t scans;
    uint64_t floods;

    uint64_t skipped_out_of_order;
} SecurityAnalyzer;

void securityInit(SecurityAnalyzer *s);

int securityProcess(
    SecurityAnalyzer *s,
    const Packet *p,
    FILE *alerts
);

void securityPrintSummary(
    SecurityAnalyzer *s,
    FILE *out
);

void securityFree(SecurityAnalyzer *s);

void printIPv4(FILE *out, uint32_t ip);
void printTcpFlags(FILE *out, uint8_t flags);

#endif
