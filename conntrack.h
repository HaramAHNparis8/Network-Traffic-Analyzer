#ifndef CONNTRACK_H
#define CONNTRACK_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "packet.h"

#define CT_HANDSHAKE_TIMEOUT 30.0
#define CT_ESTABLISHED_TIMEOUT 120.0
#define CT_MAX_CONNECTIONS 100000u

typedef enum {
    CT_SYN_SENT,
    CT_SYN_ACK_SEEN,
    CT_ESTABLISHED
} CtState;

typedef struct CtConnection {
    uint32_t client_ip;
    uint32_t server_ip;

    uint16_t client_port;
    uint16_t server_port;

    double started;
    double last_seen;

    CtState state;

    struct CtConnection *next;
} CtConnection;

typedef struct {
    CtConnection *head;
    size_t active;

    uint64_t syn_seen;
    uint64_t syn_ack_seen;
    uint64_t completed;
    uint64_t incomplete;
    uint64_t retransmitted_syn;
    uint64_t reset_connections;
    uint64_t out_of_order;
    uint64_t ignored_due_to_limit;

    double last_timestamp;
    int has_timestamp;
} ConnTracker;

void conntrackInit(ConnTracker *ct);

void conntrackProcess(
    ConnTracker *ct,
    const Packet *p
);

void conntrackFinish(ConnTracker *ct);

void conntrackSummary(
    const ConnTracker *ct,
    FILE *out
);

void conntrackFree(ConnTracker *ct);

#endif
