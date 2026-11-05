#ifndef QUEUE_H
#define QUEUE_H

#include <stddef.h>
#include "packet.h"

typedef struct Node {
	Packet packet;
	struct Node *next;
} Node;

typedef struct Queue {
	Node *front;
	Node *rear;
	size_t size;
} Queue;

void initQueue(Queue *queue);
int enqueue(Queue *queue, Packet packet);
int dequeue(QUEUE *queue, Packet *packet);
int isEmpty(con);
#endif


