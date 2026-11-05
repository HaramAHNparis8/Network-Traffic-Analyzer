#include <stdlib.h>
#include "queue.h"

void initQueue(Queue *queue){

	queue -> front = NULL;
	queue -> rear = NULL;
	queue -> size = 0;
}

int enqueue(Queue *queue, Packet packet) {
    Node *newNode = malloc(sizeof(Node));

    if (newNode == NULL)
        return 0;

    newNode -> packet = packet;
    newNode -> next = NULL;

    if (queue -> rear == NULL)
        queue -> front = newNode;
    else
        queue -> rear -> next = newNode;

    queue -> rear = newNode;
    queue -> size++;

    return 1;
}

void freeQueue(Queue *queue) {
    Node *current = queue->front;

    while (current != NULL) {
        Node *next = current->next;
        free(current);
        current = next;
    }

    initQueue(queue);
}
