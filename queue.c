#include <stdlib.h>
#include "queue.h"

void initQueue(Queue *queue){

	queue -> front = NULL;
	queue -> rear = NULL;
	queue -> size = 0;
}


int isEmpty(const Queue *queue) {
    return queue->front == NULL;
}


int dequeue(Queue *queue, Packet *packet) {

    // 빈 큐이거나 잘못된 인자면 실패
    if (queue == NULL || packet == NULL ||
        queue->front == NULL) {
        return 0;
    }

    // 삭제 대상 노드 보관
    Node *temp = queue->front;

    // 패킷 데이터 복사
    *packet = temp->packet;

    // Front 이동
    queue->front = temp->next;

    // 큐가 완전히 비었다면 Rear 초기화
    if (queue->front == NULL) {
        queue->rear = NULL;
    }

    // 기존 노드 해제
    free(temp);

    queue->size--;

    return 1;
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
