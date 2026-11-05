#include <stdio.h>
#include <assert.h>
#include "queue.h"

// 큐의 전체 상태 출력
void printQueue(const Queue *queue) {
    const Node *current = queue->front;

    printf("큐 : 프론트 -> ");

    while (current != NULL) {
        printf("%u -> ", current->packet.src_ip);
        current = current->next;
    }

    printf("NULL\n");
    printf("Size: %zu\n\n", queue->size);
}

int main(void) {
    Queue queue;
    initQueue(&queue);

    printf("===================== 큐 테스트 =====================\n\n");

    // 1. 초기화
    printf("[1] Initialize Queue\n");
    printQueue(&queue);

    assert(queue.size == 0);
    assert(queue.front == NULL);
    assert(queue.rear == NULL);

    // 2. 패킷 생성
    Packet p1 = {0};
    Packet p2 = {0};
    Packet p3 = {0};

    p1.src_ip = 10;
    p2.src_ip = 20;
    p3.src_ip = 30;

    // 3. 첫 번째 삽입
    printf("[2] Enqueue 10\n");
    assert(enqueue(&queue, p1) == 1);
    printQueue(&queue);

    // 4. 두 번째 삽입
    printf("[3] Enqueue 20\n");
    assert(enqueue(&queue, p2) == 1);
    printQueue(&queue);

    // 5. 세 번째 삽입
    printf("[4] Enqueue 30\n");
    assert(enqueue(&queue, p3) == 1);
    printQueue(&queue);

    // 6. 연결 상태 검증
    printf("[5] Verify Linked List\n");

    assert(queue.size == 3);
    assert(queue.front->packet.src_ip == 10);
    assert(queue.front->next->packet.src_ip == 20);
    assert(queue.rear->packet.src_ip == 30);
    assert(queue.rear->next == NULL);

    printf("Linked List: PASS\n\n");

    // 7. 메모리 해제
    printf("[6] Free Queue\n");
    freeQueue(&queue);
    printQueue(&queue);

    assert(queue.size == 0);
    assert(queue.front == NULL);
    assert(queue.rear == NULL);

    printf("메모리 청소 : PASS\n\n");
    printf("===================== 모든 테스트가 완료되었음 =================\n");

    return 0;
}
