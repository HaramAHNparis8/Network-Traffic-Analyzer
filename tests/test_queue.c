#include <stdio.h>

#include "test_framework.h"
#include "queue.h"

// 큐 전체 상태 출력
void printQueue(const Queue *queue) {
    const Node *current = queue->front;

    printf("큐 : FRONT -> ");

    while (current != NULL) {
        printf("%u -> ", current->packet.src_ip);
        current = current->next;
    }

    printf("NULL\n");
    printf("Size: %zu\n\n", queue->size);
}

int main(void) {
    initTestFramework();    
	
    Queue queue;
    initQueue(&queue);

    printf("================================ 큐 테스트 ================================\n\n");

    // 1. 초기화 검증
    printf("[1] Initialize Queue\n");
    printQueue(&queue);

    CHECK_EQ(queue.size, 0, "초기 큐 크기");
    CHECK(queue.front == NULL, "초기 Front");
    CHECK(queue.rear == NULL, "초기 Rear");

    // 2. 패킷 생성
    Packet p1 = {0};
    Packet p2 = {0};
    Packet p3 = {0};

    p1.src_ip = 10;
    p2.src_ip = 20;
    p3.src_ip = 30;

    // 3. 첫 번째 삽입
    printf("\n[2] Enqueue 10\n");

    int r1 = enqueue(&queue, p1);
    CHECK_EQ(r1, 1, "첫 번째 삽입 성공");
    printQueue(&queue);

    // 4. 두 번째 삽입
    printf("[3] Enqueue 20\n");

    int r2 = enqueue(&queue, p2);
    CHECK_EQ(r2, 1, "두 번째 삽입 성공");
    printQueue(&queue);

    // 5. 세 번째 삽입
    printf("[4] Enqueue 30\n");

    int r3 = enqueue(&queue, p3);
    CHECK_EQ(r3, 1, "세 번째 삽입 성공");
    printQueue(&queue);

    // 6. 연결 리스트 검증
    printf("[5] Verify Linked List\n");

    CHECK_EQ(queue.size, 3, "전체 노드 개수");

    CHECK(queue.front != NULL, "Front 노드 존재");
    CHECK(queue.rear != NULL, "Rear 노드 존재");

    if (queue.front != NULL) {
        CHECK_EQ(queue.front->packet.src_ip,
                 10, "첫 번째 노드 데이터");

        CHECK(queue.front->next != NULL,
              "두 번째 노드 존재");

        if (queue.front->next != NULL) {
            CHECK_EQ(queue.front->next->packet.src_ip,
                     20, "두 번째 노드 데이터");

            CHECK(queue.front->next->next == queue.rear,
                  "세 번째 노드 연결");
        }
    }

    if (queue.rear != NULL) {
        CHECK_EQ(queue.rear->packet.src_ip,
                 30, "마지막 노드 데이터");

        CHECK(queue.rear->next == NULL,
              "마지막 노드의 next == NULL");
    }

    // 7. 메모리 해제
    printf("\n[6] Free Queue\n");

    freeQueue(&queue);
    printQueue(&queue);

    CHECK_EQ(queue.size, 0, "해제 후 큐 크기");
    CHECK(queue.front == NULL, "해제 후 Front");
    CHECK(queue.rear == NULL, "해제 후 Rear");

    // 8. 전체 결과
    printf("\n[7] Failure Detection Test\n");

    // 정상적인 큐 크기는 0이지만 일부러 5를 기대
    CHECK_EQ(queue.size, 5, "큐 크기 불일치 탐지");

    // front는 NULL이지만 일부러 NULL이 아니라고 검사
    CHECK(queue.front != NULL, "Front 포인터 오류 탐지");

    // 실제로는 정상적인 조건도 함께 확인
    CHECK_EQ(queue.size, 0, "정상 조건 검증");
    TEST_SUMMARY();

    return tests_failed == 0 ? 0 : 1;
}
