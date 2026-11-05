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

    // 0. 초기화 검증
    printf("[1] Initialize Queue\n");
    printQueue(&queue);

    CHECK_EQ(queue.size, 0, "초기 큐 크기");
    CHECK(queue.front == NULL, "초기 Front");
    CHECK(queue.rear == NULL, "초기 Rear");

    // 1. 패킷 생성
    Packet p1 = {0};
    Packet p2 = {0};
    Packet p3 = {0};

    p1.src_ip = 10;
    p2.src_ip = 20;
    p3.src_ip = 30;

    // 2. 첫 번째 삽입
    printf("\n[2] Enqueue 10\n");

    int r1 = enqueue(&queue, p1);
    CHECK_EQ(r1, 1, "첫 번째 삽입 성공");
    printQueue(&queue);

    // 3. 두 번째 삽입
    printf("[3] Enqueue 20\n");

    int r2 = enqueue(&queue, p2);
    CHECK_EQ(r2, 1, "두 번째 삽입 성공");
    printQueue(&queue);

    // 4. 세 번째 삽입
    printf("[4] Enqueue 30\n");

    int r3 = enqueue(&queue, p3);
    CHECK_EQ(r3, 1, "세 번째 삽입 성공");
    printQueue(&queue);

    // 5. 연결 리스트 검증
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
    //6.dequeue검증
    printf("\n[6] Dequeue Test\n");

    Packet removed = {0};

    int result = dequeue(&queue, &removed);

    CHECK_EQ(result, 1, "Dequeue 성공");
    CHECK_EQ(removed.src_ip, 10, "FIFO 순서 확인");
    CHECK_EQ(queue.size, 2, "삭제 후 큐 크기");

    CHECK(queue.front != NULL, "Front 존재");

    if (queue.front != NULL) {

        CHECK_EQ(queue.front->packet.src_ip,
		20, "Front 이동 확인");
}

    printQueue(&queue);

    // 7. 메모리 해제
    printf("\n[7] Free Queue\n");

    freeQueue(&queue);
    printQueue(&queue);

    CHECK_EQ(queue.size, 0, "해제 후 큐 크기");
    CHECK(queue.front == NULL, "해제 후 Front");
    CHECK(queue.rear == NULL, "해제 후 Rear");

// 8. isEmpty 검증
    printf("\n[8] isEmpty Test\n");

    CHECK_EQ(isEmpty(&queue), 1,
         "빈 큐 상태 확인");

// 9. 의도적인 오류 탐지 테스트
    printf("\n[9] Failure Detection Test\n");

    CHECK_EQ(queue.size, 5,
         "큐 크기 불일치 탐지");

    CHECK(queue.front != NULL,
      "Front 포인터 오류 탐지");

    CHECK_EQ(queue.size, 0,
         "정상 조건 검증");

    // 10. Queue Boundary Test
    printf("\n[10] Queue Boundary Test\n");

    // 1. 빈 큐에서 Dequeue
    Packet erase = {0};

    int res = dequeue(&queue, &erase);

    CHECK_EQ(res, 0, "빈 큐 Dequeue 실패 처리");
    CHECK_EQ(queue.size, 0, "빈 큐 크기 유지");
    CHECK(queue.front == NULL, "빈 큐 Front 유지");
    CHECK(queue.rear == NULL, "빈 큐 Rear 유지");

    // 2. 노드 하나 삽입 후 삭제
    Packet p4 = {0};
    p4.src_ip = 40;

    res = enqueue(&queue, p4);

    CHECK_EQ(res, 1, "단일 노드 삽입");

    if (res == 1) {
        CHECK_EQ(queue.size, 1, "단일 노드 크기");
        CHECK(queue.front == queue.rear,
              "단일 노드 Front/Rear 일치");

        res = dequeue(&queue, &erase);

        CHECK_EQ(res, 1, "마지막 노드 삭제");

        if (res == 1) {
            CHECK_EQ(erase.src_ip, 40,
                     "삭제된 패킷 확인");
        }

        CHECK(queue.front == NULL,
              "Front NULL 확인");

        CHECK(queue.rear == NULL,
              "Rear NULL 확인");

        CHECK_EQ(queue.size, 0,
                 "삭제 후 크기 0");
    }

    // 3. 큐 재사용
    Packet p5 = {0};
    p5.src_ip = 50;

    res = enqueue(&queue, p5);

    CHECK_EQ(res, 1, "큐 재삽입 성공");

    if (res == 1) {
        CHECK_EQ(queue.size, 1,
                 "재삽입 후 크기");

        CHECK(queue.front != NULL,
              "재삽입 Front 존재");

        CHECK(queue.front == queue.rear,
              "재삽입 Front/Rear 일치");

        if (queue.front != NULL) {
            CHECK_EQ(queue.front->packet.src_ip,
                     50, "재삽입 데이터 확인");

            CHECK(queue.front->next == NULL,
                  "재삽입 노드 Next NULL");
        }
    }

    printQueue(&queue);

    // 4. 최종 메모리 해제
    freeQueue(&queue);

    CHECK_EQ(queue.size, 0, "최종 큐 크기");
    CHECK(queue.front == NULL, "최종 Front");
    CHECK(queue.rear == NULL, "최종 Rear");
// 최종 결과
    TEST_SUMMARY();

    return tests_failed == 0 ? 0 : 1;

}
