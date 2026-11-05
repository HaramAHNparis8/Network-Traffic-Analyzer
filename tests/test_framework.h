
#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define CHECK(condition, message) do {             \
    if (condition) {                               \
        printf("[통과] %s\n", message);             \
        tests_passed++;                            \
    } else {                                       \
        printf("[실패] %s (%s:%d)\n",               \
               message, __FILE__, __LINE__);       \
        tests_failed++;                            \
    }                                              \
} while (0)

#define CHECK_EQ(actual, expected, message) do {   \
    long long a = (long long)(actual);             \
    long long e = (long long)(expected);           \
    if (a == e) {                                  \
        printf("[통과] %s\n", message);             \
        tests_passed++;                            \
    } else {                                       \
        printf("[실패] %s (%s:%d)\n",               \
               message, __FILE__, __LINE__);       \
        printf(" 예상: %lld\n", e);             \
        printf(" 결과:   %lld\n", a);             \
        tests_failed++;                            \
    }                                              \
} while (0)

#define TEST_SUMMARY() do {                         \
    printf("\n================================ 테스트 요약 ================================\n");       \
    printf("통과: %d\n", tests_passed);             \
    printf("실패: %d\n", tests_failed);             \
    printf("========================\n");         \
} while (0)

#endif
