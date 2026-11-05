#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

// ANSI 색상 코드
#define RED    "\033[31m"
#define GREEN  "\033[32m"
#define RESET  "\033[0m"

// 테스트 결과
static int tests_passed = 0;
static int tests_failed = 0;
static int colors_enabled = 0;

// 터미널 색상 활성화
static void initTestFramework(void) {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;

    if (h == NULL || h == INVALID_HANDLE_VALUE)
        return;

    if (!GetConsoleMode(h, &mode))
        return;

    colors_enabled = SetConsoleMode(
        h,
        mode | ENABLE_PROCESSED_OUTPUT |
               ENABLE_VIRTUAL_TERMINAL_PROCESSING
    ) != 0;
#else
    colors_enabled = isatty(STDOUT_FILENO) != 0;
#endif
}

// 색상 선택
static const char *getColor(int success) {
    if (!colors_enabled)
        return "";

    return success ? GREEN : RED;
}

// 일반 조건 검증
#define CHECK(condition, message) do {                    \
    if (condition) {                                      \
        printf("[%s통과%s] %s\n",                         \
               getColor(1),                              \
               colors_enabled ? RESET : "",              \
               message);                                  \
        tests_passed++;                                   \
    } else {                                              \
        printf("[%s실패%s] %s\n",                         \
               getColor(0),                              \
               colors_enabled ? RESET : "",              \
               message);                                  \
        printf("%s[오류 위치] %s:%d%s\n",                  \
               getColor(0), __FILE__, __LINE__,           \
               colors_enabled ? RESET : "");              \
        tests_failed++;                                   \
    }                                                     \
} while (0)

// 정수값 비교 검증
#define CHECK_EQ(actual, expected, message) do {          \
    long long a = (long long)(actual);                     \
    long long e = (long long)(expected);                   \
                                                          \
    if (a == e) {                                         \
        printf("[%s통과%s] %s\n",                         \
               getColor(1),                              \
               colors_enabled ? RESET : "",              \
               message);                                  \
        tests_passed++;                                   \
    } else {                                              \
        printf("[%s실패%s] %s\n",                         \
               getColor(0),                              \
               colors_enabled ? RESET : "",              \
               message);                                  \
        printf("%s[오류 위치] %s:%d%s\n",                  \
               getColor(0), __FILE__, __LINE__,           \
               colors_enabled ? RESET : "");              \
        printf(" 예상: %lld\n", e);                        \
        printf(" 결과: %s%lld%s\n",                        \
               getColor(0), a,                            \
               colors_enabled ? RESET : "");              \
        tests_failed++;                                   \
    }                                                     \
} while (0)

// 전체 테스트 결과
#define TEST_SUMMARY() do {                                \
    printf("\n================================ 테스트 요약 ================================\n"); \
    printf("통과: %s%d%s\n",                              \
           getColor(1), tests_passed,                      \
           colors_enabled ? RESET : "");                   \
    printf("실패: %s%d%s\n",                              \
           getColor(0), tests_failed,                      \
           colors_enabled ? RESET : "");                   \
    printf("=============================================================================\n"); \
} while (0)

#endif
