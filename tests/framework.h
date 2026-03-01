/*
 * framework.h - Minimal single-header test framework
 *
 * Usage:
 *   #include "framework.h"
 *
 *   TEST(my_test) {
 *       CHECK(1 + 1 == 2);
 *       CHECK_STR_EQ("hello", "hello");
 *   }
 *
 *   int main(void) {
 *       RUN(my_test);
 *       TEST_RESULTS();
 *   }
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <string.h>

static int _pass = 0;
static int _fail = 0;

#define TEST(name) static void name(void)

/* Assert that expr is true */
#define CHECK(expr) do { \
    if (expr) { \
        _pass++; \
    } else { \
        _fail++; \
        fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
    } \
} while (0)

/* Assert with custom message */
#define CHECK_MSG(expr, msg) do { \
    if (expr) { \
        _pass++; \
    } else { \
        _fail++; \
        fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, msg); \
    } \
} while (0)

/* Assert that two C strings are equal */
#define CHECK_STR_EQ(a, b) do { \
    const char *_a = (a), *_b = (b); \
    if (_a && _b && strcmp(_a, _b) == 0) { \
        _pass++; \
    } else { \
        _fail++; \
        fprintf(stderr, "  FAIL %s:%d: \"%s\" != \"%s\"\n", \
                __FILE__, __LINE__, _a ? _a : "(null)", _b ? _b : "(null)"); \
    } \
} while (0)

/* Assert that two integers are equal */
#define CHECK_INT_EQ(a, b) do { \
    int _a = (int)(a), _b = (int)(b); \
    if (_a == _b) { \
        _pass++; \
    } else { \
        _fail++; \
        fprintf(stderr, "  FAIL %s:%d: %d != %d\n", \
                __FILE__, __LINE__, _a, _b); \
    } \
} while (0)

/* Run a named test function and print its name */
#define RUN(name) do { \
    printf("  " #name "\n"); \
    name(); \
} while (0)

/* Alias used by some test files */
#define RUN_TEST(name) RUN(name)

/* Expose pass/fail counters under the names some tests use */
#define g_passed _pass
#define g_failed _fail

/* Print summary and return exit code (0 = all passed, 1 = any failed) */
#define TEST_RESULTS() do { \
    printf("\n%d passed, %d failed\n", _pass, _fail); \
    return _fail ? 1 : 0; \
} while (0)

/* Print-only variant: does NOT return (caller decides exit code) */
#define PRINT_RESULTS() do { \
    printf("\n%d passed, %d failed\n", _pass, _fail); \
} while (0)

#endif /* TEST_FRAMEWORK_H */
