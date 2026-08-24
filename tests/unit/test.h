/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * test.h - minimal test framework for the auth_httpsig unit tests.
 *
 * TEST(name) expands to a static function taking an ngx_pool_t, so a
 * suite's test bodies stay private to their translation unit. Each
 * test_*.c exposes a single TEST_SUITE(name) function that RUN()s its
 * own tests, since test_main.c cannot call a static function directly.
 */

#ifndef TEST_H
#define TEST_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdio.h>
#include <string.h>


extern int test_passed;
extern int test_failed;

#define ASSERT(cond)                                                        \
        do {                                                                    \
            if (!(cond)) {                                                      \
                fprintf(stderr, "  FAIL  %s:%d: %s\n", __FILE__, __LINE__,      \
                        #cond);                                                 \
                return -1;                                                     \
            }                                                                   \
        } while (0)

#define ASSERT_EQ_INT(a, b)                                                  \
        do {                                                                    \
            long long _a = (long long) (a);                                    \
            long long _b = (long long) (b);                                    \
            if (_a != _b) {                                                    \
                fprintf(stderr, "  FAIL  %s:%d: %s (%lld) != %s (%lld)\n",     \
                        __FILE__, __LINE__, #a, _a, #b, _b);                   \
                return -1;                                                     \
            }                                                                   \
        } while (0)

#define ASSERT_STR_EQ(s, expected)                                           \
        do {                                                                    \
            ngx_str_t _s = (s);                                                 \
            const char *_e = (expected);                                       \
            size_t _elen = strlen(_e);                                         \
            if (_s.len != _elen || memcmp(_s.data, _e, _elen) != 0) {          \
                fprintf(stderr, "  FAIL  %s:%d: %s != \"%s\"\n", __FILE__,     \
                        __LINE__, #s, _e);                                     \
                return -1;                                                     \
            }                                                                   \
        } while (0)

#define TEST(name)  static int test_ ## name(ngx_pool_t * pool)

#define RUN(name)                                                            \
        do {                                                                    \
            ngx_pool_t *_pool = ngx_create_pool(0, log);                       \
            int _rc = test_ ## name(_pool);                                    \
            ngx_destroy_pool(_pool);                                           \
            if (_rc == 0) {                                                    \
                test_passed++;                                                 \
                printf("  PASS  %s\n", #name);                                 \
            } else {                                                            \
                test_failed++;                                                 \
            }                                                                   \
        } while (0)

#define TEST_SUITE(suite)  void test_suite_ ## suite(ngx_log_t * log)

#endif /* TEST_H */
