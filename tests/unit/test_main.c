/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * test_main.c - entry point for the auth_httpsig unit tests. Calls
 * each suite's test_suite_<name>() function and reports the totals.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdio.h>


int test_passed = 0;
int test_failed = 0;

void test_suite_sfv(ngx_log_t *log);
void test_suite_sfv_httpwg(ngx_log_t *log);
void test_suite_base(ngx_log_t *log);
void test_suite_keys(ngx_log_t *log);
void test_suite_verify(ngx_log_t *log);


int
main(void)
{
    ngx_log_t log;

    log.log_level = NGX_LOG_WARN;

    test_suite_sfv(&log);
    test_suite_sfv_httpwg(&log);
    test_suite_base(&log);
    test_suite_keys(&log);
    test_suite_verify(&log);

    printf("%d passed, %d failed\n", test_passed, test_failed);

    return test_failed ? 1 : 0;
}
