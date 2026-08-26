/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * test_directory.c - coverage for the key-directory host allowlist and
 * Cache-Control-derived cache TTL.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_directory.h"
#include "test.h"


#define TEST_MIN_TTL  300
#define TEST_MAX_TTL  3600


static ngx_str_t
str(const char *s)
{
    ngx_str_t v;

    v.data = (u_char *) s;
    v.len = ngx_strlen(v.data);

    return v;
}


static ngx_int_t
normalize(ngx_pool_t *pool, const char *in, ngx_str_t *out,
    ngx_auth_httpsig_host_reason_t *reason)
{
    ngx_str_t s;

    s = str(in);

    return ngx_auth_httpsig_directory_normalize_host(pool, &s, out, reason);
}


TEST(directory_normalize_lowercases)
{
    ngx_str_t out;

    ASSERT_EQ_INT(NGX_OK,
        normalize(pool, "Bot.Example.COM", &out, NULL));
    ASSERT_STR_EQ(out, "bot.example.com");

    return 0;
}


TEST(directory_normalize_strips_default_https_port)
{
    ngx_str_t out;

    ASSERT_EQ_INT(NGX_OK,
        normalize(pool, "bot.example.com:443", &out, NULL));
    ASSERT_STR_EQ(out, "bot.example.com");

    return 0;
}


TEST(directory_normalize_keeps_non_default_port)
{
    ngx_str_t out;

    ASSERT_EQ_INT(NGX_OK,
        normalize(pool, "bot.example.com:8443", &out, NULL));
    ASSERT_STR_EQ(out, "bot.example.com:8443");

    return 0;
}


TEST(directory_normalize_rejects_scheme)
{
    ngx_str_t                       out;
    ngx_auth_httpsig_host_reason_t  reason;

    reason = 0;

    ASSERT_EQ_INT(NGX_ERROR,
        normalize(pool, "https://bot.example.com", &out, &reason));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_HOST_HAS_SCHEME, reason);

    return 0;
}


TEST(directory_normalize_rejects_wildcard)
{
    ngx_str_t                       out;
    ngx_auth_httpsig_host_reason_t  reason;

    reason = 0;

    ASSERT_EQ_INT(NGX_ERROR,
        normalize(pool, "*.example.com", &out, &reason));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_HOST_WILDCARD, reason);

    return 0;
}


TEST(directory_normalize_rejects_path)
{
    ngx_str_t                       out;
    ngx_auth_httpsig_host_reason_t  reason;

    reason = 0;

    ASSERT_EQ_INT(NGX_ERROR,
        normalize(pool, "bot.example.com/path", &out, &reason));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_HOST_INVALID_CHAR, reason);

    return 0;
}


TEST(directory_normalize_rejects_userinfo)
{
    ngx_str_t                       out;
    ngx_auth_httpsig_host_reason_t  reason;

    reason = 0;

    ASSERT_EQ_INT(NGX_ERROR,
        normalize(pool, "user@bot.example.com", &out, &reason));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_HOST_INVALID_CHAR, reason);

    return 0;
}


TEST(directory_normalize_rejects_empty)
{
    ngx_str_t                       out;
    ngx_auth_httpsig_host_reason_t  reason;

    reason = 0;

    ASSERT_EQ_INT(NGX_ERROR, normalize(pool, "", &out, &reason));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_HOST_EMPTY, reason);

    return 0;
}


TEST(directory_allowed_exact_match)
{
    ngx_array_t *allow;
    ngx_str_t    host, *entry;

    allow = ngx_array_create(pool, 1, sizeof(ngx_str_t));
    entry = ngx_array_push(allow);
    *entry = str("bot.example.com");

    host = str("bot.example.com");

    ASSERT_EQ_INT(1, ngx_auth_httpsig_directory_allowed(allow, &host));

    return 0;
}


TEST(directory_allowed_rejects_prefix_variant)
{
    ngx_array_t *allow;
    ngx_str_t    host, *entry;

    allow = ngx_array_create(pool, 1, sizeof(ngx_str_t));
    entry = ngx_array_push(allow);
    *entry = str("bot.example.com");

    host = str("evil-bot.example.com");

    ASSERT_EQ_INT(0, ngx_auth_httpsig_directory_allowed(allow, &host));

    return 0;
}


TEST(directory_allowed_rejects_suffix_variant)
{
    ngx_array_t *allow;
    ngx_str_t    host, *entry;

    allow = ngx_array_create(pool, 1, sizeof(ngx_str_t));
    entry = ngx_array_push(allow);
    *entry = str("example.com");

    host = str("bot.example.com");

    ASSERT_EQ_INT(0, ngx_auth_httpsig_directory_allowed(allow, &host));

    return 0;
}


TEST(directory_allowed_rejects_null_and_empty)
{
    ngx_array_t *empty;
    ngx_str_t    host;

    host = str("bot.example.com");

    ASSERT_EQ_INT(0, ngx_auth_httpsig_directory_allowed(NULL, &host));

    empty = ngx_array_create(pool, 1, sizeof(ngx_str_t));
    ASSERT_EQ_INT(0, ngx_auth_httpsig_directory_allowed(empty, &host));

    return 0;
}


TEST(directory_ttl_header_absent_is_floor)
{
    ASSERT_EQ_INT(TEST_MIN_TTL,
        ngx_auth_httpsig_directory_ttl(NULL, 0, TEST_MIN_TTL, TEST_MAX_TTL));

    return 0;
}


TEST(directory_ttl_max_age_zero_is_floor)
{
    ngx_str_t cc;

    cc = str("max-age=0");

    ASSERT_EQ_INT(TEST_MIN_TTL,
        ngx_auth_httpsig_directory_ttl(&cc, 0, TEST_MIN_TTL, TEST_MAX_TTL));

    return 0;
}


TEST(directory_ttl_no_store_is_floor)
{
    ngx_str_t cc;

    cc = str("no-store");

    ASSERT_EQ_INT(TEST_MIN_TTL,
        ngx_auth_httpsig_directory_ttl(&cc, 0, TEST_MIN_TTL, TEST_MAX_TTL));

    return 0;
}


TEST(directory_ttl_no_cache_is_floor)
{
    ngx_str_t cc;

    cc = str("no-cache");

    ASSERT_EQ_INT(TEST_MIN_TTL,
        ngx_auth_httpsig_directory_ttl(&cc, 0, TEST_MIN_TTL, TEST_MAX_TTL));

    return 0;
}


TEST(directory_ttl_private_is_floor)
{
    ngx_str_t cc;

    cc = str("private");

    ASSERT_EQ_INT(TEST_MIN_TTL,
        ngx_auth_httpsig_directory_ttl(&cc, 0, TEST_MIN_TTL, TEST_MAX_TTL));

    return 0;
}


TEST(directory_ttl_unparseable_is_floor)
{
    ngx_str_t cc;

    cc = str("max-age=abc");

    ASSERT_EQ_INT(TEST_MIN_TTL,
        ngx_auth_httpsig_directory_ttl(&cc, 0, TEST_MIN_TTL, TEST_MAX_TTL));

    return 0;
}


TEST(directory_ttl_max_age_within_bounds)
{
    ngx_str_t cc;

    cc = str("max-age=600");

    ASSERT_EQ_INT(600,
        ngx_auth_httpsig_directory_ttl(&cc, 0, TEST_MIN_TTL, TEST_MAX_TTL));

    return 0;
}


TEST(directory_ttl_max_age_clamped_to_ceiling)
{
    ngx_str_t cc;

    cc = str("max-age=999999");

    ASSERT_EQ_INT(TEST_MAX_TTL,
        ngx_auth_httpsig_directory_ttl(&cc, 0, TEST_MIN_TTL, TEST_MAX_TTL));

    return 0;
}


TEST(directory_ttl_s_maxage_takes_priority)
{
    ngx_str_t cc;

    /* If max-age (100) won instead of s-maxage (800), the result would
     * clamp to the 300 floor rather than 800. */
    cc = str("max-age=100, s-maxage=800");

    ASSERT_EQ_INT(800,
        ngx_auth_httpsig_directory_ttl(&cc, 0, TEST_MIN_TTL, TEST_MAX_TTL));

    return 0;
}


TEST(directory_ttl_overflow_saturates_to_ceiling)
{
    ngx_str_t cc;

    cc = str("max-age=99999999999999999999");

    ASSERT_EQ_INT(TEST_MAX_TTL,
        ngx_auth_httpsig_directory_ttl(&cc, 0, TEST_MIN_TTL, TEST_MAX_TTL));

    return 0;
}


TEST(directory_ttl_age_is_subtracted)
{
    ngx_str_t cc;

    cc = str("max-age=600");

    ASSERT_EQ_INT(500,
        ngx_auth_httpsig_directory_ttl(&cc, 100, TEST_MIN_TTL, TEST_MAX_TTL));

    return 0;
}


#define TEST_MEDIA_TYPE \
        "application/http-message-signatures-directory+json"


TEST(directory_check_response_accepts_profile_media_type)
{
    ngx_str_t                        schema, ctype, media;
    ngx_auth_httpsig_fetch_reason_t  reason;

    schema = str("https");
    ctype = str(TEST_MEDIA_TYPE);
    media = str(TEST_MEDIA_TYPE);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_directory_check_response(&schema, 200, &ctype,
            &media, 3, 64, &reason));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_FETCH_OK, reason);

    return 0;
}


TEST(directory_check_response_accepts_application_json)
{
    ngx_str_t                        schema, ctype, media;
    ngx_auth_httpsig_fetch_reason_t  reason;

    schema = str("https");
    ctype = str("application/json; charset=utf-8");
    media = str(TEST_MEDIA_TYPE);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_directory_check_response(&schema, 200, &ctype,
            &media, 3, 64, &reason));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_FETCH_OK, reason);

    return 0;
}


TEST(directory_check_response_rejects_non_https_schema)
{
    ngx_str_t                        schema, ctype, media;
    ngx_auth_httpsig_fetch_reason_t  reason;

    schema = str("http");
    ctype = str("application/json");
    media = str(TEST_MEDIA_TYPE);

    ASSERT_EQ_INT(NGX_DECLINED,
        ngx_auth_httpsig_directory_check_response(&schema, 200, &ctype,
            &media, 3, 64, &reason));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_FETCH_NOT_HTTPS, reason);

    return 0;
}


TEST(directory_check_response_rejects_redirect_status)
{
    ngx_str_t                        schema, ctype, media;
    ngx_auth_httpsig_fetch_reason_t  reason;

    schema = str("https");
    ctype = str("application/json");
    media = str(TEST_MEDIA_TYPE);

    ASSERT_EQ_INT(NGX_DECLINED,
        ngx_auth_httpsig_directory_check_response(&schema, 302, &ctype,
            &media, 3, 64, &reason));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_FETCH_REDIRECT, reason);

    return 0;
}


TEST(directory_check_response_rejects_non_200_status)
{
    ngx_str_t                        schema, ctype, media;
    ngx_auth_httpsig_fetch_reason_t  reason;

    schema = str("https");
    ctype = str("application/json");
    media = str(TEST_MEDIA_TYPE);

    ASSERT_EQ_INT(NGX_DECLINED,
        ngx_auth_httpsig_directory_check_response(&schema, 404, &ctype,
            &media, 3, 64, &reason));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_FETCH_STATUS, reason);

    return 0;
}


TEST(directory_check_response_rejects_mismatched_media_type)
{
    ngx_str_t                        schema, ctype, media;
    ngx_auth_httpsig_fetch_reason_t  reason;

    schema = str("https");
    ctype = str("text/plain");
    media = str(TEST_MEDIA_TYPE);

    ASSERT_EQ_INT(NGX_DECLINED,
        ngx_auth_httpsig_directory_check_response(&schema, 200, &ctype,
            &media, 3, 64, &reason));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_FETCH_MEDIA_TYPE, reason);

    return 0;
}


TEST(directory_check_response_rejects_missing_content_type)
{
    ngx_str_t                        schema, media;
    ngx_auth_httpsig_fetch_reason_t  reason;

    schema = str("https");
    media = str(TEST_MEDIA_TYPE);

    ASSERT_EQ_INT(NGX_DECLINED,
        ngx_auth_httpsig_directory_check_response(&schema, 200, NULL,
            &media, 3, 64, &reason));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_FETCH_MEDIA_TYPE, reason);

    return 0;
}


TEST(directory_check_response_rejects_oversized_body)
{
    ngx_str_t                        schema, ctype, media;
    ngx_auth_httpsig_fetch_reason_t  reason;

    schema = str("https");
    ctype = str("application/json");
    media = str(TEST_MEDIA_TYPE);

    ASSERT_EQ_INT(NGX_DECLINED,
        ngx_auth_httpsig_directory_check_response(&schema, 200, &ctype,
            &media, 65, 64, &reason));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_FETCH_TOO_LARGE, reason);

    return 0;
}


TEST(directory_check_response_rejects_empty_body)
{
    ngx_str_t                        schema, ctype, media;
    ngx_auth_httpsig_fetch_reason_t  reason;

    schema = str("https");
    ctype = str("application/json");
    media = str(TEST_MEDIA_TYPE);

    ASSERT_EQ_INT(NGX_DECLINED,
        ngx_auth_httpsig_directory_check_response(&schema, 200, &ctype,
            &media, 0, 64, &reason));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_FETCH_EMPTY, reason);

    return 0;
}


TEST_SUITE(directory)
{
    RUN(directory_normalize_lowercases);
    RUN(directory_normalize_strips_default_https_port);
    RUN(directory_normalize_keeps_non_default_port);
    RUN(directory_normalize_rejects_scheme);
    RUN(directory_normalize_rejects_wildcard);
    RUN(directory_normalize_rejects_path);
    RUN(directory_normalize_rejects_userinfo);
    RUN(directory_normalize_rejects_empty);
    RUN(directory_allowed_exact_match);
    RUN(directory_allowed_rejects_prefix_variant);
    RUN(directory_allowed_rejects_suffix_variant);
    RUN(directory_allowed_rejects_null_and_empty);
    RUN(directory_ttl_header_absent_is_floor);
    RUN(directory_ttl_max_age_zero_is_floor);
    RUN(directory_ttl_no_store_is_floor);
    RUN(directory_ttl_no_cache_is_floor);
    RUN(directory_ttl_private_is_floor);
    RUN(directory_ttl_unparseable_is_floor);
    RUN(directory_ttl_max_age_within_bounds);
    RUN(directory_ttl_max_age_clamped_to_ceiling);
    RUN(directory_ttl_s_maxage_takes_priority);
    RUN(directory_ttl_overflow_saturates_to_ceiling);
    RUN(directory_ttl_age_is_subtracted);
    RUN(directory_check_response_accepts_profile_media_type);
    RUN(directory_check_response_accepts_application_json);
    RUN(directory_check_response_rejects_non_https_schema);
    RUN(directory_check_response_rejects_redirect_status);
    RUN(directory_check_response_rejects_non_200_status);
    RUN(directory_check_response_rejects_mismatched_media_type);
    RUN(directory_check_response_rejects_missing_content_type);
    RUN(directory_check_response_rejects_oversized_body);
    RUN(directory_check_response_rejects_empty_body);
}
