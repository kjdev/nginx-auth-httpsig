/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * test_keys_cache.c - coverage for the worker-local JWKS parse cache:
 * generation matching, LRU eviction, malformed-input handling, and
 * pool lifetime under churn and parent-pool teardown.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_keys_cache.h"
#include "test.h"
#include "test_crypto.h"


static ngx_str_t
str(const char *s)
{
    ngx_str_t v;

    v.data = (u_char *) s;
    v.len = ngx_strlen(v.data);

    return v;
}


/* A fresh, valid single-key JWKS document; the keypair is discarded --
 * only the public JWK ends up in the returned document. */
static ngx_str_t
valid_jwks(ngx_pool_t *pool)
{
    EVP_PKEY *pkey;
    ngx_str_t jwk, jwks_json;

    pkey = test_gen_ed25519();
    jwk = test_jwk_okp(pkey, "Ed25519", 32, NULL, NULL, pool);
    jwks_json = test_jwks_build(&jwk, 1, pool);
    EVP_PKEY_free(pkey);

    return jwks_json;
}


TEST(keys_cache_create_rejects_null_pool)
{
    ASSERT(ngx_auth_httpsig_keys_cache_create(NULL) == NULL);
    return 0;
}


TEST(keys_cache_get_same_generation_returns_same_pointer)
{
    ngx_auth_httpsig_keys_cache_t *kc;
    ngx_str_t host, jwks;
    ngx_auth_httpsig_keys_t *put_keys, *get1, *get2;

    kc = ngx_auth_httpsig_keys_cache_create(pool);
    ASSERT(kc != NULL);

    host = str("get-same.example.com");
    jwks = valid_jwks(pool);

    put_keys = NULL;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_cache_put(kc, &host, &jwks, 1, pool->log,
            &put_keys));
    ASSERT(put_keys != NULL);

    get1 = ngx_auth_httpsig_keys_cache_get(kc, &host, 1);
    get2 = ngx_auth_httpsig_keys_cache_get(kc, &host, 1);

    ASSERT(get1 == put_keys);
    ASSERT(get2 == put_keys);

    return 0;
}


TEST(keys_cache_get_generation_mismatch_is_a_miss)
{
    ngx_auth_httpsig_keys_cache_t *kc;
    ngx_str_t host, jwks;

    kc = ngx_auth_httpsig_keys_cache_create(pool);
    ASSERT(kc != NULL);

    host = str("gen-mismatch.example.com");
    jwks = valid_jwks(pool);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_cache_put(kc, &host, &jwks, 5, pool->log,
            NULL));

    ASSERT(ngx_auth_httpsig_keys_cache_get(kc, &host, 6) == NULL);
    ASSERT(ngx_auth_httpsig_keys_cache_get(kc, &host, 4) == NULL);

    /* An unseen host is a miss too, regardless of generation. */
    host = str("never-seen.example.com");
    ASSERT(ngx_auth_httpsig_keys_cache_get(kc, &host, 5) == NULL);

    return 0;
}


TEST(keys_cache_generation_zero_always_fails)
{
    ngx_auth_httpsig_keys_cache_t *kc;
    ngx_str_t host, jwks;

    kc = ngx_auth_httpsig_keys_cache_create(pool);
    ASSERT(kc != NULL);

    host = str("gen-zero.example.com");
    jwks = valid_jwks(pool);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_cache_put(kc, &host, &jwks, 7, pool->log,
            NULL));

    /* Stored at generation 7; looking up generation 0 must still miss. */
    ASSERT(ngx_auth_httpsig_keys_cache_get(kc, &host, 0) == NULL);

    /* Storing at generation 0 is a caller bug, not a valid put. */
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_keys_cache_put(kc, &host, &jwks, 0, pool->log,
            NULL));

    return 0;
}


TEST(keys_cache_put_replaces_previous_entry_for_host)
{
    ngx_auth_httpsig_keys_cache_t *kc;
    ngx_str_t host, jwks1, jwks2;
    ngx_auth_httpsig_keys_t *first, *second;

    kc = ngx_auth_httpsig_keys_cache_create(pool);
    ASSERT(kc != NULL);

    host = str("replace.example.com");
    jwks1 = valid_jwks(pool);
    jwks2 = valid_jwks(pool);

    first = NULL;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_cache_put(kc, &host, &jwks1, 1, pool->log,
            &first));
    ASSERT(first != NULL);
    ASSERT(ngx_auth_httpsig_keys_cache_get(kc, &host, 1) == first);

    second = NULL;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_cache_put(kc, &host, &jwks2, 2, pool->log,
            &second));
    ASSERT(second != NULL);
    ASSERT(second != first);

    /* The old generation is gone -- not just superseded, but its pool
     * has been torn down, so any lingering pointer to `first` would be
     * dangling under ASAN. */
    ASSERT(ngx_auth_httpsig_keys_cache_get(kc, &host, 1) == NULL);
    ASSERT(ngx_auth_httpsig_keys_cache_get(kc, &host, 2) == second);

    return 0;
}


TEST(keys_cache_put_malformed_jwks_declines_without_leaving_a_slot)
{
    ngx_auth_httpsig_keys_cache_t *kc;
    ngx_str_t host, bad_jwks;
    ngx_auth_httpsig_keys_t *out;

    kc = ngx_auth_httpsig_keys_cache_create(pool);
    ASSERT(kc != NULL);

    host = str("malformed.example.com");
    bad_jwks = str("not a json document");

    out = (ngx_auth_httpsig_keys_t *) 0x1; /* sentinel: must stay untouched */
    ASSERT_EQ_INT(NGX_DECLINED,
        ngx_auth_httpsig_keys_cache_put(kc, &host, &bad_jwks, 1, pool->log,
            &out));
    ASSERT(out == (ngx_auth_httpsig_keys_t *) 0x1);

    /* No half-written slot: a lookup for this host is a plain miss, not
     * a hit on garbage. */
    ASSERT(ngx_auth_httpsig_keys_cache_get(kc, &host, 1) == NULL);

    return 0;
}


TEST(keys_cache_put_rejects_null_arguments)
{
    ngx_auth_httpsig_keys_cache_t *kc;
    ngx_str_t host, jwks;

    kc = ngx_auth_httpsig_keys_cache_create(pool);
    ASSERT(kc != NULL);

    host = str("null-args.example.com");
    jwks = valid_jwks(pool);

    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_keys_cache_put(NULL, &host, &jwks, 1, pool->log,
            NULL));
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_keys_cache_put(kc, NULL, &jwks, 1, pool->log, NULL));
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_keys_cache_put(kc, &host, NULL, 1, pool->log, NULL));
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_keys_cache_put(kc, &host, &jwks, 1, NULL, NULL));

    ASSERT(ngx_auth_httpsig_keys_cache_get(NULL, &host, 1) == NULL);
    ASSERT(ngx_auth_httpsig_keys_cache_get(kc, NULL, 1) == NULL);

    return 0;
}


TEST(keys_cache_lru_evicts_only_the_least_recently_touched_entry)
{
    ngx_auth_httpsig_keys_cache_t *kc;
    ngx_str_t hosts[NGX_AUTH_HTTPSIG_MAX_KEYS_CACHE_ENTRIES];
    ngx_str_t jwks, overflow_host;
    ngx_uint_t i;
    char buf[NGX_AUTH_HTTPSIG_MAX_KEYS_CACHE_ENTRIES][64];

    kc = ngx_auth_httpsig_keys_cache_create(pool);
    ASSERT(kc != NULL);

    jwks = valid_jwks(pool);

    for (i = 0; i < NGX_AUTH_HTTPSIG_MAX_KEYS_CACHE_ENTRIES; i++) {
        snprintf(buf[i], sizeof(buf[i]), "lru-%u.example.com", (unsigned) i);
        hosts[i] = str(buf[i]);

        ASSERT_EQ_INT(NGX_OK,
            ngx_auth_httpsig_keys_cache_put(kc, &hosts[i], &jwks, i + 1,
                pool->log, NULL));
    }

    /* Touch every entry except hosts[0], so it alone is left as the
     * least-recently-touched slot. */
    for (i = 1; i < NGX_AUTH_HTTPSIG_MAX_KEYS_CACHE_ENTRIES; i++) {
        ASSERT(ngx_auth_httpsig_keys_cache_get(kc, &hosts[i], i + 1) != NULL);
    }

    overflow_host = str("lru-overflow.example.com");
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_cache_put(kc, &overflow_host, &jwks, 1000,
            pool->log, NULL));

    /* hosts[0] was the only untouched entry and must be the one evicted. */
    ASSERT(ngx_auth_httpsig_keys_cache_get(kc, &hosts[0], 1) == NULL);

    for (i = 1; i < NGX_AUTH_HTTPSIG_MAX_KEYS_CACHE_ENTRIES; i++) {
        ASSERT(ngx_auth_httpsig_keys_cache_get(kc, &hosts[i], i + 1) != NULL);
    }

    ASSERT(ngx_auth_httpsig_keys_cache_get(kc, &overflow_host, 1000) != NULL);

    return 0;
}


TEST(keys_cache_same_host_survives_a_thousand_generations)
{
    ngx_auth_httpsig_keys_cache_t *kc;
    ngx_str_t host, jwks;
    ngx_uint_t gen;
    ngx_auth_httpsig_keys_t *last;

    kc = ngx_auth_httpsig_keys_cache_create(pool);
    ASSERT(kc != NULL);

    host = str("churn.example.com");
    jwks = valid_jwks(pool);

    last = NULL;
    for (gen = 1; gen <= 1000; gen++) {
        ASSERT_EQ_INT(NGX_OK,
            ngx_auth_httpsig_keys_cache_put(kc, &host, &jwks, gen, pool->log,
                &last));
    }

    ASSERT(ngx_auth_httpsig_keys_cache_get(kc, &host, 1000) == last);
    ASSERT(ngx_auth_httpsig_keys_cache_get(kc, &host, 999) == NULL);

    return 0;
}


TEST(keys_cache_parent_pool_destruction_frees_all_entries)
{
    ngx_pool_t *child_pool;
    ngx_auth_httpsig_keys_cache_t *kc;
    ngx_str_t host_a, host_b, jwks;

    child_pool = ngx_create_pool(0, pool->log);
    ASSERT(child_pool != NULL);

    kc = ngx_auth_httpsig_keys_cache_create(child_pool);
    ASSERT(kc != NULL);

    host_a = str("teardown-a.example.com");
    host_b = str("teardown-b.example.com");
    jwks = valid_jwks(pool);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_cache_put(kc, &host_a, &jwks, 1, pool->log,
            NULL));
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_cache_put(kc, &host_b, &jwks, 1, pool->log,
            NULL));

    /* Destroying the owning pool must destroy every entry's pool too,
     * with no double free and no leak (verified under ASAN). */
    ngx_destroy_pool(child_pool);

    return 0;
}


TEST_SUITE(keys_cache)
{
    RUN(keys_cache_create_rejects_null_pool);
    RUN(keys_cache_get_same_generation_returns_same_pointer);
    RUN(keys_cache_get_generation_mismatch_is_a_miss);
    RUN(keys_cache_generation_zero_always_fails);
    RUN(keys_cache_put_replaces_previous_entry_for_host);
    RUN(keys_cache_put_malformed_jwks_declines_without_leaving_a_slot);
    RUN(keys_cache_put_rejects_null_arguments);
    RUN(keys_cache_lru_evicts_only_the_least_recently_touched_entry);
    RUN(keys_cache_same_host_survives_a_thousand_generations);
    RUN(keys_cache_parent_pool_destruction_frees_all_entries);
}
