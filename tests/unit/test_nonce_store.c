/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * test_nonce_store.c - coverage for the SHM nonce store: key generation
 * (NUL-joined, not plain concatenation), TTL derivation, and the
 * SHM rbtree + slab replay check's OK/DECLINED/ABORT/ERROR transitions.
 * The Redis backend is not covered here (NGX_HAVE_AUTH_HTTPSIG_NONCE_REDIS
 * is not defined for the unit build, so that code is not compiled in);
 * it is covered by tests/prove/auth_httpsig_nonce_redis.t instead.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_nonce_store.h"
#include "test.h"


#define TEST_ZONE_NAME  "test-nonce-zone"


static ngx_str_t
str(const char *s)
{
    ngx_str_t v;

    v.data = (u_char *) s;
    v.len = ngx_strlen(v.data);

    return v;
}


static ngx_auth_httpsig_nonce_store_ctx_t *
nonce_store_new(ngx_pool_t *pool, size_t budget, const char *zone_name)
{
    ngx_auth_httpsig_nonce_store_ctx_t *ctx;
    ngx_shm_zone_t *zone;

    ctx = ngx_pcalloc(pool, sizeof(ngx_auth_httpsig_nonce_store_ctx_t));
    zone = ngx_pcalloc(pool, sizeof(ngx_shm_zone_t));

    zone->shm.addr = (u_char *) ngx_stub_slab_create(budget, pool->log);
    zone->shm.exists = 0;
    zone->shm.name = str(zone_name);
    zone->data = ctx;

    if (ngx_auth_httpsig_nonce_store_init_zone(zone, NULL) != NGX_OK) {
        return NULL;
    }

    return ctx;
}


static void
nonce_store_free(ngx_auth_httpsig_nonce_store_ctx_t *ctx)
{
    ngx_stub_slab_destroy(ctx->shpool);
}


/*
 * Mirrors the log_ctx sizing in ngx_auth_httpsig_nonce_store_init_zone(),
 * so a budget built from this leaves exactly one entry's worth of room --
 * no slack that would hide a broken fail-open path.
 */
static size_t
nonce_store_zone_overhead(const char *zone_name)
{
    return sizeof(ngx_auth_httpsig_nonce_store_sh_t)
           + sizeof(" in auth_httpsig nonce store zone \"\"")
           + ngx_strlen((u_char *) zone_name);
}


TEST(nonce_store_key_has_expected_prefix_and_length)
{
    ngx_str_t host, keyid, nonce, key;

    host = str("bot.example.com");
    keyid = str("keyid123");
    nonce = str("nonceABC");

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_key(pool, &host, &keyid, &nonce, &key));

    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_NONCE_KEY_PREFIX_LEN + host.len + 1
                      + keyid.len + 1 + nonce.len,
                  key.len);
    ASSERT(ngx_memcmp(key.data, NGX_AUTH_HTTPSIG_NONCE_KEY_PREFIX,
                      NGX_AUTH_HTTPSIG_NONCE_KEY_PREFIX_LEN) == 0);
    ASSERT(key.data[NGX_AUTH_HTTPSIG_NONCE_KEY_PREFIX_LEN + host.len]
           == '\0');
    ASSERT(key.data[NGX_AUTH_HTTPSIG_NONCE_KEY_PREFIX_LEN + host.len + 1
                     + keyid.len]
           == '\0');

    return 0;
}


TEST(nonce_store_key_uses_nul_separator_not_concatenation)
{
    ngx_str_t host_a, keyid_a, host_b, keyid_b, nonce, key_a, key_b;

    /* "a"+"bc" and "ab"+"c" concatenate to the same bytes ("abc"); the
     * NUL separator must keep the two keys distinct. */
    host_a = str("a");
    keyid_a = str("bc");
    host_b = str("ab");
    keyid_b = str("c");
    nonce = str("n");

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_key(pool, &host_a, &keyid_a, &nonce,
            &key_a));
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_key(pool, &host_b, &keyid_b, &nonce,
            &key_b));

    ASSERT_EQ_INT(key_a.len, key_b.len);
    ASSERT(ngx_memcmp(key_a.data, key_b.data, key_a.len) != 0);

    return 0;
}


TEST(nonce_store_key_rejects_null_args)
{
    ngx_str_t host, keyid, nonce, key;

    host = str("h");
    keyid = str("k");
    nonce = str("n");

    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_nonce_store_key(NULL, &host, &keyid, &nonce, &key));
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_nonce_store_key(pool, NULL, &keyid, &nonce, &key));
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_nonce_store_key(pool, &host, NULL, &nonce, &key));
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_nonce_store_key(pool, &host, &keyid, NULL, &key));
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_nonce_store_key(pool, &host, &keyid, &nonce, NULL));

    return 0;
}


TEST(nonce_store_ttl_computes_expires_plus_skew_minus_now)
{
    ASSERT_EQ_INT(50, ngx_auth_httpsig_nonce_store_ttl(1000, 20, 970));
    return 0;
}


TEST(nonce_store_ttl_floors_zero_and_negative_to_one)
{
    /* now == expires + max_skew: profile_verify()'s time window accepts
     * this instant, so the store must still get a positive TTL. */
    ASSERT_EQ_INT(1, ngx_auth_httpsig_nonce_store_ttl(1000, 20, 1020));

    /* now well past expires + max_skew. */
    ASSERT_EQ_INT(1, ngx_auth_httpsig_nonce_store_ttl(1000, 0, 5000));

    return 0;
}


TEST(nonce_store_shm_check_ok_on_fresh_key)
{
    ngx_auth_httpsig_nonce_store_ctx_t *ctx;
    ngx_str_t key;

    key = str("auth_httpsig:nonce:fresh");

    ctx = nonce_store_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key, 60, 1000, NULL));

    nonce_store_free(ctx);
    return 0;
}


TEST(nonce_store_shm_check_declined_on_live_replay)
{
    ngx_auth_httpsig_nonce_store_ctx_t *ctx;
    ngx_str_t key;

    key = str("auth_httpsig:nonce:replay");

    ctx = nonce_store_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key, 60, 1000, NULL));

    /* Still within [1000, 1060): the first record is live, so this is a
     * replay. */
    ASSERT_EQ_INT(NGX_DECLINED,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key, 60, 1010, NULL));

    nonce_store_free(ctx);
    return 0;
}


TEST(nonce_store_shm_check_declined_at_exact_expiry_boundary)
{
    ngx_auth_httpsig_nonce_store_ctx_t *ctx;
    ngx_str_t key;

    key = str("auth_httpsig:nonce:boundary-live");

    ctx = nonce_store_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key, 60, 1000, NULL));

    /* now (1060) == expires_at (1000 + 60) exactly: profile_verify()'s
     * time window still accepts this instant, so the record must still
     * read as a replay ("<= expires_at" reads as live, per the ">="
     * check in ngx_auth_httpsig_nonce_store_shm_check()). */
    ASSERT_EQ_INT(NGX_DECLINED,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key, 60, 1060, NULL));

    nonce_store_free(ctx);
    return 0;
}


TEST(nonce_store_shm_check_ok_one_second_past_expiry_boundary)
{
    ngx_auth_httpsig_nonce_store_ctx_t *ctx;
    ngx_str_t key;

    key = str("auth_httpsig:nonce:boundary-expired");

    ctx = nonce_store_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key, 60, 1000, NULL));

    /* now (1061) is exactly one second past expires_at (1060): the very
     * first instant the record must read as expired. */
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key, 60, 1061, NULL));

    nonce_store_free(ctx);
    return 0;
}


TEST(nonce_store_shm_check_ok_on_expired_reuse)
{
    ngx_auth_httpsig_nonce_store_ctx_t *ctx;
    ngx_str_t key;

    key = str("auth_httpsig:nonce:expired-reuse");

    ctx = nonce_store_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key, 10, 1000, NULL));

    /* now (1015) is past the first record's expiry (1010): not a replay,
     * the existing slab allocation is reused in place. */
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key, 10, 1015, NULL));

    /* The reused record is live again under its new expiry (1025). */
    ASSERT_EQ_INT(NGX_DECLINED,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key, 10, 1016, NULL));

    nonce_store_free(ctx);
    return 0;
}


TEST(nonce_store_shm_check_aborts_when_zone_is_full)
{
    ngx_auth_httpsig_nonce_store_ctx_t *ctx;
    ngx_str_t key_a, key_b;
    size_t budget;

    key_a = str("auth_httpsig:nonce:aaaaaaaa");
    key_b = str("auth_httpsig:nonce:bbbbbbbb");
    ASSERT_EQ_INT(key_a.len, key_b.len);

    /* Room for exactly one node, so the second insert has nowhere to go
     * and must fail open (NGX_ABORT) rather than evict a live node. */
    budget = nonce_store_zone_overhead(TEST_ZONE_NAME)
             + sizeof(ngx_auth_httpsig_nonce_store_node_t) + key_a.len;

    ctx = nonce_store_new(pool, budget, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key_a, 60, 1000, NULL));
    ASSERT_EQ_INT(NGX_ABORT,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key_b, 60, 1000, NULL));

    nonce_store_free(ctx);
    return 0;
}


TEST(nonce_store_shm_check_recovers_after_expiry_when_zone_was_full)
{
    ngx_auth_httpsig_nonce_store_ctx_t *ctx;
    ngx_str_t key_a, key_b, key_c;
    size_t budget;

    key_a = str("auth_httpsig:nonce:aaaaaaaa");
    key_b = str("auth_httpsig:nonce:bbbbbbbb");
    key_c = str("auth_httpsig:nonce:cccccccc");

    budget = nonce_store_zone_overhead(TEST_ZONE_NAME)
             + sizeof(ngx_auth_httpsig_nonce_store_node_t) + key_a.len;

    ctx = nonce_store_new(pool, budget, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key_a, 60, 1000, NULL));

    /* expires_at == now is still live: nothing to reclaim yet. */
    ASSERT_EQ_INT(NGX_ABORT,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key_b, 60, 1060, NULL));

    /* One second later key_a has expired and its slot is reclaimed, even
     * though key_a itself is never looked up again. */
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key_b, 60, 1061, NULL));
    ASSERT_EQ_INT(NGX_DECLINED,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key_b, 60, 1062, NULL));

    /* The recovered slot is now held by a live node again. */
    ASSERT_EQ_INT(NGX_ABORT,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key_c, 60, 1062, NULL));

    nonce_store_free(ctx);
    return 0;
}


TEST(nonce_store_shm_check_reclaim_stops_at_live_head)
{
    ngx_auth_httpsig_nonce_store_ctx_t *ctx;
    ngx_str_t key_a, key_b, key_c, key_d;
    size_t budget;

    key_a = str("auth_httpsig:nonce:aaaaaaaa");
    key_b = str("auth_httpsig:nonce:bbbbbbbb");
    key_c = str("auth_httpsig:nonce:cccccccc");
    key_d = str("auth_httpsig:nonce:dddddddd");

    budget = nonce_store_zone_overhead(TEST_ZONE_NAME)
             + 2 * (sizeof(ngx_auth_httpsig_nonce_store_node_t) + key_a.len);

    ctx = nonce_store_new(pool, budget, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    /* key_a (long-lived) heads the queue; key_b (short-lived) is behind it. */
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key_a, 100, 1000, NULL));
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key_b, 10, 1000, NULL));

    /* key_b has expired but sits behind a live head, so it is not reclaimed
     * yet and the zone still reads as full. */
    ASSERT_EQ_INT(NGX_ABORT,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key_c, 10, 1011, NULL));

    /* Once the head expires, both are reclaimed. */
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key_c, 10, 1101, NULL));
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key_d, 10, 1101, NULL));

    nonce_store_free(ctx);
    return 0;
}


TEST(nonce_store_shm_check_expired_reuse_moves_node_to_queue_tail)
{
    ngx_auth_httpsig_nonce_store_ctx_t *ctx;
    ngx_str_t key_a, key_b, key_c;
    size_t budget;

    key_a = str("auth_httpsig:nonce:aaaaaaaa");
    key_b = str("auth_httpsig:nonce:bbbbbbbb");
    key_c = str("auth_httpsig:nonce:cccccccc");

    budget = nonce_store_zone_overhead(TEST_ZONE_NAME)
             + 2 * (sizeof(ngx_auth_httpsig_nonce_store_node_t) + key_a.len);

    ctx = nonce_store_new(pool, budget, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key_a, 10, 1000, NULL));
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key_b, 100, 1000, NULL));

    /* key_a expired and is reused with a long TTL; it must move behind
     * key_b, otherwise the head would be a live node with a later one
     * expired behind it. */
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key_a, 200, 1011, NULL));

    /* Head is now key_b (expires 1100); at 1101 it is reclaimed. */
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key_c, 10, 1101, NULL));

    /* key_a (expires 1211) is still live. */
    ASSERT_EQ_INT(NGX_DECLINED,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key_a, 10, 1101, NULL));

    nonce_store_free(ctx);
    return 0;
}


TEST(nonce_store_shm_check_rejects_bad_args)
{
    ngx_auth_httpsig_nonce_store_ctx_t *ctx;
    ngx_str_t key;

    key = str("auth_httpsig:nonce:badargs");

    ctx = nonce_store_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_nonce_store_shm_check(NULL, &key, 60, 1000, NULL));
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, NULL, 60, 1000, NULL));
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key, 0, 1000, NULL));
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_nonce_store_shm_check(ctx, &key, -1, 1000, NULL));

    nonce_store_free(ctx);
    return 0;
}


TEST_SUITE(nonce_store)
{
    RUN(nonce_store_key_has_expected_prefix_and_length);
    RUN(nonce_store_key_uses_nul_separator_not_concatenation);
    RUN(nonce_store_key_rejects_null_args);
    RUN(nonce_store_ttl_computes_expires_plus_skew_minus_now);
    RUN(nonce_store_ttl_floors_zero_and_negative_to_one);
    RUN(nonce_store_shm_check_ok_on_fresh_key);
    RUN(nonce_store_shm_check_declined_on_live_replay);
    RUN(nonce_store_shm_check_declined_at_exact_expiry_boundary);
    RUN(nonce_store_shm_check_ok_one_second_past_expiry_boundary);
    RUN(nonce_store_shm_check_ok_on_expired_reuse);
    RUN(nonce_store_shm_check_aborts_when_zone_is_full);
    RUN(nonce_store_shm_check_recovers_after_expiry_when_zone_was_full);
    RUN(nonce_store_shm_check_reclaim_stops_at_live_head);
    RUN(nonce_store_shm_check_expired_reuse_moves_node_to_queue_tail);
    RUN(nonce_store_shm_check_rejects_bad_args);
}
