/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * test_cache.c - coverage for the SHM key-directory cache: claim/hit/busy
 * status transitions, stale-jwks retention across a failed refetch,
 * eviction under slab memory pressure, and the zone-wide generation
 * counter handed out on each successful store.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_cache.h"
#include "test.h"


#define TEST_ZONE_NAME  "test-zone"


static ngx_str_t
str(const char *s)
{
    ngx_str_t v;

    v.data = (u_char *) s;
    v.len = ngx_strlen(v.data);

    return v;
}


static ngx_auth_httpsig_cache_ctx_t *
cache_new(ngx_pool_t *pool, size_t budget, const char *zone_name)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_shm_zone_t *zone;

    ctx = ngx_pcalloc(pool, sizeof(ngx_auth_httpsig_cache_ctx_t));
    zone = ngx_pcalloc(pool, sizeof(ngx_shm_zone_t));

    zone->shm.addr = (u_char *) ngx_stub_slab_create(budget, pool->log);
    zone->shm.exists = 0;
    zone->shm.name = str(zone_name);
    zone->data = ctx;

    if (ngx_auth_httpsig_cache_init_zone(zone, NULL) != NGX_OK) {
        return NULL;
    }

    return ctx;
}


static void
cache_free(ngx_auth_httpsig_cache_ctx_t *ctx)
{
    ngx_stub_slab_destroy(ctx->shpool);
}


/*
 * Mirrors the log_ctx sizing in ngx_auth_httpsig_cache_init_zone(), so a
 * budget built from this leaves exactly one entry's worth of room -- no
 * slack that would hide a broken eviction path.
 */
static size_t
cache_zone_overhead(const char *zone_name)
{
    return sizeof(ngx_auth_httpsig_cache_sh_t)
           + sizeof(" in auth_httpsig key cache zone \"\"")
           + ngx_strlen((u_char *) zone_name);
}


TEST(cache_lookup_claims_on_miss)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host, out;
    ngx_auth_httpsig_cache_status_t status;

    host = str("claim.example.com");

    ctx = cache_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1000, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_CLAIMED, status);

    cache_free(ctx);
    return 0;
}


TEST(cache_lookup_reports_busy_while_fetching)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host, out;
    ngx_auth_httpsig_cache_status_t status;

    host = str("busy.example.com");

    ctx = cache_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1000, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_CLAIMED, status);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1010, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_BUSY, status);

    cache_free(ctx);
    return 0;
}


TEST(cache_lookup_reclaims_stranded_fetch)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host, out;
    ngx_auth_httpsig_cache_status_t status;

    host = str("stranded.example.com");

    ctx = cache_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1000, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_CLAIMED, status);

    /* fetching_since=1000, timeout is 30s: 31s later the fetch right is
     * up for grabs again instead of staying BUSY forever. */
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1031, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_CLAIMED, status);

    cache_free(ctx);
    return 0;
}


TEST(cache_store_then_lookup_hits)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host, jwks, out;
    ngx_auth_httpsig_cache_status_t status;

    host = str("hit.example.com");
    jwks = str("{\"keys\":[\"hit\"]}");

    ctx = cache_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1000, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_CLAIMED, status);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host, &jwks, 2000, NULL));

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1500, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_HIT, status);
    ASSERT_STR_EQ(out, "{\"keys\":[\"hit\"]}");

    cache_free(ctx);
    return 0;
}


TEST(cache_lookup_refetches_after_expiry)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host, jwks, out;
    ngx_auth_httpsig_cache_status_t status;

    host = str("expiry.example.com");
    jwks = str("{\"keys\":[\"stale\"]}");

    ctx = cache_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host, &jwks, 100, NULL));

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 200, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_CLAIMED, status);

    cache_free(ctx);
    return 0;
}


TEST(cache_release_reports_negative_without_prior_jwks)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host, out;
    ngx_auth_httpsig_cache_status_t status;

    host = str("negative.example.com");

    ctx = cache_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1000, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_CLAIMED, status);

    ngx_auth_httpsig_cache_release(ctx, &host, 2000);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1500, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_NEGATIVE, status);

    cache_free(ctx);
    return 0;
}


TEST(cache_release_keeps_stale_jwks)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host, jwks, out;
    ngx_auth_httpsig_cache_status_t status;

    host = str("stale.example.com");
    jwks = str("{\"keys\":[\"original\"]}");

    ctx = cache_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host, &jwks, 1100, NULL));

    /* Expiry forces a refetch claim, and that refetch fails -- release()
     * must not touch the still-cached jwks payload (ADR 0015: serve
     * stale on a failed refresh). */
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1150, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_CLAIMED, status);

    ngx_auth_httpsig_cache_release(ctx, &host, 1300);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1200, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_HIT, status);
    ASSERT_STR_EQ(out, "{\"keys\":[\"original\"]}");

    cache_free(ctx);
    return 0;
}


TEST(cache_store_replaces_previous_jwks)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host, jwks1, jwks2, out;
    ngx_auth_httpsig_cache_status_t status;
    size_t used_after_first, used_after_second;

    host = str("replace.example.com");
    jwks1 = str("AAAA");
    jwks2 = str("BBBBBBBB");

    ctx = cache_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host, &jwks1, 5000, NULL));
    used_after_first = ctx->shpool->used;

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host, &jwks2, 6000, NULL));
    used_after_second = ctx->shpool->used;

    /* The old jwks allocation must be freed before/around the new one,
     * not left dangling alongside it. */
    ASSERT_EQ_INT((long long) (jwks2.len - jwks1.len),
        (long long) (used_after_second - used_after_first));

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 5500, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_HIT, status);
    ASSERT_STR_EQ(out, "BBBBBBBB");

    cache_free(ctx);
    return 0;
}


TEST(cache_store_evicts_expired_node_under_pressure)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host_a, host_b, jwks_a, jwks_b, out;
    ngx_auth_httpsig_cache_status_t status;
    size_t budget;

    host_a = str("host-a.example.com");
    host_b = str("host-b.example.com");
    jwks_a = str("{\"keys\":[1]}");
    jwks_b = str("{\"keys\":[2]}");

    /* Room for exactly one node+jwks pair (host_a/host_b share the same
     * lengths), so storing host_b forces host_a's expired node out. */
    budget = cache_zone_overhead(TEST_ZONE_NAME)
             + sizeof(ngx_auth_httpsig_cache_node_t) + host_a.len + jwks_a.len;

    ctx = cache_new(pool, budget, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host_a, &jwks_a, 100, NULL));

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host_b, &jwks_b, 100, NULL));

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host_b, 50, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_HIT, status);
    ASSERT_STR_EQ(out, "{\"keys\":[2]}");

    /* host_b's node now holds the entire budget and is not expired as of
     * this lookup's `now`, so re-claiming host_a has nowhere to go: it
     * must fail open (UNAVAILABLE) rather than pretend to hold a fetch
     * right for a node that was never created. */
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host_a, 50, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_UNAVAILABLE, status);

    cache_free(ctx);
    return 0;
}


TEST(cache_does_not_evict_fetching_node)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host_a, host_b, out;
    ngx_auth_httpsig_cache_status_t status;
    size_t budget;

    host_a = str("host-a.example.com");
    host_b = str("host-b.example.com");

    budget = cache_zone_overhead(TEST_ZONE_NAME)
             + sizeof(ngx_auth_httpsig_cache_node_t) + host_a.len;

    ctx = cache_new(pool, budget, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host_a, 1000, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_CLAIMED, status);

    /* host_a's node is fetching, so find_victim must skip it; with no
     * room left, host_b must fail open (UNAVAILABLE) rather than evict
     * an in-flight fetch or falsely claim a fetch right of its own. */
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host_b, 1000, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_UNAVAILABLE, status);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host_a, 1010, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_BUSY, status);

    cache_free(ctx);
    return 0;
}


TEST(cache_tracks_multiple_hosts_independently)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host_a, host_b, jwks_a, jwks_b, out;
    ngx_auth_httpsig_cache_status_t status;

    host_a = str("multi-a.example.com");
    host_b = str("multi-b.example.com");
    jwks_a = str("{\"keys\":[\"a\"]}");
    jwks_b = str("{\"keys\":[\"b\"]}");

    ctx = cache_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host_a, &jwks_a, 5000, NULL));
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host_b, &jwks_b, 5000, NULL));

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host_a, 1000, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_HIT, status);
    ASSERT_STR_EQ(out, "{\"keys\":[\"a\"]}");

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host_b, 1000, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_HIT, status);
    ASSERT_STR_EQ(out, "{\"keys\":[\"b\"]}");

    cache_free(ctx);
    return 0;
}


TEST(cache_lookup_rejects_null_arguments)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host, out;
    ngx_auth_httpsig_cache_status_t status;

    host = str("null.example.com");

    ctx = cache_new(pool, 4096, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_cache_lookup(NULL, pool, &host, 1, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_cache_lookup(ctx, NULL, &host, 1, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_cache_lookup(ctx, pool, NULL, 1, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1, NULL, &status,
            NULL));
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1, &out, NULL,
            NULL));

    /* generation is not a required argument: passing NULL for it must
     * not turn an otherwise-valid call into NGX_ERROR. */
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1, &out, &status,
            NULL));

    cache_free(ctx);
    return 0;
}


TEST(cache_init_zone_reattaches_on_reload)
{
    ngx_auth_httpsig_cache_ctx_t ctx1, ctx2;
    ngx_shm_zone_t zone1, zone2;
    ngx_slab_pool_t *shpool;
    ngx_str_t host, jwks, out;
    ngx_auth_httpsig_cache_status_t status;

    ngx_memzero(&ctx1, sizeof(ctx1));
    ngx_memzero(&ctx2, sizeof(ctx2));
    ngx_memzero(&zone1, sizeof(zone1));
    ngx_memzero(&zone2, sizeof(zone2));

    shpool = ngx_stub_slab_create(65536, pool->log);
    ASSERT(shpool != NULL);

    zone1.shm.addr = (u_char *) shpool;
    zone1.shm.exists = 0;
    zone1.shm.name = str(TEST_ZONE_NAME);
    zone1.data = &ctx1;

    ASSERT_EQ_INT(NGX_OK, ngx_auth_httpsig_cache_init_zone(&zone1, NULL));

    host = str("reload.example.com");
    jwks = str("{\"keys\":[]}");

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(&ctx1, &host, &jwks, 5000, NULL));

    /* A reload hands the module the previous cycle's ctx as `data`; it
     * must reattach to the existing sh/shpool rather than reinitializing
     * the rbtree and losing what's cached. */
    zone2.shm.addr = (u_char *) shpool;
    zone2.shm.exists = 1;
    zone2.shm.name = str(TEST_ZONE_NAME);
    zone2.data = &ctx2;

    ASSERT_EQ_INT(NGX_OK, ngx_auth_httpsig_cache_init_zone(&zone2, &ctx1));

    ASSERT(ctx2.sh == ctx1.sh);
    ASSERT(ctx2.shpool == ctx1.shpool);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(&ctx2, pool, &host, 1000, &out,
            &status, NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_HIT, status);
    ASSERT_STR_EQ(out, "{\"keys\":[]}");

    ngx_stub_slab_destroy(shpool);
    return 0;
}


TEST(cache_store_assigns_nonzero_generation)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host, jwks;
    ngx_uint_t generation;

    host = str("gen-nonzero.example.com");
    jwks = str("{\"keys\":[]}");

    ctx = cache_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    generation = 0;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host, &jwks, 5000, &generation));
    ASSERT(generation != 0);

    cache_free(ctx);
    return 0;
}


TEST(cache_lookup_hit_returns_stored_generation)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host, jwks, out;
    ngx_auth_httpsig_cache_status_t status;
    ngx_uint_t stored_generation, hit_generation;

    host = str("gen-roundtrip.example.com");
    jwks = str("{\"keys\":[]}");

    ctx = cache_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host, &jwks, 5000,
            &stored_generation));
    ASSERT(stored_generation != 0);

    hit_generation = 0;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1000, &out, &status,
            &hit_generation));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_HIT, status);
    ASSERT_EQ_INT((long long) stored_generation, (long long) hit_generation);

    cache_free(ctx);
    return 0;
}


TEST(cache_store_generation_is_monotonic)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host, jwks1, jwks2;
    ngx_uint_t generation1, generation2;

    host = str("gen-monotonic.example.com");
    jwks1 = str("{\"keys\":[1]}");
    jwks2 = str("{\"keys\":[2]}");

    ctx = cache_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host, &jwks1, 5000,
            &generation1));

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host, &jwks2, 6000,
            &generation2));

    ASSERT(generation2 > generation1);

    cache_free(ctx);
    return 0;
}


TEST(cache_store_generation_is_zone_wide)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host_a, host_b, jwks;
    ngx_uint_t gen_a1, gen_b, gen_a2;

    host_a = str("gen-zone-a.example.com");
    host_b = str("gen-zone-b.example.com");
    jwks = str("{\"keys\":[]}");

    ctx = cache_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    /* host_a -> host_b -> host_a must hand out three strictly increasing
     * values: the counter lives on the zone, not on either host's node. */
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host_a, &jwks, 5000, &gen_a1));
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host_b, &jwks, 5000, &gen_b));
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host_a, &jwks, 6000, &gen_a2));

    ASSERT(gen_a1 < gen_b);
    ASSERT(gen_b < gen_a2);

    cache_free(ctx);
    return 0;
}


TEST(cache_lookup_generation_zero_for_non_hit_statuses)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host, host_b, out;
    ngx_auth_httpsig_cache_status_t status;
    ngx_uint_t generation;
    size_t tiny_budget;

    /* CLAIMED: plain miss. */
    host = str("gen-zero-claimed.example.com");
    ctx = cache_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    generation = 42;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1000, &out, &status,
            &generation));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_CLAIMED, status);
    ASSERT_EQ_INT(0, (long long) generation);

    /* BUSY: still fetching. */
    generation = 42;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1010, &out, &status,
            &generation));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_BUSY, status);
    ASSERT_EQ_INT(0, (long long) generation);

    /* NEGATIVE: released without ever having a jwks. */
    ngx_auth_httpsig_cache_release(ctx, &host, 2000);

    generation = 42;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1500, &out, &status,
            &generation));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_NEGATIVE, status);
    ASSERT_EQ_INT(0, (long long) generation);

    cache_free(ctx);

    /* UNAVAILABLE: no room for a node at all. */
    host_b = str("gen-zero-unavailable.example.com");
    tiny_budget = cache_zone_overhead(TEST_ZONE_NAME);

    ctx = cache_new(pool, tiny_budget, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    generation = 42;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host_b, 1000, &out, &status,
            &generation));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_UNAVAILABLE, status);
    ASSERT_EQ_INT(0, (long long) generation);

    cache_free(ctx);
    return 0;
}


TEST(cache_release_does_not_change_generation)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host, jwks, out;
    ngx_auth_httpsig_cache_status_t status;
    ngx_uint_t stored_generation, generation_after_release;

    host = str("gen-release.example.com");
    jwks = str("{\"keys\":[\"kept\"]}");

    ctx = cache_new(pool, 65536, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host, &jwks, 1100,
            &stored_generation));

    /* Expiry forces a refetch claim, but the refetch fails; release()
     * must leave the previously stored generation untouched alongside
     * the stale jwks it keeps. */
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1150, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_CLAIMED, status);

    ngx_auth_httpsig_cache_release(ctx, &host, 1300);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1200, &out, &status,
            &generation_after_release));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_HIT, status);
    ASSERT_EQ_INT((long long) stored_generation,
        (long long) generation_after_release);

    cache_free(ctx);
    return 0;
}


TEST(cache_store_jwks_alloc_failure_reports_zero_generation)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host, jwks;
    ngx_uint_t generation;
    size_t budget;

    host = str("gen-jwks-alloc-fail.example.com");
    jwks = str("{\"keys\":[\"unstoreable\"]}");

    /* Room for the node itself, but nothing left over for the jwks
     * payload: store() must report generation 0 rather than pairing a
     * fresh number with bytes that were never actually written. */
    budget = cache_zone_overhead(TEST_ZONE_NAME)
             + sizeof(ngx_auth_httpsig_cache_node_t) + host.len;

    ctx = cache_new(pool, budget, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    generation = 42;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host, &jwks, 5000, &generation));
    ASSERT_EQ_INT(0, (long long) generation);

    cache_free(ctx);
    return 0;
}


TEST(cache_store_after_eviction_generation_differs_from_evicted_node)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host_a, host_b, jwks_a, jwks_b;
    ngx_uint_t gen_a1, gen_b, gen_a2;
    size_t budget;

    host_a = str("gen-evict-a.example.com");
    host_b = str("gen-evict-b.example.com");
    jwks_a = str("{\"keys\":[1]}");
    jwks_b = str("{\"keys\":[2]}");

    /* Room for exactly one node+jwks pair, so storing host_b evicts
     * host_a's expired node and its slab memory is recycled. */
    budget = cache_zone_overhead(TEST_ZONE_NAME)
             + sizeof(ngx_auth_httpsig_cache_node_t) + host_a.len
             + jwks_a.len;

    ctx = cache_new(pool, budget, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host_a, &jwks_a, 100, &gen_a1));

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host_b, &jwks_b, 5000, &gen_b));

    /* host_b's node reuses host_a's evicted slab memory (ngx_memzero'd
     * back to 0 by alloc_node()), yet its generation must not collide
     * with -- or fall back to -- host_a's original number. A per-node
     * counter would restart at 0 here and hand out gen_a1's successor
     * again; the zone-wide counter must not. */
    ASSERT(gen_b != gen_a1);
    ASSERT(gen_b > gen_a1);

    /* Storing host_a again (evicting host_b's node in turn) must yield
     * yet another new value, not a reuse of gen_a1. */
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_store(ctx, &host_a, &jwks_a, 6000, &gen_a2));
    ASSERT(gen_a2 != gen_a1);
    ASSERT(gen_a2 > gen_b);

    cache_free(ctx);
    return 0;
}


TEST(cache_lookup_node_alloc_failure_reports_unavailable_without_fetching)
{
    ngx_auth_httpsig_cache_ctx_t *ctx;
    ngx_str_t host, out;
    ngx_auth_httpsig_cache_status_t status;
    ngx_uint_t generation;
    size_t budget;

    host = str("no-room.example.com");

    /* No room for even a bare node, so alloc_node() fails on the very
     * first lookup and there is no expired victim to evict either. */
    budget = cache_zone_overhead(TEST_ZONE_NAME);

    ctx = cache_new(pool, budget, TEST_ZONE_NAME);
    ASSERT(ctx != NULL);

    generation = 42;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1000, &out, &status,
            &generation));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_UNAVAILABLE, status);
    ASSERT_EQ_INT(0, (long long) generation);

    /* A repeat lookup must still be UNAVAILABLE, not BUSY: no half-
     * initialized node with `fetching` set was left behind. */
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_cache_lookup(ctx, pool, &host, 1001, &out, &status,
            NULL));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_CACHE_UNAVAILABLE, status);

    cache_free(ctx);
    return 0;
}


TEST_SUITE(cache)
{
    RUN(cache_lookup_claims_on_miss);
    RUN(cache_lookup_reports_busy_while_fetching);
    RUN(cache_lookup_reclaims_stranded_fetch);
    RUN(cache_store_then_lookup_hits);
    RUN(cache_lookup_refetches_after_expiry);
    RUN(cache_release_reports_negative_without_prior_jwks);
    RUN(cache_release_keeps_stale_jwks);
    RUN(cache_store_replaces_previous_jwks);
    RUN(cache_store_evicts_expired_node_under_pressure);
    RUN(cache_does_not_evict_fetching_node);
    RUN(cache_tracks_multiple_hosts_independently);
    RUN(cache_lookup_rejects_null_arguments);
    RUN(cache_init_zone_reattaches_on_reload);
    RUN(cache_store_assigns_nonzero_generation);
    RUN(cache_lookup_hit_returns_stored_generation);
    RUN(cache_store_generation_is_monotonic);
    RUN(cache_store_generation_is_zone_wide);
    RUN(cache_lookup_generation_zero_for_non_hit_statuses);
    RUN(cache_release_does_not_change_generation);
    RUN(cache_store_jwks_alloc_failure_reports_zero_generation);
    RUN(cache_store_after_eviction_generation_differs_from_evicted_node);
    RUN(cache_lookup_node_alloc_failure_reports_unavailable_without_fetching);
}
