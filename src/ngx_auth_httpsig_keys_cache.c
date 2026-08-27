/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_keys_cache.c - see the header for the cache's
 * purpose and API contract.
 *
 * Memory: each entry owns a dedicated ngx_pool_t that holds its host
 * copy and its parsed ngx_auth_httpsig_keys_t (including every
 * EVP_PKEY nxe_jwx allocated while parsing). Replacing or evicting an
 * entry destroys that pool outright, so a worker's memory for this
 * cache never grows past NGX_AUTH_HTTPSIG_MAX_KEYS_CACHE_ENTRIES
 * pools regardless of how many generations pass through it. Parsing
 * straight into a shared long-lived pool would have no equivalent way
 * to reclaim the previous generation's allocations: nginx pools free
 * as a whole, not per-object.
 *
 * Use-after-free safety: this cache hands out a borrowed pointer from
 * ngx_auth_httpsig_keys_cache_get()/_put() with no refcount. That is
 * only safe because every caller in this module uses the pointer
 * entirely within ngx_http_auth_httpsig_module.c's evaluate(), which
 * is synchronous end to end (no subrequest, no I/O yield) and never
 * stores the pointer anywhere that outlives that call. Do not add a
 * caller that retains a keyset pointer across a yield point; doing so
 * reintroduces the eviction-during-upstream-round-trip use-after-free
 * this cache was designed to avoid.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_keys_cache.h"


/*
 * Small relative to NGX_AUTH_HTTPSIG_MAX_JWKS_SIZE: a JWKS document's
 * parsed form (EVP_PKEY per key, thumbprint index) is far smaller
 * than its JSON source, and nginx pools grow past this via their
 * large-allocation path when a single request needs more.
 */
#define NGX_AUTH_HTTPSIG_KEYS_CACHE_POOL_SIZE  4096


typedef struct {
    ngx_pool_t               *pool;        /* NULL: slot is free */
    ngx_str_t                 host;        /* copied into pool */
    ngx_uint_t                generation;
    ngx_auth_httpsig_keys_t  *keys;
    ngx_uint_t                touched;
} ngx_auth_httpsig_keys_cache_slot_t;

struct ngx_auth_httpsig_keys_cache_s {
    ngx_auth_httpsig_keys_cache_slot_t
        slots[NGX_AUTH_HTTPSIG_MAX_KEYS_CACHE_ENTRIES];
    ngx_uint_t  clock;    /* incremented on every touch; the slot with
                           * the smallest `touched` is the LRU victim */
};


static ngx_auth_httpsig_keys_cache_slot_t *ngx_auth_httpsig_keys_cache_find(
    ngx_auth_httpsig_keys_cache_t *kc, const ngx_str_t *host);
static ngx_auth_httpsig_keys_cache_slot_t *
    ngx_auth_httpsig_keys_cache_slot_for(ngx_auth_httpsig_keys_cache_t *kc,
    const ngx_str_t *host);
static void ngx_auth_httpsig_keys_cache_evict(
    ngx_auth_httpsig_keys_cache_slot_t *slot);
static void ngx_auth_httpsig_keys_cache_cleanup(void *data);


ngx_auth_httpsig_keys_cache_t *
ngx_auth_httpsig_keys_cache_create(ngx_pool_t *pool)
{
    ngx_auth_httpsig_keys_cache_t *kc;
    ngx_pool_cleanup_t *cln;

    if (pool == NULL) {
        return NULL;
    }

    kc = ngx_pcalloc(pool, sizeof(ngx_auth_httpsig_keys_cache_t));
    if (kc == NULL) {
        return NULL;
    }

    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_auth_httpsig_keys_cache_cleanup;
    cln->data = kc;

    return kc;
}


ngx_auth_httpsig_keys_t *
ngx_auth_httpsig_keys_cache_get(ngx_auth_httpsig_keys_cache_t *kc,
    const ngx_str_t *host, ngx_uint_t generation)
{
    ngx_auth_httpsig_keys_cache_slot_t *slot;

    if (kc == NULL || host == NULL || generation == 0) {
        return NULL;
    }

    slot = ngx_auth_httpsig_keys_cache_find(kc, host);
    if (slot == NULL || slot->generation != generation) {
        return NULL;
    }

    slot->touched = ++kc->clock;

    return slot->keys;
}


ngx_int_t
ngx_auth_httpsig_keys_cache_put(ngx_auth_httpsig_keys_cache_t *kc,
    const ngx_str_t *host, const ngx_str_t *jwks, ngx_uint_t generation,
    ngx_log_t *log, ngx_auth_httpsig_keys_t **keys)
{
    ngx_int_t rc;
    ngx_log_t *saved_log;
    ngx_str_t host_copy;
    ngx_pool_t *entry_pool;
    ngx_auth_httpsig_keys_t *parsed;
    ngx_auth_httpsig_keys_cache_slot_t *slot;

    if (kc == NULL || host == NULL || jwks == NULL || generation == 0
        || log == NULL)
    {
        return NGX_ERROR;
    }

    entry_pool = ngx_create_pool(NGX_AUTH_HTTPSIG_KEYS_CACHE_POOL_SIZE,
                                  ngx_cycle->log);
    if (entry_pool == NULL) {
        return NGX_ERROR;
    }

    /* `log` is valid only for the duration of this call (it may be a
     * request log); the pool itself outlives any single request, so
     * its log is restored to ngx_cycle->log before returning. */
    saved_log = entry_pool->log;
    entry_pool->log = log;

    rc = ngx_auth_httpsig_keys_load_jwks(entry_pool, jwks, host,
                                          NGX_LOG_WARN, &parsed);

    entry_pool->log = saved_log;

    if (rc != NGX_OK) {
        ngx_destroy_pool(entry_pool);
        return NGX_DECLINED;
    }

    host_copy.len = host->len;
    host_copy.data = ngx_pnalloc(entry_pool, host->len);
    if (host_copy.data == NULL) {
        ngx_destroy_pool(entry_pool);
        return NGX_ERROR;
    }

    ngx_memcpy(host_copy.data, host->data, host->len);

    slot = ngx_auth_httpsig_keys_cache_slot_for(kc, host);

    slot->pool = entry_pool;
    slot->host = host_copy;
    slot->generation = generation;
    slot->keys = parsed;
    slot->touched = ++kc->clock;

    if (keys != NULL) {
        *keys = parsed;
    }

    return NGX_OK;
}


static ngx_auth_httpsig_keys_cache_slot_t *
ngx_auth_httpsig_keys_cache_find(ngx_auth_httpsig_keys_cache_t *kc,
    const ngx_str_t *host)
{
    ngx_uint_t i;
    ngx_auth_httpsig_keys_cache_slot_t *slot;

    for (i = 0; i < NGX_AUTH_HTTPSIG_MAX_KEYS_CACHE_ENTRIES; i++) {
        slot = &kc->slots[i];

        if (slot->pool != NULL
            && slot->host.len == host->len
            && ngx_memcmp(slot->host.data, host->data, host->len) == 0)
        {
            return slot;
        }
    }

    return NULL;
}


/*
 * Picks the slot a new entry for `host` should occupy: an existing
 * entry for the same host (evicted first, regardless of generation),
 * else a free slot, else the least-recently-touched entry. The
 * returned slot always has pool == NULL.
 */
static ngx_auth_httpsig_keys_cache_slot_t *
ngx_auth_httpsig_keys_cache_slot_for(ngx_auth_httpsig_keys_cache_t *kc,
    const ngx_str_t *host)
{
    ngx_uint_t i;
    ngx_auth_httpsig_keys_cache_slot_t *slot, *victim;

    slot = ngx_auth_httpsig_keys_cache_find(kc, host);
    if (slot != NULL) {
        ngx_auth_httpsig_keys_cache_evict(slot);
        return slot;
    }

    victim = NULL;

    for (i = 0; i < NGX_AUTH_HTTPSIG_MAX_KEYS_CACHE_ENTRIES; i++) {
        slot = &kc->slots[i];

        if (slot->pool == NULL) {
            return slot;
        }

        if (victim == NULL || slot->touched < victim->touched) {
            victim = slot;
        }
    }

    ngx_auth_httpsig_keys_cache_evict(victim);

    return victim;
}


static void
ngx_auth_httpsig_keys_cache_evict(ngx_auth_httpsig_keys_cache_slot_t *slot)
{
    ngx_destroy_pool(slot->pool);

    slot->pool = NULL;
    slot->keys = NULL;
    ngx_str_null(&slot->host);
}


static void
ngx_auth_httpsig_keys_cache_cleanup(void *data)
{
    ngx_uint_t i;
    ngx_auth_httpsig_keys_cache_t *kc = data;

    for (i = 0; i < NGX_AUTH_HTTPSIG_MAX_KEYS_CACHE_ENTRIES; i++) {
        if (kc->slots[i].pool != NULL) {
            ngx_destroy_pool(kc->slots[i].pool);
        }
    }
}
