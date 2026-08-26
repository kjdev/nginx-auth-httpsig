/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_cache.h - shared-memory storage for dynamically
 * fetched key-directory JWKS documents, keyed by the Signature-Agent
 * host. This covers only what auth_httpsig_key_cache_zone needs to
 * reserve and initialize the zone; node lookup/store belongs to the
 * fetch path that consumes this cache.
 */

#ifndef NGX_AUTH_HTTPSIG_CACHE_H
#define NGX_AUTH_HTTPSIG_CACHE_H


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
} ngx_auth_httpsig_cache_sh_t;

typedef struct {
    ngx_rbtree_node_t  node;
    ngx_str_t          host;   /* immutable once allocated; stored right
                                * after this struct in the same slab
                                * allocation */
    ngx_str_t          jwks;   /* separate slab allocation; replaced
                                * wholesale on each successful fetch */
    time_t             expires_at;
    time_t             fetching_since; /* lets another worker reclaim a
                                        * fetching flag stranded by a
                                        * worker that died mid-fetch */
    unsigned           fetching:1;
} ngx_auth_httpsig_cache_node_t;

typedef struct {
    ngx_auth_httpsig_cache_sh_t *sh;
    ngx_slab_pool_t             *shpool;
} ngx_auth_httpsig_cache_ctx_t;

typedef enum {
    NGX_AUTH_HTTPSIG_CACHE_HIT = 0,   /* a valid jwks was copied into *jwks */
    NGX_AUTH_HTTPSIG_CACHE_CLAIMED,   /* caller now holds the fetch right */
    NGX_AUTH_HTTPSIG_CACHE_BUSY,      /* another worker is fetching */
    NGX_AUTH_HTTPSIG_CACHE_NEGATIVE   /* the last fetch failed; too soon
                                       * to retry */
} ngx_auth_httpsig_cache_status_t;


/*
 * ngx_shm_zone_t.init callback for auth_httpsig_key_cache_zone. Mirrors
 * ngx_http_limit_req_module's init_zone: on reload, `data` carries the
 * previous cycle's ctx, so the existing rbtree is reattached rather than
 * re-initialized. A fresh ngx_slab_alloc()/ngx_rbtree_init() here would
 * strand the previous cycle's nodes while other workers are still
 * walking the old tree, corrupting it out from under them.
 */
ngx_int_t ngx_auth_httpsig_cache_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);

/*
 * Looks up `host`'s cached key-directory JWKS, or claims the right to
 * fetch it if no other worker currently holds that right.
 *
 * Return value: NGX_OK with `*status` set, or NGX_ERROR (a required
 * argument is NULL, or `pool` allocation failed while copying a hit).
 *
 *   NGX_AUTH_HTTPSIG_CACHE_HIT       `*jwks` holds a copy of the cached
 *                                    document, allocated from `pool`.
 *   NGX_AUTH_HTTPSIG_CACHE_CLAIMED   the caller now holds the fetch
 *                                    right for `host` and must eventually
 *                                    call _store() or _release().
 *   NGX_AUTH_HTTPSIG_CACHE_BUSY      another worker holds the fetch
 *                                    right; try again later.
 *   NGX_AUTH_HTTPSIG_CACHE_NEGATIVE  the last fetch failed too recently
 *                                    to retry.
 */
ngx_int_t ngx_auth_httpsig_cache_lookup(ngx_auth_httpsig_cache_ctx_t *ctx,
    ngx_pool_t *pool, const ngx_str_t *host, time_t now, ngx_str_t *jwks,
    ngx_auth_httpsig_cache_status_t *status);

/*
 * Records a successful fetch for `host` and releases the fetch right.
 * `jwks` is copied into the shared zone, replacing any previous value.
 */
ngx_int_t ngx_auth_httpsig_cache_store(ngx_auth_httpsig_cache_ctx_t *ctx,
    const ngx_str_t *host, const ngx_str_t *jwks, time_t expires_at);

/*
 * Releases `host`'s fetch right after a failed fetch, without touching
 * any previously cached jwks (ADR 0015: keep serving a stale key set
 * across a failed refetch). `retry_at` becomes the new expiry, so a
 * lookup before then reports NGX_AUTH_HTTPSIG_CACHE_NEGATIVE if there is
 * no prior jwks, or NGX_AUTH_HTTPSIG_CACHE_HIT with the stale jwks
 * otherwise.
 */
void ngx_auth_httpsig_cache_release(ngx_auth_httpsig_cache_ctx_t *ctx,
    const ngx_str_t *host, time_t retry_at);


#endif /* NGX_AUTH_HTTPSIG_CACHE_H */
