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
    ngx_str_t          host;
    ngx_str_t          jwks;
    time_t             expires_at;
    unsigned           fetching:1;
} ngx_auth_httpsig_cache_node_t;

typedef struct {
    ngx_auth_httpsig_cache_sh_t *sh;
    ngx_slab_pool_t             *shpool;
} ngx_auth_httpsig_cache_ctx_t;


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


#endif /* NGX_AUTH_HTTPSIG_CACHE_H */
