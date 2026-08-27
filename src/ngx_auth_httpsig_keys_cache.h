/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_keys_cache.h - worker-local cache of parsed key
 * directory JWKS documents, keyed by host and the SHM cache's
 * zone-wide generation number (ngx_auth_httpsig_cache.h). This exists
 * so that a worker does not reparse the same JWKS document -- and
 * re-derive every EVP_PKEY in it -- on every request once the SHM
 * cache has already resolved the fetch for that host.
 *
 * A generation mismatch (including a host the cache has never seen)
 * is reported the same way as an outright miss: the caller re-parses
 * from the raw bytes and _put()s the result, which naturally replaces
 * any stale entry for that host. There is no separate invalidation
 * path.
 */

#ifndef NGX_AUTH_HTTPSIG_KEYS_CACHE_H
#define NGX_AUTH_HTTPSIG_KEYS_CACHE_H


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_keys.h"


/*
 * The set of hosts a worker will ever look up is bounded by the
 * trusted-agent allowlist (ADR 0013), which operators size in the
 * tens of entries at most; a fixed array with linear search is
 * simpler than a tree and cheap enough at this scale.
 */
#define NGX_AUTH_HTTPSIG_MAX_KEYS_CACHE_ENTRIES  16


typedef struct ngx_auth_httpsig_keys_cache_s ngx_auth_httpsig_keys_cache_t;


/*
 * Creates an empty cache. `pool` owns the cache: a cleanup handler
 * registered on it destroys every entry's own pool (see
 * ngx_auth_httpsig_keys_cache_put()) when `pool` is destroyed, so the
 * caller does not need an explicit teardown call.
 *
 * Returns NULL if `pool` is NULL or allocation fails.
 */
ngx_auth_httpsig_keys_cache_t *ngx_auth_httpsig_keys_cache_create(
    ngx_pool_t *pool);

/*
 * Looks up the keyset previously _put() for `host` at exactly
 * `generation`. Returns NULL on a miss (no entry for `host`, or its
 * stored generation differs from `generation`) or if any argument is
 * invalid, including `generation == 0` -- the SHM cache never reports
 * generation 0 for a successful store, so a caller passing it is a
 * bug, not a legitimate lookup.
 *
 * The returned pointer is owned by the cache and remains valid only
 * until the next _put() for the same host evicts it, or the cache
 * evicts it under LRU pressure; the caller must not retain it past
 * the synchronous call chain that requested it (see the .c file's
 * module-level comment for why this is safe in practice).
 */
ngx_auth_httpsig_keys_t *ngx_auth_httpsig_keys_cache_get(
    ngx_auth_httpsig_keys_cache_t *kc, const ngx_str_t *host,
    ngx_uint_t generation);

/*
 * Parses `jwks` and stores it for `host` at `generation`, evicting any
 * existing entry for `host` first regardless of its generation. If
 * the cache has no free slot and `host` has no existing entry, the
 * least-recently-touched entry is evicted to make room.
 *
 * `log` is used only for the NGX_LOG_WARN logged on a parse failure;
 * it may be a request-scoped log, since it is used synchronously
 * within this call and never retained. The entry's own pool -- which
 * outlives any single request -- always logs through ngx_cycle->log.
 *
 * Return value:
 *   NGX_OK        `*keys` (if non-NULL) receives the parsed keyset,
 *                 same pointer as a subsequent matching _get() would
 *                 return.
 *   NGX_DECLINED  `jwks` failed to parse (reported at NGX_LOG_WARN via
 *                 `log`); no cache slot is touched.
 *   NGX_ERROR     a required argument is NULL, `generation == 0`, or
 *                 pool allocation failed.
 */
ngx_int_t ngx_auth_httpsig_keys_cache_put(ngx_auth_httpsig_keys_cache_t *kc,
    const ngx_str_t *host, const ngx_str_t *jwks, ngx_uint_t generation,
    ngx_log_t *log, ngx_auth_httpsig_keys_t **keys);


#endif /* NGX_AUTH_HTTPSIG_KEYS_CACHE_H */
