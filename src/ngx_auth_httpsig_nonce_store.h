/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_nonce_store.h - shared-memory zone reservation, key/TTL
 * derivation, the SHM rbtree + slab nonce store, and the Redis SET NX EX
 * client for replay-prevention nonce storage (auth_httpsig_nonce_store_zone
 * / auth_httpsig_nonce_store_redis). The SHM backend mirrors
 * ngx_auth_httpsig_cache.c's rbtree + ngx_slab_pool_t structure
 * but with inverted hit semantics (a live node is a replay, not a value to
 * reuse) and no eviction: a full zone fails open instead of evicting an
 * expired node, since nonces are unique per request and an LRU/victim scan
 * would be an O(n) walk under the zone mutex on every request once the
 * zone fills. The Redis backend is carried end to end.
 */

#ifndef NGX_AUTH_HTTPSIG_NONCE_STORE_H
#define NGX_AUTH_HTTPSIG_NONCE_STORE_H


#include <ngx_config.h>
#include <ngx_core.h>

#if (NGX_HAVE_AUTH_HTTPSIG_NONCE_REDIS)
#include <hiredis/hiredis.h>
#endif


/*
 * Fixed upper bound on a signature's nonce length. A signer-controlled
 * value this large is rejected outright rather than truncated or stored
 * unbounded, so an attacker cannot bypass replay detection by sending an
 * oversized nonce that the store silently drops.
 */
#define NGX_AUTH_HTTPSIG_NONCE_MAX_LEN   256

/*
 * Fixed namespace prefix for store keys. This module has no "zone name"
 * of its own to scope by (unlike nginx-keyval's keyval_zone_redis, which
 * has "zone="), so without a prefix a nonce key could collide with
 * unrelated data an operator keeps in the same Redis database.
 */
#define NGX_AUTH_HTTPSIG_NONCE_KEY_PREFIX       "auth_httpsig:nonce:"
#define NGX_AUTH_HTTPSIG_NONCE_KEY_PREFIX_LEN   \
        (sizeof(NGX_AUTH_HTTPSIG_NONCE_KEY_PREFIX) - 1)


/* auth_httpsig_nonce_store_redis connection parameters: vocabulary
 * matches nginx-keyval's keyval_zone_redis, minus "zone=" (this module
 * keeps a single connection, not a named store). */
typedef struct {
    u_char     *hostname;
    ngx_int_t   port;
    ngx_int_t   db;
    time_t      connect_timeout;
    time_t      command_timeout;
    ngx_flag_t  configured;
} ngx_auth_httpsig_nonce_redis_conf_t;

typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_rbtree_t       exp_rbtree; /* the same nodes keyed by expires_at;
                                    * touched only under shpool->mutex.
                                    * Expired nodes are reclaimed from its
                                    * minimum. */
    ngx_rbtree_node_t  exp_sentinel;
    time_t             last_nomem_log; /* zone-wide, touched only under
                                        * shpool->mutex. Throttles the
                                        * exhaustion WARN to once per
                                        * NGX_AUTH_HTTPSIG_NONCE_STORE_NOMEM_LOG_INTERVAL
                                        * seconds instead of once per
                                        * request while the zone is full. */
} ngx_auth_httpsig_nonce_store_sh_t;

typedef struct {
    ngx_rbtree_node_t  node;     /* keyed by the crc32 of nonce_key */
    ngx_rbtree_node_t  exp_node; /* keyed by expires_at */
    ngx_str_t          nonce_key; /* immutable once allocated; stored right
                                   * after this struct in the same slab
                                   * allocation. Named distinctly from
                                   * node.key (the rbtree hash) to keep the
                                   * two from being confused at a call
                                   * site. */
    time_t  expires_at;
} ngx_auth_httpsig_nonce_store_node_t;

typedef struct {
    ngx_auth_httpsig_nonce_store_sh_t *sh;
    ngx_slab_pool_t                   *shpool;
} ngx_auth_httpsig_nonce_store_ctx_t;


/*
 * ngx_shm_zone_t.init callback for auth_httpsig_nonce_store_zone. Mirrors
 * ngx_auth_httpsig_cache_init_zone's reload reattachment: on reload,
 * `data` carries the previous cycle's ctx, so the existing rbtree is
 * reattached rather than re-initialized.
 */
ngx_int_t ngx_auth_httpsig_nonce_store_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);


/*
 * Builds the replay-detection store key for a verified signature:
 * `agent_host`, `keyid` and `nonce` joined with NUL separators behind
 * the fixed namespace prefix. A NUL byte cannot appear in any of the
 * three (agent_host is a URI authority; keyid/nonce are Structured
 * Fields sf-string values), so this join is unambiguous -- plain
 * concatenation could not tell ("a", "bc") apart from ("ab", "c").
 * `key` is allocated from `pool`. Shared by both the Redis and SHM
 * backends so the format is defined once.
 */
ngx_int_t ngx_auth_httpsig_nonce_store_key(ngx_pool_t *pool,
    const ngx_str_t *agent_host, const ngx_str_t *keyid,
    const ngx_str_t *nonce, ngx_str_t *key);

/*
 * Derives the store TTL (seconds) from a verified signature's `expires`
 * and the profile's `max_skew`, evaluated at the same `now` the time-
 * window check itself used. Clamped to at least
 * 1: profile_verify()'s time-window check accepts "now == expires +
 * max_skew" (TTL 0), but ngx_auth_httpsig_nonce_store_shm_check()
 * rejects ttl < 1 as a caller-bug NGX_ERROR, so the floor is a
 * store-validity requirement, not an additional policy bound.
 */
time_t ngx_auth_httpsig_nonce_store_ttl(int64_t expires, time_t max_skew,
    time_t now);

/*
 * Checks and records `key` in the SHM nonce store, expiring at `now +
 * ttl`. Before a new entry is allocated, at most a small fixed number of
 * expired nodes are reclaimed in expires_at order (O(log n) each under the
 * zone lock, independent of the order signers' `expires` arrive in); if the
 * allocation still fails, one more bounded reclaim is attempted before
 * failing open. A live node is never evicted.
 *
 * Return value: same contract as
 * ngx_auth_httpsig_nonce_store_redis_check():
 *
 *   NGX_OK        `key` was not previously recorded (or its prior record
 *                 had already expired) and now is; no replay.
 *   NGX_DECLINED  `key` is already recorded and still live; this is a
 *                 replay. The existing expiry is left untouched (SET NX
 *                 does not refresh a live key's TTL either).
 *   NGX_ABORT     the zone has no room for a new entry even after
 *                 reclaiming expired ones. Caller must fail
 *                 open, not treat this as a replay.
 *   NGX_ERROR     a required argument is invalid; indicates a caller
 *                 bug, never an ordinary runtime condition.
 */
ngx_int_t ngx_auth_httpsig_nonce_store_shm_check(
    ngx_auth_httpsig_nonce_store_ctx_t *ctx, ngx_str_t *key, time_t ttl,
    time_t now, ngx_log_t *log);

#if (NGX_HAVE_AUTH_HTTPSIG_NONCE_REDIS)

/*
 * Checks and records `key` in the Redis nonce store with "SET key 1 NX
 * EX ttl". Connects lazily and keeps the connection open for the
 * worker process's lifetime (reused across requests); a failed
 * connect or command tears the connection down and starts a fixed
 * backoff window equal to `conf->connect_timeout`, so a persistently
 * unreachable Redis does not force every subsequent signed request to
 * block for a full connect timeout.
 *
 * Return value:
 *   NGX_OK        `key` was not previously recorded and now is; no
 *                 replay.
 *   NGX_DECLINED  `key` was already recorded; this is a replay.
 *   NGX_ABORT     Redis is unreachable (connect failure, command
 *                 error, an unexpected reply shape, or still inside
 *                 the post-failure backoff window). Caller must fail
 *                 open, not treat this as a replay.
 *   NGX_ERROR     a required argument is invalid; indicates a caller
 *                 bug, never an ordinary runtime condition.
 */
ngx_int_t ngx_auth_httpsig_nonce_store_redis_check(
    ngx_auth_httpsig_nonce_redis_conf_t *conf, ngx_str_t *key, time_t ttl,
    ngx_log_t *log);

/*
 * Frees the worker-local Redis connection, if one is open. Safe to
 * call when none was ever opened. Called from the module's
 * exit_process so a graceful worker shutdown/reload does not leak the
 * socket, and from ngx_auth_httpsig_nonce_store_redis_check() itself
 * whenever it tears down a failed connection.
 */
void ngx_auth_httpsig_nonce_store_redis_close(void);

#endif /* NGX_HAVE_AUTH_HTTPSIG_NONCE_REDIS */


#endif /* NGX_AUTH_HTTPSIG_NONCE_STORE_H */
