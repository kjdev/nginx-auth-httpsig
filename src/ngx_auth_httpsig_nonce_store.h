/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_nonce_store.h - shared-memory zone reservation, key/TTL
 * derivation, and the Redis SET NX EX client for replay-prevention nonce
 * storage (auth_httpsig_nonce_store_zone / auth_httpsig_nonce_store_redis).
 * The SHM backend's rbtree + slab lookup/store logic is added on top of
 * this in later work (ADR 0049); this header already carries the Redis
 * backend end to end (ADR 0046, ADR 0047, ADR 0052).
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
 * oversized nonce that the store silently drops (ADR 0051 decision 7).
 */
#define NGX_AUTH_HTTPSIG_NONCE_MAX_LEN   256

/*
 * Fixed namespace prefix for store keys. This module has no "zone name"
 * of its own to scope by (unlike nginx-keyval's keyval_zone_redis, ADR
 * 0051 decision 4 drops "zone="), so without a prefix a nonce key could
 * collide with unrelated data an operator keeps in the same Redis
 * database.
 */
#define NGX_AUTH_HTTPSIG_NONCE_KEY_PREFIX       "auth_httpsig:nonce:"
#define NGX_AUTH_HTTPSIG_NONCE_KEY_PREFIX_LEN   \
        (sizeof(NGX_AUTH_HTTPSIG_NONCE_KEY_PREFIX) - 1)


/* auth_httpsig_nonce_store_redis connection parameters (ADR 0046 decision
 * 4, ADR 0051 decision 4): vocabulary matches nginx-keyval's
 * keyval_zone_redis, minus "zone=" (this module keeps a single
 * connection, not a named store). */
typedef struct {
    u_char     *hostname;
    ngx_int_t   port;
    ngx_int_t   db;
    time_t      connect_timeout;
    time_t      command_timeout;
    ngx_flag_t  configured;
} ngx_auth_httpsig_nonce_redis_conf_t;

/* Placeholder for auth_httpsig_nonce_store_zone's shm_zone->data; the
 * rbtree + slab node storage is added when the SHM backend is
 * implemented. */
typedef struct {
    ngx_uint_t  reserved;
} ngx_auth_httpsig_nonce_store_ctx_t;


/*
 * ngx_shm_zone_t.init callback for auth_httpsig_nonce_store_zone.
 * Returns NGX_OK without attaching any rbtree/slab state; replaced with
 * the real init (mirroring ngx_auth_httpsig_cache_init_zone's reload
 * reattachment) once the SHM backend stores nonce records.
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
 * window check itself used (ADR 0047 decision 2). Clamped to at least
 * 1: profile_verify()'s time-window check accepts "now == expires +
 * max_skew" (TTL 0), but ngx_auth_httpsig_nonce_store_shm_check()
 * rejects ttl < 1 as a caller-bug NGX_ERROR, so the floor is a
 * store-validity requirement, not an additional policy bound -- ADR
 * 0047 deliberately sets none.
 */
time_t ngx_auth_httpsig_nonce_store_ttl(int64_t expires, time_t max_skew,
    time_t now);

#if (NGX_HAVE_AUTH_HTTPSIG_NONCE_REDIS)

/*
 * Checks and records `key` in the Redis nonce store with "SET key 1 NX
 * EX ttl". Connects lazily and keeps the connection open for the
 * worker process's lifetime (reused across requests); a failed
 * connect or command tears the connection down and starts a fixed
 * backoff window equal to `conf->connect_timeout`, so a persistently
 * unreachable Redis does not force every subsequent signed request to
 * block for a full connect timeout (ADR 0052).
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
