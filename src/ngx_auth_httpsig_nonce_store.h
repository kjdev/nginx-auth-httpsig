/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_nonce_store.h - shared-memory zone and Redis
 * connection settings for replay-prevention nonce storage
 * (auth_httpsig_nonce_store_zone / auth_httpsig_nonce_store_redis).
 * The rbtree + slab lookup/store logic and the hiredis SET NX EX client
 * are added on top of this in later work; this header only reserves the
 * zone and carries the parsed connection parameters (ADR 0051).
 */

#ifndef NGX_AUTH_HTTPSIG_NONCE_STORE_H
#define NGX_AUTH_HTTPSIG_NONCE_STORE_H


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * Fixed upper bound on a signature's nonce length. A signer-controlled
 * value this large is rejected outright rather than truncated or stored
 * unbounded, so an attacker cannot bypass replay detection by sending an
 * oversized nonce that the store silently drops (ADR 0051 decision 7).
 */
#define NGX_AUTH_HTTPSIG_NONCE_MAX_LEN   256


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


#endif /* NGX_AUTH_HTTPSIG_NONCE_STORE_H */
