/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_nonce_store.h"


ngx_int_t
ngx_auth_httpsig_nonce_store_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    return NGX_OK;
}


ngx_int_t
ngx_auth_httpsig_nonce_store_key(ngx_pool_t *pool,
    const ngx_str_t *agent_host, const ngx_str_t *keyid,
    const ngx_str_t *nonce, ngx_str_t *key)
{
    u_char *p;

    if (pool == NULL || agent_host == NULL || keyid == NULL || nonce == NULL
        || key == NULL)
    {
        return NGX_ERROR;
    }

    key->len = NGX_AUTH_HTTPSIG_NONCE_KEY_PREFIX_LEN
               + agent_host->len + 1 + keyid->len + 1 + nonce->len;

    key->data = ngx_pnalloc(pool, key->len);
    if (key->data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(key->data, NGX_AUTH_HTTPSIG_NONCE_KEY_PREFIX,
                   NGX_AUTH_HTTPSIG_NONCE_KEY_PREFIX_LEN);
    p = ngx_cpymem(p, agent_host->data, agent_host->len);
    *p++ = '\0';
    p = ngx_cpymem(p, keyid->data, keyid->len);
    *p++ = '\0';
    ngx_memcpy(p, nonce->data, nonce->len);

    return NGX_OK;
}


time_t
ngx_auth_httpsig_nonce_store_ttl(int64_t expires, time_t max_skew,
    time_t now)
{
    int64_t ttl;

    ttl = expires + (int64_t) max_skew - (int64_t) now;

    if (ttl < 1) {
        ttl = 1;
    }

    return (time_t) ttl;
}


#if (NGX_HAVE_AUTH_HTTPSIG_NONCE_REDIS)

/*
 * Worker-local, lazily-connected Redis connection (ADR 0052): reused
 * across requests instead of reconnecting per request, since this
 * module's target traffic (bot/agent requests hitting a signed
 * endpoint) can mean every request needs a nonce check, and
 * redisConnectWithTimeout()'s handshake is synchronous. retry_after
 * holds off reconnect attempts for connect_timeout seconds after a
 * failure so an unreachable Redis does not turn into a per-request
 * connect-timeout stall.
 */
static redisContext *ngx_auth_httpsig_nonce_redis_conn;
static time_t ngx_auth_httpsig_nonce_redis_retry_after;


void
ngx_auth_httpsig_nonce_store_redis_close(void)
{
    if (ngx_auth_httpsig_nonce_redis_conn != NULL) {
        redisFree(ngx_auth_httpsig_nonce_redis_conn);
        ngx_auth_httpsig_nonce_redis_conn = NULL;
    }
}


static ngx_int_t
ngx_auth_httpsig_nonce_store_redis_connect(
    ngx_auth_httpsig_nonce_redis_conf_t *conf, ngx_log_t *log)
{
    struct timeval timeout;
    redisReply *resp;

    if (ngx_auth_httpsig_nonce_redis_conn != NULL) {
        if (!ngx_auth_httpsig_nonce_redis_conn->err) {
            return NGX_OK;
        }

        ngx_auth_httpsig_nonce_store_redis_close();
    }

    ngx_memzero(&timeout, sizeof(struct timeval));
    timeout.tv_sec = conf->connect_timeout;

    ngx_auth_httpsig_nonce_redis_conn
        = redisConnectWithTimeout((const char *) conf->hostname, conf->port,
                                  timeout);

    if (ngx_auth_httpsig_nonce_redis_conn == NULL
        || ngx_auth_httpsig_nonce_redis_conn->err)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_httpsig: failed to connect redis: "
                      "hostname=%s port=%d connect_timeout=%ds%s%s",
                      conf->hostname, (int) conf->port,
                      (int) conf->connect_timeout,
                      ngx_auth_httpsig_nonce_redis_conn ? ": " : "",
                      ngx_auth_httpsig_nonce_redis_conn
                          ? ngx_auth_httpsig_nonce_redis_conn->errstr : "");
        ngx_auth_httpsig_nonce_store_redis_close();
        return NGX_ERROR;
    }

    timeout.tv_sec = conf->command_timeout;

    if (redisSetTimeout(ngx_auth_httpsig_nonce_redis_conn, timeout)
        != REDIS_OK)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_httpsig: failed to set redis command timeout: "
                      "command_timeout=%ds: %s",
                      (int) conf->command_timeout,
                      ngx_auth_httpsig_nonce_redis_conn->errstr);
        ngx_auth_httpsig_nonce_store_redis_close();
        return NGX_ERROR;
    }

    if (conf->db > 0) {
        resp = redisCommand(ngx_auth_httpsig_nonce_redis_conn, "SELECT %d",
                            (int) conf->db);

        if (resp == NULL || resp->type == REDIS_REPLY_ERROR) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "auth_httpsig: failed to command redis: SELECT%s%s",
                          resp ? ": " : "", resp ? resp->str : "");
            if (resp != NULL) {
                freeReplyObject(resp);
            }
            ngx_auth_httpsig_nonce_store_redis_close();
            return NGX_ERROR;
        }

        freeReplyObject(resp);
    }

    return NGX_OK;
}


ngx_int_t
ngx_auth_httpsig_nonce_store_redis_check(
    ngx_auth_httpsig_nonce_redis_conf_t *conf, ngx_str_t *key, time_t ttl,
    ngx_log_t *log)
{
    redisReply *resp;
    ngx_int_t rc;

    if (conf == NULL || key == NULL || ttl < 1) {
        return NGX_ERROR;
    }

    if (ngx_auth_httpsig_nonce_redis_retry_after != 0
        && ngx_time() < ngx_auth_httpsig_nonce_redis_retry_after)
    {
        return NGX_ABORT;
    }

    if (ngx_auth_httpsig_nonce_store_redis_connect(conf, log) != NGX_OK) {
        /* ngx_time() is the cached time from the last event-loop
         * iteration; redisConnectWithTimeout() blocks synchronously for
         * up to connect_timeout on an unreachable (not merely refusing)
         * host, so without refreshing it here the backoff window would
         * collapse to ~0 for exactly the persistently-unreachable case
         * this backoff exists to cover. */
        ngx_time_update();
        ngx_auth_httpsig_nonce_redis_retry_after
            = ngx_time() + conf->connect_timeout;
        return NGX_ABORT;
    }

    /* ttl + 1: mirrors the SHM backend's inclusive liveness check (">="
     * at the "now == expires + max_skew" boundary, ngx_auth_httpsig_
     * nonce_store_shm_check()) -- Redis's EX has no such inclusive
     * option at the boundary, so the key is kept one second past the
     * raw window to guarantee it is still present at that instant. */
    resp = redisCommand(ngx_auth_httpsig_nonce_redis_conn,
                        "SET %b 1 NX EX %ld",
                        key->data, key->len, (long) (ttl + 1));

    if (resp == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_httpsig: failed to command redis: SET NX EX");
        ngx_auth_httpsig_nonce_store_redis_close();
        ngx_time_update(); /* redisCommand() blocks up to command_timeout;
                            * see the connect-failure branch above for why
                            * the cached time needs refreshing first. */
        ngx_auth_httpsig_nonce_redis_retry_after
            = ngx_time() + conf->connect_timeout;
        return NGX_ABORT;
    }

    if (resp->type == REDIS_REPLY_ERROR) {
        /* Treated the same as a connect failure (close + backoff), not
         * a one-off: a command-level error (NOAUTH, READONLY, OOM,
         * MISCONF, ...) is normally persistent for the life of the
         * connection, matching this function's documented contract. */
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_httpsig: failed to command redis: "
                      "SET NX EX: %s", resp->str);
        freeReplyObject(resp);
        ngx_auth_httpsig_nonce_store_redis_close();
        ngx_time_update();
        ngx_auth_httpsig_nonce_redis_retry_after
            = ngx_time() + conf->connect_timeout;
        return NGX_ABORT;
    }

    if (resp->type == REDIS_REPLY_NIL) {
        rc = NGX_DECLINED;

    } else if (resp->type == REDIS_REPLY_STATUS
               && resp->len == sizeof("OK") - 1
               && ngx_strncmp(resp->str, "OK", sizeof("OK") - 1) == 0)
    {
        rc = NGX_OK;

    } else {
        /* An unexpected reply shape almost never means a misbehaving
         * endpoint -- it means this connection's request/reply stream
         * is desynced (e.g. a prior command's reply was misread), and
         * every SET after this one would read the wrong reply too.
         * Fail open (must not be read as "not a replay") and close the
         * connection so the next check reconnects on a clean stream;
         * unlike the other failure branches, the round trip itself
         * succeeded, so there is no reason to also arm the connect-
         * failure backoff. */
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_httpsig: unexpected redis reply to "
                      "SET NX EX (type %d)", resp->type);
        ngx_auth_httpsig_nonce_store_redis_close();
        rc = NGX_ABORT;
    }

    freeReplyObject(resp);

    if (rc != NGX_ABORT) {
        /* retry_after is only ever armed on failure paths above; a
         * definite OK/DECLINED here confirms the connection is
         * healthy, so clear any stale backoff left over from an
         * earlier transient failure. */
        ngx_auth_httpsig_nonce_redis_retry_after = 0;
    }

    return rc;
}

#endif /* NGX_HAVE_AUTH_HTTPSIG_NONCE_REDIS */
