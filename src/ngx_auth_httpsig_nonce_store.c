/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_nonce_store.h"


/* Once the zone is full, it stays full (nonces are unique, so no later
 * lookup ever frees an expired node) -- throttles the exhaustion WARN to
 * once per this many seconds instead of once per request. */
#define NGX_AUTH_HTTPSIG_NONCE_STORE_NOMEM_LOG_INTERVAL 60


static void ngx_auth_httpsig_nonce_store_rbtree_insert_value(
    ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);
static ngx_auth_httpsig_nonce_store_node_t *ngx_auth_httpsig_nonce_store_find(
    ngx_auth_httpsig_nonce_store_ctx_t *ctx, uint32_t hash,
    const ngx_str_t *key);


ngx_int_t
ngx_auth_httpsig_nonce_store_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_auth_httpsig_nonce_store_ctx_t *octx = data;
    ngx_auth_httpsig_nonce_store_ctx_t *ctx;
    size_t len;

    ctx = shm_zone->data;

    if (octx) {
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool,
                             sizeof(ngx_auth_httpsig_nonce_store_sh_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_auth_httpsig_nonce_store_rbtree_insert_value);

    ctx->sh->last_nomem_log = 0;

    len = sizeof(" in auth_httpsig nonce store zone \"\"")
          + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx,
                " in auth_httpsig nonce store zone \"%V\"%Z",
                &shm_zone->shm.name);

    ctx->shpool->log_nomem = 0;

    return NGX_OK;
}


/*
 * Non-root inserts must set node->parent/left/right and ngx_rbt_red()
 * explicitly: ngx_rbtree_insert() only fills these in for the very first
 * (root) node, leaving it to this callback otherwise. Slab memory is not
 * zeroed, so skipping this leaves node->parent pointing at garbage and
 * the second insert walks off into it.
 */
static void
ngx_auth_httpsig_nonce_store_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t **p;
    ngx_auth_httpsig_nonce_store_node_t *cn, *cnt;

    for ( ;; ) {
        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else {
            cn = (ngx_auth_httpsig_nonce_store_node_t *) node;
            cnt = (ngx_auth_httpsig_nonce_store_node_t *) temp;

            p = (ngx_memn2cmp(cn->nonce_key.data, cnt->nonce_key.data,
                              cn->nonce_key.len, cnt->nonce_key.len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_auth_httpsig_nonce_store_node_t *
ngx_auth_httpsig_nonce_store_find(ngx_auth_httpsig_nonce_store_ctx_t *ctx,
    uint32_t hash, const ngx_str_t *key)
{
    ngx_rbtree_node_t *node, *sentinel;
    ngx_auth_httpsig_nonce_store_node_t *cn;
    ngx_int_t rc;

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    while (node != sentinel) {
        if (hash != node->key) {
            node = (hash < node->key) ? node->left : node->right;
            continue;
        }

        cn = (ngx_auth_httpsig_nonce_store_node_t *) node;

        rc = ngx_memn2cmp(key->data, cn->nonce_key.data, key->len,
                          cn->nonce_key.len);

        if (rc == 0) {
            return cn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


ngx_int_t
ngx_auth_httpsig_nonce_store_shm_check(
    ngx_auth_httpsig_nonce_store_ctx_t *ctx, ngx_str_t *key, time_t ttl,
    time_t now, ngx_log_t *log)
{
    uint32_t hash;
    ngx_auth_httpsig_nonce_store_node_t *cn;
    ngx_flag_t do_log;

    if (ctx == NULL || key == NULL || ttl < 1) {
        return NGX_ERROR;
    }

    hash = ngx_crc32_long(key->data, key->len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    cn = ngx_auth_httpsig_nonce_store_find(ctx, hash, key);

    if (cn != NULL && cn->expires_at >= now) {
        /* >= , not > : profile_verify()'s own time-window check accepts
         * "now == expires + max_skew" (the same instant expires_at is
         * derived from), so a record must still read as live at that
         * exact second -- a strict ">" would let a replay through in
         * the one second the signature is still valid but the record
         * already reads as expired. Leave expires_at untouched -- Redis's
         * SET ... NX never refreshes an existing key's TTL either. */
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_DECLINED;
    }

    if (cn != NULL) {
        /* Found but expired. The key is byte-for-byte identical to what
         * is already stored (find() matched on it), so the existing
         * slab allocation is reused in place rather than freed and
         * reallocated. */
        cn->expires_at = now + ttl;

        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_OK;
    }

    cn = ngx_slab_alloc_locked(ctx->shpool,
                               sizeof(ngx_auth_httpsig_nonce_store_node_t)
                               + key->len);

    if (cn == NULL) {
        /* No eviction attempt: nonces are
         * unique per request, so an expired node is never freed by a
         * later lookup for the same key, and a victim scan would be an
         * O(n) walk under this mutex on every request once the zone is
         * full -- unlike the key-directory cache's small per-host node
         * count. Once full, the zone stays full until nginx restarts
         * (reload reattaches the existing tree via init_zone); operators
         * size the zone accordingly. */
        do_log = 0;

        if (now - ctx->sh->last_nomem_log
            >= NGX_AUTH_HTTPSIG_NONCE_STORE_NOMEM_LOG_INTERVAL)
        {
            ctx->sh->last_nomem_log = now;
            do_log = 1;
        }

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        if (do_log) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "auth_httpsig: nonce store zone has no room for "
                          "a new entry (%uz bytes), failing open",
                          key->len);
        }

        return NGX_ABORT;
    }

    ngx_memzero(cn, sizeof(ngx_auth_httpsig_nonce_store_node_t));

    cn->nonce_key.len = key->len;
    cn->nonce_key.data = (u_char *) cn
                         + sizeof(ngx_auth_httpsig_nonce_store_node_t);
    ngx_memcpy(cn->nonce_key.data, key->data, key->len);

    cn->node.key = hash;
    cn->expires_at = now + ttl;

    ngx_rbtree_insert(&ctx->sh->rbtree, &cn->node);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

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
 * Worker-local, lazily-connected Redis connection: reused
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
    ngx_flag_t retried = 0;

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

    /* A connection that the server (or a middlebox) closed while idle
     * only shows up as an error on the first command sent over it, so
     * that failure says nothing about Redis being down: reconnect and
     * retry once before backing off. A timeout is not retried, since
     * the retry would block for command_timeout again. */
    if (resp == NULL
        && (ngx_auth_httpsig_nonce_redis_conn->err == REDIS_ERR_IO
            || ngx_auth_httpsig_nonce_redis_conn->err == REDIS_ERR_EOF))
    {
        ngx_auth_httpsig_nonce_store_redis_close();

        if (ngx_auth_httpsig_nonce_store_redis_connect(conf, log) == NGX_OK) {
            retried = 1;
            resp = redisCommand(ngx_auth_httpsig_nonce_redis_conn,
                                "SET %b 1 NX EX %ld",
                                key->data, key->len, (long) (ttl + 1));
        }
    }

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
        /* After a retry the first SET may have landed with only its reply
         * lost, so NIL can be this request's own write, not a replay. */
        rc = retried ? NGX_ABORT : NGX_DECLINED;

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
