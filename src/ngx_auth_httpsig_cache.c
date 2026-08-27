/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_cache.c - see ngx_auth_httpsig_cache.h.
 */

#include "ngx_auth_httpsig_cache.h"


/* Lets another worker reclaim a fetch right stranded by a worker that
 * died mid-fetch, instead of that host staying NGX_AUTH_HTTPSIG_CACHE_BUSY
 * forever. */
#define NGX_AUTH_HTTPSIG_CACHE_FETCH_TIMEOUT 30


static void ngx_auth_httpsig_cache_rbtree_insert_value(
    ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);
static ngx_auth_httpsig_cache_node_t *ngx_auth_httpsig_cache_find(
    ngx_auth_httpsig_cache_ctx_t *ctx, uint32_t hash, const ngx_str_t *host);
static ngx_auth_httpsig_cache_node_t *ngx_auth_httpsig_cache_find_victim(
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, time_t now);
static ngx_auth_httpsig_cache_node_t *ngx_auth_httpsig_cache_alloc_node(
    ngx_auth_httpsig_cache_ctx_t *ctx, const ngx_str_t *host, uint32_t hash,
    time_t now);


ngx_int_t
ngx_auth_httpsig_cache_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_auth_httpsig_cache_ctx_t *octx = data;
    ngx_auth_httpsig_cache_ctx_t *ctx;
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
                             sizeof(ngx_auth_httpsig_cache_sh_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_auth_httpsig_cache_rbtree_insert_value);

    ctx->sh->generation = 0;

    len = sizeof(" in auth_httpsig key cache zone \"\"")
          + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx,
                " in auth_httpsig key cache zone \"%V\"%Z",
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
ngx_auth_httpsig_cache_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t **p;
    ngx_auth_httpsig_cache_node_t *cn, *cnt;

    for ( ;; ) {
        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else {
            cn = (ngx_auth_httpsig_cache_node_t *) node;
            cnt = (ngx_auth_httpsig_cache_node_t *) temp;

            p = (ngx_memn2cmp(cn->host.data, cnt->host.data,
                              cn->host.len, cnt->host.len) < 0)
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


static ngx_auth_httpsig_cache_node_t *
ngx_auth_httpsig_cache_find(ngx_auth_httpsig_cache_ctx_t *ctx, uint32_t hash,
    const ngx_str_t *host)
{
    ngx_rbtree_node_t *node, *sentinel;
    ngx_auth_httpsig_cache_node_t *cn;
    ngx_int_t rc;

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    while (node != sentinel) {
        if (hash != node->key) {
            node = (hash < node->key) ? node->left : node->right;
            continue;
        }

        cn = (ngx_auth_httpsig_cache_node_t *) node;

        rc = ngx_memn2cmp(host->data, cn->host.data, host->len, cn->host.len);

        if (rc == 0) {
            return cn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


/* In-order walk for a node that is safe to evict (expired, not currently
 * being fetched). Only reached under slab memory pressure, so a plain
 * recursive walk is fine. */
static ngx_auth_httpsig_cache_node_t *
ngx_auth_httpsig_cache_find_victim(ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel, time_t now)
{
    ngx_auth_httpsig_cache_node_t *cn, *victim;

    if (node == sentinel) {
        return NULL;
    }

    victim = ngx_auth_httpsig_cache_find_victim(node->left, sentinel, now);
    if (victim != NULL) {
        return victim;
    }

    cn = (ngx_auth_httpsig_cache_node_t *) node;

    if (!cn->fetching && cn->expires_at <= now) {
        return cn;
    }

    return ngx_auth_httpsig_cache_find_victim(node->right, sentinel, now);
}


/* Allocates and links a new node for `host`, evicting one expired,
 * non-fetching node and retrying once if the slab pool is out of room.
 * Returns NULL (without leaving a half-linked node) if that still fails.
 */
static ngx_auth_httpsig_cache_node_t *
ngx_auth_httpsig_cache_alloc_node(ngx_auth_httpsig_cache_ctx_t *ctx,
    const ngx_str_t *host, uint32_t hash, time_t now)
{
    ngx_auth_httpsig_cache_node_t *cn, *victim;
    size_t size;

    size = sizeof(ngx_auth_httpsig_cache_node_t) + host->len;

    cn = ngx_slab_alloc_locked(ctx->shpool, size);

    if (cn == NULL) {
        victim = ngx_auth_httpsig_cache_find_victim(ctx->sh->rbtree.root,
                                                    ctx->sh->rbtree.sentinel,
                                                    now);

        if (victim != NULL) {
            ngx_rbtree_delete(&ctx->sh->rbtree, &victim->node);

            if (victim->jwks.data != NULL) {
                ngx_slab_free_locked(ctx->shpool, victim->jwks.data);
            }

            ngx_slab_free_locked(ctx->shpool, victim);

            cn = ngx_slab_alloc_locked(ctx->shpool, size);
        }
    }

    if (cn == NULL) {
        return NULL;
    }

    ngx_memzero(cn, sizeof(ngx_auth_httpsig_cache_node_t));

    cn->host.len = host->len;
    cn->host.data = (u_char *) cn + sizeof(ngx_auth_httpsig_cache_node_t);
    ngx_memcpy(cn->host.data, host->data, host->len);

    cn->node.key = hash;

    ngx_rbtree_insert(&ctx->sh->rbtree, &cn->node);

    return cn;
}


ngx_int_t
ngx_auth_httpsig_cache_lookup(ngx_auth_httpsig_cache_ctx_t *ctx,
    ngx_pool_t *pool, const ngx_str_t *host, time_t now, ngx_str_t *jwks,
    ngx_auth_httpsig_cache_status_t *status, ngx_uint_t *generation)
{
    uint32_t hash;
    ngx_auth_httpsig_cache_node_t *cn;

    if (ctx == NULL || pool == NULL || host == NULL || jwks == NULL
        || status == NULL)
    {
        return NGX_ERROR;
    }

    if (generation != NULL) {
        *generation = 0;
    }

    hash = ngx_crc32_short(host->data, host->len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    cn = ngx_auth_httpsig_cache_find(ctx, hash, host);

    if (cn != NULL && cn->expires_at > now) {
        if (cn->jwks.len > 0) {
            jwks->data = ngx_pnalloc(pool, cn->jwks.len);
            if (jwks->data == NULL) {
                ngx_shmtx_unlock(&ctx->shpool->mutex);
                return NGX_ERROR;
            }

            ngx_memcpy(jwks->data, cn->jwks.data, cn->jwks.len);
            jwks->len = cn->jwks.len;

            if (generation != NULL) {
                *generation = cn->generation;
            }

            *status = NGX_AUTH_HTTPSIG_CACHE_HIT;

        } else {
            *status = NGX_AUTH_HTTPSIG_CACHE_NEGATIVE;
        }

        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_OK;
    }

    if (cn != NULL && cn->fetching
        && now - cn->fetching_since < NGX_AUTH_HTTPSIG_CACHE_FETCH_TIMEOUT)
    {
        *status = NGX_AUTH_HTTPSIG_CACHE_BUSY;
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_OK;
    }

    if (cn == NULL) {
        cn = ngx_auth_httpsig_cache_alloc_node(ctx, host, hash, now);

        if (cn == NULL) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);

            ngx_log_error(NGX_LOG_WARN, pool->log, 0,
                          "auth_httpsig: key cache zone has no room for "
                          "\"%V\", failing open without fetching", host);

            *status = NGX_AUTH_HTTPSIG_CACHE_UNAVAILABLE;
            return NGX_OK;
        }
    }

    cn->fetching = 1;
    cn->fetching_since = now;

    *status = NGX_AUTH_HTTPSIG_CACHE_CLAIMED;

    ngx_shmtx_unlock(&ctx->shpool->mutex);
    return NGX_OK;
}


ngx_int_t
ngx_auth_httpsig_cache_store(ngx_auth_httpsig_cache_ctx_t *ctx,
    const ngx_str_t *host, const ngx_str_t *jwks, time_t expires_at,
    ngx_uint_t *generation)
{
    uint32_t hash;
    ngx_auth_httpsig_cache_node_t *cn;
    u_char *data;

    if (ctx == NULL || host == NULL || jwks == NULL) {
        return NGX_ERROR;
    }

    if (generation != NULL) {
        *generation = 0;
    }

    hash = ngx_crc32_short(host->data, host->len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    cn = ngx_auth_httpsig_cache_find(ctx, hash, host);

    if (cn == NULL) {
        cn = ngx_auth_httpsig_cache_alloc_node(ctx, host, hash, ngx_time());

        if (cn == NULL) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);

            ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                          "auth_httpsig: key cache zone has no room for "
                          "\"%V\", not caching this fetch", host);

            return NGX_OK;
        }
    }

    data = ngx_slab_alloc_locked(ctx->shpool, jwks->len);

    if (data == NULL) {
        cn->fetching = 0;

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "auth_httpsig: key cache zone has no room to store "
                      "the fetched key set for \"%V\"", host);

        return NGX_OK;
    }

    ngx_memcpy(data, jwks->data, jwks->len);

    if (cn->jwks.data != NULL) {
        ngx_slab_free_locked(ctx->shpool, cn->jwks.data);
    }

    cn->jwks.data = data;
    cn->jwks.len = jwks->len;
    cn->expires_at = expires_at;
    cn->fetching = 0;
    cn->generation = ++ctx->sh->generation;

    if (generation != NULL) {
        *generation = cn->generation;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}


void
ngx_auth_httpsig_cache_release(ngx_auth_httpsig_cache_ctx_t *ctx,
    const ngx_str_t *host, time_t retry_at)
{
    uint32_t hash;
    ngx_auth_httpsig_cache_node_t *cn;

    if (ctx == NULL || host == NULL) {
        return;
    }

    hash = ngx_crc32_short(host->data, host->len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    cn = ngx_auth_httpsig_cache_find(ctx, hash, host);

    if (cn != NULL) {
        cn->fetching = 0;
        cn->expires_at = retry_at;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);
}
