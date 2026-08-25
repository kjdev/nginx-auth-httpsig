/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_cache.c - see ngx_auth_httpsig_cache.h.
 */

#include "ngx_auth_httpsig_cache.h"


static void ngx_auth_httpsig_cache_rbtree_insert_value(
    ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);


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
