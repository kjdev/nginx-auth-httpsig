/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_keys.c - JWKS-backed key resolution. See the header
 * for the source-table rationale.
 *
 * Ownership: nxe_jwx_jwks_parse() registers its own pool cleanup, so a
 * keyset allocated from a pool that is destroyed on a predictable
 * schedule (e.g. a per-cycle configuration pool that is torn down and
 * replaced wholesale on reload) needs nothing further. A keyset that
 * must outlive that schedule (a long-lived pool kept across reloads)
 * must have ngx_auth_httpsig_keys_free() invoked explicitly -- e.g. via
 * an additional ngx_pool_cleanup_add() registered by the caller -- so
 * the EVP_PKEY objects do not accumulate across reloads.
 * nxe_jwx_jwks_free() disarms its own cleanup handler, so this does not
 * double-free.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_keys.h"

#include <nxe_json.h>
#include <nxe_jwx.h>


static ngx_int_t ngx_auth_httpsig_keys_check_ed25519_only(
    const ngx_str_t *jwks_json, ngx_pool_t *pool, ngx_uint_t log_level);
static ngx_int_t ngx_auth_httpsig_keys_check_ed25519_only_body(
    nxe_json_t *root, ngx_pool_t *pool, ngx_uint_t log_level);

static ngx_flag_t ngx_auth_httpsig_keys_jwks_has(
    const ngx_auth_httpsig_keys_t *keys, const ngx_str_t *keyid);
static ngx_flag_t ngx_auth_httpsig_keys_jwks_has_kid(
    const ngx_auth_httpsig_keys_t *keys, const ngx_str_t *kid);
static ngx_int_t ngx_auth_httpsig_keys_jwks_verify(
    const ngx_auth_httpsig_keys_t *keys, const ngx_str_t *keyid,
    const ngx_str_t *msg, const ngx_str_t *sig, ngx_pool_t *pool);
static void ngx_auth_httpsig_keys_jwks_free(ngx_auth_httpsig_keys_t *keys);

static ngx_flag_t ngx_auth_httpsig_keys_chain_has(
    const ngx_auth_httpsig_keys_t *keys, const ngx_str_t *keyid);
static ngx_flag_t ngx_auth_httpsig_keys_chain_has_kid(
    const ngx_auth_httpsig_keys_t *keys, const ngx_str_t *kid);
static ngx_int_t ngx_auth_httpsig_keys_chain_verify(
    const ngx_auth_httpsig_keys_t *keys, const ngx_str_t *keyid,
    const ngx_str_t *msg, const ngx_str_t *sig, ngx_pool_t *pool);
static void ngx_auth_httpsig_keys_chain_free(ngx_auth_httpsig_keys_t *keys);


static const ngx_auth_httpsig_keys_source_t
    ngx_auth_httpsig_keys_jwks_source =
{
    ngx_string("jwks_file"),
    ngx_auth_httpsig_keys_jwks_has,
    ngx_auth_httpsig_keys_jwks_has_kid,
    ngx_auth_httpsig_keys_jwks_verify,
    ngx_auth_httpsig_keys_jwks_free
};

static const ngx_auth_httpsig_keys_source_t
    ngx_auth_httpsig_keys_chain_source =
{
    ngx_string("chain"),
    ngx_auth_httpsig_keys_chain_has,
    ngx_auth_httpsig_keys_chain_has_kid,
    ngx_auth_httpsig_keys_chain_verify,
    ngx_auth_httpsig_keys_chain_free
};

typedef struct {
    ngx_auth_httpsig_keys_t *first;
    ngx_auth_httpsig_keys_t *second;
} ngx_auth_httpsig_keys_chain_data_t;


ngx_int_t
ngx_auth_httpsig_keys_load_jwks(ngx_pool_t *pool,
    const ngx_str_t *jwks_json, const ngx_str_t *origin,
    ngx_uint_t log_level, ngx_auth_httpsig_keys_t **out)
{
    nxe_jwx_jwks_t *jwks;
    ngx_auth_httpsig_keys_t *keys;

    if (pool == NULL || jwks_json == NULL || out == NULL) {
        return NGX_ERROR;
    }

    if (jwks_json->len > NGX_AUTH_HTTPSIG_MAX_JWKS_SIZE) {
        ngx_log_error(log_level, pool->log, 0,
                      "auth_httpsig: JWKS document exceeds %ui bytes",
                      (ngx_uint_t) NGX_AUTH_HTTPSIG_MAX_JWKS_SIZE);
        return NGX_ERROR;
    }

    if (ngx_auth_httpsig_keys_check_ed25519_only(jwks_json, pool, log_level)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    jwks = nxe_jwx_jwks_parse(jwks_json, pool);
    if (jwks == NULL) {
        ngx_log_error(log_level, pool->log, 0,
                      "auth_httpsig: failed to parse JWKS document");
        return NGX_ERROR;
    }

    keys = ngx_pcalloc(pool, sizeof(ngx_auth_httpsig_keys_t));
    if (keys == NULL) {
        nxe_jwx_jwks_free(jwks);
        return NGX_ERROR;
    }

    keys->source = &ngx_auth_httpsig_keys_jwks_source;
    keys->data = jwks;
    keys->count = nxe_jwx_jwks_count(jwks);

    if (origin != NULL && origin->len > 0) {
        keys->origin.data = ngx_pnalloc(pool, origin->len);
        if (keys->origin.data == NULL) {
            nxe_jwx_jwks_free(jwks);
            return NGX_ERROR;
        }

        ngx_memcpy(keys->origin.data, origin->data, origin->len);
        keys->origin.len = origin->len;
    }

    *out = keys;

    return NGX_OK;
}


ngx_flag_t
ngx_auth_httpsig_keys_has(const ngx_auth_httpsig_keys_t *keys,
    const ngx_str_t *keyid)
{
    if (keys == NULL || keyid == NULL) {
        return 0;
    }

    return keys->source->has(keys, keyid);
}


ngx_flag_t
ngx_auth_httpsig_keys_has_kid(const ngx_auth_httpsig_keys_t *keys,
    const ngx_str_t *kid)
{
    if (keys == NULL || kid == NULL) {
        return 0;
    }

    return keys->source->has_kid(keys, kid);
}


ngx_int_t
ngx_auth_httpsig_keys_verify(const ngx_auth_httpsig_keys_t *keys,
    const ngx_str_t *keyid, const ngx_str_t *msg, const ngx_str_t *sig,
    ngx_pool_t *pool)
{
    if (keys == NULL || keyid == NULL || msg == NULL || sig == NULL
        || pool == NULL)
    {
        return NGX_ERROR;
    }

    return keys->source->verify(keys, keyid, msg, sig, pool);
}


void
ngx_auth_httpsig_keys_free(ngx_auth_httpsig_keys_t *keys)
{
    if (keys == NULL) {
        return;
    }

    keys->source->free(keys);
}


ngx_auth_httpsig_keys_t *
ngx_auth_httpsig_keys_chain(ngx_pool_t *pool, ngx_auth_httpsig_keys_t *first,
    ngx_auth_httpsig_keys_t *second)
{
    ngx_auth_httpsig_keys_t *keys;
    ngx_auth_httpsig_keys_chain_data_t *data;

    if (pool == NULL) {
        return NULL;
    }

    if (first == NULL) {
        return second;
    }

    if (second == NULL) {
        return first;
    }

    data = ngx_palloc(pool, sizeof(ngx_auth_httpsig_keys_chain_data_t));
    if (data == NULL) {
        return NULL;
    }

    data->first = first;
    data->second = second;

    keys = ngx_pcalloc(pool, sizeof(ngx_auth_httpsig_keys_t));
    if (keys == NULL) {
        return NULL;
    }

    keys->source = &ngx_auth_httpsig_keys_chain_source;
    keys->data = data;
    keys->count = first->count + second->count;

    return keys;
}


/*
 * nxe_jwx_jwks_parse() accepts RSA / EC / OKP keys interchangeably and
 * skips unsupported entries with a warning instead of failing, so it
 * cannot be relied on to reject a JWKS that mixes Ed25519 with other
 * key types. This walks the raw JSON first and rejects the whole
 * document -- rather than silently dropping the offending keys -- if
 * any key is not `kty: "OKP", crv: "Ed25519"`, since a mixed-kty JWKS
 * is an operator configuration mistake that should surface as a
 * startup error, not a partially-loaded keyset.
 */
static ngx_int_t
ngx_auth_httpsig_keys_check_ed25519_only(const ngx_str_t *jwks_json,
    ngx_pool_t *pool, ngx_uint_t log_level)
{
    ngx_int_t rc;
    nxe_json_t *root;

    root = nxe_json_parse((ngx_str_t *) jwks_json, pool);
    if (root == NULL) {
        ngx_log_error(log_level, pool->log, 0,
                      "auth_httpsig: JWKS document is not valid JSON");
        return NGX_ERROR;
    }

    rc = ngx_auth_httpsig_keys_check_ed25519_only_body(root, pool, log_level);

    nxe_json_free(root);

    return rc;
}


static ngx_int_t
ngx_auth_httpsig_keys_check_ed25519_only_body(nxe_json_t *root,
    ngx_pool_t *pool, ngx_uint_t log_level)
{
    size_t i, n;
    ngx_str_t kty, crv;
    ngx_int_t rc;
    nxe_json_t *keys, *key;

    if (!nxe_json_is_object(root)) {
        ngx_log_error(log_level, pool->log, 0,
                      "auth_httpsig: JWKS document is not a JSON object");
        return NGX_ERROR;
    }

    keys = nxe_json_object_get(root, "keys");
    if (keys == NULL || !nxe_json_is_array(keys)) {
        ngx_log_error(log_level, pool->log, 0,
                      "auth_httpsig: JWKS document has no \"keys\" array");
        return NGX_ERROR;
    }

    n = nxe_json_array_size(keys);

    if (n > NGX_AUTH_HTTPSIG_MAX_JWKS_KEYS) {
        ngx_log_error(log_level, pool->log, 0,
                      "auth_httpsig: JWKS document has more than %ui keys",
                      (ngx_uint_t) NGX_AUTH_HTTPSIG_MAX_JWKS_KEYS);
        return NGX_ERROR;
    }

    for (i = 0; i < n; i++) {
        key = nxe_json_array_get(keys, i);

        rc = nxe_json_object_get_string(key, "kty", &kty, pool);

        if (rc != NGX_OK
            || kty.len != sizeof("OKP") - 1
            || ngx_strncmp(kty.data, "OKP", kty.len) != 0)
        {
            ngx_log_error(log_level, pool->log, 0,
                          "auth_httpsig: JWKS key %ui is not an Ed25519 "
                          "(OKP) key; only Ed25519 keys are supported",
                          (ngx_uint_t) i);
            return NGX_ERROR;
        }

        rc = nxe_json_object_get_string(key, "crv", &crv, pool);

        if (rc != NGX_OK
            || crv.len != sizeof("Ed25519") - 1
            || ngx_strncmp(crv.data, "Ed25519", crv.len) != 0)
        {
            ngx_log_error(log_level, pool->log, 0,
                          "auth_httpsig: JWKS key %ui does not use the "
                          "Ed25519 curve", (ngx_uint_t) i);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_flag_t
ngx_auth_httpsig_keys_jwks_has(const ngx_auth_httpsig_keys_t *keys,
    const ngx_str_t *keyid)
{
    return nxe_jwx_jwks_has_thumbprint(keys->data, keyid);
}


static ngx_flag_t
ngx_auth_httpsig_keys_jwks_has_kid(const ngx_auth_httpsig_keys_t *keys,
    const ngx_str_t *kid)
{
    return nxe_jwx_jwks_has_kid(keys->data, kid);
}


static ngx_int_t
ngx_auth_httpsig_keys_jwks_verify(const ngx_auth_httpsig_keys_t *keys,
    const ngx_str_t *keyid, const ngx_str_t *msg, const ngx_str_t *sig,
    ngx_pool_t *pool)
{
    return nxe_jwx_jwks_verify_raw(keys->data, keyid, NULL, msg, sig, pool);
}


static void
ngx_auth_httpsig_keys_jwks_free(ngx_auth_httpsig_keys_t *keys)
{
    nxe_jwx_jwks_free(keys->data);
}


static ngx_flag_t
ngx_auth_httpsig_keys_chain_has(const ngx_auth_httpsig_keys_t *keys,
    const ngx_str_t *keyid)
{
    ngx_auth_httpsig_keys_chain_data_t *data = keys->data;

    return ngx_auth_httpsig_keys_has(data->first, keyid)
           || ngx_auth_httpsig_keys_has(data->second, keyid);
}


static ngx_flag_t
ngx_auth_httpsig_keys_chain_has_kid(const ngx_auth_httpsig_keys_t *keys,
    const ngx_str_t *kid)
{
    ngx_auth_httpsig_keys_chain_data_t *data = keys->data;

    return ngx_auth_httpsig_keys_has_kid(data->first, kid)
           || ngx_auth_httpsig_keys_has_kid(data->second, kid);
}


/*
 * Falls through from `first` to `second` on any NGX_DECLINED, including
 * "signature did not verify" -- not only "no such keyid" -- since the
 * two are indistinguishable by design (oracle resistance). This only
 * matters if the same keyid exists in both keysets, which the RFC 7638
 * thumbprint keying makes practically impossible for two different
 * public keys.
 */
static ngx_int_t
ngx_auth_httpsig_keys_chain_verify(const ngx_auth_httpsig_keys_t *keys,
    const ngx_str_t *keyid, const ngx_str_t *msg, const ngx_str_t *sig,
    ngx_pool_t *pool)
{
    ngx_auth_httpsig_keys_chain_data_t *data = keys->data;
    ngx_int_t rc;

    rc = ngx_auth_httpsig_keys_verify(data->first, keyid, msg, sig, pool);
    if (rc == NGX_OK) {
        return NGX_OK;
    }

    return ngx_auth_httpsig_keys_verify(data->second, keyid, msg, sig, pool);
}


/* Ownership of `first`/`second` stays with whoever loaded them. */
static void
ngx_auth_httpsig_keys_chain_free(ngx_auth_httpsig_keys_t *keys)
{
}
