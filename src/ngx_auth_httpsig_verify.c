/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_verify.c - Ed25519 verification of an RFC 9421
 * signature base string.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_verify.h"


const char *
ngx_auth_httpsig_result_name(ngx_auth_httpsig_result_t result)
{
    switch (result) {
    case NGX_AUTH_HTTPSIG_RESULT_OK:
        return "ok";
    case NGX_AUTH_HTTPSIG_RESULT_NOT_SIGNED:
        return "not_signed";
    case NGX_AUTH_HTTPSIG_RESULT_PARSE_ERROR:
        return "parse_error";
    case NGX_AUTH_HTTPSIG_RESULT_UNKNOWN_KEYID:
        return "unknown_keyid";
    case NGX_AUTH_HTTPSIG_RESULT_SIGNATURE_MISMATCH:
        return "signature_mismatch";
    case NGX_AUTH_HTTPSIG_RESULT_EXPIRED:
        return "expired";
    case NGX_AUTH_HTTPSIG_RESULT_PROFILE_MISMATCH:
        return "profile_mismatch";
    }

    return "unknown";
}


ngx_int_t
ngx_auth_httpsig_verify_ed25519(ngx_pool_t *pool,
    const ngx_auth_httpsig_keys_t *keys, const ngx_str_t *keyid,
    const ngx_str_t *base, const ngx_str_t *signature,
    ngx_auth_httpsig_result_t *result)
{
    ngx_int_t rc;

    if (pool == NULL || base == NULL || signature == NULL
        || result == NULL)
    {
        return NGX_ERROR;
    }

    if (keys == NULL || keyid == NULL || keyid->len == 0) {
        *result = NGX_AUTH_HTTPSIG_RESULT_UNKNOWN_KEYID;
        return NGX_DECLINED;
    }

    if (signature->len != NGX_AUTH_HTTPSIG_ED25519_SIGNATURE_LENGTH) {
        *result = NGX_AUTH_HTTPSIG_RESULT_SIGNATURE_MISMATCH;
        return NGX_DECLINED;
    }

    /* Distinguishing "unknown keyid" from "signature mismatch" here is
     * for logging only: ngx_auth_httpsig_keys_verify() below already
     * collapses the same two cases into one NGX_DECLINED, so a caller
     * that skipped this check would reach the identical outcome. */
    if (!ngx_auth_httpsig_keys_has(keys, keyid)) {
        *result = NGX_AUTH_HTTPSIG_RESULT_UNKNOWN_KEYID;
        return NGX_DECLINED;
    }

    rc = ngx_auth_httpsig_keys_verify(keys, keyid, base, signature, pool);

    switch (rc) {
    case NGX_OK:
        *result = NGX_AUTH_HTTPSIG_RESULT_OK;
        return NGX_OK;

    case NGX_DECLINED:
        *result = NGX_AUTH_HTTPSIG_RESULT_SIGNATURE_MISMATCH;
        return NGX_DECLINED;

    default:
        return NGX_ERROR;
    }
}
