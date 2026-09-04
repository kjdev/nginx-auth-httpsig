/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_verify.h - Ed25519 verification of an RFC 9421
 * signature base string against a resolved keyset.
 */

#ifndef NGX_AUTH_HTTPSIG_VERIFY_H
#define NGX_AUTH_HTTPSIG_VERIFY_H


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_keys.h"


/* Ed25519 signatures are always exactly 64 bytes. */
#define NGX_AUTH_HTTPSIG_ED25519_SIGNATURE_LENGTH   64


typedef enum {
    NGX_AUTH_HTTPSIG_RESULT_OK = 0,
    NGX_AUTH_HTTPSIG_RESULT_NOT_SIGNED,
    NGX_AUTH_HTTPSIG_RESULT_PARSE_ERROR,
    NGX_AUTH_HTTPSIG_RESULT_UNKNOWN_KEYID,
    NGX_AUTH_HTTPSIG_RESULT_SIGNATURE_MISMATCH,
    NGX_AUTH_HTTPSIG_RESULT_EXPIRED,
    NGX_AUTH_HTTPSIG_RESULT_PROFILE_MISMATCH,
    NGX_AUTH_HTTPSIG_RESULT_KEY_UNAVAILABLE,
    NGX_AUTH_HTTPSIG_RESULT_KEYID_NOT_THUMBPRINT
} ngx_auth_httpsig_result_t;


/* Static string, safe to log or expose; never derived from a request. */
const char *ngx_auth_httpsig_result_name(ngx_auth_httpsig_result_t result);

/*
 * Verifies `signature` (raw bytes, already base64-decoded) as an
 * Ed25519 signature of `base` (the reconstructed signature base
 * string) under the key identified by `keyid` in `keys`.
 *
 * `*result` distinguishes NGX_AUTH_HTTPSIG_RESULT_UNKNOWN_KEYID from
 * NGX_AUTH_HTTPSIG_RESULT_SIGNATURE_MISMATCH for logging only: the
 * underlying keyset lookup is oracle-resistant, so both cases must
 * still be treated identically by the caller wherever the outcome is
 * observable to the client (e.g. $httpsig_verified).
 *
 * NGX_AUTH_HTTPSIG_RESULT_KEYID_NOT_THUMBPRINT is a refinement of
 * UNKNOWN_KEYID: `keyid` does not match any key's RFC 7638 thumbprint,
 * but does match a raw JWK `kid` in the keyset (e.g. a crawler that
 * puts its JWKS `kid` label straight into `keyid` instead of computing
 * the thumbprint the draft requires). By default this is diagnostic
 * only -- key resolution and the fail-close outcome are unchanged, and
 * it carries no more oracle risk than UNKNOWN_KEYID, since it only
 * reports on the JWKS the operator already published.
 *
 * `kid_fallback_keys` is NULL unless the operator opted in via
 * "auth_httpsig_keyid_fallback_allow on", in which case it names the
 * (caller-scoped, typically dynamically fetched) keyset that a
 * KEYID_NOT_THUMBPRINT match is additionally allowed to
 * verify against by raw `kid`. A verification that succeeds this way
 * still surfaces as plain NGX_AUTH_HTTPSIG_RESULT_OK, and a failure
 * still surfaces as the same KEYID_NOT_THUMBPRINT it would without the
 * fallback, so this does not introduce any outcome an attacker could
 * not already probe for.
 *
 * Return value:
 *   NGX_OK        `*result` is NGX_AUTH_HTTPSIG_RESULT_OK.
 *   NGX_DECLINED  the signature did not verify; `*result` explains why
 *                 (UNKNOWN_KEYID, KEYID_NOT_THUMBPRINT, or
 *                 SIGNATURE_MISMATCH). An ordinary verification
 *                 failure, not an internal error.
 *   NGX_ERROR     a required argument is NULL, or the underlying
 *                 verification call failed internally; `*result` is
 *                 left unset.
 */
ngx_int_t ngx_auth_httpsig_verify_ed25519(ngx_pool_t *pool,
    const ngx_auth_httpsig_keys_t *keys, const ngx_str_t *keyid,
    const ngx_str_t *base, const ngx_str_t *signature,
    const ngx_auth_httpsig_keys_t *kid_fallback_keys,
    ngx_auth_httpsig_result_t *result);


#endif /* NGX_AUTH_HTTPSIG_VERIFY_H */
