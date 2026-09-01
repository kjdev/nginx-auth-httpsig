/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_keys.h - verification key resolution. Wraps a JWKS
 * document behind a source table (has / verify / free) instead of
 * exposing key material directly, so the caller never touches an
 * EVP_PKEY. The dynamic key-directory fetch plugs in as a second
 * ngx_auth_httpsig_keys_source_t (the "jwks" source, reused as-is) and
 * ngx_auth_httpsig_keys_chain() combines it with the static keyset.
 */

#ifndef NGX_AUTH_HTTPSIG_KEYS_H
#define NGX_AUTH_HTTPSIG_KEYS_H


#include <ngx_config.h>
#include <ngx_core.h>


/* Matches nxe-jwx's own ceiling (NXE_JWX_MAX_JWKS_SIZE); duplicated here
 * so this header does not need to pull in nxe_jwx.h. */
#define NGX_AUTH_HTTPSIG_MAX_JWKS_SIZE   262144
#define NGX_AUTH_HTTPSIG_MAX_JWKS_KEYS       64


typedef struct ngx_auth_httpsig_keys_s ngx_auth_httpsig_keys_t;

typedef ngx_flag_t (*ngx_auth_httpsig_keys_has_pt)(
    const ngx_auth_httpsig_keys_t *keys, const ngx_str_t *keyid);
typedef ngx_flag_t (*ngx_auth_httpsig_keys_has_kid_pt)(
    const ngx_auth_httpsig_keys_t *keys, const ngx_str_t *kid);
typedef ngx_int_t (*ngx_auth_httpsig_keys_verify_pt)(
    const ngx_auth_httpsig_keys_t *keys, const ngx_str_t *keyid,
    const ngx_str_t *msg, const ngx_str_t *sig, ngx_pool_t *pool);
typedef void (*ngx_auth_httpsig_keys_free_pt)(ngx_auth_httpsig_keys_t *keys);

typedef struct {
    ngx_str_t                         name;
    ngx_auth_httpsig_keys_has_pt      has;
    ngx_auth_httpsig_keys_has_kid_pt  has_kid;
    ngx_auth_httpsig_keys_verify_pt   verify;
    ngx_auth_httpsig_keys_free_pt     free;
} ngx_auth_httpsig_keys_source_t;

struct ngx_auth_httpsig_keys_s {
    const ngx_auth_httpsig_keys_source_t *source;
    void                                 *data;
    ngx_str_t                             origin;    /* logging only */
    ngx_uint_t                            count;
};


/*
 * Loads verification keys from a JWKS document (`{"keys": [...]}`).
 *
 * Rejects the document outright, before handing it to the underlying
 * JWKS parser, unless every key is `kty: "OKP"` with `crv: "Ed25519"`:
 * only Ed25519 is supported, and the underlying parser accepts
 * RSA/EC/OKP interchangeably and skips unsupported keys with a warning
 * rather than failing, which would silently admit a mixed-kty JWKS.
 *
 * `origin` is copied for use in log messages (e.g. the configured file
 * path); it may be NULL.
 *
 * `log_level` is the ngx_log_error() level used for a rejected
 * document. Configuration loading passes NGX_LOG_EMERG; a dynamically
 * fetched document -- content an unauthenticated remote party
 * controls -- passes NGX_LOG_WARN instead, so a malformed response
 * cannot be used to flood the error log at EMERG.
 *
 * Return value:
 *   NGX_OK     `*out` holds the loaded keyset, pool-allocated.
 *   NGX_ERROR  the document is missing, too large, exceeds the key
 *              count limit, contains a non-Ed25519 key, or failed to
 *              parse. Details are logged at `log_level`.
 *
 * The caller is responsible for releasing `*out` with
 * ngx_auth_httpsig_keys_free() before `pool` is destroyed, if `pool`
 * outlives a single configuration lifetime (see the .c file for the
 * cleanup-ownership rationale).
 */
ngx_int_t ngx_auth_httpsig_keys_load_jwks(ngx_pool_t *pool,
    const ngx_str_t *jwks_json, const ngx_str_t *origin,
    ngx_uint_t log_level, ngx_auth_httpsig_keys_t **out);

/* Reports whether `keys` holds a key identified by `keyid` (an RFC 7638
 * thumbprint). Returns 0 if `keys` or `keyid` is NULL. */
ngx_flag_t ngx_auth_httpsig_keys_has(const ngx_auth_httpsig_keys_t *keys,
    const ngx_str_t *keyid);

/*
 * Reports whether `keys` holds a key whose raw JWK `kid` (not its RFC
 * 7638 thumbprint) matches `kid`. Diagnostic only: this module never
 * resolves a key by `kid` for verification, since a `kid`-keyed lookup
 * gives up the thumbprint's self-certifying property (a given keyid
 * value is guaranteed to name one specific public key). Use this only
 * to tell "keyid isn't a thumbprint of any key we hold, but matches a
 * raw kid" apart from "keyid matches nothing at all" when reporting
 * $httpsig_error. Returns 0 if `keys` or `kid` is NULL.
 */
ngx_flag_t ngx_auth_httpsig_keys_has_kid(const ngx_auth_httpsig_keys_t *keys,
    const ngx_str_t *kid);

/*
 * Verifies a detached signature against the key identified by `keyid`.
 *
 * Return value:
 *   NGX_OK        signature verified.
 *   NGX_DECLINED  no key with that keyid, or the signature did not
 *                 verify. Indistinguishable by design (oracle
 *                 resistance); use ngx_auth_httpsig_keys_has() first if
 *                 the caller needs to log the two cases separately.
 *   NGX_ERROR     a required argument is NULL.
 */
ngx_int_t ngx_auth_httpsig_keys_verify(const ngx_auth_httpsig_keys_t *keys,
    const ngx_str_t *keyid, const ngx_str_t *msg, const ngx_str_t *sig,
    ngx_pool_t *pool);

/* Releases the keyset's underlying key material. Safe to call with
 * NULL; safe to call more than once. */
void ngx_auth_httpsig_keys_free(ngx_auth_httpsig_keys_t *keys);

/*
 * Combines two keysets into one that tries `first` before `second` for
 * both ngx_auth_httpsig_keys_has() and ngx_auth_httpsig_keys_verify().
 * Intended for a dynamically fetched keyset (`first`) falling back to
 * the statically configured one (`second`), so an origin that serves a
 * key directory takes priority over a stale static entry for the same
 * keyid.
 *
 * Neither `first` nor `second` is freed by the combined keyset's
 * ngx_auth_httpsig_keys_free() -- ownership stays with whoever loaded
 * them.
 *
 * Returns `second` if `first` is NULL, `first` if `second` is NULL, a
 * combined keyset otherwise, or NULL if `pool` is NULL or allocation
 * fails.
 */
ngx_auth_httpsig_keys_t *ngx_auth_httpsig_keys_chain(ngx_pool_t *pool,
    ngx_auth_httpsig_keys_t *first, ngx_auth_httpsig_keys_t *second);


#endif /* NGX_AUTH_HTTPSIG_KEYS_H */
