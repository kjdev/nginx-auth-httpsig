/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * test_crypto.h - Ed25519 fixture helpers for the auth_httpsig unit
 * tests, trimmed from nxe-jwx's test_crypto.{c,h} (this module only
 * ever verifies Ed25519 signatures).
 */

#ifndef TEST_CRYPTO_H
#define TEST_CRYPTO_H


#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/evp.h>


/* Base64URL encode `len` bytes into a pool-allocated ngx_str_t (no padding). */
ngx_str_t test_b64url(const u_char *src, size_t len, ngx_pool_t *pool);

/* Generate an Ed25519 keypair (caller must EVP_PKEY_free). */
EVP_PKEY *test_gen_ed25519(void);

/*
 * Build an OKP JWK JSON literal (NOT wrapped in a JWKS document) for
 * the public part of `pkey`. `kid` and `alg` may be NULL.
 */
ngx_str_t test_jwk_okp(EVP_PKEY *pkey, const char *crv, size_t key_len,
    const char *kid, const char *alg, ngx_pool_t *pool);

/* Wrap one or more JWKs in a JWKS document {"keys":[...]}. */
ngx_str_t test_jwks_build(const ngx_str_t *jwks, size_t njwks,
    ngx_pool_t *pool);

/*
 * Sign `msg` with `pkey` using EdDSA (one-shot; Ed25519 does not
 * support streaming digest updates). Returns the raw 64-byte
 * signature in *out / *out_len, allocated on `pool`.
 */
ngx_int_t test_sign(EVP_PKEY *pkey, const u_char *msg, size_t msg_len,
    u_char **out, size_t *out_len, ngx_pool_t *pool);


#endif /* TEST_CRYPTO_H */
