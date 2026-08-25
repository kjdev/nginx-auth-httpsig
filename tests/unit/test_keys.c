/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * test_keys.c - coverage for JWKS-backed key resolution: RFC 7638
 * thumbprint lookup and the Ed25519-only rejection rules.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_keys.h"
#include "test.h"
#include "test_crypto.h"

#include <nxe_jwx.h>


static ngx_str_t
str(const char *s)
{
    ngx_str_t v;

    v.data = (u_char *) s;
    v.len = ngx_strlen(v.data);

    return v;
}


TEST(keys_thumbprint_match_and_mismatch)
{
    EVP_PKEY                *pkey;
    ngx_str_t                jwk, jwks_json, thumbprint, bogus;
    ngx_auth_httpsig_keys_t *keys;
    nxe_jwx_jwks_t           *ref;

    pkey = test_gen_ed25519();
    ASSERT(pkey != NULL);

    jwk = test_jwk_okp(pkey, "Ed25519", 32, NULL, NULL, pool);
    ASSERT(jwk.data != NULL);

    jwks_json = test_jwks_build(&jwk, 1, pool);
    ASSERT(jwks_json.data != NULL);

    keys = NULL;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_json, NULL, &keys));
    ASSERT(keys != NULL);

    /* Independently re-parse the same JWKS to obtain the expected
     * thumbprint, rather than reaching into keys->data: the keys layer
     * deliberately keeps that field opaque. */
    ref = nxe_jwx_jwks_parse(&jwks_json, pool);
    ASSERT(ref != NULL);
    ASSERT_EQ_INT(NGX_OK, nxe_jwx_jwks_thumbprint(ref, 0, &thumbprint));

    ASSERT(ngx_auth_httpsig_keys_has(keys, &thumbprint));

    bogus = str("not-a-real-thumbprint");
    ASSERT(!ngx_auth_httpsig_keys_has(keys, &bogus));

    ngx_auth_httpsig_keys_free(keys);
    EVP_PKEY_free(pkey);

    return 0;
}


TEST(keys_reject_mixed_kty)
{
    EVP_PKEY                *pkey;
    ngx_str_t                jwks[2], jwks_json;
    ngx_auth_httpsig_keys_t *keys;

    pkey = test_gen_ed25519();
    ASSERT(pkey != NULL);

    jwks[0] = test_jwk_okp(pkey, "Ed25519", 32, NULL, NULL, pool);
    ASSERT(jwks[0].data != NULL);

    jwks[1] = str("{\"kty\":\"EC\",\"crv\":\"P-256\","
                   "\"x\":\"AAAA\",\"y\":\"AAAA\"}");

    jwks_json = test_jwks_build(jwks, 2, pool);
    ASSERT(jwks_json.data != NULL);

    keys = NULL;
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_json, NULL, &keys));
    ASSERT(keys == NULL);

    EVP_PKEY_free(pkey);

    return 0;
}


TEST(keys_reject_non_ed25519_curve)
{
    ngx_str_t                 jwk, jwks_json;
    ngx_auth_httpsig_keys_t  *keys;

    jwk = str("{\"kty\":\"OKP\",\"crv\":\"Ed448\",\"x\":\"AAAA\"}");
    jwks_json = test_jwks_build(&jwk, 1, pool);
    ASSERT(jwks_json.data != NULL);

    keys = NULL;
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_json, NULL, &keys));
    ASSERT(keys == NULL);

    return 0;
}


TEST(keys_reject_too_many_keys)
{
    EVP_PKEY                *pkey;
    ngx_str_t                jwk, jwks_json;
    ngx_str_t                jwks[NGX_AUTH_HTTPSIG_MAX_JWKS_KEYS + 1];
    ngx_auth_httpsig_keys_t *keys;
    ngx_uint_t               i;

    pkey = test_gen_ed25519();
    ASSERT(pkey != NULL);

    jwk = test_jwk_okp(pkey, "Ed25519", 32, NULL, NULL, pool);
    ASSERT(jwk.data != NULL);

    for (i = 0; i < NGX_AUTH_HTTPSIG_MAX_JWKS_KEYS + 1; i++) {
        jwks[i] = jwk;
    }

    jwks_json = test_jwks_build(jwks, NGX_AUTH_HTTPSIG_MAX_JWKS_KEYS + 1,
                                 pool);
    ASSERT(jwks_json.data != NULL);

    keys = NULL;
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_json, NULL, &keys));
    ASSERT(keys == NULL);

    EVP_PKEY_free(pkey);

    return 0;
}


TEST(keys_reject_oversized_document)
{
    ngx_str_t                 jwks_json;
    ngx_auth_httpsig_keys_t  *keys;

    jwks_json.len = NGX_AUTH_HTTPSIG_MAX_JWKS_SIZE + 1;
    jwks_json.data = ngx_pnalloc(pool, jwks_json.len);
    ASSERT(jwks_json.data != NULL);
    ngx_memset(jwks_json.data, 'A', jwks_json.len);

    keys = NULL;
    ASSERT_EQ_INT(NGX_ERROR,
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_json, NULL, &keys));
    ASSERT(keys == NULL);

    return 0;
}


TEST_SUITE(keys)
{
    RUN(keys_thumbprint_match_and_mismatch);
    RUN(keys_reject_mixed_kty);
    RUN(keys_reject_non_ed25519_curve);
    RUN(keys_reject_too_many_keys);
    RUN(keys_reject_oversized_document);
}
