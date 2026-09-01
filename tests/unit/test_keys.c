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
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_json, NULL, NGX_LOG_EMERG, &keys));
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
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_json, NULL, NGX_LOG_EMERG, &keys));
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
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_json, NULL, NGX_LOG_EMERG, &keys));
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
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_json, NULL, NGX_LOG_EMERG, &keys));
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
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_json, NULL, NGX_LOG_EMERG, &keys));
    ASSERT(keys == NULL);

    return 0;
}


TEST(keys_chain_prefers_first_when_both_have_keyid)
{
    EVP_PKEY                *pkey_a, *pkey_b;
    ngx_str_t                jwk_a, jwk_b, jwks_a, jwks_b, msg, sig;
    ngx_str_t                thumb_a, thumb_b;
    ngx_auth_httpsig_keys_t *first, *second, *chain;
    nxe_jwx_jwks_t           *ref_a, *ref_b;

    pkey_a = test_gen_ed25519();
    ASSERT(pkey_a != NULL);
    pkey_b = test_gen_ed25519();
    ASSERT(pkey_b != NULL);

    jwk_a = test_jwk_okp(pkey_a, "Ed25519", 32, NULL, NULL, pool);
    jwk_b = test_jwk_okp(pkey_b, "Ed25519", 32, NULL, NULL, pool);
    jwks_a = test_jwks_build(&jwk_a, 1, pool);
    jwks_b = test_jwks_build(&jwk_b, 1, pool);

    ref_a = nxe_jwx_jwks_parse(&jwks_a, pool);
    ASSERT(ref_a != NULL);
    ASSERT_EQ_INT(NGX_OK, nxe_jwx_jwks_thumbprint(ref_a, 0, &thumb_a));

    ref_b = nxe_jwx_jwks_parse(&jwks_b, pool);
    ASSERT(ref_b != NULL);
    ASSERT_EQ_INT(NGX_OK, nxe_jwx_jwks_thumbprint(ref_b, 0, &thumb_b));

    first = NULL;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_a, NULL, NGX_LOG_EMERG,
                                        &first));
    second = NULL;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_b, NULL, NGX_LOG_EMERG,
                                        &second));

    chain = ngx_auth_httpsig_keys_chain(pool, first, second);
    ASSERT(chain != NULL);

    /* Each keyid is only in one of the two keysets; the chain must
     * still resolve both, proving it tries both sources. */
    ASSERT(ngx_auth_httpsig_keys_has(chain, &thumb_a));
    ASSERT(ngx_auth_httpsig_keys_has(chain, &thumb_b));

    msg = str("test message");
    ASSERT_EQ_INT(NGX_OK,
        test_sign(pkey_a, msg.data, msg.len, &sig.data, &sig.len, pool));
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_verify(chain, &thumb_a, &msg, &sig, pool));

    ASSERT_EQ_INT(NGX_OK,
        test_sign(pkey_b, msg.data, msg.len, &sig.data, &sig.len, pool));
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_verify(chain, &thumb_b, &msg, &sig, pool));

    ngx_auth_httpsig_keys_free(first);
    ngx_auth_httpsig_keys_free(second);
    EVP_PKEY_free(pkey_a);
    EVP_PKEY_free(pkey_b);

    return 0;
}


TEST(keys_chain_first_null_returns_second)
{
    EVP_PKEY                *pkey;
    ngx_str_t                jwk, jwks_json;
    ngx_auth_httpsig_keys_t *second, *chain;

    pkey = test_gen_ed25519();
    ASSERT(pkey != NULL);

    jwk = test_jwk_okp(pkey, "Ed25519", 32, NULL, NULL, pool);
    jwks_json = test_jwks_build(&jwk, 1, pool);

    second = NULL;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_json, NULL,
                                        NGX_LOG_EMERG, &second));

    chain = ngx_auth_httpsig_keys_chain(pool, NULL, second);
    ASSERT(chain == second);

    ngx_auth_httpsig_keys_free(second);
    EVP_PKEY_free(pkey);

    return 0;
}


TEST(keys_chain_second_null_returns_first)
{
    EVP_PKEY                *pkey;
    ngx_str_t                jwk, jwks_json;
    ngx_auth_httpsig_keys_t *first, *chain;

    pkey = test_gen_ed25519();
    ASSERT(pkey != NULL);

    jwk = test_jwk_okp(pkey, "Ed25519", 32, NULL, NULL, pool);
    jwks_json = test_jwks_build(&jwk, 1, pool);

    first = NULL;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_json, NULL,
                                        NGX_LOG_EMERG, &first));

    chain = ngx_auth_httpsig_keys_chain(pool, first, NULL);
    ASSERT(chain == first);

    ngx_auth_httpsig_keys_free(first);
    EVP_PKEY_free(pkey);

    return 0;
}


TEST(keys_has_kid_matches_label_not_thumbprint)
{
    EVP_PKEY                *pkey;
    ngx_str_t                jwk, jwks_json, thumbprint, kid;
    ngx_auth_httpsig_keys_t *keys;
    nxe_jwx_jwks_t           *ref;

    pkey = test_gen_ed25519();
    ASSERT(pkey != NULL);

    kid = str("short-label");

    jwk = test_jwk_okp(pkey, "Ed25519", 32, (const char *) kid.data, NULL,
                        pool);
    ASSERT(jwk.data != NULL);

    jwks_json = test_jwks_build(&jwk, 1, pool);
    ASSERT(jwks_json.data != NULL);

    keys = NULL;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_json, NULL, NGX_LOG_EMERG, &keys));
    ASSERT(keys != NULL);

    ref = nxe_jwx_jwks_parse(&jwks_json, pool);
    ASSERT(ref != NULL);
    ASSERT_EQ_INT(NGX_OK, nxe_jwx_jwks_thumbprint(ref, 0, &thumbprint));

    ASSERT(!ngx_auth_httpsig_keys_has(keys, &kid));
    ASSERT(ngx_auth_httpsig_keys_has_kid(keys, &kid));

    ASSERT(ngx_auth_httpsig_keys_has(keys, &thumbprint));
    ASSERT(!ngx_auth_httpsig_keys_has_kid(keys, &thumbprint));

    ngx_auth_httpsig_keys_free(keys);
    EVP_PKEY_free(pkey);

    return 0;
}


TEST(keys_chain_has_kid_checks_both)
{
    EVP_PKEY                *pkey_a, *pkey_b;
    ngx_str_t                jwk_a, jwk_b, jwks_a, jwks_b, kid_a, kid_b;
    ngx_auth_httpsig_keys_t *first, *second, *chain;

    pkey_a = test_gen_ed25519();
    ASSERT(pkey_a != NULL);
    pkey_b = test_gen_ed25519();
    ASSERT(pkey_b != NULL);

    kid_a = str("label-a");
    kid_b = str("label-b");

    jwk_a = test_jwk_okp(pkey_a, "Ed25519", 32, (const char *) kid_a.data,
                          NULL, pool);
    jwk_b = test_jwk_okp(pkey_b, "Ed25519", 32, (const char *) kid_b.data,
                          NULL, pool);
    jwks_a = test_jwks_build(&jwk_a, 1, pool);
    jwks_b = test_jwks_build(&jwk_b, 1, pool);

    first = NULL;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_a, NULL, NGX_LOG_EMERG,
                                        &first));
    second = NULL;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_b, NULL, NGX_LOG_EMERG,
                                        &second));

    chain = ngx_auth_httpsig_keys_chain(pool, first, second);
    ASSERT(chain != NULL);

    ASSERT(ngx_auth_httpsig_keys_has_kid(chain, &kid_a));
    ASSERT(ngx_auth_httpsig_keys_has_kid(chain, &kid_b));

    ngx_auth_httpsig_keys_free(first);
    ngx_auth_httpsig_keys_free(second);
    EVP_PKEY_free(pkey_a);
    EVP_PKEY_free(pkey_b);

    return 0;
}


TEST(keys_chain_same_keyid_in_both_resolves)
{
    EVP_PKEY                *pkey;
    ngx_str_t                jwk, jwks_a, jwks_b, msg, sig;
    ngx_str_t                thumb;
    ngx_auth_httpsig_keys_t *first, *second, *chain;
    nxe_jwx_jwks_t           *ref;

    /* The RFC 7638 thumbprint depends only on the public key material
     * (kty/crv/x), so the only way for `first` and `second` to
     * genuinely share a keyid is to load the same key into both --
     * this covers a key directory response that happens to republish
     * a keyid already present in the static JWKS. */
    pkey = test_gen_ed25519();
    ASSERT(pkey != NULL);

    jwk = test_jwk_okp(pkey, "Ed25519", 32, NULL, NULL, pool);
    jwks_a = test_jwks_build(&jwk, 1, pool);
    jwks_b = test_jwks_build(&jwk, 1, pool);

    ref = nxe_jwx_jwks_parse(&jwks_a, pool);
    ASSERT(ref != NULL);
    ASSERT_EQ_INT(NGX_OK, nxe_jwx_jwks_thumbprint(ref, 0, &thumb));

    first = NULL;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_a, NULL, NGX_LOG_EMERG,
                                        &first));
    second = NULL;
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_load_jwks(pool, &jwks_b, NULL, NGX_LOG_EMERG,
                                        &second));

    chain = ngx_auth_httpsig_keys_chain(pool, first, second);
    ASSERT(chain != NULL);

    ASSERT(ngx_auth_httpsig_keys_has(chain, &thumb));

    msg = str("test message");
    ASSERT_EQ_INT(NGX_OK,
        test_sign(pkey, msg.data, msg.len, &sig.data, &sig.len, pool));
    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_keys_verify(chain, &thumb, &msg, &sig, pool));

    ngx_auth_httpsig_keys_free(first);
    ngx_auth_httpsig_keys_free(second);
    EVP_PKEY_free(pkey);

    return 0;
}


TEST_SUITE(keys)
{
    RUN(keys_thumbprint_match_and_mismatch);
    RUN(keys_reject_mixed_kty);
    RUN(keys_reject_non_ed25519_curve);
    RUN(keys_reject_too_many_keys);
    RUN(keys_reject_oversized_document);
    RUN(keys_chain_prefers_first_when_both_have_keyid);
    RUN(keys_chain_first_null_returns_second);
    RUN(keys_chain_second_null_returns_first);
    RUN(keys_has_kid_matches_label_not_thumbprint);
    RUN(keys_chain_has_kid_checks_both);
    RUN(keys_chain_same_keyid_in_both_resolves);
}
