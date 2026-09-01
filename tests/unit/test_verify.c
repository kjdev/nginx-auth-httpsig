/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * test_verify.c - coverage for Ed25519 signature verification against
 * a resolved keyset.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_keys.h"
#include "ngx_auth_httpsig_verify.h"
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


/*
 * Generates an Ed25519 keypair, loads it as a single-key JWKS (with
 * raw JWK `kid` set to `kid` when non-NULL), and signs `base`. Returns
 * the loaded keyset, the key's thumbprint, and the raw signature via
 * the out params; the caller must EVP_PKEY_free(*pkey_out).
 */
static ngx_int_t
build_fixture_kid(ngx_pool_t *pool, const ngx_str_t *base, const char *kid,
    ngx_auth_httpsig_keys_t **keys_out, ngx_str_t *thumbprint_out,
    ngx_str_t *signature_out, EVP_PKEY **pkey_out)
{
    EVP_PKEY        *pkey;
    ngx_str_t        jwk, jwks_json;
    nxe_jwx_jwks_t   *ref;
    u_char           *sig;
    size_t            sig_len;

    pkey = test_gen_ed25519();
    if (pkey == NULL) {
        return NGX_ERROR;
    }

    jwk = test_jwk_okp(pkey, "Ed25519", 32, kid, NULL, pool);
    if (jwk.data == NULL) {
        return NGX_ERROR;
    }

    jwks_json = test_jwks_build(&jwk, 1, pool);
    if (jwks_json.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_auth_httpsig_keys_load_jwks(pool, &jwks_json, NULL, NGX_LOG_EMERG, keys_out)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ref = nxe_jwx_jwks_parse(&jwks_json, pool);
    if (ref == NULL) {
        return NGX_ERROR;
    }

    if (nxe_jwx_jwks_thumbprint(ref, 0, thumbprint_out) != NGX_OK) {
        return NGX_ERROR;
    }

    if (test_sign(pkey, base->data, base->len, &sig, &sig_len, pool)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    signature_out->data = sig;
    signature_out->len = sig_len;

    *pkey_out = pkey;

    return NGX_OK;
}


static ngx_int_t
build_fixture(ngx_pool_t *pool, const ngx_str_t *base,
    ngx_auth_httpsig_keys_t **keys_out, ngx_str_t *thumbprint_out,
    ngx_str_t *signature_out, EVP_PKEY **pkey_out)
{
    return build_fixture_kid(pool, base, NULL, keys_out, thumbprint_out,
                              signature_out, pkey_out);
}


TEST(verify_success)
{
    ngx_auth_httpsig_keys_t   *keys;
    ngx_str_t                  base, thumbprint, signature;
    EVP_PKEY                  *pkey;
    ngx_auth_httpsig_result_t  result;

    base = str("this is the signature base string");

    ASSERT_EQ_INT(NGX_OK,
        build_fixture(pool, &base, &keys, &thumbprint, &signature, &pkey));

    ASSERT_EQ_INT(NGX_OK,
        ngx_auth_httpsig_verify_ed25519(pool, keys, &thumbprint, &base,
                                         &signature, &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_OK, result);

    ngx_auth_httpsig_keys_free(keys);
    EVP_PKEY_free(pkey);

    return 0;
}


TEST(verify_tampered_signature_is_mismatch)
{
    ngx_auth_httpsig_keys_t   *keys;
    ngx_str_t                  base, thumbprint, signature;
    EVP_PKEY                  *pkey;
    ngx_auth_httpsig_result_t  result;

    base = str("this is the signature base string");

    ASSERT_EQ_INT(NGX_OK,
        build_fixture(pool, &base, &keys, &thumbprint, &signature, &pkey));

    signature.data[0] ^= 0xff;

    ASSERT_EQ_INT(NGX_DECLINED,
        ngx_auth_httpsig_verify_ed25519(pool, keys, &thumbprint, &base,
                                         &signature, &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_SIGNATURE_MISMATCH, result);

    ngx_auth_httpsig_keys_free(keys);
    EVP_PKEY_free(pkey);

    return 0;
}


TEST(verify_unknown_keyid)
{
    ngx_auth_httpsig_keys_t   *keys;
    ngx_str_t                  base, thumbprint, signature, unknown;
    EVP_PKEY                  *pkey;
    ngx_auth_httpsig_result_t  result;

    base = str("this is the signature base string");

    ASSERT_EQ_INT(NGX_OK,
        build_fixture(pool, &base, &keys, &thumbprint, &signature, &pkey));

    unknown = str("no-such-key-in-the-set");

    ASSERT_EQ_INT(NGX_DECLINED,
        ngx_auth_httpsig_verify_ed25519(pool, keys, &unknown, &base,
                                         &signature, &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_UNKNOWN_KEYID, result);

    ngx_auth_httpsig_keys_free(keys);
    EVP_PKEY_free(pkey);

    return 0;
}


TEST(verify_non_thumbprint_keyid_reports_kid_label)
{
    ngx_auth_httpsig_keys_t   *keys;
    ngx_str_t                  base, thumbprint, signature, kid;
    EVP_PKEY                  *pkey;
    ngx_auth_httpsig_result_t  result;

    base = str("this is the signature base string");

    ASSERT_EQ_INT(NGX_OK,
        build_fixture_kid(pool, &base, "short-label", &keys, &thumbprint,
                           &signature, &pkey));

    kid = str("short-label");

    ASSERT_EQ_INT(NGX_DECLINED,
        ngx_auth_httpsig_verify_ed25519(pool, keys, &kid, &base,
                                         &signature, &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_KEYID_NOT_THUMBPRINT, result);

    ngx_auth_httpsig_keys_free(keys);
    EVP_PKEY_free(pkey);

    return 0;
}


TEST(verify_wrong_signature_length)
{
    ngx_auth_httpsig_keys_t   *keys;
    ngx_str_t                  base, thumbprint, signature, truncated;
    EVP_PKEY                  *pkey;
    ngx_auth_httpsig_result_t  result;

    base = str("this is the signature base string");

    ASSERT_EQ_INT(NGX_OK,
        build_fixture(pool, &base, &keys, &thumbprint, &signature, &pkey));

    truncated.data = signature.data;
    truncated.len = 10;

    ASSERT_EQ_INT(NGX_DECLINED,
        ngx_auth_httpsig_verify_ed25519(pool, keys, &thumbprint, &base,
                                         &truncated, &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_SIGNATURE_MISMATCH, result);

    ngx_auth_httpsig_keys_free(keys);
    EVP_PKEY_free(pkey);

    return 0;
}


TEST_SUITE(verify)
{
    RUN(verify_success);
    RUN(verify_tampered_signature_is_mismatch);
    RUN(verify_unknown_keyid);
    RUN(verify_non_thumbprint_keyid_reports_kid_label);
    RUN(verify_wrong_signature_length);
}
