/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * test_crypto.c - Ed25519 fixture helpers for the auth_httpsig unit
 * tests, trimmed from nxe-jwx's test_crypto.{c,h} (this module only
 * ever verifies Ed25519 signatures).
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "test_crypto.h"

#include <stdarg.h>
#include <stdio.h>


static u_char *test_pmprintf(ngx_pool_t *pool, const char *fmt, ...);


ngx_str_t
test_b64url(const u_char *src, size_t len, ngx_pool_t *pool)
{
    static const char  b64url[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz0123456789-_";
    ngx_str_t   dst;
    size_t      i;
    u_char     *p;
    ngx_uint_t  v;

    dst.data = ngx_pnalloc(pool, ((len + 2) / 3) * 4);
    if (dst.data == NULL) {
        dst.len = 0;
        return dst;
    }

    p = dst.data;
    i = 0;

    while (i + 3 <= len) {
        v = ((ngx_uint_t) src[i] << 16) | ((ngx_uint_t) src[i + 1] << 8)
            | (ngx_uint_t) src[i + 2];
        *p++ = b64url[(v >> 18) & 0x3f];
        *p++ = b64url[(v >> 12) & 0x3f];
        *p++ = b64url[(v >> 6) & 0x3f];
        *p++ = b64url[v & 0x3f];
        i += 3;
    }

    if (len - i == 1) {
        v = (ngx_uint_t) src[i] << 16;
        *p++ = b64url[(v >> 18) & 0x3f];
        *p++ = b64url[(v >> 12) & 0x3f];

    } else if (len - i == 2) {
        v = ((ngx_uint_t) src[i] << 16) | ((ngx_uint_t) src[i + 1] << 8);
        *p++ = b64url[(v >> 18) & 0x3f];
        *p++ = b64url[(v >> 12) & 0x3f];
        *p++ = b64url[(v >> 6) & 0x3f];
    }

    dst.len = (size_t) (p - dst.data);

    return dst;
}


EVP_PKEY *
test_gen_ed25519(void)
{
    EVP_PKEY_CTX  *ctx;
    EVP_PKEY      *pkey;

    pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (ctx == NULL) {
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);

    return pkey;
}


ngx_str_t
test_jwk_okp(EVP_PKEY *pkey, const char *crv, size_t key_len,
    const char *kid, const char *alg, ngx_pool_t *pool)
{
    u_char     raw[64];
    size_t     raw_len;
    ngx_str_t  x, null_str;
    u_char    *json;

    null_str.data = NULL;
    null_str.len = 0;

    raw_len = sizeof(raw);

    if (EVP_PKEY_get_raw_public_key(pkey, raw, &raw_len) != 1
        || raw_len != key_len)
    {
        return null_str;
    }

    x = test_b64url(raw, raw_len, pool);
    if (x.data == NULL) {
        return null_str;
    }

    json = test_pmprintf(pool,
        "{\"kty\":\"OKP\",\"crv\":\"%s\",\"x\":\"%.*s\"%s%s%s%s%s%s}",
        crv, (int) x.len, x.data,
        kid != NULL ? ",\"kid\":\"" : "",
        kid != NULL ? kid : "",
        kid != NULL ? "\"" : "",
        alg != NULL ? ",\"alg\":\"" : "",
        alg != NULL ? alg : "",
        alg != NULL ? "\"" : "");

    if (json == NULL) {
        return null_str;
    }

    null_str.data = json;
    null_str.len = ngx_strlen(json);

    return null_str;
}


ngx_str_t
test_jwks_build(const ngx_str_t *jwks, size_t njwks, ngx_pool_t *pool)
{
    ngx_str_t   out, null_str;
    u_char     *p;
    size_t      len, i;

    null_str.data = NULL;
    null_str.len = 0;

    len = sizeof("{\"keys\":[]}") - 1;

    for (i = 0; i < njwks; i++) {
        len += jwks[i].len + (i > 0 ? 1 : 0);
    }

    out.data = ngx_pnalloc(pool, len);
    if (out.data == NULL) {
        return null_str;
    }

    p = out.data;
    p = ngx_cpymem(p, "{\"keys\":[", sizeof("{\"keys\":[") - 1);

    for (i = 0; i < njwks; i++) {
        if (i > 0) {
            *p++ = ',';
        }

        p = ngx_cpymem(p, jwks[i].data, jwks[i].len);
    }

    p = ngx_cpymem(p, "]}", sizeof("]}") - 1);

    out.len = (size_t) (p - out.data);

    return out;
}


ngx_int_t
test_sign(EVP_PKEY *pkey, const u_char *msg, size_t msg_len,
    u_char **out, size_t *out_len, ngx_pool_t *pool)
{
    EVP_MD_CTX  *ctx;
    size_t       sig_len;
    u_char      *sig;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1) {
        EVP_MD_CTX_free(ctx);
        return NGX_ERROR;
    }

    if (EVP_DigestSign(ctx, NULL, &sig_len, msg, msg_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return NGX_ERROR;
    }

    sig = ngx_pnalloc(pool, sig_len);
    if (sig == NULL) {
        EVP_MD_CTX_free(ctx);
        return NGX_ERROR;
    }

    if (EVP_DigestSign(ctx, sig, &sig_len, msg, msg_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return NGX_ERROR;
    }

    EVP_MD_CTX_free(ctx);

    *out = sig;
    *out_len = sig_len;

    return NGX_OK;
}


static u_char *
test_pmprintf(ngx_pool_t *pool, const char *fmt, ...)
{
    va_list  args;
    int      n;
    size_t   size;
    u_char  *buf;

    va_start(args, fmt);
    n = vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    if (n < 0) {
        return NULL;
    }

    size = (size_t) n + 1;

    buf = ngx_pnalloc(pool, size);
    if (buf == NULL) {
        return NULL;
    }

    va_start(args, fmt);
    vsnprintf((char *) buf, size, fmt, args);
    va_end(args);

    return buf;
}
