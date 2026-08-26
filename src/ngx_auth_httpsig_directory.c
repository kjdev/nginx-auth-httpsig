/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_directory.c - host allow-list normalization/matching
 * and Cache-Control-derived TTL clamping for the dynamic key
 * directory. No nginx string helpers beyond ngx_core primitives are
 * assumed (ngx_atoi/ngx_strlchr are deliberately not used, so this
 * file also builds against the unit-test shim).
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_directory.h"


/* Leaves three orders of magnitude of headroom below the largest
 * representable time_t, so "value = value * 10 + digit" can never
 * itself overflow (signed overflow is undefined behavior) even on the
 * step that reaches the cap. */
#define NGX_AUTH_HTTPSIG_TTL_PARSE_CAP \
        ((time_t) (NGX_MAX_INT_T_VALUE / 1000))


static ngx_flag_t ngx_auth_httpsig_directory_is_host_char(u_char c);
static void ngx_auth_httpsig_directory_trim(ngx_str_t *s);
static ngx_flag_t ngx_auth_httpsig_directory_token_is(
    const ngx_str_t *token, const char *name);
static time_t ngx_auth_httpsig_directory_parse_uint(u_char *p, size_t len,
    size_t *consumed);
static ngx_int_t ngx_auth_httpsig_directory_parse_directive(
    const ngx_str_t *token, const char *name, time_t *value);


ngx_int_t
ngx_auth_httpsig_directory_normalize_host(ngx_pool_t *pool,
    const ngx_str_t *in, ngx_str_t *out,
    ngx_auth_httpsig_host_reason_t *reason)
{
    u_char *p;
    size_t i, len;

    if (pool == NULL || in == NULL || out == NULL) {
        return NGX_ERROR;
    }

    if (in->len == 0) {
        if (reason != NULL) {
            *reason = NGX_AUTH_HTTPSIG_HOST_EMPTY;
        }

        return NGX_ERROR;
    }

    p = in->data;

    for (i = 0; i + 3 <= in->len; i++) {
        if (p[i] == ':' && p[i + 1] == '/' && p[i + 2] == '/') {
            if (reason != NULL) {
                *reason = NGX_AUTH_HTTPSIG_HOST_HAS_SCHEME;
            }

            return NGX_ERROR;
        }
    }

    for (i = 0; i < in->len; i++) {
        if (p[i] == '*') {
            if (reason != NULL) {
                *reason = NGX_AUTH_HTTPSIG_HOST_WILDCARD;
            }

            return NGX_ERROR;
        }
    }

    for (i = 0; i < in->len; i++) {
        if (!ngx_auth_httpsig_directory_is_host_char(p[i])) {
            if (reason != NULL) {
                *reason = NGX_AUTH_HTTPSIG_HOST_INVALID_CHAR;
            }

            return NGX_ERROR;
        }
    }

    len = in->len;

    out->data = ngx_pnalloc(pool, len);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < len; i++) {
        out->data[i] = ngx_tolower(p[i]);
    }

    out->len = len;

    /* The default HTTPS port carries no matching information (ADR
     * 0012 pins this fetch path to HTTPS); ":8443" and other
     * non-default ports are left intact. */
    if (out->len > 4 && ngx_memcmp(out->data + out->len - 4, ":443", 4) == 0) {
        out->len -= 4;
    }

    return NGX_OK;
}


ngx_flag_t
ngx_auth_httpsig_directory_allowed(const ngx_array_t *allow,
    const ngx_str_t *host)
{
    ngx_str_t *entries;
    ngx_uint_t i;

    if (allow == NULL || allow->nelts == 0 || host == NULL) {
        return 0;
    }

    entries = allow->elts;

    for (i = 0; i < allow->nelts; i++) {
        if (entries[i].len == host->len
            && ngx_memcmp(entries[i].data, host->data, host->len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


time_t
ngx_auth_httpsig_directory_ttl(const ngx_str_t *cache_control, time_t age,
    time_t min_ttl, time_t max_ttl)
{
    u_char *p, *end, *tok_start;
    ngx_str_t token;
    ngx_flag_t forbid, have_maxage, have_smaxage;
    time_t maxage_val, smaxage_val, derived, value;

    forbid = 0;
    have_maxage = 0;
    have_smaxage = 0;
    maxage_val = 0;
    smaxage_val = 0;

    if (cache_control != NULL && cache_control->len > 0) {
        p = cache_control->data;
        end = p + cache_control->len;

        while (p < end) {
            tok_start = p;

            while (p < end && *p != ',') {
                p++;
            }

            token.data = tok_start;
            token.len = (size_t) (p - tok_start);
            ngx_auth_httpsig_directory_trim(&token);

            if (token.len > 0) {
                if (ngx_auth_httpsig_directory_token_is(&token, "no-store")
                    || ngx_auth_httpsig_directory_token_is(&token,
                                                           "no-cache")
                    || ngx_auth_httpsig_directory_token_is(&token, "private"))
                {
                    forbid = 1;

                } else if (ngx_auth_httpsig_directory_parse_directive(&token,
                                                                      "s-maxage",
                                                                      &
                                                                      smaxage_val)
                           == NGX_OK)
                {
                    have_smaxage = 1;

                } else if (ngx_auth_httpsig_directory_parse_directive(&token,
                                                                      "max-age",
                                                                      &
                                                                      maxage_val)
                           == NGX_OK)
                {
                    have_maxage = 1;
                }
            }

            if (p < end) {
                p++;
            }
        }
    }

    /* no-store/no-cache/private and an absent/unparseable max-age all
     * derive the same pre-clamp value: min_ttl is a floor regardless
     * of what the origin claims, not a signal to skip caching (ADR
     * 0014.2), so there is nothing to distinguish here. */
    derived = 0;

    if (have_maxage) {
        derived = maxage_val;
    }

    /* s-maxage wins over max-age regardless of the order the two
     * directives appear in the header. */
    if (have_smaxage) {
        derived = smaxage_val;
    }

    if (forbid) {
        derived = 0;
    }

    value = derived - age;

    if (value < 0) {
        value = 0;
    }

    if (value < min_ttl) {
        value = min_ttl;
    }

    if (value > max_ttl) {
        value = max_ttl;
    }

    return value;
}


static ngx_flag_t
ngx_auth_httpsig_directory_is_host_char(u_char c)
{
    return (c >= 'a' && c <= 'z')
           || (c >= 'A' && c <= 'Z')
           || (c >= '0' && c <= '9')
           || c == '.' || c == '-' || c == ':';
}


static void
ngx_auth_httpsig_directory_trim(ngx_str_t *s)
{
    while (s->len > 0 && (*s->data == ' ' || *s->data == '\t')) {
        s->data++;
        s->len--;
    }

    while (s->len > 0
           && (s->data[s->len - 1] == ' ' || s->data[s->len - 1] == '\t'))
    {
        s->len--;
    }
}


static ngx_flag_t
ngx_auth_httpsig_directory_token_is(const ngx_str_t *token, const char *name)
{
    size_t name_len;

    name_len = ngx_strlen(name);

    return token->len == name_len
           && ngx_strncasecmp(token->data, (u_char *) name, name_len) == 0;
}


/* Hand-rolled instead of ngx_atoi(): ngx_atoi() is unavailable in the
 * unit-test shim and, in production, returns NGX_ERROR on overflow,
 * which would send an enormous max-age down the "unparseable" path
 * instead of the "at least max_ttl" path. */
static time_t
ngx_auth_httpsig_directory_parse_uint(u_char *p, size_t len,
    size_t *consumed)
{
    time_t value;
    size_t i;

    value = 0;

    for (i = 0; i < len; i++) {
        if (p[i] < '0' || p[i] > '9') {
            break;
        }

        if (value < NGX_AUTH_HTTPSIG_TTL_PARSE_CAP) {
            value = value * 10 + (p[i] - '0');

        } else {
            value = NGX_AUTH_HTTPSIG_TTL_PARSE_CAP;
        }
    }

    *consumed = i;

    return value;
}


ngx_int_t
ngx_auth_httpsig_directory_check_response(const ngx_str_t *schema,
    ngx_uint_t status, const ngx_str_t *content_type,
    const ngx_str_t *media_type, size_t body_len, size_t max_size,
    ngx_auth_httpsig_fetch_reason_t *reason)
{
    ngx_str_t type;
    size_t i;

    if (schema == NULL || reason == NULL) {
        return NGX_ERROR;
    }

    *reason = NGX_AUTH_HTTPSIG_FETCH_OK;

    if (schema->len != 5 || ngx_strncasecmp(schema->data, (u_char *) "https", 5)
        != 0)
    {
        *reason = NGX_AUTH_HTTPSIG_FETCH_NOT_HTTPS;
        return NGX_DECLINED;
    }

    if (status >= 300 && status <= 399) {
        *reason = NGX_AUTH_HTTPSIG_FETCH_REDIRECT;
        return NGX_DECLINED;
    }

    if (status != 200) {
        *reason = NGX_AUTH_HTTPSIG_FETCH_STATUS;
        return NGX_DECLINED;
    }

    type.data = (content_type != NULL) ? content_type->data : NULL;
    type.len = (content_type != NULL) ? content_type->len : 0;

    for (i = 0; i < type.len; i++) {
        if (type.data[i] == ';') {
            type.len = i;
            break;
        }
    }

    ngx_auth_httpsig_directory_trim(&type);

    if (type.len == 0
        || !((media_type != NULL && media_type->len > 0
              && type.len == media_type->len
              && ngx_strncasecmp(type.data, media_type->data, type.len) == 0)
             || ngx_auth_httpsig_directory_token_is(&type, "application/json")))
    {
        *reason = NGX_AUTH_HTTPSIG_FETCH_MEDIA_TYPE;
        return NGX_DECLINED;
    }

    if (body_len > max_size) {
        *reason = NGX_AUTH_HTTPSIG_FETCH_TOO_LARGE;
        return NGX_DECLINED;
    }

    if (body_len == 0) {
        *reason = NGX_AUTH_HTTPSIG_FETCH_EMPTY;
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_auth_httpsig_directory_parse_directive(const ngx_str_t *token,
    const char *name, time_t *value)
{
    size_t name_len, pos, consumed;

    name_len = ngx_strlen(name);

    if (token->len < name_len
        || ngx_strncasecmp(token->data, (u_char *) name, name_len) != 0)
    {
        return NGX_DECLINED;
    }

    pos = name_len;

    while (pos < token->len
           && (token->data[pos] == ' ' || token->data[pos] == '\t'))
    {
        pos++;
    }

    if (pos >= token->len || token->data[pos] != '=') {
        return NGX_DECLINED;
    }

    pos++;

    while (pos < token->len
           && (token->data[pos] == ' ' || token->data[pos] == '\t'))
    {
        pos++;
    }

    *value = ngx_auth_httpsig_directory_parse_uint(token->data + pos,
                                                   token->len - pos,
                                                   &consumed);

    if (consumed == 0) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}
