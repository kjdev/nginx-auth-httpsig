/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_sfv.h"


typedef struct {
    ngx_pool_t                   *pool;
    const u_char                 *start;
    const u_char                 *pos;
    const u_char                 *last;
    ngx_uint_t                    depth;
    ngx_auth_httpsig_sfv_error_t *err;
} ngx_auth_httpsig_sfv_ctx_t;

typedef struct {
    ngx_pool_t  *pool;
    ngx_array_t *buf;    /* u_char */
} ngx_auth_httpsig_sfv_wbuf_t;


static ngx_int_t ngx_auth_httpsig_sfv_fail(ngx_auth_httpsig_sfv_ctx_t *ctx,
    const char *reason);
static void ngx_auth_httpsig_sfv_skip_ows(ngx_auth_httpsig_sfv_ctx_t *ctx);
static void ngx_auth_httpsig_sfv_skip_sp(ngx_auth_httpsig_sfv_ctx_t *ctx);

static ngx_int_t ngx_auth_httpsig_sfv_read_key(ngx_auth_httpsig_sfv_ctx_t *ctx,
    ngx_str_t *out);
static ngx_int_t ngx_auth_httpsig_sfv_read_string(
    ngx_auth_httpsig_sfv_ctx_t *ctx, ngx_str_t *out);
static ngx_int_t ngx_auth_httpsig_sfv_read_byte_sequence(
    ngx_auth_httpsig_sfv_ctx_t *ctx, ngx_str_t *out);
static ngx_int_t ngx_auth_httpsig_sfv_read_boolean(
    ngx_auth_httpsig_sfv_ctx_t *ctx, ngx_auth_httpsig_sfv_bare_t *out);
static ngx_int_t ngx_auth_httpsig_sfv_read_token(
    ngx_auth_httpsig_sfv_ctx_t *ctx, ngx_str_t *out);
static ngx_int_t ngx_auth_httpsig_sfv_read_number(
    ngx_auth_httpsig_sfv_ctx_t *ctx, ngx_auth_httpsig_sfv_bare_t *out);
static ngx_int_t ngx_auth_httpsig_sfv_read_bare_item(
    ngx_auth_httpsig_sfv_ctx_t *ctx, ngx_auth_httpsig_sfv_bare_t *out);
static ngx_int_t ngx_auth_httpsig_sfv_read_parameters(
    ngx_auth_httpsig_sfv_ctx_t *ctx, ngx_array_t **out);
static ngx_int_t ngx_auth_httpsig_sfv_read_item(ngx_auth_httpsig_sfv_ctx_t *ctx,
    ngx_auth_httpsig_sfv_item_t *out);
static ngx_int_t ngx_auth_httpsig_sfv_read_inner_list(
    ngx_auth_httpsig_sfv_ctx_t *ctx, ngx_auth_httpsig_sfv_inner_list_t *out);
static ngx_int_t ngx_auth_httpsig_sfv_read_member(
    ngx_auth_httpsig_sfv_ctx_t *ctx, ngx_auth_httpsig_sfv_value_t *out);
static ngx_int_t ngx_auth_httpsig_sfv_read_dictionary(
    ngx_auth_httpsig_sfv_ctx_t *ctx, ngx_auth_httpsig_sfv_dictionary_t *out);
static ngx_int_t ngx_auth_httpsig_sfv_read_list(ngx_auth_httpsig_sfv_ctx_t *ctx,
    ngx_auth_httpsig_sfv_list_t *out);

static ngx_int_t ngx_auth_httpsig_sfv_wbuf_init(ngx_auth_httpsig_sfv_wbuf_t *w,
    ngx_pool_t *pool);
static ngx_int_t ngx_auth_httpsig_sfv_wbuf_put(ngx_auth_httpsig_sfv_wbuf_t *w,
    const u_char *data, size_t len);
static ngx_int_t ngx_auth_httpsig_sfv_wbuf_putc(ngx_auth_httpsig_sfv_wbuf_t *w,
    u_char c);
static void ngx_auth_httpsig_sfv_wbuf_finish(ngx_auth_httpsig_sfv_wbuf_t *w,
    ngx_str_t *out);

static ngx_int_t ngx_auth_httpsig_sfv_write_integer(
    ngx_auth_httpsig_sfv_wbuf_t *w, int64_t v);
static ngx_int_t ngx_auth_httpsig_sfv_write_decimal(
    ngx_auth_httpsig_sfv_wbuf_t *w, int64_t v);
static ngx_int_t ngx_auth_httpsig_sfv_write_string(
    ngx_auth_httpsig_sfv_wbuf_t *w, const ngx_str_t *value);
static ngx_int_t ngx_auth_httpsig_sfv_write_byte_sequence(
    ngx_auth_httpsig_sfv_wbuf_t *w, const ngx_str_t *value);
static ngx_int_t ngx_auth_httpsig_sfv_write_boolean(
    ngx_auth_httpsig_sfv_wbuf_t *w, int64_t v);
static ngx_int_t ngx_auth_httpsig_sfv_write_bare_item(
    ngx_auth_httpsig_sfv_wbuf_t *w, const ngx_auth_httpsig_sfv_bare_t *bare);
static ngx_int_t ngx_auth_httpsig_sfv_write_params(
    ngx_auth_httpsig_sfv_wbuf_t *w, const ngx_array_t *params);
static ngx_int_t ngx_auth_httpsig_sfv_write_item(
    ngx_auth_httpsig_sfv_wbuf_t *w, const ngx_auth_httpsig_sfv_item_t *item);
static ngx_int_t ngx_auth_httpsig_sfv_write_inner_list(
    ngx_auth_httpsig_sfv_wbuf_t *w,
    const ngx_auth_httpsig_sfv_inner_list_t *list);


static ngx_int_t
ngx_auth_httpsig_sfv_fail(ngx_auth_httpsig_sfv_ctx_t *ctx, const char *reason)
{
    if (ctx->err != NULL) {
        ctx->err->offset = (ngx_uint_t) (ctx->pos - ctx->start);
        ctx->err->reason = reason;
    }

    return NGX_DECLINED;
}


static void
ngx_auth_httpsig_sfv_skip_ows(ngx_auth_httpsig_sfv_ctx_t *ctx)
{
    while (ctx->pos < ctx->last && (*ctx->pos == ' ' || *ctx->pos == '\t')) {
        ctx->pos++;
    }
}


static void
ngx_auth_httpsig_sfv_skip_sp(ngx_auth_httpsig_sfv_ctx_t *ctx)
{
    while (ctx->pos < ctx->last && *ctx->pos == ' ') {
        ctx->pos++;
    }
}


static ngx_inline ngx_flag_t
ngx_auth_httpsig_sfv_is_lcalpha(u_char c)
{
    return (c >= 'a' && c <= 'z') ? 1 : 0;
}


static ngx_inline ngx_flag_t
ngx_auth_httpsig_sfv_is_digit(u_char c)
{
    return (c >= '0' && c <= '9') ? 1 : 0;
}


static ngx_inline ngx_flag_t
ngx_auth_httpsig_sfv_is_alpha(u_char c)
{
    return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) ? 1 : 0;
}


static ngx_inline ngx_flag_t
ngx_auth_httpsig_sfv_is_key_char(u_char c)
{
    return (ngx_auth_httpsig_sfv_is_lcalpha(c)
            || ngx_auth_httpsig_sfv_is_digit(c)
            || c == '_' || c == '-' || c == '.' || c == '*') ? 1 : 0;
}


static ngx_inline ngx_flag_t
ngx_auth_httpsig_sfv_is_tchar(u_char c)
{
    return (ngx_auth_httpsig_sfv_is_alpha(c) || ngx_auth_httpsig_sfv_is_digit(c)
            || c == '!' || c == '#' || c == '$' || c == '%' || c == '&'
            || c == '\'' || c == '*' || c == '+' || c == '-' || c == '.'
            || c == '^' || c == '_' || c == '`' || c == '|' || c == '~')
           ? 1 : 0;
}


static ngx_inline ngx_flag_t
ngx_auth_httpsig_sfv_is_token_char(u_char c)
{
    return (ngx_auth_httpsig_sfv_is_tchar(c) || c == ':' || c == '/') ? 1 : 0;
}


static ngx_int_t
ngx_auth_httpsig_sfv_read_key(ngx_auth_httpsig_sfv_ctx_t *ctx, ngx_str_t *out)
{
    const u_char *start;

    if (ctx->pos >= ctx->last
        || !(ngx_auth_httpsig_sfv_is_lcalpha(*ctx->pos) || *ctx->pos == '*'))
    {
        return ngx_auth_httpsig_sfv_fail(ctx, "invalid key");
    }

    start = ctx->pos;
    ctx->pos++;

    while (ctx->pos < ctx->last
           && ngx_auth_httpsig_sfv_is_key_char(*ctx->pos))
    {
        ctx->pos++;
    }

    out->data = (u_char *) start;
    out->len = (size_t) (ctx->pos - start);

    return NGX_OK;
}


static ngx_int_t
ngx_auth_httpsig_sfv_read_string(ngx_auth_httpsig_sfv_ctx_t *ctx,
    ngx_str_t *out)
{
    const u_char *start, *p;
    u_char *buf, *d, c;
    ngx_uint_t escapes;

    if (ctx->pos >= ctx->last || *ctx->pos != '"') {
        return ngx_auth_httpsig_sfv_fail(ctx, "invalid string");
    }

    ctx->pos++;
    start = ctx->pos;
    escapes = 0;

    for ( ;; ) {
        if (ctx->pos >= ctx->last) {
            return ngx_auth_httpsig_sfv_fail(ctx, "unterminated string");
        }

        c = *ctx->pos;

        if (c == '"') {
            break;
        }

        if (c == '\\') {
            ctx->pos++;

            if (ctx->pos >= ctx->last
                || (*ctx->pos != '"' && *ctx->pos != '\\'))
            {
                return ngx_auth_httpsig_sfv_fail(ctx, "invalid string escape");
            }

            escapes++;
            ctx->pos++;
            continue;
        }

        if (c < 0x20 || c > 0x7e) {
            return ngx_auth_httpsig_sfv_fail(ctx, "invalid string character");
        }

        ctx->pos++;
    }

    if (escapes == 0) {
        out->data = (u_char *) start;
        out->len = (size_t) (ctx->pos - start);
        ctx->pos++;

        return NGX_OK;
    }

    buf = ngx_palloc(ctx->pool, (size_t) (ctx->pos - start) - escapes);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    d = buf;
    p = start;

    while (p < ctx->pos) {
        if (*p == '\\') {
            p++;
        }

        *d++ = *p++;
    }

    ctx->pos++;

    out->data = buf;
    out->len = (size_t) (d - buf);

    return NGX_OK;
}


static ngx_int_t
ngx_auth_httpsig_sfv_read_byte_sequence(ngx_auth_httpsig_sfv_ctx_t *ctx,
    ngx_str_t *out)
{
    ngx_str_t encoded;
    const u_char *start;
    ngx_uint_t i, pad;

    if (ctx->pos >= ctx->last || *ctx->pos != ':') {
        return ngx_auth_httpsig_sfv_fail(ctx, "invalid byte sequence");
    }

    ctx->pos++;
    start = ctx->pos;

    while (ctx->pos < ctx->last && *ctx->pos != ':') {
        ctx->pos++;
    }

    if (ctx->pos >= ctx->last) {
        return ngx_auth_httpsig_sfv_fail(ctx, "unterminated byte sequence");
    }

    encoded.data = (u_char *) start;
    encoded.len = (size_t) (ctx->pos - start);
    ctx->pos++;

    /*
     * ngx_decode_base64() stops at the first '=' and ignores everything
     * after it, so it accepts "=" padding that is not confined to the
     * end of the content (e.g. leading or interior "="). RFC 8941
     * requires "=" to appear only as trailing padding, so that has to be
     * checked here before handing the content to ngx_decode_base64().
     */

    pad = 0;

    for (i = 0; i < encoded.len; i++) {
        if (encoded.data[i] == '=') {
            pad++;
            continue;
        }

        if (pad > 0) {
            return ngx_auth_httpsig_sfv_fail(ctx,
                                             "invalid byte sequence padding");
        }
    }

    if (pad > 2) {
        return ngx_auth_httpsig_sfv_fail(ctx, "invalid byte sequence padding");
    }

    out->data = ngx_palloc(ctx->pool, ngx_base64_decoded_length(encoded.len));
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64(out, &encoded) != NGX_OK) {
        return ngx_auth_httpsig_sfv_fail(ctx, "invalid byte sequence encoding");
    }

    return NGX_OK;
}


static ngx_int_t
ngx_auth_httpsig_sfv_read_boolean(ngx_auth_httpsig_sfv_ctx_t *ctx,
    ngx_auth_httpsig_sfv_bare_t *out)
{
    if (ctx->pos >= ctx->last || *ctx->pos != '?') {
        return ngx_auth_httpsig_sfv_fail(ctx, "invalid boolean");
    }

    ctx->pos++;

    if (ctx->pos >= ctx->last || (*ctx->pos != '0' && *ctx->pos != '1')) {
        return ngx_auth_httpsig_sfv_fail(ctx, "invalid boolean");
    }

    out->type = NGX_AUTH_HTTPSIG_SFV_BOOLEAN;
    out->integer = (*ctx->pos == '1') ? 1 : 0;
    ctx->pos++;

    return NGX_OK;
}


static ngx_int_t
ngx_auth_httpsig_sfv_read_token(ngx_auth_httpsig_sfv_ctx_t *ctx, ngx_str_t *out)
{
    const u_char *start;

    if (ctx->pos >= ctx->last
        || !(ngx_auth_httpsig_sfv_is_alpha(*ctx->pos) || *ctx->pos == '*'))
    {
        return ngx_auth_httpsig_sfv_fail(ctx, "invalid token");
    }

    start = ctx->pos;
    ctx->pos++;

    while (ctx->pos < ctx->last
           && ngx_auth_httpsig_sfv_is_token_char(*ctx->pos))
    {
        ctx->pos++;
    }

    out->data = (u_char *) start;
    out->len = (size_t) (ctx->pos - start);

    return NGX_OK;
}


static ngx_int_t
ngx_auth_httpsig_sfv_read_number(ngx_auth_httpsig_sfv_ctx_t *ctx,
    ngx_auth_httpsig_sfv_bare_t *out)
{
    ngx_flag_t negative;
    ngx_uint_t int_digits, frac_digits;
    int64_t int_part, frac_part;

    negative = 0;

    if (ctx->pos < ctx->last && *ctx->pos == '-') {
        negative = 1;
        ctx->pos++;
    }

    if (ctx->pos >= ctx->last || !ngx_auth_httpsig_sfv_is_digit(*ctx->pos)) {
        return ngx_auth_httpsig_sfv_fail(ctx, "invalid number");
    }

    int_part = 0;
    int_digits = 0;

    while (ctx->pos < ctx->last && ngx_auth_httpsig_sfv_is_digit(*ctx->pos)) {
        if (int_digits == 15) {
            return ngx_auth_httpsig_sfv_fail(ctx, "number too long");
        }

        int_part = int_part * 10 + (*ctx->pos - '0');
        int_digits++;
        ctx->pos++;
    }

    if (ctx->pos >= ctx->last || *ctx->pos != '.') {
        out->type = NGX_AUTH_HTTPSIG_SFV_INTEGER;
        out->integer = negative ? -int_part : int_part;

        return NGX_OK;
    }

    if (int_digits > 12) {
        return ngx_auth_httpsig_sfv_fail(ctx, "decimal integer part too long");
    }

    ctx->pos++;

    if (ctx->pos >= ctx->last || !ngx_auth_httpsig_sfv_is_digit(*ctx->pos)) {
        return ngx_auth_httpsig_sfv_fail(ctx, "invalid decimal");
    }

    frac_part = 0;
    frac_digits = 0;

    while (ctx->pos < ctx->last && ngx_auth_httpsig_sfv_is_digit(*ctx->pos)) {
        if (frac_digits == 3) {
            return ngx_auth_httpsig_sfv_fail(ctx, "decimal fraction too long");
        }

        frac_part = frac_part * 10 + (*ctx->pos - '0');
        frac_digits++;
        ctx->pos++;
    }

    while (frac_digits < 3) {
        frac_part *= 10;
        frac_digits++;
    }

    out->type = NGX_AUTH_HTTPSIG_SFV_DECIMAL;
    out->integer = (negative ? -1 : 1) * (int_part * 1000 + frac_part);

    return NGX_OK;
}


static ngx_int_t
ngx_auth_httpsig_sfv_read_bare_item(ngx_auth_httpsig_sfv_ctx_t *ctx,
    ngx_auth_httpsig_sfv_bare_t *out)
{
    u_char c;

    if (ctx->pos >= ctx->last) {
        return ngx_auth_httpsig_sfv_fail(ctx, "expected a bare item");
    }

    c = *ctx->pos;

    if (c == '-' || ngx_auth_httpsig_sfv_is_digit(c)) {
        return ngx_auth_httpsig_sfv_read_number(ctx, out);
    }

    if (c == '"') {
        out->type = NGX_AUTH_HTTPSIG_SFV_STRING;
        return ngx_auth_httpsig_sfv_read_string(ctx, &out->value);
    }

    if (c == ':') {
        out->type = NGX_AUTH_HTTPSIG_SFV_BYTE_SEQUENCE;
        return ngx_auth_httpsig_sfv_read_byte_sequence(ctx, &out->value);
    }

    if (c == '?') {
        return ngx_auth_httpsig_sfv_read_boolean(ctx, out);
    }

    if (ngx_auth_httpsig_sfv_is_alpha(c) || c == '*') {
        out->type = NGX_AUTH_HTTPSIG_SFV_TOKEN;
        return ngx_auth_httpsig_sfv_read_token(ctx, &out->value);
    }

    return ngx_auth_httpsig_sfv_fail(ctx, "unrecognized bare item");
}


static ngx_int_t
ngx_auth_httpsig_sfv_read_parameters(ngx_auth_httpsig_sfv_ctx_t *ctx,
    ngx_array_t **out)
{
    ngx_array_t *params;
    ngx_auth_httpsig_sfv_param_t *param, *existing;
    ngx_str_t key;
    ngx_uint_t i;
    ngx_int_t rc;

    params = ngx_array_create(ctx->pool, 4,
                              sizeof(ngx_auth_httpsig_sfv_param_t));
    if (params == NULL) {
        return NGX_ERROR;
    }

    while (ctx->pos < ctx->last && *ctx->pos == ';') {
        ctx->pos++;
        ngx_auth_httpsig_sfv_skip_sp(ctx);

        rc = ngx_auth_httpsig_sfv_read_key(ctx, &key);
        if (rc != NGX_OK) {
            return rc;
        }

        existing = NULL;
        param = params->elts;

        for (i = 0; i < params->nelts; i++) {
            if (param[i].key.len == key.len
                && ngx_memcmp(param[i].key.data, key.data, key.len) == 0)
            {
                existing = &param[i];
                break;
            }
        }

        if (existing == NULL) {
            if (params->nelts >= NGX_AUTH_HTTPSIG_MAX_SFV_PARAMS) {
                return ngx_auth_httpsig_sfv_fail(ctx, "too many parameters");
            }

            existing = ngx_array_push(params);
            if (existing == NULL) {
                return NGX_ERROR;
            }

            existing->key = key;
        }

        if (ctx->pos < ctx->last && *ctx->pos == '=') {
            ctx->pos++;

            rc = ngx_auth_httpsig_sfv_read_bare_item(ctx, &existing->value);
            if (rc != NGX_OK) {
                return rc;
            }

        } else {
            existing->value.type = NGX_AUTH_HTTPSIG_SFV_BOOLEAN;
            existing->value.integer = 1;
        }
    }

    *out = params;

    return NGX_OK;
}


static ngx_int_t
ngx_auth_httpsig_sfv_read_item(ngx_auth_httpsig_sfv_ctx_t *ctx,
    ngx_auth_httpsig_sfv_item_t *out)
{
    ngx_int_t rc;

    rc = ngx_auth_httpsig_sfv_read_bare_item(ctx, &out->bare);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_auth_httpsig_sfv_read_parameters(ctx, &out->params);
}


static ngx_int_t
ngx_auth_httpsig_sfv_read_inner_list(ngx_auth_httpsig_sfv_ctx_t *ctx,
    ngx_auth_httpsig_sfv_inner_list_t *out)
{
    ngx_array_t *items;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_int_t rc;

    /* caller has already confirmed *ctx->pos == '(' */
    ctx->pos++;

    items = ngx_array_create(ctx->pool, 8,
                             sizeof(ngx_auth_httpsig_sfv_item_t));
    if (items == NULL) {
        return NGX_ERROR;
    }

    ngx_auth_httpsig_sfv_skip_sp(ctx);

    while (ctx->pos < ctx->last && *ctx->pos != ')') {
        if (items->nelts >= NGX_AUTH_HTTPSIG_MAX_SFV_ITEMS) {
            return ngx_auth_httpsig_sfv_fail(ctx, "too many inner list items");
        }

        item = ngx_array_push(items);
        if (item == NULL) {
            return NGX_ERROR;
        }

        rc = ngx_auth_httpsig_sfv_read_item(ctx, item);
        if (rc != NGX_OK) {
            return rc;
        }

        if (ctx->pos < ctx->last && *ctx->pos == ')') {
            break;
        }

        if (ctx->pos >= ctx->last || *ctx->pos != ' ') {
            return ngx_auth_httpsig_sfv_fail(ctx,
                                             "expected a space in inner list");
        }

        ngx_auth_httpsig_sfv_skip_sp(ctx);
    }

    if (ctx->pos >= ctx->last) {
        return ngx_auth_httpsig_sfv_fail(ctx, "unterminated inner list");
    }

    ctx->pos++;
    out->items = items;

    return ngx_auth_httpsig_sfv_read_parameters(ctx, &out->params);
}


static ngx_int_t
ngx_auth_httpsig_sfv_read_member(ngx_auth_httpsig_sfv_ctx_t *ctx,
    ngx_auth_httpsig_sfv_value_t *out)
{
    ngx_int_t rc;

    if (ctx->depth >= NGX_AUTH_HTTPSIG_MAX_SFV_DEPTH) {
        return ngx_auth_httpsig_sfv_fail(ctx, "nested too deeply");
    }

    ctx->depth++;

    if (ctx->pos < ctx->last && *ctx->pos == '(') {
        out->type = NGX_AUTH_HTTPSIG_SFV_MEMBER_INNER_LIST;
        rc = ngx_auth_httpsig_sfv_read_inner_list(ctx, &out->inner_list);

    } else {
        out->type = NGX_AUTH_HTTPSIG_SFV_MEMBER_ITEM;
        rc = ngx_auth_httpsig_sfv_read_item(ctx, &out->item);
    }

    ctx->depth--;

    return rc;
}


static ngx_int_t
ngx_auth_httpsig_sfv_read_dictionary(ngx_auth_httpsig_sfv_ctx_t *ctx,
    ngx_auth_httpsig_sfv_dictionary_t *dict)
{
    ngx_array_t *entries;
    ngx_auth_httpsig_sfv_dict_entry_t *entry, *existing;
    ngx_str_t key;
    ngx_uint_t i;
    ngx_int_t rc;

    entries = ngx_array_create(ctx->pool, 8,
                               sizeof(ngx_auth_httpsig_sfv_dict_entry_t));
    if (entries == NULL) {
        return NGX_ERROR;
    }

    while (ctx->pos < ctx->last) {
        rc = ngx_auth_httpsig_sfv_read_key(ctx, &key);
        if (rc != NGX_OK) {
            return rc;
        }

        existing = NULL;
        entry = entries->elts;

        for (i = 0; i < entries->nelts; i++) {
            if (entry[i].key.len == key.len
                && ngx_memcmp(entry[i].key.data, key.data, key.len) == 0)
            {
                existing = &entry[i];
                break;
            }
        }

        if (existing != NULL) {
            dict->duplicate_keys = 1;

        } else {
            if (entries->nelts >= NGX_AUTH_HTTPSIG_MAX_SFV_ITEMS) {
                return ngx_auth_httpsig_sfv_fail(ctx,
                                                 "too many dictionary entries");
            }

            existing = ngx_array_push(entries);
            if (existing == NULL) {
                return NGX_ERROR;
            }

            existing->key = key;
        }

        if (ctx->pos < ctx->last && *ctx->pos == '=') {
            ctx->pos++;

            rc = ngx_auth_httpsig_sfv_read_member(ctx, &existing->value);
            if (rc != NGX_OK) {
                return rc;
            }

        } else {
            existing->value.type = NGX_AUTH_HTTPSIG_SFV_MEMBER_ITEM;
            existing->value.item.bare.type = NGX_AUTH_HTTPSIG_SFV_BOOLEAN;
            existing->value.item.bare.integer = 1;

            rc = ngx_auth_httpsig_sfv_read_parameters(ctx,
                                                      &existing->value.item.
                                                      params);
            if (rc != NGX_OK) {
                return rc;
            }
        }

        ngx_auth_httpsig_sfv_skip_ows(ctx);

        if (ctx->pos >= ctx->last) {
            break;
        }

        if (*ctx->pos != ',') {
            return ngx_auth_httpsig_sfv_fail(ctx, "expected a comma");
        }

        ctx->pos++;
        ngx_auth_httpsig_sfv_skip_ows(ctx);

        if (ctx->pos >= ctx->last) {
            return ngx_auth_httpsig_sfv_fail(ctx, "trailing comma");
        }
    }

    dict->entries = entries;

    return NGX_OK;
}


static ngx_int_t
ngx_auth_httpsig_sfv_read_list(ngx_auth_httpsig_sfv_ctx_t *ctx,
    ngx_auth_httpsig_sfv_list_t *list)
{
    ngx_array_t *members;
    ngx_auth_httpsig_sfv_value_t *member;
    ngx_int_t rc;

    members = ngx_array_create(ctx->pool, 8,
                               sizeof(ngx_auth_httpsig_sfv_value_t));
    if (members == NULL) {
        return NGX_ERROR;
    }

    while (ctx->pos < ctx->last) {
        if (members->nelts >= NGX_AUTH_HTTPSIG_MAX_SFV_ITEMS) {
            return ngx_auth_httpsig_sfv_fail(ctx, "too many list members");
        }

        member = ngx_array_push(members);
        if (member == NULL) {
            return NGX_ERROR;
        }

        rc = ngx_auth_httpsig_sfv_read_member(ctx, member);
        if (rc != NGX_OK) {
            return rc;
        }

        ngx_auth_httpsig_sfv_skip_ows(ctx);

        if (ctx->pos >= ctx->last) {
            break;
        }

        if (*ctx->pos != ',') {
            return ngx_auth_httpsig_sfv_fail(ctx, "expected a comma");
        }

        ctx->pos++;
        ngx_auth_httpsig_sfv_skip_ows(ctx);

        if (ctx->pos >= ctx->last) {
            return ngx_auth_httpsig_sfv_fail(ctx, "trailing comma");
        }
    }

    list->members = members;

    return NGX_OK;
}


static ngx_int_t
ngx_auth_httpsig_sfv_wbuf_init(ngx_auth_httpsig_sfv_wbuf_t *w, ngx_pool_t *pool)
{
    w->pool = pool;
    w->buf = ngx_array_create(pool, 64, sizeof(u_char));

    return (w->buf == NULL) ? NGX_ERROR : NGX_OK;
}


static ngx_int_t
ngx_auth_httpsig_sfv_wbuf_put(ngx_auth_httpsig_sfv_wbuf_t *w,
    const u_char *data, size_t len)
{
    u_char *dst;

    dst = ngx_array_push_n(w->buf, len);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(dst, data, len);

    return NGX_OK;
}


static ngx_int_t
ngx_auth_httpsig_sfv_wbuf_putc(ngx_auth_httpsig_sfv_wbuf_t *w, u_char c)
{
    u_char *dst;

    dst = ngx_array_push(w->buf);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    *dst = c;

    return NGX_OK;
}


static void
ngx_auth_httpsig_sfv_wbuf_finish(ngx_auth_httpsig_sfv_wbuf_t *w, ngx_str_t *out)
{
    out->data = w->buf->elts;
    out->len = w->buf->nelts;
}


static ngx_int_t
ngx_auth_httpsig_sfv_write_integer(ngx_auth_httpsig_sfv_wbuf_t *w, int64_t v)
{
    u_char digits[20];
    u_char *p;
    uint64_t abs_v;

    if (v < 0) {
        if (ngx_auth_httpsig_sfv_wbuf_putc(w, '-') != NGX_OK) {
            return NGX_ERROR;
        }

        abs_v = (uint64_t) (-v);

    } else {
        abs_v = (uint64_t) v;
    }

    p = digits + sizeof(digits);

    do {
        *--p = (u_char) ('0' + (abs_v % 10));
        abs_v /= 10;
    } while (abs_v != 0);

    return ngx_auth_httpsig_sfv_wbuf_put(w, p,
                                         (size_t) (digits + sizeof(digits) -
                                                   p));
}


static ngx_int_t
ngx_auth_httpsig_sfv_write_decimal(ngx_auth_httpsig_sfv_wbuf_t *w, int64_t v)
{
    uint64_t abs_v, int_part, frac;
    u_char digits[3];
    ngx_int_t last, i;

    if (v < 0) {
        if (ngx_auth_httpsig_sfv_wbuf_putc(w, '-') != NGX_OK) {
            return NGX_ERROR;
        }

        abs_v = (uint64_t) (-v);

    } else {
        abs_v = (uint64_t) v;
    }

    int_part = abs_v / 1000;
    frac = abs_v % 1000;

    if (ngx_auth_httpsig_sfv_write_integer(w, (int64_t) int_part) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_auth_httpsig_sfv_wbuf_putc(w, '.') != NGX_OK) {
        return NGX_ERROR;
    }

    if (frac == 0) {
        return ngx_auth_httpsig_sfv_wbuf_putc(w, '0');
    }

    digits[0] = (u_char) (frac / 100);
    digits[1] = (u_char) ((frac / 10) % 10);
    digits[2] = (u_char) (frac % 10);

    last = 2;

    while (last > 0 && digits[last] == 0) {
        last--;
    }

    for (i = 0; i <= last; i++) {
        if (ngx_auth_httpsig_sfv_wbuf_putc(w, (u_char) ('0' + digits[i]))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_auth_httpsig_sfv_write_string(ngx_auth_httpsig_sfv_wbuf_t *w,
    const ngx_str_t *value)
{
    size_t i;

    if (ngx_auth_httpsig_sfv_wbuf_putc(w, '"') != NGX_OK) {
        return NGX_ERROR;
    }

    for (i = 0; i < value->len; i++) {
        if ((value->data[i] == '"' || value->data[i] == '\\')
            && ngx_auth_httpsig_sfv_wbuf_putc(w, '\\') != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (ngx_auth_httpsig_sfv_wbuf_putc(w, value->data[i]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return ngx_auth_httpsig_sfv_wbuf_putc(w, '"');
}


static ngx_int_t
ngx_auth_httpsig_sfv_write_byte_sequence(ngx_auth_httpsig_sfv_wbuf_t *w,
    const ngx_str_t *value)
{
    ngx_str_t src, encoded;

    src = *value;

    encoded.data = ngx_palloc(w->pool, ngx_base64_encoded_length(src.len));
    if (encoded.data == NULL) {
        return NGX_ERROR;
    }

    ngx_encode_base64(&encoded, &src);

    if (ngx_auth_httpsig_sfv_wbuf_putc(w, ':') != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_auth_httpsig_sfv_wbuf_put(w, encoded.data, encoded.len) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_auth_httpsig_sfv_wbuf_putc(w, ':');
}


static ngx_int_t
ngx_auth_httpsig_sfv_write_boolean(ngx_auth_httpsig_sfv_wbuf_t *w, int64_t v)
{
    if (ngx_auth_httpsig_sfv_wbuf_putc(w, '?') != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_auth_httpsig_sfv_wbuf_putc(w, v ? '1' : '0');
}


static ngx_int_t
ngx_auth_httpsig_sfv_write_bare_item(ngx_auth_httpsig_sfv_wbuf_t *w,
    const ngx_auth_httpsig_sfv_bare_t *bare)
{
    switch (bare->type) {

    case NGX_AUTH_HTTPSIG_SFV_INTEGER:
        return ngx_auth_httpsig_sfv_write_integer(w, bare->integer);

    case NGX_AUTH_HTTPSIG_SFV_DECIMAL:
        return ngx_auth_httpsig_sfv_write_decimal(w, bare->integer);

    case NGX_AUTH_HTTPSIG_SFV_STRING:
        return ngx_auth_httpsig_sfv_write_string(w, &bare->value);

    case NGX_AUTH_HTTPSIG_SFV_TOKEN:
        return ngx_auth_httpsig_sfv_wbuf_put(w, bare->value.data,
                                             bare->value.len);

    case NGX_AUTH_HTTPSIG_SFV_BYTE_SEQUENCE:
        return ngx_auth_httpsig_sfv_write_byte_sequence(w, &bare->value);

    case NGX_AUTH_HTTPSIG_SFV_BOOLEAN:
        return ngx_auth_httpsig_sfv_write_boolean(w, bare->integer);
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_auth_httpsig_sfv_write_params(ngx_auth_httpsig_sfv_wbuf_t *w,
    const ngx_array_t *params)
{
    ngx_auth_httpsig_sfv_param_t *param;
    ngx_uint_t i;

    param = params->elts;

    for (i = 0; i < params->nelts; i++) {
        if (ngx_auth_httpsig_sfv_wbuf_putc(w, ';') != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_auth_httpsig_sfv_wbuf_put(w, param[i].key.data,
                                          param[i].key.len)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (param[i].value.type == NGX_AUTH_HTTPSIG_SFV_BOOLEAN
            && param[i].value.integer == 1)
        {
            continue;
        }

        if (ngx_auth_httpsig_sfv_wbuf_putc(w, '=') != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_auth_httpsig_sfv_write_bare_item(w,
                                                 &param[i].value) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_auth_httpsig_sfv_write_item(ngx_auth_httpsig_sfv_wbuf_t *w,
    const ngx_auth_httpsig_sfv_item_t *item)
{
    if (ngx_auth_httpsig_sfv_write_bare_item(w, &item->bare) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_auth_httpsig_sfv_write_params(w, item->params);
}


static ngx_int_t
ngx_auth_httpsig_sfv_write_inner_list(ngx_auth_httpsig_sfv_wbuf_t *w,
    const ngx_auth_httpsig_sfv_inner_list_t *list)
{
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_uint_t i;

    if (ngx_auth_httpsig_sfv_wbuf_putc(w, '(') != NGX_OK) {
        return NGX_ERROR;
    }

    item = list->items->elts;

    for (i = 0; i < list->items->nelts; i++) {
        if (i > 0 && ngx_auth_httpsig_sfv_wbuf_putc(w, ' ') != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_auth_httpsig_sfv_write_item(w, &item[i]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ngx_auth_httpsig_sfv_wbuf_putc(w, ')') != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_auth_httpsig_sfv_write_params(w, list->params);
}


ngx_int_t
ngx_auth_httpsig_sfv_parse_dictionary(ngx_pool_t *pool, const ngx_str_t *input,
    ngx_auth_httpsig_sfv_dictionary_t **out, ngx_auth_httpsig_sfv_error_t *err)
{
    ngx_auth_httpsig_sfv_ctx_t ctx;
    ngx_auth_httpsig_sfv_dictionary_t *dict;
    ngx_int_t rc;

    if (input->len > NGX_AUTH_HTTPSIG_MAX_SFV_LENGTH) {
        if (err != NULL) {
            err->offset = 0;
            err->reason = "input too long";
        }

        return NGX_DECLINED;
    }

    ngx_memzero(&ctx, sizeof(ngx_auth_httpsig_sfv_ctx_t));
    ctx.pool = pool;
    ctx.start = input->data;
    ctx.pos = input->data;
    ctx.last = input->data + input->len;
    ctx.err = err;

    dict = ngx_pcalloc(pool, sizeof(ngx_auth_httpsig_sfv_dictionary_t));
    if (dict == NULL) {
        return NGX_ERROR;
    }

    ngx_auth_httpsig_sfv_skip_sp(&ctx);

    rc = ngx_auth_httpsig_sfv_read_dictionary(&ctx, dict);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_auth_httpsig_sfv_skip_sp(&ctx);

    if (ctx.pos != ctx.last) {
        return ngx_auth_httpsig_sfv_fail(&ctx, "trailing data");
    }

    *out = dict;

    return NGX_OK;
}


ngx_int_t
ngx_auth_httpsig_sfv_parse_list(ngx_pool_t *pool, const ngx_str_t *input,
    ngx_auth_httpsig_sfv_list_t **out, ngx_auth_httpsig_sfv_error_t *err)
{
    ngx_auth_httpsig_sfv_ctx_t ctx;
    ngx_auth_httpsig_sfv_list_t *list;
    ngx_int_t rc;

    if (input->len > NGX_AUTH_HTTPSIG_MAX_SFV_LENGTH) {
        if (err != NULL) {
            err->offset = 0;
            err->reason = "input too long";
        }

        return NGX_DECLINED;
    }

    ngx_memzero(&ctx, sizeof(ngx_auth_httpsig_sfv_ctx_t));
    ctx.pool = pool;
    ctx.start = input->data;
    ctx.pos = input->data;
    ctx.last = input->data + input->len;
    ctx.err = err;

    list = ngx_pcalloc(pool, sizeof(ngx_auth_httpsig_sfv_list_t));
    if (list == NULL) {
        return NGX_ERROR;
    }

    ngx_auth_httpsig_sfv_skip_sp(&ctx);

    rc = ngx_auth_httpsig_sfv_read_list(&ctx, list);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_auth_httpsig_sfv_skip_sp(&ctx);

    if (ctx.pos != ctx.last) {
        return ngx_auth_httpsig_sfv_fail(&ctx, "trailing data");
    }

    *out = list;

    return NGX_OK;
}


ngx_int_t
ngx_auth_httpsig_sfv_parse_item(ngx_pool_t *pool, const ngx_str_t *input,
    ngx_auth_httpsig_sfv_item_t **out, ngx_auth_httpsig_sfv_error_t *err)
{
    ngx_auth_httpsig_sfv_ctx_t ctx;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_int_t rc;

    if (input->len > NGX_AUTH_HTTPSIG_MAX_SFV_LENGTH) {
        if (err != NULL) {
            err->offset = 0;
            err->reason = "input too long";
        }

        return NGX_DECLINED;
    }

    ngx_memzero(&ctx, sizeof(ngx_auth_httpsig_sfv_ctx_t));
    ctx.pool = pool;
    ctx.start = input->data;
    ctx.pos = input->data;
    ctx.last = input->data + input->len;
    ctx.err = err;

    item = ngx_pcalloc(pool, sizeof(ngx_auth_httpsig_sfv_item_t));
    if (item == NULL) {
        return NGX_ERROR;
    }

    ngx_auth_httpsig_sfv_skip_sp(&ctx);

    rc = ngx_auth_httpsig_sfv_read_item(&ctx, item);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_auth_httpsig_sfv_skip_sp(&ctx);

    if (ctx.pos != ctx.last) {
        return ngx_auth_httpsig_sfv_fail(&ctx, "trailing data");
    }

    *out = item;

    return NGX_OK;
}


ngx_int_t
ngx_auth_httpsig_sfv_serialize_item(ngx_pool_t *pool,
    const ngx_auth_httpsig_sfv_item_t *item, ngx_str_t *out)
{
    ngx_auth_httpsig_sfv_wbuf_t w;

    if (ngx_auth_httpsig_sfv_wbuf_init(&w, pool) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_auth_httpsig_sfv_write_item(&w, item) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_auth_httpsig_sfv_wbuf_finish(&w, out);

    return NGX_OK;
}


ngx_int_t
ngx_auth_httpsig_sfv_serialize_inner_list(ngx_pool_t *pool,
    const ngx_auth_httpsig_sfv_inner_list_t *list, ngx_str_t *out)
{
    ngx_auth_httpsig_sfv_wbuf_t w;

    if (ngx_auth_httpsig_sfv_wbuf_init(&w, pool) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_auth_httpsig_sfv_write_inner_list(&w, list) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_auth_httpsig_sfv_wbuf_finish(&w, out);

    return NGX_OK;
}


ngx_int_t
ngx_auth_httpsig_sfv_serialize_params(ngx_pool_t *pool,
    const ngx_array_t *params, ngx_str_t *out)
{
    ngx_auth_httpsig_sfv_wbuf_t w;

    if (ngx_auth_httpsig_sfv_wbuf_init(&w, pool) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_auth_httpsig_sfv_write_params(&w, params) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_auth_httpsig_sfv_wbuf_finish(&w, out);

    return NGX_OK;
}


const ngx_auth_httpsig_sfv_value_t *
ngx_auth_httpsig_sfv_dict_get(const ngx_auth_httpsig_sfv_dictionary_t *dict,
    const ngx_str_t *key)
{
    ngx_auth_httpsig_sfv_dict_entry_t *entry;
    ngx_uint_t i;

    entry = dict->entries->elts;

    for (i = 0; i < dict->entries->nelts; i++) {
        if (entry[i].key.len == key->len
            && ngx_memcmp(entry[i].key.data, key->data, key->len) == 0)
        {
            return &entry[i].value;
        }
    }

    return NULL;
}


const ngx_auth_httpsig_sfv_bare_t *
ngx_auth_httpsig_sfv_param_get(const ngx_array_t *params, const char *key)
{
    ngx_auth_httpsig_sfv_param_t *param;
    size_t len;
    ngx_uint_t i;

    len = ngx_strlen(key);
    param = params->elts;

    for (i = 0; i < params->nelts; i++) {
        if (param[i].key.len == len
            && ngx_memcmp(param[i].key.data, key, len) == 0)
        {
            return &param[i].value;
        }
    }

    return NULL;
}
