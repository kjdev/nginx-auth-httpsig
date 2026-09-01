/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_base.c - RFC 9421 signature base string
 * reconstruction (section 2.5). Field values in
 * ngx_auth_httpsig_request_t.headers are already lowercased (name) and
 * OWS-stripped (value); the HTTP layer owns that normalization, this
 * layer only joins repeated occurrences with ", ".
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_base.h"
#include "ngx_auth_httpsig_str.h"


typedef struct {
    u_char *data;
    size_t  len;
    size_t  cap;
} ngx_auth_httpsig_base_buf_t;


static ngx_int_t ngx_auth_httpsig_base_buf_put(
    ngx_auth_httpsig_base_buf_t *buf, const u_char *data, size_t len);
static ngx_int_t ngx_auth_httpsig_base_buf_puts(
    ngx_auth_httpsig_base_buf_t *buf, const char *s);
static ngx_int_t ngx_auth_httpsig_base_buf_put_str(
    ngx_auth_httpsig_base_buf_t *buf, const ngx_str_t *s);

static ngx_int_t ngx_auth_httpsig_base_reject_params(
    const ngx_array_t *params, ngx_auth_httpsig_base_reason_t *reason);
static const ngx_auth_httpsig_sfv_bare_t *
ngx_auth_httpsig_base_field_agent_key(const ngx_str_t *name,
    const ngx_array_t *params);
static ngx_int_t ngx_auth_httpsig_base_field_agent_member(ngx_pool_t *pool,
    const ngx_auth_httpsig_request_t *req, const ngx_str_t *key,
    ngx_str_t *out, ngx_auth_httpsig_base_reason_t *reason);
static ngx_str_t ngx_auth_httpsig_base_effective_path(
    const ngx_auth_httpsig_request_t *req);

static const ngx_str_t ngx_auth_httpsig_base_signature_agent
    = ngx_string("signature-agent");

static ngx_int_t ngx_auth_httpsig_base_query(ngx_pool_t *pool,
    const ngx_auth_httpsig_request_t *req, ngx_str_t *out);
static ngx_int_t ngx_auth_httpsig_base_target_uri(ngx_pool_t *pool,
    const ngx_auth_httpsig_request_t *req, ngx_str_t *out);
static ngx_int_t ngx_auth_httpsig_base_query_param(ngx_pool_t *pool,
    const ngx_auth_httpsig_request_t *req,
    const ngx_auth_httpsig_sfv_item_t *component, ngx_str_t *out,
    ngx_auth_httpsig_base_reason_t *reason);
static ngx_int_t ngx_auth_httpsig_base_field(ngx_pool_t *pool,
    const ngx_auth_httpsig_request_t *req,
    const ngx_auth_httpsig_sfv_item_t *component, ngx_str_t *out,
    ngx_auth_httpsig_base_reason_t *reason);

static u_char *ngx_auth_httpsig_base_find(u_char *start, u_char *end,
    u_char c);
static ngx_flag_t ngx_auth_httpsig_base_is_hex(u_char c);
static ngx_uint_t ngx_auth_httpsig_base_hex_val(u_char c);
static ngx_flag_t ngx_auth_httpsig_base_qs_key_eq(u_char *raw,
    u_char *raw_end, const ngx_str_t *target);
static ngx_int_t ngx_auth_httpsig_base_qs_decode(ngx_pool_t *pool,
    const ngx_str_t *raw, ngx_str_t *out);
static ngx_flag_t ngx_auth_httpsig_base_qs_unreserved(u_char c);
static ngx_int_t ngx_auth_httpsig_base_qs_encode(ngx_pool_t *pool,
    const ngx_str_t *decoded, ngx_str_t *out);


static ngx_int_t
ngx_auth_httpsig_base_buf_put(ngx_auth_httpsig_base_buf_t *buf,
    const u_char *data, size_t len)
{
    if (buf->len + len > buf->cap) {
        return NGX_DECLINED;
    }

    ngx_memcpy(buf->data + buf->len, data, len);
    buf->len += len;

    return NGX_OK;
}


static ngx_int_t
ngx_auth_httpsig_base_buf_puts(ngx_auth_httpsig_base_buf_t *buf,
    const char *s)
{
    return ngx_auth_httpsig_base_buf_put(buf, (const u_char *) s,
                                         ngx_strlen(s));
}


static ngx_int_t
ngx_auth_httpsig_base_buf_put_str(ngx_auth_httpsig_base_buf_t *buf,
    const ngx_str_t *s)
{
    return ngx_auth_httpsig_base_buf_put(buf, s->data, s->len);
}


static ngx_int_t
ngx_auth_httpsig_base_reject_params(const ngx_array_t *params,
    ngx_auth_httpsig_base_reason_t *reason)
{
    if (params->nelts != 0) {
        *reason = NGX_AUTH_HTTPSIG_BASE_UNSUPPORTED_PARAM;
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_str_t
ngx_auth_httpsig_base_effective_path(const ngx_auth_httpsig_request_t *req)
{
    static u_char root[] = "/";
    ngx_str_t out;

    if (req->path.len == 0) {
        out.data = root;
        out.len = 1;

    } else {
        out = req->path;
    }

    return out;
}


static ngx_int_t
ngx_auth_httpsig_base_query(ngx_pool_t *pool,
    const ngx_auth_httpsig_request_t *req, ngx_str_t *out)
{
    u_char *data;

    /* RFC 9421 section 2.2.7: "?" alone even when there is no query. */
    data = ngx_pnalloc(pool, req->query.len + 1);
    if (data == NULL) {
        return NGX_ERROR;
    }

    data[0] = '?';

    if (req->query.len != 0) {
        ngx_memcpy(data + 1, req->query.data, req->query.len);
    }

    out->data = data;
    out->len = req->query.len + 1;

    return NGX_OK;
}


static ngx_int_t
ngx_auth_httpsig_base_target_uri(ngx_pool_t *pool,
    const ngx_auth_httpsig_request_t *req, ngx_str_t *out)
{
    ngx_auth_httpsig_base_buf_t buf;
    ngx_str_t path;
    size_t cap;

    path = ngx_auth_httpsig_base_effective_path(req);

    cap = req->scheme.len + ngx_strlen("://") + req->authority.len
          + path.len + (req->has_query ? 1 + req->query.len : 0);

    buf.data = ngx_pnalloc(pool, cap);
    if (buf.data == NULL) {
        return NGX_ERROR;
    }

    buf.cap = cap;
    buf.len = 0;

    if (ngx_auth_httpsig_base_buf_put_str(&buf, &req->scheme) != NGX_OK
        || ngx_auth_httpsig_base_buf_puts(&buf, "://") != NGX_OK
        || ngx_auth_httpsig_base_buf_put_str(&buf, &req->authority) != NGX_OK
        || ngx_auth_httpsig_base_buf_put_str(&buf, &path) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (req->has_query
        && (ngx_auth_httpsig_base_buf_puts(&buf, "?") != NGX_OK
            || ngx_auth_httpsig_base_buf_put_str(&buf, &req->query)
            != NGX_OK))
    {
        return NGX_ERROR;
    }

    out->data = buf.data;
    out->len = buf.len;

    return NGX_OK;
}


static u_char *
ngx_auth_httpsig_base_find(u_char *start, u_char *end, u_char c)
{
    for ( /* void */ ; start < end; start++) {
        if (*start == c) {
            return start;
        }
    }

    return NULL;
}


static ngx_flag_t
ngx_auth_httpsig_base_is_hex(u_char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
           || (c >= 'A' && c <= 'F');
}


static ngx_uint_t
ngx_auth_httpsig_base_hex_val(u_char c)
{
    if (c >= '0' && c <= '9') {
        return (ngx_uint_t) (c - '0');
    }

    if (c >= 'a' && c <= 'f') {
        return (ngx_uint_t) (c - 'a' + 10);
    }

    return (ngx_uint_t) (c - 'A' + 10);
}


/*
 * Compares a raw (still percent/'+'-encoded) query-string key against an
 * already-decoded target, decoding "raw" on the fly so no allocation is
 * needed just to test equality.
 */
static ngx_flag_t
ngx_auth_httpsig_base_qs_key_eq(u_char *raw, u_char *raw_end,
    const ngx_str_t *target)
{
    u_char c;
    size_t j;

    j = 0;

    while (raw < raw_end) {
        if (*raw == '+') {
            c = ' ';
            raw++;

        } else if (*raw == '%' && raw + 2 < raw_end
                   && ngx_auth_httpsig_base_is_hex(raw[1])
                   && ngx_auth_httpsig_base_is_hex(raw[2]))
        {
            c = (u_char) ((ngx_auth_httpsig_base_hex_val(raw[1]) << 4)
                          | ngx_auth_httpsig_base_hex_val(raw[2]));
            raw += 3;

        } else {
            c = *raw;
            raw++;
        }

        if (j >= target->len || target->data[j] != c) {
            return 0;
        }

        j++;
    }

    return j == target->len;
}


/*
 * application/x-www-form-urlencoded parsing (WHATWG URL Standard):
 * "+" decodes to space, "%XX" decodes to the encoded byte, anything else
 * passes through unchanged.
 */
static ngx_int_t
ngx_auth_httpsig_base_qs_decode(ngx_pool_t *pool, const ngx_str_t *raw,
    ngx_str_t *out)
{
    u_char *dst;
    ngx_uint_t i;
    size_t n;

    if (raw->len == 0) {
        out->data = NULL;
        out->len = 0;
        return NGX_OK;
    }

    dst = ngx_pnalloc(pool, raw->len);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    n = 0;

    for (i = 0; i < raw->len; i++) {
        if (raw->data[i] == '+') {
            dst[n++] = ' ';

        } else if (raw->data[i] == '%' && i + 2 < raw->len
                   && ngx_auth_httpsig_base_is_hex(raw->data[i + 1])
                   && ngx_auth_httpsig_base_is_hex(raw->data[i + 2]))
        {
            dst[n++] = (u_char)
                       ((ngx_auth_httpsig_base_hex_val(raw->data[i + 1]) << 4)
                        | ngx_auth_httpsig_base_hex_val(raw->data[i + 2]));
            i += 2;

        } else {
            dst[n++] = raw->data[i];
        }
    }

    out->data = dst;
    out->len = n;

    return NGX_OK;
}


static ngx_flag_t
ngx_auth_httpsig_base_qs_unreserved(u_char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')
           || (c >= 'a' && c <= 'z') || c == '*' || c == '-' || c == '.'
           || c == '_';
}


/*
 * application/x-www-form-urlencoded serializing (WHATWG URL Standard):
 * space encodes to "+", unreserved bytes pass through, anything else
 * percent-encodes.
 */
static ngx_int_t
ngx_auth_httpsig_base_qs_encode(ngx_pool_t *pool, const ngx_str_t *decoded,
    ngx_str_t *out)
{
    static u_char hex[] = "0123456789ABCDEF";
    u_char *dst, *p;
    ngx_uint_t i;
    size_t cap;

    if (decoded->len == 0) {
        out->data = NULL;
        out->len = 0;
        return NGX_OK;
    }

    cap = 0;

    for (i = 0; i < decoded->len; i++) {
        cap += (decoded->data[i] == ' '
                || ngx_auth_httpsig_base_qs_unreserved(decoded->data[i]))
               ? 1 : 3;
    }

    dst = ngx_pnalloc(pool, cap);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    p = dst;

    for (i = 0; i < decoded->len; i++) {
        if (decoded->data[i] == ' ') {
            *p++ = '+';

        } else if (ngx_auth_httpsig_base_qs_unreserved(decoded->data[i])) {
            *p++ = decoded->data[i];

        } else {
            *p++ = '%';
            *p++ = hex[decoded->data[i] >> 4];
            *p++ = hex[decoded->data[i] & 0xf];
        }
    }

    out->data = dst;
    out->len = (size_t) (p - dst);

    return NGX_OK;
}


/*
 * RFC 9421 section 2.2.8. The query string is parsed per the WHATWG URL
 * Standard's application/x-www-form-urlencoded algorithm. The "name"
 * parameter itself carries the form-urlencoded (encoded) form of the
 * target key, so it is decoded once up front and then compared against
 * each candidate key decoded on the fly. A name that occurs more than
 * once MUST NOT be included in the signature base (RFC 9421 section
 * 2.2.8), so a second match after the first is rejected rather than
 * silently ignored.
 */
static ngx_int_t
ngx_auth_httpsig_base_query_param(ngx_pool_t *pool,
    const ngx_auth_httpsig_request_t *req,
    const ngx_auth_httpsig_sfv_item_t *component, ngx_str_t *out,
    ngx_auth_httpsig_base_reason_t *reason)
{
    const ngx_auth_httpsig_sfv_bare_t *name_param;
    ngx_str_t decoded_name, decoded, value_raw;
    u_char *p, *end, *seg_end, *eq_pos;
    ngx_flag_t found;

    name_param = ngx_auth_httpsig_sfv_param_get(component->params, "name");

    if (name_param == NULL
        || name_param->type != NGX_AUTH_HTTPSIG_SFV_STRING)
    {
        *reason = NGX_AUTH_HTTPSIG_BASE_UNKNOWN_COMPONENT;
        return NGX_DECLINED;
    }

    /* The SFV parser rejects duplicate parameter keys (sfv.c), so
     * finding "name" above and nelts != 1 together mean some other,
     * unsupported parameter is also present. */
    if (component->params->nelts != 1) {
        *reason = NGX_AUTH_HTTPSIG_BASE_UNSUPPORTED_PARAM;
        return NGX_DECLINED;
    }

    if (ngx_auth_httpsig_base_qs_decode(pool, &name_param->value,
                                        &decoded_name)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    found = 0;
    value_raw.data = NULL;
    value_raw.len = 0;

    p = req->query.data;
    end = p + req->query.len;

    while (p < end) {
        ngx_str_t key;

        seg_end = ngx_auth_httpsig_base_find(p, end, '&');
        if (seg_end == NULL) {
            seg_end = end;
        }

        eq_pos = ngx_auth_httpsig_base_find(p, seg_end, '=');

        key.data = p;
        key.len = (size_t) ((eq_pos != NULL ? eq_pos : seg_end) - p);

        if (ngx_auth_httpsig_base_qs_key_eq(key.data, key.data + key.len,
                                            &decoded_name))
        {
            if (found) {
                *reason = NGX_AUTH_HTTPSIG_BASE_MISSING_FIELD;
                return NGX_DECLINED;
            }

            found = 1;

            if (eq_pos != NULL) {
                value_raw.data = eq_pos + 1;
                value_raw.len = (size_t) (seg_end - (eq_pos + 1));

            } else {
                value_raw.data = seg_end;
                value_raw.len = 0;
            }
        }

        p = (seg_end < end) ? seg_end + 1 : end;
    }

    if (!found) {
        *reason = NGX_AUTH_HTTPSIG_BASE_MISSING_FIELD;
        return NGX_DECLINED;
    }

    if (ngx_auth_httpsig_base_qs_decode(pool, &value_raw, &decoded)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_auth_httpsig_base_qs_encode(pool, &decoded, out) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Recognizes the field-component parameters this layer supports on
 * "signature-agent": "key" alone, or "key" together with a Boolean-true
 * "sf" (RFC 9421 section 2.1: "the sf parameter's functionality is
 * already covered when the key parameter is used on a Dictionary item",
 * i.e. redundant, not incompatible). Returns the "key" parameter's bare
 * value (always a String, RFC 9421 section 2.1.2) or NULL if `component`
 * doesn't have exactly one of those two shapes, in which case the caller
 * falls back to ngx_auth_httpsig_base_reject_params() so every other
 * combination (an unrelated field with any params, "key" with the wrong
 * bare type, "sf" with a false or non-Boolean value, "key" alongside a
 * parameter other than "sf") keeps being rejected exactly as before.
 * Restricted to "signature-agent" rather than generalized to any
 * Dictionary-valued HTTP field because this module only interprets
 * Structured Fields for Signature-Input / Signature / Signature-Agent.
 */
static const ngx_auth_httpsig_sfv_bare_t *
ngx_auth_httpsig_base_field_agent_key(const ngx_str_t *name,
    const ngx_array_t *params)
{
    const ngx_auth_httpsig_sfv_bare_t *key, *sf;

    if (!ngx_auth_httpsig_str_eq(name,
                                 &ngx_auth_httpsig_base_signature_agent))
    {
        return NULL;
    }

    if (params->nelts == 0 || params->nelts > 2) {
        return NULL;
    }

    key = ngx_auth_httpsig_sfv_param_get(params, "key");
    if (key == NULL || key->type != NGX_AUTH_HTTPSIG_SFV_STRING) {
        return NULL;
    }

    if (params->nelts == 2) {
        sf = ngx_auth_httpsig_sfv_param_get(params, "sf");
        if (sf == NULL || sf->type != NGX_AUTH_HTTPSIG_SFV_BOOLEAN
            || sf->integer != 1)
        {
            return NULL;
        }
    }

    return key;
}


/*
 * RFC 9421 section 2.1.2: naming "key" selects one member of a
 * Dictionary-valued HTTP field, and the base string carries that
 * member's own canonical serialization (RFC 8941 section 4.1.1) --
 * never the field's raw bytes. A named key absent from the Dictionary,
 * or a field that isn't a well-formed Dictionary at all, "MUST cause
 * an error in the signature base generation" (ibid.).
 *
 * This is independent of, and stricter than, the Dictionary ->
 * Item(String) -> raw-bytes fallback chain
 * ngx_auth_httpsig_profile_agent_url() uses to tolerate legacy senders when
 * extracting $httpsig_agent: that fallback exists only because the
 * draft still lets verifiers accept a bare string, and only matters
 * after a signature has already verified. Naming "key" is the signer
 * stating unambiguously that this field is a Dictionary, so there is
 * no lower form to fall back to here.
 */
static ngx_int_t
ngx_auth_httpsig_base_field_agent_member(ngx_pool_t *pool,
    const ngx_auth_httpsig_request_t *req, const ngx_str_t *key,
    ngx_str_t *out, ngx_auth_httpsig_base_reason_t *reason)
{
    ngx_auth_httpsig_sfv_dictionary_t *dict;
    const ngx_auth_httpsig_sfv_value_t *member;
    const ngx_str_t *name;
    ngx_str_t raw;
    ngx_int_t rc;

    name = &ngx_auth_httpsig_base_signature_agent;

    rc = ngx_auth_httpsig_base_field_value(pool, req, name, &raw);
    if (rc == NGX_DECLINED) {
        *reason = NGX_AUTH_HTTPSIG_BASE_MISSING_FIELD;
        return NGX_DECLINED;
    }
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_auth_httpsig_sfv_parse_dictionary(pool, &raw, &dict, NULL);
    if (rc == NGX_DECLINED) {
        *reason = NGX_AUTH_HTTPSIG_BASE_MISSING_FIELD;
        return NGX_DECLINED;
    }
    if (rc != NGX_OK) {
        return rc;
    }

    member = ngx_auth_httpsig_sfv_dict_get(dict, key);
    if (member == NULL) {
        *reason = NGX_AUTH_HTTPSIG_BASE_MISSING_FIELD;
        return NGX_DECLINED;
    }

    if (member->type == NGX_AUTH_HTTPSIG_SFV_MEMBER_INNER_LIST) {
        return ngx_auth_httpsig_sfv_serialize_inner_list(pool,
                                                         &member->inner_list,
                                                         out);
    }

    return ngx_auth_httpsig_sfv_serialize_item(pool, &member->item, out);
}


static ngx_int_t
ngx_auth_httpsig_base_field(ngx_pool_t *pool,
    const ngx_auth_httpsig_request_t *req,
    const ngx_auth_httpsig_sfv_item_t *component, ngx_str_t *out,
    ngx_auth_httpsig_base_reason_t *reason)
{
    const ngx_str_t *name;
    const ngx_auth_httpsig_sfv_bare_t *agent_key;
    ngx_uint_t i;
    ngx_int_t rc;

    name = &component->bare.value;

    /* RFC 9421 section 2.1: field-name component identifiers are
     * always lowercase. */
    for (i = 0; i < name->len; i++) {
        if (name->data[i] >= 'A' && name->data[i] <= 'Z') {
            *reason = NGX_AUTH_HTTPSIG_BASE_UNKNOWN_COMPONENT;
            return NGX_DECLINED;
        }
    }

    agent_key = ngx_auth_httpsig_base_field_agent_key(name,
                                                      component->params);
    if (agent_key != NULL) {
        return ngx_auth_httpsig_base_field_agent_member(pool, req,
                                                        &agent_key->value,
                                                        out, reason);
    }

    rc = ngx_auth_httpsig_base_reject_params(component->params, reason);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_auth_httpsig_base_field_value(pool, req, name, out);

    if (rc == NGX_DECLINED) {
        *reason = NGX_AUTH_HTTPSIG_BASE_MISSING_FIELD;
    }

    return rc;
}


typedef enum {
    NGX_AUTH_HTTPSIG_BASE_DERIVE_METHOD,
    NGX_AUTH_HTTPSIG_BASE_DERIVE_SCHEME,
    NGX_AUTH_HTTPSIG_BASE_DERIVE_AUTHORITY,
    NGX_AUTH_HTTPSIG_BASE_DERIVE_PATH,
    NGX_AUTH_HTTPSIG_BASE_DERIVE_QUERY,
    NGX_AUTH_HTTPSIG_BASE_DERIVE_QUERY_PARAM,
    NGX_AUTH_HTTPSIG_BASE_DERIVE_REQUEST_TARGET,
    NGX_AUTH_HTTPSIG_BASE_DERIVE_TARGET_URI
} ngx_auth_httpsig_base_derive_id_t;


typedef struct {
    ngx_str_t                          name;
    ngx_auth_httpsig_base_derive_id_t  id;
    ngx_flag_t                         needs_target;
} ngx_auth_httpsig_base_derive_t;


static const ngx_auth_httpsig_base_derive_t
    ngx_auth_httpsig_base_derive_table[] =
{
    { ngx_string("@method"),
      NGX_AUTH_HTTPSIG_BASE_DERIVE_METHOD,         0 },
    { ngx_string("@scheme"),
      NGX_AUTH_HTTPSIG_BASE_DERIVE_SCHEME,         0 },
    { ngx_string("@authority"),
      NGX_AUTH_HTTPSIG_BASE_DERIVE_AUTHORITY,      0 },
    { ngx_string("@path"),
      NGX_AUTH_HTTPSIG_BASE_DERIVE_PATH,           1 },
    { ngx_string("@query"),
      NGX_AUTH_HTTPSIG_BASE_DERIVE_QUERY,          1 },
    { ngx_string("@query-param"),
      NGX_AUTH_HTTPSIG_BASE_DERIVE_QUERY_PARAM,    0 },
    { ngx_string("@request-target"),
      NGX_AUTH_HTTPSIG_BASE_DERIVE_REQUEST_TARGET, 1 },
    { ngx_string("@target-uri"),
      NGX_AUTH_HTTPSIG_BASE_DERIVE_TARGET_URI,     1 },
};


ngx_int_t
ngx_auth_httpsig_base_derive_component(ngx_pool_t *pool,
    const ngx_auth_httpsig_request_t *req,
    const ngx_auth_httpsig_sfv_item_t *component, ngx_str_t *out,
    ngx_auth_httpsig_base_reason_t *reason)
{
    const ngx_str_t *name;
    const ngx_auth_httpsig_base_derive_t *d;
    ngx_uint_t i;
    ngx_int_t rc;

    name = &component->bare.value;

    if (name->len == 0 || name->data[0] != '@') {
        *reason = NGX_AUTH_HTTPSIG_BASE_UNKNOWN_COMPONENT;
        return NGX_DECLINED;
    }

    d = NULL;

    for (i = 0;
         i < sizeof(ngx_auth_httpsig_base_derive_table)
         / sizeof(ngx_auth_httpsig_base_derive_table[0]);
         i++)
    {
        if (ngx_auth_httpsig_str_eq(&ngx_auth_httpsig_base_derive_table[i].name,
                                    name))
        {
            d = &ngx_auth_httpsig_base_derive_table[i];
            break;
        }
    }

    if (d == NULL) {
        *reason = NGX_AUTH_HTTPSIG_BASE_UNKNOWN_COMPONENT;
        return NGX_DECLINED;
    }

    /* @query-param carries its own "name" parameter rather than
     * rejecting all params, so it must bypass the shared reject_params()
     * check below. */
    if (d->id == NGX_AUTH_HTTPSIG_BASE_DERIVE_QUERY_PARAM) {
        return ngx_auth_httpsig_base_query_param(pool, req, component, out,
                                                 reason);
    }

    rc = ngx_auth_httpsig_base_reject_params(component->params, reason);
    if (rc != NGX_OK) {
        return rc;
    }

    /* @path, @query, @request-target, and @target-uri all describe a
     * concrete request target; without one (CONNECT authority-form,
     * OPTIONS * asterisk-form) there is nothing meaningful to derive. */
    if (d->needs_target && !req->target_defined) {
        *reason = NGX_AUTH_HTTPSIG_BASE_UNDEFINED_TARGET;
        return NGX_DECLINED;
    }

    switch (d->id) {

    case NGX_AUTH_HTTPSIG_BASE_DERIVE_METHOD:
        *out = req->method;
        return NGX_OK;

    case NGX_AUTH_HTTPSIG_BASE_DERIVE_SCHEME:
        *out = req->scheme;
        return NGX_OK;

    case NGX_AUTH_HTTPSIG_BASE_DERIVE_AUTHORITY:
        *out = req->authority;
        return NGX_OK;

    case NGX_AUTH_HTTPSIG_BASE_DERIVE_PATH:
        *out = ngx_auth_httpsig_base_effective_path(req);
        return NGX_OK;

    case NGX_AUTH_HTTPSIG_BASE_DERIVE_QUERY:
        return ngx_auth_httpsig_base_query(pool, req, out);

    case NGX_AUTH_HTTPSIG_BASE_DERIVE_REQUEST_TARGET:
        *out = req->request_target;
        return NGX_OK;

    case NGX_AUTH_HTTPSIG_BASE_DERIVE_TARGET_URI:
        return ngx_auth_httpsig_base_target_uri(pool, req, out);

    default:
        *reason = NGX_AUTH_HTTPSIG_BASE_UNKNOWN_COMPONENT;
        return NGX_DECLINED;
    }
}


ngx_int_t
ngx_auth_httpsig_base_field_value(ngx_pool_t *pool,
    const ngx_auth_httpsig_request_t *req, const ngx_str_t *name,
    ngx_str_t *out)
{
    ngx_auth_httpsig_header_t *headers;
    ngx_uint_t i, n, count;
    size_t len;
    u_char *data, *p;

    headers = req->headers->elts;
    n = req->headers->nelts;
    count = 0;
    len = 0;

    for (i = 0; i < n; i++) {
        if (ngx_auth_httpsig_str_eq(&headers[i].name, name)) {
            if (count > 0) {
                len += 2;   /* ", " */
            }

            len += headers[i].value.len;
            count++;
        }
    }

    if (count == 0) {
        return NGX_DECLINED;
    }

    data = ngx_pnalloc(pool, len);
    if (data == NULL) {
        return NGX_ERROR;
    }

    p = data;
    count = 0;

    for (i = 0; i < n; i++) {
        if (ngx_auth_httpsig_str_eq(&headers[i].name, name)) {
            if (count > 0) {
                *p++ = ',';
                *p++ = ' ';
            }

            p = ngx_cpymem(p, headers[i].value.data, headers[i].value.len);
            count++;
        }
    }

    out->data = data;
    out->len = len;

    return NGX_OK;
}


ngx_int_t
ngx_auth_httpsig_base_build(ngx_pool_t *pool,
    const ngx_auth_httpsig_request_t *req,
    const ngx_auth_httpsig_sfv_inner_list_t *covered_components,
    ngx_str_t *out, ngx_auth_httpsig_base_reason_t *reason)
{
    ngx_auth_httpsig_base_buf_t buf;
    ngx_auth_httpsig_sfv_item_t *items;
    ngx_str_t labels[NGX_AUTH_HTTPSIG_MAX_SFV_ITEMS];
    ngx_str_t label, value, params_value;
    ngx_uint_t n, i, j;
    ngx_int_t rc;

    n = covered_components->items->nelts;

    if (n > NGX_AUTH_HTTPSIG_MAX_SFV_ITEMS) {
        *reason = NGX_AUTH_HTTPSIG_BASE_TOO_LONG;
        return NGX_DECLINED;
    }

    items = covered_components->items->elts;

    buf.cap = NGX_AUTH_HTTPSIG_MAX_BASE_LENGTH;
    buf.len = 0;
    buf.data = ngx_pnalloc(pool, buf.cap);
    if (buf.data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < n; i++) {
        if (items[i].bare.type != NGX_AUTH_HTTPSIG_SFV_STRING) {
            *reason = NGX_AUTH_HTTPSIG_BASE_UNKNOWN_COMPONENT;
            return NGX_DECLINED;
        }

        if (ngx_auth_httpsig_sfv_serialize_item(pool, &items[i], &label)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        for (j = 0; j < i; j++) {
            if (ngx_auth_httpsig_str_eq(&label, &labels[j])) {
                *reason = NGX_AUTH_HTTPSIG_BASE_DUPLICATE_COMPONENT;
                return NGX_DECLINED;
            }
        }

        labels[i] = label;

        if (items[i].bare.value.len != 0
            && items[i].bare.value.data[0] == '@')
        {
            rc = ngx_auth_httpsig_base_derive_component(pool, req, &items[i],
                                                        &value, reason);

        } else {
            rc = ngx_auth_httpsig_base_field(pool, req, &items[i], &value,
                                             reason);
        }

        if (rc != NGX_OK) {
            return rc;
        }

        if (ngx_auth_httpsig_base_buf_put_str(&buf, &label) != NGX_OK
            || ngx_auth_httpsig_base_buf_puts(&buf, ": ") != NGX_OK
            || ngx_auth_httpsig_base_buf_put_str(&buf, &value) != NGX_OK
            || ngx_auth_httpsig_base_buf_puts(&buf, "\n") != NGX_OK)
        {
            *reason = NGX_AUTH_HTTPSIG_BASE_TOO_LONG;
            return NGX_DECLINED;
        }
    }

    if (ngx_auth_httpsig_sfv_serialize_inner_list(pool, covered_components,
                                                  &params_value)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_auth_httpsig_base_buf_puts(&buf, "\"@signature-params\": ")
        != NGX_OK
        || ngx_auth_httpsig_base_buf_put_str(&buf, &params_value) != NGX_OK)
    {
        *reason = NGX_AUTH_HTTPSIG_BASE_TOO_LONG;
        return NGX_DECLINED;
    }

    out->data = buf.data;
    out->len = buf.len;
    *reason = NGX_AUTH_HTTPSIG_BASE_OK;

    return NGX_OK;
}
