/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_sfv.h - Structured Field Values (RFC 8941) parsing and
 * serialization, restricted to what RFC 9421 needs to interpret
 * Signature-Input / Signature / Signature-Agent: Dictionary, List, Inner
 * List, Item, and Parameters, with bare value types Integer, Decimal,
 * String, Token, Byte Sequence, and Boolean.
 */

#ifndef NGX_AUTH_HTTPSIG_SFV_H
#define NGX_AUTH_HTTPSIG_SFV_H


#include <ngx_config.h>
#include <ngx_core.h>


/* DoS limits for parsing untrusted header field values. */
#define NGX_AUTH_HTTPSIG_MAX_SFV_LENGTH   8192
#define NGX_AUTH_HTTPSIG_MAX_SFV_ITEMS    64
#define NGX_AUTH_HTTPSIG_MAX_SFV_DEPTH    4
#define NGX_AUTH_HTTPSIG_MAX_SFV_PARAMS   16


typedef enum {
    NGX_AUTH_HTTPSIG_SFV_INTEGER = 0,
    NGX_AUTH_HTTPSIG_SFV_DECIMAL,
    NGX_AUTH_HTTPSIG_SFV_STRING,
    NGX_AUTH_HTTPSIG_SFV_TOKEN,
    NGX_AUTH_HTTPSIG_SFV_BYTE_SEQUENCE,
    NGX_AUTH_HTTPSIG_SFV_BOOLEAN
} ngx_auth_httpsig_sfv_type_t;

typedef enum {
    NGX_AUTH_HTTPSIG_SFV_MEMBER_ITEM = 0,
    NGX_AUTH_HTTPSIG_SFV_MEMBER_INNER_LIST
} ngx_auth_httpsig_sfv_member_type_t;


/*
 * A bare item: the value with no parameters attached.  `value` holds the
 * decoded bytes for STRING / TOKEN / BYTE_SEQUENCE.  `integer` holds the
 * value for INTEGER as-is, for DECIMAL scaled by 1000 (RFC 8941 allows at
 * most 3 fractional digits, so this is exact, unlike a double), and for
 * BOOLEAN as 0 or 1.
 */
typedef struct {
    ngx_auth_httpsig_sfv_type_t  type;
    ngx_str_t                    value;
    int64_t                      integer;
} ngx_auth_httpsig_sfv_bare_t;

typedef struct {
    ngx_str_t                    key;
    ngx_auth_httpsig_sfv_bare_t  value;
} ngx_auth_httpsig_sfv_param_t;

typedef struct {
    ngx_auth_httpsig_sfv_bare_t  bare;
    ngx_array_t                 *params;    /* ngx_auth_httpsig_sfv_param_t */
} ngx_auth_httpsig_sfv_item_t;

typedef struct {
    ngx_array_t *items;                     /* ngx_auth_httpsig_sfv_item_t */
    ngx_array_t *params;                    /* ngx_auth_httpsig_sfv_param_t */
} ngx_auth_httpsig_sfv_inner_list_t;

/* A List Member (RFC 8941 §3.1): either a bare Item or an Inner List. */
typedef struct {
    ngx_auth_httpsig_sfv_member_type_t  type;
    ngx_auth_httpsig_sfv_item_t         item;
    ngx_auth_httpsig_sfv_inner_list_t   inner_list;
} ngx_auth_httpsig_sfv_value_t;

typedef struct {
    ngx_str_t                     key;
    ngx_auth_httpsig_sfv_value_t  value;
} ngx_auth_httpsig_sfv_dict_entry_t;

/*
 * A Dictionary preserves insertion order; a later occurrence of the same
 * key overwrites the value in place, at the position of its first
 * occurrence (RFC 8941 §3.2). `duplicate_keys` is set when this happened
 * at least once, so callers that must reject repeated Signature-Input /
 * Signature labels can fail closed instead of silently keeping the last
 * value.
 */
typedef struct {
    ngx_array_t *entries;     /* ngx_auth_httpsig_sfv_dict_entry_t */
    ngx_flag_t   duplicate_keys;
} ngx_auth_httpsig_sfv_dictionary_t;

typedef struct {
    ngx_array_t *members;     /* ngx_auth_httpsig_sfv_value_t */
} ngx_auth_httpsig_sfv_list_t;

/* `reason` is a static string (safe to log as-is; never request-derived). */
typedef struct {
    ngx_uint_t  offset;
    const char *reason;
} ngx_auth_httpsig_sfv_error_t;


/*
 * Parsing entry points.
 *
 * Return value:
 *   NGX_OK        `*out` holds the parsed value.
 *   NGX_DECLINED  the input is not well-formed Structured Fields, or
 *                 exceeds a DoS limit; `*err` (if non-NULL) is filled in.
 *                 A malformed header is an ordinary client-side condition,
 *                 not an internal error.
 *   NGX_ERROR     pool allocation failed.
 */
ngx_int_t ngx_auth_httpsig_sfv_parse_dictionary(ngx_pool_t *pool,
    const ngx_str_t *input, ngx_auth_httpsig_sfv_dictionary_t **out,
    ngx_auth_httpsig_sfv_error_t *err);
ngx_int_t ngx_auth_httpsig_sfv_parse_list(ngx_pool_t *pool,
    const ngx_str_t *input, ngx_auth_httpsig_sfv_list_t **out,
    ngx_auth_httpsig_sfv_error_t *err);
ngx_int_t ngx_auth_httpsig_sfv_parse_item(ngx_pool_t *pool,
    const ngx_str_t *input, ngx_auth_httpsig_sfv_item_t **out,
    ngx_auth_httpsig_sfv_error_t *err);

/*
 * Serialization (RFC 8941 §4.1). Always produces the canonical form,
 * regardless of how the value was parsed (e.g. a Decimal with trailing
 * zero fractional digits is trimmed). Used to reconstruct the
 * "@signature-params" line from the parsed Inner List rather than reusing
 * the bytes the client sent.
 *
 * Return value: NGX_OK, or NGX_ERROR on pool allocation failure. There is
 * no NGX_DECLINED path: a value that parsed successfully always
 * serializes successfully.
 */
ngx_int_t ngx_auth_httpsig_sfv_serialize_item(ngx_pool_t *pool,
    const ngx_auth_httpsig_sfv_item_t *item, ngx_str_t *out);
ngx_int_t ngx_auth_httpsig_sfv_serialize_inner_list(ngx_pool_t *pool,
    const ngx_auth_httpsig_sfv_inner_list_t *list, ngx_str_t *out);
ngx_int_t ngx_auth_httpsig_sfv_serialize_params(ngx_pool_t *pool,
    const ngx_array_t *params, ngx_str_t *out);

/* Lookup helpers; return NULL when the key is absent. */
const ngx_auth_httpsig_sfv_value_t *ngx_auth_httpsig_sfv_dict_get(
    const ngx_auth_httpsig_sfv_dictionary_t *dict, const ngx_str_t *key);
const ngx_auth_httpsig_sfv_bare_t *ngx_auth_httpsig_sfv_param_get(
    const ngx_array_t *params, const char *key);


#endif /* NGX_AUTH_HTTPSIG_SFV_H */
