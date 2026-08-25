/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_base.h - reconstruction of the RFC 9421 signature base
 * string (section 2.5) from a covered-components Inner List and a
 * request snapshot. This layer is a pure function of its arguments: it
 * never touches ngx_http_request_t, so the caller (the HTTP layer) is
 * responsible for filling in ngx_auth_httpsig_request_t from the live
 * request.
 */

#ifndef NGX_AUTH_HTTPSIG_BASE_H
#define NGX_AUTH_HTTPSIG_BASE_H


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_sfv.h"


/* Bounds the pool allocation used to assemble the base string. */
#define NGX_AUTH_HTTPSIG_MAX_BASE_LENGTH   16384


/* A single HTTP field as seen on the wire: name lowercased, value with
 * leading/trailing optional whitespace already stripped. Multiple
 * occurrences of the same field name are represented as multiple
 * entries, in receipt order. */
typedef struct {
    ngx_str_t  name;
    ngx_str_t  value;
} ngx_auth_httpsig_header_t;

/*
 * Snapshot of the request state that the signature base string can
 * depend on. `path` and `request_target` must come from the raw
 * request line (nginx's ngx_http_request_t.unparsed_uri), not from the
 * normalized ngx_http_request_t.uri: nginx decodes %XX and resolves
 * "../" before exposing r->uri, so it no longer matches the bytes the
 * signer covered.
 *
 * `target_defined` is 0 for request forms where @target-uri /
 * @request-target have no defined value (e.g. CONNECT's authority-form,
 * OPTIONS *'s asterisk-form).
 */
typedef struct {
    ngx_str_t    method;
    ngx_str_t    scheme;
    ngx_str_t    authority;
    ngx_str_t    path;
    ngx_str_t    query;           /* raw, without the leading '?' */
    ngx_flag_t   has_query;
    ngx_str_t    request_target;
    ngx_flag_t   target_defined;
    ngx_array_t *headers;         /* ngx_auth_httpsig_header_t */
} ngx_auth_httpsig_request_t;

typedef enum {
    NGX_AUTH_HTTPSIG_BASE_OK = 0,
    NGX_AUTH_HTTPSIG_BASE_UNKNOWN_COMPONENT,
    NGX_AUTH_HTTPSIG_BASE_UNSUPPORTED_PARAM,
    NGX_AUTH_HTTPSIG_BASE_DUPLICATE_COMPONENT,
    NGX_AUTH_HTTPSIG_BASE_MISSING_FIELD,
    NGX_AUTH_HTTPSIG_BASE_UNDEFINED_TARGET,
    NGX_AUTH_HTTPSIG_BASE_TOO_LONG
} ngx_auth_httpsig_base_reason_t;


/*
 * Reconstructs the signature base string for `covered_components`
 * (the Inner List value of a Signature-Input dictionary entry).
 *
 * Return value:
 *   NGX_OK        `*out` holds the base string, pool-allocated.
 *   NGX_DECLINED  the component list cannot be turned into a base
 *                 string for this request; `*reason` explains why.
 *                 This is an ordinary verification failure, not an
 *                 internal error.
 *   NGX_ERROR     pool allocation failed.
 */
ngx_int_t ngx_auth_httpsig_base_build(ngx_pool_t *pool,
    const ngx_auth_httpsig_request_t *req,
    const ngx_auth_httpsig_sfv_inner_list_t *covered_components,
    ngx_str_t *out, ngx_auth_httpsig_base_reason_t *reason);

/*
 * Derives the value of a single "@..." component. Exposed for unit
 * testing; ngx_auth_httpsig_base_build() is the entry point production
 * code should call. `component->bare.value` must start with '@'.
 */
ngx_int_t ngx_auth_httpsig_base_derive_component(ngx_pool_t *pool,
    const ngx_auth_httpsig_request_t *req,
    const ngx_auth_httpsig_sfv_item_t *component,
    ngx_str_t *out, ngx_auth_httpsig_base_reason_t *reason);

/*
 * Normalizes an HTTP field's value: every occurrence of `name` (in
 * receipt order), each with leading/trailing OWS stripped, joined with
 * ", ". Exposed for unit testing.
 *
 * Return value: NGX_OK, or NGX_DECLINED with *out untouched if `name`
 * was not present (the caller maps this to MISSING_FIELD).
 */
ngx_int_t ngx_auth_httpsig_base_field_value(ngx_pool_t *pool,
    const ngx_auth_httpsig_request_t *req, const ngx_str_t *name,
    ngx_str_t *out);


#endif /* NGX_AUTH_HTTPSIG_BASE_H */
