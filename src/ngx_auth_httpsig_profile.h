/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_profile.h - matches a request's Signature-Input /
 * Signature fields against a named profile (e.g. web-bot-auth): which
 * parameters and covered components are required, and the time window
 * a signature must fall within. Profile definitions live in a single
 * table (ngx_auth_httpsig_profile_get()) so that churn in an
 * Internet-Draft profile is absorbed by editing table data, not the
 * verification code that walks it.
 */

#ifndef NGX_AUTH_HTTPSIG_PROFILE_H
#define NGX_AUTH_HTTPSIG_PROFILE_H


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_base.h"
#include "ngx_auth_httpsig_keys.h"
#include "ngx_auth_httpsig_sfv.h"
#include "ngx_auth_httpsig_verify.h"


/* Bits of ngx_auth_httpsig_profile_t.required_params: which
 * Signature-Input parameters a profile mandates. */
#define NGX_AUTH_HTTPSIG_PARAM_CREATED   0x0001
#define NGX_AUTH_HTTPSIG_PARAM_EXPIRES   0x0002
#define NGX_AUTH_HTTPSIG_PARAM_KEYID     0x0004
#define NGX_AUTH_HTTPSIG_PARAM_ALG       0x0008
#define NGX_AUTH_HTTPSIG_PARAM_NONCE     0x0010
#define NGX_AUTH_HTTPSIG_PARAM_TAG       0x0020

/* Bits of ngx_auth_httpsig_profile_t.any_of_components /
 * all_of_components: covered components a profile cares about. Any
 * component not listed here (e.g. an arbitrary HTTP field) still
 * contributes to the signature base string but never sets a bit. */
#define NGX_AUTH_HTTPSIG_COMP_METHOD           0x0001
#define NGX_AUTH_HTTPSIG_COMP_TARGET_URI       0x0002
#define NGX_AUTH_HTTPSIG_COMP_AUTHORITY        0x0004
#define NGX_AUTH_HTTPSIG_COMP_SCHEME           0x0008
#define NGX_AUTH_HTTPSIG_COMP_REQUEST_TARGET   0x0010
#define NGX_AUTH_HTTPSIG_COMP_PATH             0x0020
#define NGX_AUTH_HTTPSIG_COMP_QUERY            0x0040
#define NGX_AUTH_HTTPSIG_COMP_SIGNATURE_AGENT  0x0080


typedef struct {
    ngx_str_t   name;                  /* auth_httpsig_profile value */
    ngx_str_t   tag;
    ngx_uint_t  required_params;       /* all of these must be present */
    ngx_uint_t  any_of_components;     /* at least one must be covered */
    ngx_uint_t  all_of_components;     /* all of these must be covered */
    ngx_flag_t  require_agent_covered; /* see step 10 in the .c file */
    time_t      expires_max;
    time_t      max_skew;
    ngx_str_t   alg;                   /* accepted "alg" parameter value */
    ngx_str_t   directory_path;        /* key-directory well-known path,
                                        * for a dynamic fetch */
    ngx_str_t   directory_media_type;  /* accepted key-directory response
                                        * media type, besides
                                        * application/json */
} ngx_auth_httpsig_profile_t;

/*
 * A signature label selected out of Signature-Input, plus everything
 * derived from it while checking it against a profile. Only the
 * fields a profile's required_params bit demands are meaningful; the
 * rest are zeroed.
 */
typedef struct {
    ngx_str_t                                label;
    ngx_str_t                                keyid;
    ngx_str_t                                alg;
    ngx_str_t                                nonce;
    ngx_str_t                                tag;
    int64_t                                  created;
    int64_t                                  expires;
    ngx_uint_t                               present; /* NGX_AUTH_HTTPSIG_PARAM_* bits actually seen */
    ngx_uint_t                               covered; /* NGX_AUTH_HTTPSIG_COMP_* bits actually seen */
    const ngx_auth_httpsig_sfv_inner_list_t *components;
    ngx_str_t                                signature; /* raw bytes, decoded from the Signature field */
    ngx_str_t                                agent_host; /* set only once verification succeeds */
} ngx_auth_httpsig_signature_t;

/* now == 0 means "use ngx_time()"; tests inject a fixed value instead so
 * that time-window checks are deterministic. */
typedef struct {
    const ngx_auth_httpsig_profile_t *profile;
    const ngx_auth_httpsig_keys_t    *keys;
    time_t                            expires_max;
    time_t                            max_skew;
    time_t                            now;
} ngx_auth_httpsig_profile_ctx_t;


/* Looks up a profile by its configured name (e.g. "web-bot-auth").
 * Returns NULL if no such profile is defined. */
const ngx_auth_httpsig_profile_t *ngx_auth_httpsig_profile_get(
    const ngx_str_t *name);

/*
 * Verifies `req` against `pctx->profile`, end to end: selects the
 * Signature-Input label tagged for this profile, checks its
 * parameters and covered components, checks its time window,
 * reconstructs the signature base string, and verifies the signature.
 *
 * Steps up to and including selecting the tagged label are fail-open:
 * "no such label" means the request simply carries no signature this
 * profile cares about (NGX_AUTH_HTTPSIG_RESULT_NOT_SIGNED), the same
 * as an unsigned request. Every step after that is fail-closed: any
 * failure is an ordinary, client-visible "not verified" outcome, never
 * silently treated as "not signed".
 *
 * Return value:
 *   NGX_OK        `*result` is NGX_AUTH_HTTPSIG_RESULT_OK; `sig` holds
 *                 the verified signature's fields, including
 *                 `agent_host`.
 *   NGX_DECLINED  `*result` explains why verification did not
 *                 succeed (including NOT_SIGNED). An ordinary
 *                 outcome, not an internal error.
 *   NGX_ERROR     a required argument is NULL, or pool allocation
 *                 failed; `*result` is left unset.
 */
ngx_int_t ngx_auth_httpsig_profile_verify(ngx_pool_t *pool,
    const ngx_auth_httpsig_profile_ctx_t *pctx,
    const ngx_auth_httpsig_request_t *req,
    ngx_auth_httpsig_signature_t *sig,
    ngx_auth_httpsig_result_t *result);

/*
 * Checks `sig` (already selected and parsed) against `profile`'s
 * parameter, component, and Signature-Agent requirements only: no SFV
 * parsing, time window, or cryptographic verification. Exposed so
 * unit tests can cover profile matching without building a full
 * request and keyset.
 *
 * Return value: NGX_OK (`*result` is NGX_AUTH_HTTPSIG_RESULT_OK) or
 * NGX_DECLINED (`*result` is NGX_AUTH_HTTPSIG_RESULT_PROFILE_MISMATCH).
 */
ngx_int_t ngx_auth_httpsig_profile_match(
    const ngx_auth_httpsig_profile_t *profile,
    const ngx_auth_httpsig_signature_t *sig,
    ngx_auth_httpsig_result_t *result);

/*
 * Extracts the lowercased host (no port) of a raw Signature-Agent
 * field value, leaving `out` empty unless the value is an https URL.
 * Exposed so $httpsig_agent can be derived from an as-yet-unverified
 * Signature-Agent value, before signature verification has run.
 */
void ngx_auth_httpsig_profile_agent_host(ngx_pool_t *pool,
    const ngx_str_t *raw, ngx_str_t *out);

/*
 * Extracts the lowercased authority (host, plus ":<port>" if present)
 * of a raw Signature-Agent field value, leaving `out` empty unless the
 * value is an https URL. Exposed so the key-directory fetch path can
 * match it against "auth_httpsig_trusted_agent" entries and dial it
 * directly, both of which need the exact authority, not just the
 * hostname.
 */
void ngx_auth_httpsig_profile_agent_authority(ngx_pool_t *pool,
    const ngx_str_t *raw, ngx_str_t *out);


#endif /* NGX_AUTH_HTTPSIG_PROFILE_H */
