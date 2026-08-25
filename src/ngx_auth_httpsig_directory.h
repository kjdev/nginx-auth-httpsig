/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_directory.h - pure logic for the dynamic key
 * directory: allow-list host normalization/matching and JWKS cache TTL
 * derivation from a fetched response's Cache-Control/Age. Kept
 * nginx-core-only (ngx_pool_t/ngx_str_t) so it is unit-testable without
 * a running nginx; SHM storage lives in ngx_auth_httpsig_cache.h.
 */

#ifndef NGX_AUTH_HTTPSIG_DIRECTORY_H
#define NGX_AUTH_HTTPSIG_DIRECTORY_H


#include <ngx_config.h>
#include <ngx_core.h>


/* Why ngx_auth_httpsig_directory_normalize_host() rejected a host;
 * meaningful only when that function returns NGX_ERROR. */
typedef enum {
    NGX_AUTH_HTTPSIG_HOST_EMPTY = 1,
    NGX_AUTH_HTTPSIG_HOST_HAS_SCHEME,
    NGX_AUTH_HTTPSIG_HOST_WILDCARD,
    NGX_AUTH_HTTPSIG_HOST_INVALID_CHAR
} ngx_auth_httpsig_host_reason_t;


/*
 * Normalizes a bare "host[:port]" argument (auth_httpsig_trusted_agent,
 * or a Signature-Agent host already extracted from a URL) for
 * allow-list matching: lowercases it and strips a trailing ":443",
 * since the default HTTPS port carries no matching information (ADR
 * 0012 pins this fetch path to HTTPS).
 *
 * Rejects, rather than silently ignoring, anything that is not a bare
 * host[:port]: a "://" scheme, a path/query/fragment/userinfo
 * separator, or a wildcard ("*"). Accepting and stripping the extra
 * parts here would let an operator write an allow-list entry that
 * looks like it restricts more than it does; this function's whole job
 * is to be the SSRF gate's normalization step, so ambiguity here is a
 * security bug, not a convenience. See tasks/adr/0013-*.md.
 *
 * Return value:
 *   NGX_OK     `*out` holds the normalized host, allocated from `pool`.
 *   NGX_ERROR  `in` is not a valid bare host; `*reason` explains why,
 *              unless the failure was a pool allocation failure.
 */
ngx_int_t ngx_auth_httpsig_directory_normalize_host(ngx_pool_t *pool,
    const ngx_str_t *in, ngx_str_t *out,
    ngx_auth_httpsig_host_reason_t *reason);

/*
 * Reports whether `host` (already normalized) exactly matches an entry
 * in `allow` (an ngx_array_t of normalized ngx_str_t, as produced by
 * the auth_httpsig_trusted_agent directive). No wildcard, prefix, or
 * suffix matching -- exact match only, by design (ADR 0013.2).
 *
 * Returns 0 if `allow` is NULL or empty, or `host` is NULL.
 */
ngx_flag_t ngx_auth_httpsig_directory_allowed(const ngx_array_t *allow,
    const ngx_str_t *host);

/*
 * Derives the cache TTL for a fetched key-directory document from its
 * Cache-Control header and Age, clamped to [min_ttl, max_ttl].
 *
 * `cache_control` may be NULL or empty (header absent). "no-store",
 * "no-cache", "private", and an absent/unparseable max-age/s-maxage all
 * derive a pre-clamp TTL of 0 -- they collapse into the same "trust
 * nothing, apply the floor" path, since min_ttl is a floor regardless
 * of what the origin claims, not a signal to skip caching (ADR 0014.2).
 * "s-maxage" takes priority over "max-age" when both are present.
 * `age` (0 if unknown) is subtracted from the derived value before
 * clamping.
 *
 * Numeric overflow in max-age/s-maxage saturates to a large value
 * rather than falling through to "unparseable", since a value that
 * reads as enormous is more accurately "at least max_ttl" than
 * "absent"; the final clamp then brings it down to max_ttl.
 */
time_t ngx_auth_httpsig_directory_ttl(const ngx_str_t *cache_control,
    time_t age, time_t min_ttl, time_t max_ttl);


#endif /* NGX_AUTH_HTTPSIG_DIRECTORY_H */
