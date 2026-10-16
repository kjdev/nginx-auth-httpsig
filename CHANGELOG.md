# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/), and this project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

#### Enforcement

- `auth_httpsig_mode enforce`: rejects a request whose signature is present, in scope, and fails verification, with a status code selected by failure category
- `auth_httpsig_require`: rejects a request with no in-scope signature (unsigned, or a mismatched `tag`), independent of `auth_httpsig_mode enforce`
- `auth_httpsig_status_parse_error`, `auth_httpsig_status_missing`, `auth_httpsig_status_replay`, `auth_httpsig_status_invalid` directives to override the default status code per failure category
- `satisfy any` support: this module's rejection status is clamped to `403` (unless already `403`/`401`) so it participates in nginx's OR aggregation with other access-phase modules
- `auth_httpsig_key_rotation_retry_ttl`: rate-limited forced key-directory refetch, per host, to rescue a signature whose `keyid` doesn't match the cached key set because the signer just rotated its key

#### Replay prevention

- `auth_httpsig_nonce_store` (`off` / `shm` / `redis`): checks a verified signature's `nonce` against a store and rejects a repeat within the signature's own `created`/`expires` window; `shm` and `redis` are mutually exclusive across the whole configuration, with no automatic fallback between them
- `auth_httpsig_nonce_store_zone`: shared-memory zone for the `shm` backend, sized by the operator; has no eviction, so a full zone fails open until nginx is restarted
- `auth_httpsig_nonce_store_redis`: connection parameters (`hostname=`, `port=`, `database=`, `connect_timeout=`, `command_timeout=`) for the `redis` backend, built only when the module is compiled with `NGX_AUTH_HTTPSIG_NONCE_REDIS` (links `hiredis`)
- `auth_httpsig_nonce_required`: rejects a verified signature that carries no `nonce` (`$httpsig_error` = `nonce_missing`, denied via `auth_httpsig_status_invalid` under `auth_httpsig_mode enforce`) so a signer cannot opt out of replay prevention by omitting it; requires `auth_httpsig_nonce_store`
- `nonce_replayed`, `nonce_too_long`, `nonce_store_unavailable` values for `$httpsig_error`: a replay denies only under `auth_httpsig_mode enforce` via `auth_httpsig_status_replay`; an oversized `nonce` (over 256 bytes) is always rejected, not fail-open; an unreachable store fails the request open with its already-successful verdict intact

### Security

- `KEY_UNAVAILABLE` outcomes (including `agent_not_allowed` and every `directory_*` fetch failure) always stay fail-open, even under `auth_httpsig_mode enforce` and `auth_httpsig_require`

### Known limitations

- Replay prevention only covers signatures that carry a `nonce`; the `web-bot-auth` profile treats `nonce` as optional, so a signer can omit it and bypass replay checking entirely — this cannot be forced from this module's configuration
- The `shm` nonce store has no eviction; once its zone fills, it stays full (and every subsequent signed request fails open) until nginx is restarted

### Dependencies

- `hiredis` (development headers), only when built with `NGX_AUTH_HTTPSIG_NONCE_REDIS` set, to enable the `redis` nonce store backend

## [0.1.0] - 2026-09-10

### Added

#### Verification

- RFC 8941 Structured Fields parsing/serialization, implemented in-tree (no external SFV dependency)
- RFC 9421 signature base string reconstruction, including `@method`, `@target-uri`, `@authority`, `@scheme`, `@request-target`, `@path`, `@query`, and `@query-param` (RFC 9421-compliant form-urlencoded decoding) derived components
- `Signature-Agent` component support, including its `key` parameter and Dictionary Structured Field form
- Ed25519 signature verification against keys resolved from a JWKS document
- Web Bot Auth profile enforcement (required `tag`, parameters, and covered components; configurable `expires`/clock-skew ceilings)
- `auth_httpsig_mode`, `auth_httpsig_profile`, `auth_httpsig_jwks_file`, `auth_httpsig_expires_max`, `auth_httpsig_max_skew`, `auth_httpsig_scheme_var` directives
- `$httpsig_verified`, `$httpsig_keyid`, `$httpsig_agent`, `$httpsig_error` variables

#### Dynamic key directory

- Fetches a signer's key directory from `/.well-known/http-message-signatures-directory` over HTTPS, gated by a mandatory host allowlist (`auth_httpsig_agent_allow`)
- Shared-memory key-directory cache with configurable TTL clamping (`auth_httpsig_key_cache_zone`, `auth_httpsig_key_cache_min_ttl`, `auth_httpsig_key_cache_max_ttl`) and per-worker fetch deduplication
- Worker-local JWKS parse cache to avoid re-parsing an unchanged cached key directory on every request
- `auth_httpsig_key_directory_request`, `auth_httpsig_key_directory_max_size` directives
- `$httpsig_directory_host` / `$httpsig_directory_hostname` variables for the internal fetch location's `Host`/`proxy_pass` and `proxy_ssl_name` (SNI), respectively
- Opt-in `auth_httpsig_keyid_fallback_allow` for directories that publish a non-thumbprint `kid`, plus a distinct `keyid_not_thumbprint` diagnostic when it's off
- Detailed `$httpsig_error` classification for every directory-fetch failure mode (`directory_busy`, `directory_unavailable`, `directory_not_https`, `directory_redirect`, `directory_status`, `directory_media_type`, `directory_too_large`, `directory_empty`, `directory_invalid`, `directory_failed`, `agent_not_allowed`, `key_unavailable`)
- Startup warning when an internal fetch location's `subrequest_output_buffer_size` is smaller than `auth_httpsig_key_directory_max_size`

#### Container images and tooling

- A Docker image (`module` target) exposing just the built dynamic module
- A standalone observe-mode proxy image (`proxy` target) that generates its full nginx configuration, including the dynamic key directory, from environment variables, and forwards the verification result as upstream request headers
- A replay tool for re-sending captured real crawler traffic against a running deployment for observe-mode testing

### Security

- The observe-proxy image rejects a cleartext `HTTPSIG_UPSTREAM` by default (`HTTPSIG_UPSTREAM_ALLOW_INSECURE` opts out for trusted loopback/internal upstreams only)
- Signature-Agent host matching preserves the authority's port instead of discarding it when checked against `auth_httpsig_agent_allow`
- The key-directory host normalization used for the fetch subrequest rejects a non-numeric port suffix instead of silently stripping it, and correctly handles bracketed IPv6 literals

### Known limitations

- Signature algorithm support is Ed25519 only
- No enforcement mode: every outcome is currently fail-open (`$httpsig_verified` reports a verdict but never causes a rejection)
- No replay prevention beyond the signature's own `expires`/`created` window — there is no nonce store

### Dependencies

- Requires OpenSSL 3.0 or later
- Vendors `nxe-json` (JSON), `nxe-jwx` (JWKS parsing / key resolution), and `nxe-phase` (cross-module phase-handler ordering) as git submodules
