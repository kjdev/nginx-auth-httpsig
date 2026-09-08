# Directive reference

Configuration directive and `$httpsig_*` variable reference for
`nginx-auth-httpsig`.

See also: [INSTALL](INSTALL.md) · [EXAMPLES](EXAMPLES.md) ·
[SECURITY](SECURITY.md) · [TROUBLESHOOTING](TROUBLESHOOTING.md)

## Directives

| Directive | Context |
|---|---|
| [auth_httpsig_mode](#auth_httpsig_mode) | http, server, location |
| [auth_httpsig_profile](#auth_httpsig_profile) | http, server, location |
| [auth_httpsig_scheme_var](#auth_httpsig_scheme_var) | http, server, location |
| [auth_httpsig_jwks_file](#auth_httpsig_jwks_file) | http, server, location |
| [auth_httpsig_agent_allow](#auth_httpsig_agent_allow) | http, server, location |
| [auth_httpsig_key_directory_request](#auth_httpsig_key_directory_request) | http, server, location |
| [auth_httpsig_key_directory_max_size](#auth_httpsig_key_directory_max_size) | http, server, location |
| [auth_httpsig_key_cache_zone](#auth_httpsig_key_cache_zone) | http |
| [auth_httpsig_key_cache_min_ttl](#auth_httpsig_key_cache_min_ttl--auth_httpsig_key_cache_max_ttl) | http, server, location |
| [auth_httpsig_key_cache_max_ttl](#auth_httpsig_key_cache_min_ttl--auth_httpsig_key_cache_max_ttl) | http, server, location |
| [auth_httpsig_expires_max](#auth_httpsig_expires_max) | http, server, location |
| [auth_httpsig_max_skew](#auth_httpsig_max_skew) | http, server, location |
| [auth_httpsig_keyid_fallback_allow](#auth_httpsig_keyid_fallback_allow) | http, server, location |

All directives are valid in `http`, `server`, and `location` blocks, except
`auth_httpsig_key_cache_zone`, which is `http`-only (a shared memory zone is
a per-instance resource, not a per-location one).

A directive left unset in a block inherits from the parent block, with one
exception noted under `auth_httpsig_agent_allow`.

## Verification mode

### auth_httpsig_mode

```text
Syntax:  auth_httpsig_mode off | observe;
Default: auth_httpsig_mode off;
Context: http, server, location
```

Turns verification on for a block.
`observe` verifies only requests that are in scope for the active
`auth_httpsig_profile`; a signed request with no Signature-Input label
tagged for that profile gets no verdict, the same as an unsigned request.
For in-scope requests it exposes the outcome through `$httpsig_*`.
It never rejects the request based on the outcome — that is a design
invariant, not a stopgap: unsigned or out-of-scope requests are always
treated as "no verdict", never as a failure (see [SECURITY.md](SECURITY.md)).
An `enforce` mode that can reject on a failed verification is planned for a
later release; there is no directive-level way to reject requests today.

### auth_httpsig_profile

```text
Syntax:  auth_httpsig_profile name;
Default: auth_httpsig_profile web-bot-auth;
Context: http, server, location
```

Selects the profile table that governs which `Signature-Input` tag,
required parameters, required covered components, `alg` value, and
`expires` ceiling a request must satisfy.
`web-bot-auth` is the only profile currently defined and requires
`alg=ed25519` when the parameter is present; a mismatch on any of these
constraints is reported as `profile_mismatch`.

A signature whose `tag` does not match the active profile is treated as
out of scope and passed through unverified, not rejected.
This is what keeps this module from misclassifying draft-cavage-style
signatures used by other ecosystems (e.g. ActivityPub) as failures.

### auth_httpsig_scheme_var

```text
Syntax:  auth_httpsig_scheme_var $name;
Default: auth_httpsig_scheme_var $scheme;
Context: http, server, location
```

Names the variable consulted for the `@scheme` derived component (and, by
extension, `@target-uri`).
The argument must be `$`-prefixed; nginx rejects a bare name.

nginx refuses to redefine the core `$scheme` variable via `map`, so an
operator running this module behind a TLS-terminating load balancer that
forwards `X-Forwarded-Proto` points this at a `map`-defined variable
instead of trying to override `$scheme` itself.
See [EXAMPLES.md](EXAMPLES.md#behind-a-tls-terminating-load-balancer).

## Key sources

A location with `auth_httpsig_mode` other than `off` must configure at
least one key source: `auth_httpsig_jwks_file`, or the dynamic key
directory (`auth_httpsig_agent_allow` + `auth_httpsig_key_directory_request`).
Configuring neither is a configuration-time error.

### auth_httpsig_jwks_file

```text
Syntax:  auth_httpsig_jwks_file path;
Default: -
Context: http, server, location
```

Loads a static JWKS document from `path` at startup (relative paths
resolve against the nginx prefix).
Keys are matched against a request's `keyid` Signature-Input parameter by
RFC 7638 JWK thumbprint, never by the JWKS `kid` field.
The file must not exceed the internal JWKS size ceiling (256 KiB); a
larger file is a configuration-time error, not a runtime fallback.

### auth_httpsig_agent_allow

```text
Syntax:  auth_httpsig_agent_allow host[:port] ...;
         auth_httpsig_agent_allow off;
Default: -
Context: http, server, location
```

Enables the dynamic key directory: the module fetches
`https://host/.well-known/http-message-signatures-directory` only when a
request carries a `Signature-Input` label tagged for the active
`auth_httpsig_profile` *and* a `Signature-Agent` that resolves to a host
on this list (see [SECURITY.md](SECURITY.md) for why this list exists at
all — it is the SSRF gate for that fetch).
`Signature-Agent` alone never triggers a fetch — an unauthenticated
client could otherwise use it to amplify traffic toward an allow-listed
host.
Hosts not on the list do not trigger a dynamic key-directory fetch. A static
JWKS, when configured, is still used through the normal static-key path.

The argument is one or more authorities (`host` or `host:port`, exact
match only — no wildcards), or the single keyword `off`.

Repeated invocations in the same block accumulate (like `allow`/`deny`).
`off` is special: it explicitly discards whatever the parent block would
otherwise have inherited, and cannot be combined with hostnames, either in
the same invocation or across invocations in the same block — a host list
containing `off` would be ambiguous about whether those hosts are allowed.
This is the one directive that does **not** simply inherit silently: a
block that declares `auth_httpsig_agent_allow` (including `off`) always
overrides the parent's value instead of adding to it.

Setting this to a non-empty list requires both
`auth_httpsig_key_directory_request` and `auth_httpsig_key_cache_zone` to
be configured somewhere the block can see.
Otherwise nginx refuses to start.

### auth_httpsig_key_directory_request

```text
Syntax:  auth_httpsig_key_directory_request uri;
Default: -
Context: http, server, location
```

Names the internal location nginx issues the key-directory fetch
subrequest against.
The argument is a path starting with `/`, containing no `$` variables.

Variables are rejected deliberately: this URI is consumed at request time,
so allowing a variable here would be the one path by which
client-controlled input could reach the fetch subrequest's target
location.
The target host is instead threaded through separately, via
`$httpsig_directory_host` — see
[EXAMPLES.md](EXAMPLES.md#dynamic-key-directory) for the internal location
this points at.

### auth_httpsig_key_directory_max_size

```text
Syntax:  auth_httpsig_key_directory_max_size size;
Default: auth_httpsig_key_directory_max_size 64k;
Context: http, server, location
```

Caps the size of a fetched key-directory response, up to a hard ceiling of
`256k` — a larger value is a configuration-time error.
Responses over this limit are rejected (`$httpsig_error` =
`directory_too_large`) and the request fails open (no verdict).

This is enforced by the module itself, *after* the response is received.
The internal fetch location's `subrequest_output_buffer_size` must
independently be set to at least this value, or nginx's own subrequest
buffer limit (default `ngx_pagesize`, usually 4096 bytes) rejects a larger
response before the module ever sees it — this can suppress
`directory_too_large` for a response that only exceeds nginx's smaller
limit.
The module logs a warning once a key-directory fetch completes if it
detects this is not the case, but cannot enforce it, since
`subrequest_output_buffer_size` belongs to nginx core.

### auth_httpsig_key_cache_zone

```text
Syntax:  auth_httpsig_key_cache_zone name:size;
Default: -
Context: http
```

Declares the shared-memory zone that caches fetched key-directory
documents across workers, keyed by host.
Required if any location in the configuration enables the dynamic key
directory.
The argument is a shared-memory zone name and size, minimum 8 pages (same
syntax and floor as `limit_req_zone`'s `zone=` parameter).

This directive may be declared at most once per nginx instance — the
cache is process-global, not per-location, so every protected location
referencing the same directory host shares one cache entry (see the
multi-location caveats in [SECURITY.md](SECURITY.md)).

### auth_httpsig_key_cache_min_ttl / auth_httpsig_key_cache_max_ttl

```text
Syntax:  auth_httpsig_key_cache_min_ttl time;
Default: auth_httpsig_key_cache_min_ttl 5m;
Context: http, server, location
```

```text
Syntax:  auth_httpsig_key_cache_max_ttl time;
Default: auth_httpsig_key_cache_max_ttl 1h;
Context: http, server, location
```

Clamps the TTL a fetched key directory is cached for.
The TTL is derived from the response's `Cache-Control` header —
`s-maxage` takes priority over `max-age` when both are present — minus
its `Age` header, then clamped into `[min_ttl, max_ttl]`.
`no-store`, `no-cache`, and `private` do not disable caching: they yield
the same pre-clamp value as an absent or unparseable max-age/s-maxage, so
the entry is still cached for at least `min_ttl`.
`min_ttl` must not be `0`; `max_ttl` must not be less than `min_ttl` (both
checked at configuration time).

This TTL governs only how long the *key set* is reused.
It is deliberately independent of a signature's own `expires` parameter,
which is still checked on every request regardless of cache state —
conflating the two would mean a cached key set could keep verifying
signatures a rotated key should no longer accept.

## Time-window validation

### auth_httpsig_expires_max

```text
Syntax:  auth_httpsig_expires_max time;
Default: -
Context: http, server, location
```

Caps the allowed lifetime of a signature: `expires` must not precede
`created`, and `expires - created` must not exceed this value, or the
signature is rejected (`$httpsig_error` = `expired`).
Defaults to the active profile's value (`86400s` / 24h for
`web-bot-auth`).

An explicit value overrides the active profile's default ceiling in
either direction: tightening it below the default is a valid way to
require freshly-signed requests, but raising it — e.g. to `7d` — is
equally possible and extends how long a captured signature stays
replayable past `web-bot-auth`'s 24h default (this module has no nonce
store; see `auth_httpsig_max_skew`).

### auth_httpsig_max_skew

```text
Syntax:  auth_httpsig_max_skew time;
Default: -
Context: http, server, location
```

Allowed clock skew when checking `created` (not in the future by more
than this) and `expires` (not in the past by more than this).
Defaults to the active profile's value (`60s` for `web-bot-auth`).

This is tolerance for clock drift between the signer and this server, not
a replay-prevention window — this module has no nonce store, so a
signature can be replayed verbatim until it expires.

## Key trust

### auth_httpsig_keyid_fallback_allow

```text
Syntax:  auth_httpsig_keyid_fallback_allow on | off;
Default: auth_httpsig_keyid_fallback_allow off;
Context: http, server, location
```

Opt-in fallback for a `keyid` that is not an RFC 7638 thumbprint but does
match a JWKS entry's `kid` field.
With this off (the default), such a signature is reported as
`$httpsig_error` = `keyid_not_thumbprint` and never verified.
With this on, the module additionally attempts verification keyed by the
raw `kid`.

This applies only to keys resolved through the dynamic key directory
(`auth_httpsig_agent_allow`); it never applies to `auth_httpsig_jwks_file`.
See [SECURITY.md](SECURITY.md#keyid-trust-model) for what this trades
away.

## `$httpsig_*` variables

All variables are read-only and `NGX_HTTP_VAR_NOCACHEABLE` (re-evaluated on
every access within a request, not cached after the first read).
The verdict variables (`$httpsig_verified`, `$httpsig_keyid`,
`$httpsig_agent`, `$httpsig_error`) are "unset" (`not_found`), not empty
string, when there is no verdict to report — check with an existence
test, not string comparison against `""`.
`if ($httpsig_verified) { ... }` is a success check, not an existence
test: it is false both for a reached failure verdict (`0`) and for no
verdict at all (unset).
Use `$httpsig_error` or an explicit comparison against
`$httpsig_verified` when a policy must distinguish failure from no
verdict.
The directory variables (`$httpsig_directory_host`,
`$httpsig_directory_hostname`) are fetch-location values, not verdicts;
they are populated during a dynamic key-directory lookup and intended
only for internal fetch configuration — never pass them to a
client-facing response.

| Variable | Set when | Value |
|---|---|---|
| `$httpsig_verified` | a verdict was reached | `1` (success) or `0` (failure); unset for unsigned or out-of-scope requests, for a key-resolution failure (`key_unavailable`, including dynamic-directory fetch failures), and for an internal evaluation error |
| `$httpsig_keyid` | verification succeeded | the verified `keyid`; normally an RFC 7638 thumbprint, but it may be a raw JWKS `kid` when `auth_httpsig_keyid_fallback_allow` is on |
| `$httpsig_agent` | verification succeeded and a host was extracted | the host extracted from `Signature-Agent`; unset when no host is available |
| `$httpsig_error` | a verdict of failure, or a fail-open decline, was reached | one of the tokens below |
| `$httpsig_directory_host` | a dynamic key-directory lookup was triggered | the authority (host[:port]) to fetch from — pass to `Host` / `proxy_pass`, never to a client-facing response |
| `$httpsig_directory_hostname` | a dynamic key-directory lookup was triggered | `$httpsig_directory_host` with any `:port` suffix stripped (IPv6 brackets kept) — pass to `proxy_ssl_name` (SNI) only |

`$httpsig_directory_host` and `$httpsig_directory_hostname` exist
specifically to keep client-influenced input (the `Signature-Agent` host)
out of the `location` block's own configuration text, while still letting
that host reach `Host` / `proxy_pass` / `proxy_ssl_name` inside the
dedicated internal fetch location.
See [EXAMPLES.md](EXAMPLES.md#dynamic-key-directory).

### `$httpsig_error` values

| Value | Meaning |
|---|---|
| `internal` | An internal error occurred while evaluating the request (never a client-caused rejection) |
| `parse_error` | `Signature-Input` / `Signature` / `Signature-Agent` failed to parse as Structured Fields |
| `unknown_keyid` | `keyid` does not match any known key's thumbprint or `kid` |
| `keyid_not_thumbprint` | `keyid` matches a `kid` but not a thumbprint (see `auth_httpsig_keyid_fallback_allow`) |
| `signature_mismatch` | Cryptographic verification failed against the resolved key |
| `expired` | The signature is outside the `created`/`expires` time window |
| `profile_mismatch` | Required parameters or covered components for the active profile are missing, or the supplied `alg` does not match the active profile |
| `key_unavailable` | The key directory fetch did not yield usable keys (fail-open; see below) |
| `agent_not_allowed` | `Signature-Agent` resolves to a host not on `auth_httpsig_agent_allow` |
| `directory_busy` | Another worker is already fetching this host's key directory |
| `directory_unavailable` | The shared cache zone had no room to track this host, or the last fetch for it failed too recently to retry |
| `directory_not_https` | The fetch target did not resolve to an HTTPS upstream |
| `directory_redirect` | The key-directory response was a redirect (not followed) |
| `directory_status` | The key-directory response status was not 200 |
| `directory_media_type` | The key-directory response media type did not match |
| `directory_too_large` | The key-directory response exceeded `auth_httpsig_key_directory_max_size` |
| `directory_empty` | The key-directory response body was empty |
| `directory_invalid` | The key-directory response body did not parse as a JWKS |
| `directory_failed` | The fetch subrequest itself failed (connect/timeout/DNS) or another internal error prevented the fetch |

Every `directory_*` value and `key_unavailable` are fail-open outcomes: the
request proceeds with no verdict, exactly as if it were unsigned.
They exist purely for operational diagnosis (see
[TROUBLESHOOTING.md](TROUBLESHOOTING.md)), not to signal a rejection.
