# Security

The design decisions here trade off against each other; this document explains what this module does and does not protect against, and why.
For directive-level detail see [DIRECTIVES.md](DIRECTIVES.md).

## Fail-open by design

Unsigned requests, out-of-scope signatures (wrong `tag`), and failed directory fetches all produce "no verdict" — `$httpsig_verified` stays unset, never a rejection — as long as `auth_httpsig_require` is off.
A failed directory fetch keeps producing "no verdict" regardless of `auth_httpsig_mode` or `auth_httpsig_require`; an unsigned or out-of-scope request does not once `auth_httpsig_require` is on (see below).
With `auth_httpsig_mode observe` (the default) and `auth_httpsig_require off` (the default), that is the *entire* behavior: this module never rejects anything, full stop.
`auth_httpsig_mode enforce` and `auth_httpsig_require` narrow this, but only in two specific, additive ways (see [DIRECTIVES.md](DIRECTIVES.md#enforcement)):

- `enforce` rejects a signature that is present, in scope, and fails cryptographic verification (wrong key, tampered bytes, expired, or a profile mismatch).
- `require` rejects a request with no in-scope signature at all (unsigned, or a `tag` that doesn't match the active profile).

`enforce` narrows one more case that isn't attributable to either signer or client: an internal evaluation error (`$httpsig_error` = `internal` — a pool allocation failure, or the verification call itself failing unexpectedly) returns `500` instead of failing open.
With `mode observe`, the same error still fails open regardless of `auth_httpsig_require`, like everything else in this document, since `observe` never turns an evaluation outcome into a denial.

Everything else still fails open, even with both of the above turned on:

- A `key_unavailable` outcome — the key-directory fetch didn't yield usable keys, for any reason, including the `Signature-Agent` host not being on `auth_httpsig_agent_allow` — is never treated as a verification failure or as "missing," under either `enforce` or `require`.
  This applies only when no usable JWKS is retained at all: if a previously-cached JWKS is still held but simply doesn't cover the requested `keyid` (for example, a rotation the retry rescue below didn't catch), evaluation reports `unknown_keyid` instead, which `enforce` rejects the same way it rejects any other failed verification (the bullet above).
  A signer this server currently can't fetch keys for is indistinguishable, from this module's point of view, from a temporarily-unreachable directory, and denying on that basis would make an operator's own infrastructure availability (DNS, the directory host, the shared cache zone) a lever for rejecting otherwise-legitimate traffic.
  If your threat model requires "reject unless a key was actually resolved," you must build that check yourself on top of `$httpsig_verified`/`$httpsig_error` (see below).
- An out-of-scope signature (wrong `tag`) is still treated as belonging to a different ecosystem, not as invalid, even under `enforce`.
  This keeps unrelated RFC 9421 consumers (or draft-cavage-style predecessors) from being misclassified as attacks against this module — but it also means a client can "opt out" of `enforce`'s rejection just by sending no signature or a differently-tagged one, which then falls to `require` (if set) instead of `enforce`.
- The narrow rescue for a just-rotated key (`auth_httpsig_key_rotation_retry_ttl`) is a rate-limited forced refetch, not a guarantee: only one rescue fetch happens per key-directory host per TTL window.
  A second signer whose key rotates in the same window is not rescued: if a stale-but-parseable JWKS is still cached, the request resolves to `unknown_keyid` and `enforce` rejects it as a failed verification; only when no usable JWKS is available at all does it resolve to `key_unavailable` and fail open, exactly as it would without the rescue.
- With `satisfy any`, this module's rejection status code is clamped to `403` so it participates in nginx's OR aggregation with other access-phase modules (see [DIRECTIVES.md](DIRECTIVES.md#satisfy-any-and-status-codes)) — this changes which status code a client sees, not whether the underlying decision was a rejection or a fail-open pass-through.

If you want to reject unsigned traffic without `auth_httpsig_require`, or reject on conditions this module doesn't cover, you build that policy on top of `$httpsig_verified`/`$httpsig_error` yourself (`if`/`map` + your own rejection, or pairing with another module — see [EXAMPLES.md](EXAMPLES.md)).

## The dynamic key directory is an SSRF surface — treat it as such

When `auth_httpsig_agent_allow` is set, this module fetches a URL derived from the client-controlled `Signature-Agent` header.
That is, by construction, server-side request forgery shaped like a feature.
The closures that make this safe are not optional hardening — they are the security boundary itself:

- **`auth_httpsig_agent_allow` is a mandatory allowlist, not a default-open list.**
  Only exact-match authorities you name are ever fetched.
  There is no wildcard support and no way to allow "anything the client claims" — if you find yourself wanting that, you have reintroduced the SSRF this directive exists to close.
- **The fetch is hardcoded to HTTPS** with certificate verification, and redirects are never followed.
  Any of `directory_not_https` / `directory_redirect` in `$httpsig_error` means the module refused a fetch that would otherwise have been an open proxy.
- **`proxy_ssl_verify on` and `proxy_ssl_trusted_certificate` are both mandatory on the internal fetch location, and neither one alone is enough.**
  nginx does not fall back to a system CA bundle just because `proxy_ssl_verify` is `on`.
  Omit `proxy_ssl_trusted_certificate` and the trust store is empty, so every fetch fails closed (safe, but nothing works).
  Omit `proxy_ssl_verify on` and certificates aren't checked at all — anyone who can intercept the connection (an on-path attacker, or the allowlisted host's own hosting provider) can then hand back arbitrary Ed25519 keys and impersonate that agent.
  Get both right, or don't bother enabling the dynamic directory.
- **Response size is capped** (`auth_httpsig_key_directory_max_size`, default 64 KiB, hard ceiling 256 KiB) and the response media type is checked against the profile's expected type.
  A response outside either bound is discarded (fail-open), not truncated-and-parsed.
- **The fetch is deduplicated across the whole nginx instance**, via the shared-memory cache zone: only one in-flight fetch per host at a time across every worker; a concurrent caller reuses a still-fresh stale key set if one exists, and only sees `directory_busy` when no stale set is available. This means a burst of requests referencing an unfetched host can't be used to hammer the target with parallel subrequests.
- **A forced refetch triggered by an unmatched `keyid` (to rescue a just-rotated key) is rate-limited per host** by `auth_httpsig_key_directory_max_size`'s sibling directive, `auth_httpsig_key_rotation_retry_ttl` (default 5m, must not be `0`).
  Without this limit, a client could send a stream of bogus `keyid` values to force a fetch against an allow-listed host on every single request, defeating the normal cache-TTL-bounded fetch rate.
- **Multiple locations sharing a key-directory host must use identical `proxy_ssl_*` / cache-TTL / size settings.**
  The cache is keyed by the normalized authority (`host[:port]`), not by location — nginx does not know which location's fetch populated a given cache entry.
  If one location has a looser `proxy_ssl_trusted_certificate` (or a longer max TTL, or a larger size cap) than another referencing the same host, its fetch can populate the shared cache entry that the stricter location's requests then trust.
  Keep these settings identical across every internal fetch location for the same host, or split hosts across separate cache zones if they genuinely need different policies.

See [DIRECTIVES.md](DIRECTIVES.md#auth_httpsig_key_directory_request) and [EXAMPLES.md](EXAMPLES.md#dynamic-key-directory) for the concrete configuration these constraints apply to.

## `keyid` trust model

`keyid` is normally required to be an RFC 7638 JWK Thumbprint — i.e., the key identifier is derived from the key material itself, so a signer can't claim someone else's `kid` and have this module treat it as authoritative.
`auth_httpsig_keyid_fallback_allow` (default `off`) opts into accepting a non-thumbprint `keyid` that matches a JWKS entry's `kid` field, for keys resolved through the dynamic directory only (never for `auth_httpsig_jwks_file`).
Turning this on means the key identifier is now whatever string the directory operator chose to publish under `kid`, rather than something self-certifying from the key bytes — you're trusting the directory operator's own bookkeeping, not just the key they hand you.
Leave this off unless you have a specific reason (e.g., interop with a directory you don't control that predates thumbprint-only `kid`s) to accept it.

## What is (and isn't) exposed

- `$httpsig_verified` / `$httpsig_keyid` / `$httpsig_agent` / `$httpsig_error` are safe to log or forward upstream — none of them contain anything a client didn't already send in cleartext, and none of them are trust decisions by themselves (see "fail-open by design" above).
- The raw `Signature` header value (the cryptographic signature bytes) is never written to the error log, regardless of log level.
  `keyid` and the `Signature-Agent` URL are logged where relevant, since both are already public information the signer sent.
- `$httpsig_directory_host` / `$httpsig_directory_hostname` exist only to route the internal key-directory fetch subrequest; they carry client-influenced input (the claimed `Signature-Agent` host, already checked against `auth_httpsig_agent_allow` by the time these are used) and are meant for `Host` / `proxy_pass` / `proxy_ssl_name` inside that internal location — not for a client-facing response header.

## Replay

This module has no nonce store or replay cache.
A captured, valid signature can be replayed verbatim by anyone until `expires` (bounded by `auth_httpsig_expires_max`) elapses.
`auth_httpsig_max_skew` bounds clock drift tolerance, not a replay window.
If your threat model requires replay prevention, it isn't provided by this module today.
