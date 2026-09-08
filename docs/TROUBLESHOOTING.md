# Troubleshooting

How to read this module's diagnostics when a signature isn't verifying the way you expect.

See also: [DIRECTIVES](DIRECTIVES.md) · [SECURITY](SECURITY.md)

## First: remember this module fails open

Nothing this module does rejects a request.
If a request you expected to be blocked went through anyway, that is expected behavior today, not a bug — see [SECURITY.md](SECURITY.md#fail-open-by-design).
What you're troubleshooting is almost always "why didn't `$httpsig_verified` come back `1`," which you diagnose through `$httpsig_error` and the error log, not through observed request outcomes.

## Reading `$httpsig_verified` / `$httpsig_error`

Expose them in your access log or as response headers (never rely on string-comparing against `""` — unset is a distinct state from empty):

```nginx
log_format httpsig_observe
    'verified="$httpsig_verified" keyid="$httpsig_keyid" '
    'agent="$httpsig_agent" claimed_agent="$http_signature_agent" '
    'error="$httpsig_error"';

access_log /var/log/nginx/httpsig_observe.log httpsig_observe;
```

- `verified` empty (unset) + `error` empty (unset): the request had no in-scope signature at all — not a failure, just nothing to verify.
  Check whether the client is actually sending `Signature-Input` and whether its `tag` matches your `auth_httpsig_profile`.
- `verified="0"` with an `error` set: a signature was present, in scope, and failed for the reason in `error` — see the table below.
- `claimed_agent` (the raw `Signature-Agent` request header) is present even when verification didn't succeed, unlike `agent` (`$httpsig_agent`), which is only set on success — compare the two to see who *claimed* to sign versus who actually verified.

Aggregate the distribution of claimed vs. verified agents from the log:

```sh
grep -oP '(?<= )claimed_agent="\K[^"]*' /var/log/nginx/httpsig_observe.log \
    | sort | uniq -c | sort -rn

grep 'verified="1"' /var/log/nginx/httpsig_observe.log \
    | grep -oP '(?<= )agent="\K[^"]*' \
    | sort | uniq -c | sort -rn
```

## `$httpsig_error` cheat sheet

| Value | Likely cause | What to check |
|---|---|---|
| `parse_error` | Malformed `Signature-Input`/`Signature`/`Signature-Agent` | Client's Structured Fields serialization; capture the raw header |
| `unknown_keyid` | Key not in your JWKS / directory hasn't been fetched yet | Confirm the key is actually published/loaded; for the dynamic directory, check `directory_*` errors first |
| `keyid_not_thumbprint` | `keyid` is a `kid`, not an RFC 7638 thumbprint | Either fix the signer to publish thumbprint-based `keyid`s, or set `auth_httpsig_keyid_fallback_allow on` (dynamic directory only — see [SECURITY.md](SECURITY.md#keyid-trust-model)) |
| `signature_mismatch` | Wrong key, or the signature base string doesn't match what the client actually signed | Check covered components match on both sides; check for a proxy in between rewriting headers/URI after the client signed |
| `expired` | Clock skew beyond `auth_httpsig_max_skew`, or `expires - created` beyond `auth_httpsig_expires_max` | Check NTP sync on both ends; check whether the signer's stated lifetime exceeds your configured ceiling |
| `profile_mismatch` | Missing a required parameter or covered component for the active profile | Compare the request's `Signature-Input` against [DIRECTIVES.md](DIRECTIVES.md#auth_httpsig_profile)'s required set |
| `agent_not_allowed` | `Signature-Agent` host isn't in `auth_httpsig_agent_allow` | Add the host, or confirm you intended to reject this signer |
| `key_unavailable` | Directory fetch didn't yield a usable key for this `keyid` | Check the `directory_*` errors below — this is usually a downstream symptom of one of them |
| `directory_busy` | Concurrent requests raced the same uncached host | Transient; if persistent, the fetch may be timing out repeatedly (see `directory_unavailable`) |
| `directory_unavailable` | Fetch subrequest failed (connect/DNS/timeout) | Check `resolver`, connectivity to the target host, and nginx error log for the underlying subrequest failure |
| `directory_not_https` | Target didn't resolve to HTTPS | Check the `Signature-Agent` host and your internal fetch location's `proxy_pass` scheme |
| `directory_redirect` | Directory response was a redirect | Not followed by design; point the fetch at the final URL directly, or ask the operator to stop redirecting |
| `directory_status` | Non-200 response | Check the directory endpoint is actually serving `/.well-known/http-message-signatures-directory` |
| `directory_media_type` | Response `Content-Type` didn't match the profile's expected type | Check the directory server's `Content-Type` header |
| `directory_too_large` | Response exceeded `auth_httpsig_key_directory_max_size` | Raise the limit (ceiling 256 KiB) if legitimate, and check `subrequest_output_buffer_size` is at least as large |
| `directory_empty` | Response body was empty | Check the directory endpoint itself, independent of this module |
| `directory_invalid` | Response didn't parse as a JWKS | Validate the directory response body against the JWKS format |
| `directory_failed` | Uncategorized fetch failure | Check the nginx error log for detail |
| `internal` | Internal error, not client-caused | Check the nginx error log; consider filing an issue with the log excerpt |

## Buffer-size warnings

When a key-directory fetch completes, the module logs a warning if `subrequest_output_buffer_size` on the internal fetch location is smaller than `auth_httpsig_key_directory_max_size` — fix by raising `subrequest_output_buffer_size` in that location (see [DIRECTIVES.md](DIRECTIVES.md#auth_httpsig_key_directory_max_size)).

## Still stuck

Check the nginx error log at `info` level for `auth_httpsig:`-prefixed lines — the module never logs raw `Signature` bytes, but does log enough context (component, parameter, or step that failed) to narrow down parse vs. crypto vs. fetch issues.
