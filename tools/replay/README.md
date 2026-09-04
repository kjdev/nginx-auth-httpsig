# Replaying real crawler traffic

A development tool for observing how `auth_httpsig`'s SFV parser and
`$httpsig_error` behave against real, in-the-wild `Signature-Input` shapes,
by replaying captured crawler traffic through a standalone proxy instance.

## Sample format

`replay-samples.pl` reads a JSONL file, one captured request per line, with
these fields:

| field | required | meaning |
|---|---|---|
| `method` | no (default `GET`) | HTTP method |
| `path` | no (default `/`) | request path |
| `host` | no | forwarded as the `Host` header |
| `scheme` | no | `https` adds `X-Forwarded-Proto: https` (see `HTTPSIG_TRUST_X_FORWARDED_PROTO` in [`docker/README.md`](../../docker/README.md)) |
| `signature` | yes | forwarded as `Signature` |
| `signature_input` | yes | forwarded as `Signature-Input` |
| `signature_agent` | no | forwarded as `Signature-Agent` |
| `user_agent` | no | forwarded as `User-Agent` |

Only `path` is used from each sample's URL; a query string carried in the
sample is not replayed. Lines missing `signature` / `signature_input` are
skipped.

`created`/`expires` are themselves signed parameters, so they cannot be
rewritten for replay, and by replay time they are almost always outside
`auth_httpsig_max_skew`. Verification only succeeds if the proxy's max skew
has been widened for this purpose (see `REPLAY_MAX_SKEW` below).

## Usage

```sh
cd tools/replay
docker compose up --build -d backend

# See which Signature-Agent authorities are in the sample file
perl replay-samples.pl /path/to/samples.jsonl --list-agents

# Register the ones you want to observe, then replay
REPLAY_TRUSTED_AGENTS='agent.bot.goog' docker compose up --build -d --wait proxy
perl replay-samples.pl /path/to/samples.jsonl --target http://localhost:8082
```

`--list-agents` extracts the `Signature-Agent` authorities present in the
sample file, without sending any requests, so they can be reviewed before
registering them.

`REPLAY_TRUSTED_AGENTS` is **not** auto-populated from `--list-agents` — you
choose which real crawlers to trust. `REPLAY_MAX_SKEW` (default `365d`)
widens `auth_httpsig_max_skew` far enough to accept a sample's original
`created`/`expires` despite the time elapsed since capture; this is only
safe for this kind of offline replay, never for a live deployment.
`auth_httpsig_expires_max` (the signed `expires - created` window size, a
property of the original signature rather than of elapsed time) is left at
the profile default and is unaffected by `REPLAY_MAX_SKEW`. The `proxy`
service also needs real outbound HTTPS access to fetch each registered
authority's key directory — there's no local agent standing in for it.

## Reading the results

Aggregate the proxy's access log by `verified` × `agent` × `claimed_agent` ×
`error`:

```sh
docker compose logs proxy \
  | grep -oP 'verified="[^"]*".*error="[^"]*"' \
  | sed -E 's/ keyid="[^"]*"//; s/\\x22//g' \
  | sort | uniq -c | sort -rn
```

`agent="..."` stays `-` unless verification fully succeeds, since
`$httpsig_agent` is only populated once verification completes.
`claimed_agent="..."` is the raw `Signature-Agent` header value (unverified
self-declaration) and is present even on rejected requests, so it can be used
to see who was turned away and why — e.g. `directory_not_allowed` means the
authority isn't registered via `auth_httpsig_trusted_agent`, not that the key
directory fetch failed.

The full `HTTPSIG_*` environment variable reference for the `proxy` service
is in [`docker/README.md`](../../docker/README.md).
