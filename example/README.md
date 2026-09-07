# Using observe.conf

To try this out end-to-end without a real environment, see the runnable
`docker compose` demo at [`demo/`](demo/README.md).

If you don't want to hand-write an `nginx.conf` at all, see
[`docker/README.md`](../docker/README.md) for a container that configures
itself from environment variables.

`observe.conf` is a deployment sample that runs `auth_httpsig_mode observe`
and records signature verification results to the access log. Observe mode
never rejects a request based on the verification outcome (it only exposes
`$httpsig_*`), so it lets you observe the following against live traffic
without affecting existing behavior:

- Whether real signed crawlers can be identified without pre-registering keys
- Whether key rotation is picked up within the cache TTL
- The distribution of `$httpsig_agent`

## Applying the sample

1. Point `load_module` at the actual location of the built module.
2. Replace `server_name` / `ssl_certificate` / `ssl_certificate_key` /
   `upstream backend` with real environment values.
3. Replace `auth_httpsig_agent_allow` with the authority (host[:port])
   published in the documentation of the real agent you want to observe.
   Matching is exact only; wildcards are not supported.
4. Replace the `resolver` and `proxy_ssl_trusted_certificate` in
   `/httpsig_fetch` with the DNS resolver and trusted CA bundle for your
   environment.
5. Run `nginx -t` to check the syntax before loading it.

**These values vary by environment.** In particular, do not copy
`auth_httpsig_agent_allow` as-is — always replace it with the agent you
intend to observe.

## Reading the log

The `httpsig_observe` log_format emits:

- `verified` — `$httpsig_verified`. `1` = verification succeeded,
  `0` = verification failed, empty = no signature (fail-open, including
  out-of-scope signatures)
- `keyid` — thumbprint of the key used for verification
- `agent` — host extracted from `Signature-Agent`
- `claimed_agent` — the raw `Signature-Agent` request header, present even
  when verification did not succeed (unlike `agent`, which is only set on
  success)
- `error` — reason verification did not succeed (`$httpsig_error`)

## Aggregating the `$httpsig_agent` distribution

Extract `agent="..."` from the access log and count occurrences:

```sh
grep -oP '(?<= )agent="\K[^"]*' /var/log/nginx/httpsig_observe.log \
    | sort | uniq -c | sort -rn
```

Filtering on `verified="1"` gives the distribution of agents that actually
passed verification:

```sh
grep 'verified="1"' /var/log/nginx/httpsig_observe.log \
    | grep -oP '(?<= )agent="\K[^"]*' \
    | sort | uniq -c | sort -rn
```
