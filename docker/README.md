# Docker images

The root `Dockerfile` builds two targets:

- `module` — stock `nginx:alpine` with `ngx_http_auth_httpsig_module.so`
  built and loaded (`load_module`), but no `auth_httpsig_*` config. Use this
  as a base image and mount your own `nginx.conf`.
- `proxy` — the `module` image plus an entrypoint script
  (`docker/25-httpsig-conf.sh`) that generates an observe-mode config from
  `HTTPSIG_*` environment variables. No hand-written `nginx.conf` is needed.
  If `HTTPSIG_UPSTREAM` is unset, the container behaves exactly like the
  `module` target (stock nginx config, module loaded but unused).

```sh
docker build --target module -t httpsig-module .
docker build --target proxy  -t httpsig-proxy  .
```

## Running the proxy image

```sh
docker run --rm -p 8080:8080 \
  -e HTTPSIG_UPSTREAM=http://backend.internal:80 \
  -e HTTPSIG_UPSTREAM_ALLOW_INSECURE=1 \
  -e HTTPSIG_TRUSTED_AGENTS='agent.bot.example crawler.bot.example' \
  httpsig-proxy
```

### Environment variables

| variable | default | effect |
|---|---|---|
| `HTTPSIG_UPSTREAM` | (required) | `proxy_pass` target. Scheme + host[:port] only, no path |
| `HTTPSIG_UPSTREAM_ALLOW_INSECURE` | — | set to any non-empty value (including `0`) to allow `http://` in `HTTPSIG_UPSTREAM` (rejected by default; `https://` always allowed) |
| `HTTPSIG_LISTEN` | `443` if TLS is configured, else `8080` | `listen` port |
| `HTTPSIG_SERVER_NAME` | `_` | `server_name` |
| `HTTPSIG_SSL_CERTIFICATE` / `HTTPSIG_SSL_CERTIFICATE_KEY` | — | set both to terminate TLS (`listen ... ssl` + `ssl_certificate*`) |
| `HTTPSIG_TRUST_X_FORWARDED_PROTO` | — | set to trust `X-Forwarded-Proto` from a front-end TLS terminator; emits a `map` and `auth_httpsig_scheme_var` (see [Behind a TLS-terminating load balancer](#behind-a-tls-terminating-load-balancer)) |
| `HTTPSIG_PROFILE` | `web-bot-auth` | `auth_httpsig_profile` |
| `HTTPSIG_MAX_SKEW` / `HTTPSIG_EXPIRES_MAX` | profile default | `auth_httpsig_max_skew` / `auth_httpsig_expires_max`; emitted only if set |
| `HTTPSIG_JWKS_FILE` | — | `auth_httpsig_jwks_file` (static key source) |
| `HTTPSIG_TRUSTED_AGENTS` | — | space/comma-separated authorities; emits `auth_httpsig_trusted_agent` per entry plus `auth_httpsig_key_cache_zone` and a `/httpsig_fetch` key-directory fetch location |
| `HTTPSIG_KEY_CACHE_ZONE_SIZE` | `1m` | `auth_httpsig_key_cache_zone` size |
| `HTTPSIG_KEY_CACHE_MIN_TTL` / `HTTPSIG_KEY_CACHE_MAX_TTL` | — | emitted only if set |
| `HTTPSIG_CA_FILE` | `/etc/ssl/certs/ca-certificates.crt` | `proxy_ssl_trusted_certificate` for the key-directory fetch |
| `HTTPSIG_RESOLVER` | first `nameserver` in `/etc/resolv.conf` | `resolver` for the key-directory fetch |
| `HTTPSIG_ACCESS_LOG` | `/dev/stdout` | access log destination |

At least one of `HTTPSIG_JWKS_FILE` or `HTTPSIG_TRUSTED_AGENTS` is required;
the entrypoint exits with an error before nginx starts if neither is set.

### Verification result headers sent upstream

The generated config always forwards the observe-mode verification result to
`HTTPSIG_UPSTREAM` as request headers:

| header | source variable |
|---|---|
| `X-Httpsig-Verified` | `$httpsig_verified` |
| `X-Httpsig-Keyid` | `$httpsig_keyid` |
| `X-Httpsig-Error` | `$httpsig_error` |
| `X-Httpsig-Agent` | `$httpsig_agent` |

A header is omitted entirely (not sent empty) when its source variable is
unset. `X-Httpsig-Verified` / `X-Httpsig-Error` are both absent when there is
no verdict (unsigned request, or a key lookup failure that fails open).
Otherwise `X-Httpsig-Verified` is sent as `1` on success or `0` on failure,
and `X-Httpsig-Error` is present only on failure. The upstream must not trust
these headers from any source other than this proxy (strip or overwrite them
at the edge if clients can reach the upstream directly).

### Behind a TLS-terminating load balancer

`nginx` does not allow `$scheme` to be overridden via `map` (it rejects a
duplicate variable definition), so a plain-HTTP-listening proxy behind a
separate TLS terminator cannot reconstruct `@scheme` or `@target-uri`
correctly by default, and any request signed over `@target-uri` (the common
case) will fail verification.

If a front-end load balancer terminates TLS and forwards `X-Forwarded-Proto`,
set `HTTPSIG_TRUST_X_FORWARDED_PROTO` to any non-empty value. The entrypoint
then emits:

```nginx
map $http_x_forwarded_proto $httpsig_scheme {
    https   https;
    default http;
}
auth_httpsig_scheme_var $httpsig_scheme;
```

so `@scheme` / `@target-uri` are reconstructed from the forwarded header
instead of nginx's own `$scheme`. Only set this when the load balancer is
trusted to set `X-Forwarded-Proto` correctly (e.g. it strips or overwrites
any client-supplied value) — the entrypoint does not validate that.

Alternatively, terminate TLS in this container itself with
`HTTPSIG_SSL_CERTIFICATE` / `HTTPSIG_SSL_CERTIFICATE_KEY`, which needs no
extra configuration since `$scheme` then reflects the real connection.
