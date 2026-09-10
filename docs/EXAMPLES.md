# Examples

Worked configurations, from a minimal static-key setup to pairing this
module with a rate limiter to actually act on verified identity.

See also: [DIRECTIVES](DIRECTIVES.md) · [INSTALL](INSTALL.md) ·
[SECURITY](SECURITY.md)

## Static JWKS

The simplest setup: a JWKS file provisioned out of band (e.g. by a
deployment pipeline that pulls known agents' published keys), no network
fetch at request time.

```nginx
http {
    server {
        location / {
            auth_httpsig_mode      observe;
            auth_httpsig_jwks_file /etc/nginx/httpsig_keys.json;

            add_header X-Httpsig-Verified $httpsig_verified always;
            add_header X-Httpsig-Keyid    $httpsig_keyid always;
            add_header X-Httpsig-Agent    $httpsig_agent always;
            add_header X-Httpsig-Error    $httpsig_error always;

            proxy_pass http://backend;
        }
    }
}
```

## Dynamic key directory

Fetches the signer's key directory at
`https://<Signature-Agent host>/.well-known/http-message-signatures-directory`
instead of requiring a pre-provisioned JWKS.
`auth_httpsig_agent_allow` is the SSRF gate: only the listed authorities
are ever fetched (see [SECURITY.md](SECURITY.md)).

```nginx
http {
    auth_httpsig_key_cache_zone httpsig_keys:1m;

    server {
        location / {
            auth_httpsig_mode                   observe;
            auth_httpsig_agent_allow             agent.bot.example crawler.bot.example;
            auth_httpsig_key_directory_request   /httpsig_fetch;

            add_header X-Httpsig-Verified $httpsig_verified always;
            add_header X-Httpsig-Agent    $httpsig_agent always;

            proxy_pass http://backend;
        }

        # Fetches the key directory; never reached directly by clients.
        location = /httpsig_fetch {
            # full body (resolver, proxy_ssl_*, subrequest_output_buffer_size)
            # in example/observe.conf
        }
    }
}
```

The internal fetch location's `resolver` / `proxy_ssl_*` /
`subrequest_output_buffer_size` settings are security-relevant, not
boilerplate — see the full, ready-to-run body in
[`example/observe.conf`](../example/observe.conf).

`subrequest_output_buffer_size` must be at least
`auth_httpsig_key_directory_max_size` (default 64 KiB).
Every internal fetch location for the same key-directory host must use
identical `proxy_ssl_*`/cache-TTL/size settings (see
[DIRECTIVES.md](DIRECTIVES.md#auth_httpsig_key_cache_zone) and
[SECURITY.md](SECURITY.md)).
A container that generates a full config from environment variables is in
[`docker/README.md`](../docker/README.md).

## Enforcing signatures

`auth_httpsig_mode observe` never rejects a request; `enforce` and
`auth_httpsig_require` add rejection, in two independent, additive ways
(see [DIRECTIVES.md](DIRECTIVES.md#enforcement) and
[SECURITY.md](SECURITY.md#fail-open-by-design) for what still fails open
even with both on).

Reject only a signature that is present and fails verification, while
still passing unsigned requests through unexamined:

```nginx
location /t {
    auth_httpsig_mode      enforce;
    auth_httpsig_jwks_file /etc/nginx/httpsig_keys.json;

    proxy_pass http://backend;
}
```

Add `auth_httpsig_require on` to also reject a request with no in-scope
signature at all:

```nginx
location /t {
    auth_httpsig_mode      enforce;
    auth_httpsig_require   on;
    auth_httpsig_jwks_file /etc/nginx/httpsig_keys.json;

    proxy_pass http://backend;
}
```

Override the default status codes per failure category (see
[DIRECTIVES.md](DIRECTIVES.md#enforcement) for the full list and their
defaults):

```nginx
location /t {
    auth_httpsig_mode          enforce;
    auth_httpsig_jwks_file     /etc/nginx/httpsig_keys.json;
    auth_httpsig_status_invalid 418;

    proxy_pass http://backend;
}
```

### Combining with `auth_basic` via `satisfy any`

`satisfy any` lets a request through if *either* this module or another
access-phase module accepts it — e.g. accept a valid signature, or fall
back to HTTP Basic auth for callers that can't sign requests.
This module clamps its own rejection status to `403` under `satisfy
any` so it participates correctly in nginx's OR aggregation (see
[DIRECTIVES.md](DIRECTIVES.md#satisfy-any-and-status-codes)):

```nginx
location /t {
    auth_httpsig_mode      enforce;
    auth_httpsig_jwks_file /etc/nginx/httpsig_keys.json;
    satisfy any;

    auth_basic           "restricted";
    auth_basic_user_file /etc/nginx/htpasswd;

    proxy_pass http://backend;
}
```

A valid signature grants access immediately, without ever consulting
`auth_basic`.
A missing or invalid signature falls through to `auth_basic`; if that
also fails, the final response is `auth_basic`'s `401` (with
`WWW-Authenticate`), not this module's `403` — nginx's OR aggregation
prefers `401` over `403` once both modules have run.

## Behind a TLS-terminating load balancer

If TLS is terminated in front of nginx and the load balancer forwards
`X-Forwarded-Proto`, `$scheme` no longer reflects the real client-facing
scheme, which breaks the `@scheme`/`@target-uri` components.
Point `auth_httpsig_scheme_var` at a `map`-derived variable instead of
trying to override `$scheme` (nginx doesn't allow redefining it):

```nginx
map $http_x_forwarded_proto $httpsig_scheme {
    https   https;
    default http;
}

server {
    auth_httpsig_scheme_var $httpsig_scheme;
    ...
}
```

Only do this when the load balancer is trusted to set `X-Forwarded-Proto`
correctly (strips or overwrites any client-supplied value) — nginx does
not validate that for you.
If you can terminate TLS in nginx itself instead, that needs no extra
configuration, since `$scheme` then already reflects the real connection.

## Pairing with nginx-ratelimit

`nginx-auth-httpsig` only identifies a signer; it does not rate-limit or
reject.
[`nginx-ratelimit`](https://github.com/kjdev/nginx-ratelimit) is a natural
pairing: rate-limit by verified agent identity (`$httpsig_agent`) instead
of by IP address, which matters because a legitimate crawler operator
commonly signs from a shared pool of IPs that a per-IP limit would either
overshare or throttle unfairly.

`$httpsig_agent` is unset (not empty string) for unverified or unsigned
requests, so fall back to `$binary_remote_addr` for that case via `map`:

```nginx
http {
    auth_httpsig_key_cache_zone httpsig_keys:1m;

    upstream redis {
        server 127.0.0.1:6379;
        keepalive 32;
    }

    # $httpsig_agent is unset (empty in a map) for unsigned/unverified
    # requests; fall back to the client address so they still get a limit.
    map $httpsig_agent $httpsig_ratelimit_key {
        ""      $binary_remote_addr;
        default $httpsig_agent;
    }

    ratelimit_zone bots key=$httpsig_ratelimit_key rate=600r/m;

    server {
        location / {
            auth_httpsig_mode                   observe;
            auth_httpsig_agent_allow             agent.bot.example crawler.bot.example;
            auth_httpsig_key_directory_request   /httpsig_fetch;

            ratelimit      zone=bots;
            ratelimit_pass redis;
            ratelimit_headers on;

            proxy_pass http://backend;
        }

        location = /httpsig_fetch {
            # ... same as the dynamic key directory example above
        }
    }
}
```

A verified agent now gets one shared budget (600 requests/minute) across
however many IPs it signs from, while any other traffic falls back to a
per-address limit.
The rate limiter acts on cryptographically verified identity instead of a
spoofable header or IP heuristic.
See
[nginx-ratelimit's own EXAMPLES.md](https://github.com/kjdev/nginx-ratelimit/blob/main/docs/EXAMPLES.md)
for its algorithm choices (fixed window / token bucket / GCRA / sliding
window) and Redis backend setup.
