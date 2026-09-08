# NGINX auth_httpsig Module

An nginx dynamic module that verifies [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html) directly inside nginx — no sidecar process, no CDN dependency, no OpenResty required.

**License**: MIT License

## Why

User-Agent strings, IP allowlists, and TLS fingerprinting are all trivially spoofable or brittle proxies for "who is making this request."
RFC 9421 lets a client cryptographically sign a request with a key it controls, so the server can verify the claimed identity instead of guessing at it from transport-layer heuristics.

The first deployment target for this module is [Web Bot Auth](https://github.com/web-bot-auth) (an IETF `webbotauth` working group effort).
It lets operators of AI crawlers and agents sign their requests, and lets site operators verify — cryptographically, without a CDN in the middle — who is crawling them.

Existing options are either SaaS/CDN-only (Cloudflare, AWS, Akamai), experimental and observe-only, or require a separate proxy process or OpenResty.
This module does the verification inline, in nginx, in C.

## Scope

This module **verifies** signatures.
It does not:

- Sign or generate requests (client/agent-side concern, out of scope)
- Judge whether a verified caller is "good" or "bad" — it identifies who signed a request and exposes that via `$httpsig_*`; accept/deny decisions belong to your configuration and upstream modules (e.g. [nginx-ratelimit](https://github.com/kjdev/nginx-ratelimit))
- Fall back to IP address or reverse DNS when a request is unsigned

Unsigned requests are never rejected: this module reports "no verdict," and your configuration decides what that means for a given location.

Supported signature algorithm: **Ed25519** only.
The signing key's own `kty`/`crv` decides the algorithm; the signature's `alg` parameter is used only to catch a mismatch, never to select behavior.

## Quick start

```nginx
http {
    server {
        location / {
            auth_httpsig_mode      observe;
            auth_httpsig_jwks_file /etc/nginx/httpsig_keys.json;

            add_header X-Httpsig-Verified $httpsig_verified always;
            add_header X-Httpsig-Agent    $httpsig_agent always;

            proxy_pass http://backend;
        }
    }
}
```

`observe` mode verifies every in-scope signed request and exposes the outcome through `$httpsig_*` and the headers above.
It never rejects anything, so it's safe to enable against live traffic to see what would happen before you start enforcing.

For the container image that generates a full configuration (including the dynamic key directory) from environment variables, see [`docker/README.md`](docker/README.md).
For a complete worked example combining a static JWKS location and a dynamic key-directory location, see [docs/EXAMPLES.md](docs/EXAMPLES.md).
To try it end to end with `docker compose`, without setting up a real environment, see the demo in [example/README.md](example/README.md).

## Documentation

- [docs/INSTALL.md](docs/INSTALL.md) — build from source, load the module
- [docs/DIRECTIVES.md](docs/DIRECTIVES.md) — every directive and `$httpsig_*` variable
- [docs/EXAMPLES.md](docs/EXAMPLES.md) — worked configurations, including pairing with `nginx-ratelimit`
- [docs/SECURITY.md](docs/SECURITY.md) — fail-open rationale, SSRF closure for the dynamic key directory, what is and isn't exposed in variables/logs
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) — reading `$httpsig_error` and the access/error log
- [example/README.md](example/README.md) — `docker compose` demo and an observe-mode deployment sample
- [tools/replay/README.md](tools/replay/README.md) — replay real crawler traffic to observe SFV parser behavior
- [CHANGELOG.md](CHANGELOG.md) — release history

## License

MIT License. See [LICENSE](LICENSE).
