# Runnable observe-mode demo

A `docker compose` stack that exercises the parts of `auth_httpsig_*` that `tests/prove` cannot: symbolic-hostname key-directory fetch through a real DNS resolver, `proxy_ssl_verify on` against a real CA, full reverse-proxy behavior via `proxy_pass`, and visible key-rotation behavior in the logs.

This demo uses synthetic traffic (`agent/demo.sh` signs its own requests) to let you *try out* verify/rotate/failopen/distribution interactively.
It's not a substitute for [`docker/README.md`](../../docker/README.md) (a container that configures itself from `HTTPSIG_*` environment variables for real deployments) or [`tools/replay/`](../../tools/replay/README.md) (replays captured real crawler traffic to *verify* the module against it).

## Services

| service | role |
|---|---|
| `proxy` | nginx with the module loaded, `auth_httpsig_mode observe`, proxies to `backend` |
| `agent` | publishes a JWKS directory over HTTPS on `agent.bot.example` / `crawler.bot.example`; also runs the signing client used by the scenarios below |
| `backend` | origin server, returns a static `200 "origin"` |

Only `proxy`'s port 8080 is published to the host.

`proxy`'s `/httpsig_fetch` internal location carries
`proxy_pass_request_headers off;` so the directory fetch to `agent` never
forwards the client's request headers (nginx subrequests otherwise inherit
`headers_in` from the parent request). Keep this if you copy the config.

## Usage

```
cd example/demo
docker compose up -d --build --wait backend agent proxy
docker compose exec agent /demo/demo.sh verify
docker compose exec agent /demo/demo.sh failopen
docker compose exec agent /demo/demo.sh distribution
docker compose exec agent /demo/demo.sh rotate
docker compose logs -f proxy
docker compose down -v
```

Run `rotate` last: it replaces `agent.bot.example`'s published key, and the `failopen` scenario's "tampered signature" case reuses the pre-rotation key, so running it after `rotate` reports `error="unknown_keyid"` instead of the expected `verified="0"`.

`up` builds the images (including the root `Dockerfile`) and generates a fresh CA, server certificate, and Ed25519 signing keys under `example/demo/secrets/` on every run.
That directory is git-ignored.

### Scenarios

- **verify** — a signed request from `agent.bot.example`; the proxy fetches its directory over HTTPS and verifies.
  Expect `verified="1"` in the proxy's access log.
- **rotate** — the agent publishes a new key, the cached directory's TTL expires, a request signed with the old key fails verification (`error="unknown_keyid"`, though observe mode still forwards it), and one signed with the new key succeeds.
- **failopen** — an unsigned request, a tampered signature, and a request from a host not listed in `auth_httpsig_agent_allow`; none of these block the request (observe mode is fail-open).
- **distribution** — sends several requests from two different agents and aggregates the access log by `agent="..."`.
