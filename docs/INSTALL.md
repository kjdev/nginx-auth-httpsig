# Install

`nginx-auth-httpsig` is a dynamic module, built against a matching nginx source tree with `--add-dynamic-module`, then loaded at runtime with `load_module`.
There are no prebuilt binaries; you build against the exact nginx version and configure flags you run in production.

See also: [DIRECTIVES](DIRECTIVES.md) · [EXAMPLES](EXAMPLES.md)

## Prerequisites

- An nginx source tree matching the version/configure flags you intend to run (the module links against nginx's internal structures, so the build must match at runtime)
- OpenSSL 3.0 or later (development headers) — this module does not support 1.1.x
- `jansson` (development headers) — consumed transitively through the `nxe-json` submodule
- A C toolchain and the usual nginx build dependencies (`pcre`, `zlib`, ...) for whatever your nginx configure line already requires

## Fetch submodules

This repository vendors its JSON/JWKS/phase-ordering dependencies as git submodules (`nxe-json`, `nxe-jwx`, `nxe-phase`) rather than linking a system package for them:

```sh
git submodule update --init --recursive
```

The module's `config` script checks for each submodule's `config.ngx` and fails with this exact instruction if it's missing — run it before configuring nginx.

## Build

From an nginx source tree matching your target version and flags:

```sh
cd nginx-<version>
./configure --add-dynamic-module=/path/to/nginx-auth-httpsig ...  # plus your other flags
make modules
```

Building against the same nginx your target environment already runs?
Run `nginx -V` there, keep its existing `--add-dynamic-module` options, and append this module's directory.

The build produces `objs/ngx_http_auth_httpsig_module.so`.
Copy it into the target nginx's modules directory (or reference the built path directly) before loading it — `load_module`'s path is resolved relative to the nginx prefix, not the nginx source tree.

## Load the module

```nginx
load_module modules/ngx_http_auth_httpsig_module.so;

http {
    server {
        location / {
            auth_httpsig_mode      observe;
            auth_httpsig_jwks_file /etc/nginx/httpsig_keys.json;
            proxy_pass http://backend;
        }
    }
}
```

Run `nginx -t` after loading to check the configuration before reloading a live worker set.
See [DIRECTIVES.md](DIRECTIVES.md) for the full directive reference and [EXAMPLES.md](EXAMPLES.md) for complete worked configurations.

## Container image

If you don't want to build from source at all, a prebuilt container that generates its own configuration from environment variables is available — see [`docker/README.md`](../docker/README.md).

## Running the test suite

Only relevant if you're building from a checkout to contribute or verify a build, not for a production deployment.

Integration tests (Test::Nginx, against the module built above):

```sh
TEST_NGINX_LOAD_MODULES=/path/to/ngx_http_auth_httpsig_module.so \
TEST_NGINX_BINARY=/path/to/nginx/objs/nginx \
prove -r tests/prove
```

Unit tests:

```sh
cd tests/unit && make test
```

The integration suite's dynamic-key-directory tests (`auth_httpsig_directory_fetch.t`) require an nginx built with `--with-http_dav_module`, used only to serve fixture responses in the test harness — this is not a runtime dependency of the module itself.
