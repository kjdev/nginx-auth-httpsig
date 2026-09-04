#!/bin/sh
# Generates /etc/nginx/conf.d/httpsig-proxy.conf from HTTPSIG_* environment
# variables, so the "proxy" image target can run as a standalone
# observe-mode reverse proxy without a hand-written nginx.conf. A no-op
# when HTTPSIG_UPSTREAM is unset, so the "proxy" image then behaves exactly
# like the "module" image (stock config, module loaded but unused).
set -eu

ME=$(basename "$0")

[ -n "${HTTPSIG_UPSTREAM:-}" ] || exit 0

case "$HTTPSIG_UPSTREAM" in
    http://|https://|http://:*|https://:*)
        echo "$ME: HTTPSIG_UPSTREAM must include a host: $HTTPSIG_UPSTREAM" >&2
        exit 1
        ;;
    http://*/*|https://*/*)
        echo "$ME: HTTPSIG_UPSTREAM must be scheme+host[:port] only, no path: $HTTPSIG_UPSTREAM" >&2
        exit 1
        ;;
    http://\[*|https://\[*)
        echo "$ME: HTTPSIG_UPSTREAM does not support bracketed IPv6 hosts: $HTTPSIG_UPSTREAM" >&2
        exit 1
        ;;
    http://*[\?#@]*|https://*[\?#@]*)
        echo "$ME: HTTPSIG_UPSTREAM must be scheme+host[:port] only: $HTTPSIG_UPSTREAM" >&2
        exit 1
        ;;
    http://*)
        [ -n "${HTTPSIG_UPSTREAM_ALLOW_INSECURE:-}" ] || {
            echo "$ME: HTTPSIG_UPSTREAM uses http://; set HTTPSIG_UPSTREAM_ALLOW_INSECURE to allow a cleartext upstream: $HTTPSIG_UPSTREAM" >&2
            exit 1
        }
        ;;
    https://*)
        ;;
    *)
        echo "$ME: HTTPSIG_UPSTREAM must start with http:// or https://: $HTTPSIG_UPSTREAM" >&2
        exit 1
        ;;
esac

ca_file=${HTTPSIG_CA_FILE:-/etc/ssl/certs/ca-certificates.crt}

upstream_tls_directive=""
case "$HTTPSIG_UPSTREAM" in
    https://*)
        upstream_host=${HTTPSIG_UPSTREAM#https://}
        upstream_host=${upstream_host%%:*}
        upstream_tls_directive="        proxy_ssl_verify                on;
        proxy_ssl_trusted_certificate   ${ca_file};
        proxy_ssl_server_name           on;
        proxy_ssl_name                  ${upstream_host};"
        ;;
esac

if [ -z "${HTTPSIG_JWKS_FILE:-}" ] && [ -z "${HTTPSIG_TRUSTED_AGENTS:-}" ]; then
    echo "$ME: set HTTPSIG_JWKS_FILE or HTTPSIG_TRUSTED_AGENTS; auth_httpsig needs a key source" >&2
    exit 1
fi

profile=${HTTPSIG_PROFILE:-web-bot-auth}
server_name=${HTTPSIG_SERVER_NAME:-_}
access_log=${HTTPSIG_ACCESS_LOG:-/dev/stdout}

if [ -n "${HTTPSIG_SSL_CERTIFICATE:-}" ] && [ -n "${HTTPSIG_SSL_CERTIFICATE_KEY:-}" ]; then
    listen=${HTTPSIG_LISTEN:-443}
    listen_directive="listen ${listen} ssl;"
    ssl_directives="    ssl_certificate     ${HTTPSIG_SSL_CERTIFICATE};
    ssl_certificate_key ${HTTPSIG_SSL_CERTIFICATE_KEY};"
elif [ -n "${HTTPSIG_SSL_CERTIFICATE:-}" ] || [ -n "${HTTPSIG_SSL_CERTIFICATE_KEY:-}" ]; then
    echo "$ME: set both HTTPSIG_SSL_CERTIFICATE and HTTPSIG_SSL_CERTIFICATE_KEY, or neither" >&2
    exit 1
else
    listen=${HTTPSIG_LISTEN:-8080}
    listen_directive="listen ${listen};"
    ssl_directives=""
fi

key_source_directive=""
[ -n "${HTTPSIG_JWKS_FILE:-}" ] && \
    key_source_directive="    auth_httpsig_jwks_file ${HTTPSIG_JWKS_FILE};"

max_skew_directive=""
[ -n "${HTTPSIG_MAX_SKEW:-}" ] && \
    max_skew_directive="    auth_httpsig_max_skew ${HTTPSIG_MAX_SKEW};"

expires_max_directive=""
[ -n "${HTTPSIG_EXPIRES_MAX:-}" ] && \
    expires_max_directive="    auth_httpsig_expires_max ${HTTPSIG_EXPIRES_MAX};"

scheme_map_directive=""
scheme_var_directive=""
if [ -n "${HTTPSIG_TRUST_X_FORWARDED_PROTO:-}" ]; then
    scheme_map_directive="map \$http_x_forwarded_proto \$httpsig_scheme {
    https   https;
    default http;
}"
    scheme_var_directive="    auth_httpsig_scheme_var \$httpsig_scheme;"
fi

# location / uses a variable-form proxy_pass (to follow HTTPSIG_UPSTREAM's
# hostname across DNS changes), which requires an explicit resolver even
# when no key directory is ever fetched.
resolver=${HTTPSIG_RESOLVER:-$(awk '/^nameserver/ { print $2; exit }' /etc/resolv.conf)}

cache_zone_directive=""
directory_directives=""
fetch_location=""

if [ -n "${HTTPSIG_TRUSTED_AGENTS:-}" ]; then
    cache_size=${HTTPSIG_KEY_CACHE_ZONE_SIZE:-1m}
    cache_zone_directive="auth_httpsig_key_cache_zone httpsig_keys:${cache_size};"

    for agent in $(echo "$HTTPSIG_TRUSTED_AGENTS" | tr ',' ' '); do
        directory_directives="${directory_directives}    auth_httpsig_trusted_agent ${agent};
"
    done
    directory_directives="${directory_directives}    auth_httpsig_key_directory_request /httpsig_fetch;"

    [ -n "${HTTPSIG_KEY_CACHE_MIN_TTL:-}" ] && \
        directory_directives="${directory_directives}
    auth_httpsig_key_cache_min_ttl ${HTTPSIG_KEY_CACHE_MIN_TTL};"
    [ -n "${HTTPSIG_KEY_CACHE_MAX_TTL:-}" ] && \
        directory_directives="${directory_directives}
    auth_httpsig_key_cache_max_ttl ${HTTPSIG_KEY_CACHE_MAX_TTL};"

    fetch_location="
        # Internal location dedicated to the key directory fetch. TLS
        # verification is delegated to this location.
        location = /httpsig_fetch {
            internal;

            auth_httpsig_mode              off;
            auth_httpsig_trusted_agent     off;

            resolver                        ${resolver};
            subrequest_output_buffer_size   128k;

            proxy_ssl_verify                on;
            proxy_ssl_trusted_certificate   ${ca_file};
            proxy_ssl_server_name           on;
            proxy_ssl_name                  \$httpsig_directory_host;
            proxy_set_header                Host \$httpsig_directory_host;
            proxy_pass  https://\$httpsig_directory_host/.well-known/http-message-signatures-directory;
        }"
fi

rm -f /etc/nginx/conf.d/default.conf

cat > /etc/nginx/conf.d/httpsig-proxy.conf <<EOF
log_format httpsig_observe
    '\$remote_addr - \$remote_user [\$time_local] '
    '"\$request" \$status \$body_bytes_sent '
    'verified="\$httpsig_verified" keyid="\$httpsig_keyid" '
    'agent="\$httpsig_agent" claimed_agent="\$http_signature_agent" '
    'error="\$httpsig_error"';

${cache_zone_directive}
${scheme_map_directive}

server {
    ${listen_directive}
    server_name ${server_name};

${ssl_directives}

    access_log ${access_log} httpsig_observe;

    auth_httpsig_profile ${profile};
    auth_httpsig_mode     observe;
${scheme_var_directive}

${key_source_directive}
${max_skew_directive}
${expires_max_directive}
${directory_directives}

    location / {
        resolver ${resolver};
        set \$httpsig_upstream_target "${HTTPSIG_UPSTREAM}";
        proxy_pass \$httpsig_upstream_target\$request_uri;
${upstream_tls_directive}
        proxy_http_version 1.1;
        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Connection        "";
        # \$httpsig_verified / \$httpsig_error are both unset (empty) when
        # there is no verdict (unsigned request, or a key lookup failure
        # that fails open); nginx omits a proxy_set_header whose value is
        # empty, so upstream sees no header at all rather than one with an
        # empty value.
        proxy_set_header X-Httpsig-Verified \$httpsig_verified;
        proxy_set_header X-Httpsig-Keyid    \$httpsig_keyid;
        proxy_set_header X-Httpsig-Agent    \$httpsig_agent;
        proxy_set_header X-Httpsig-Error    \$httpsig_error;
    }
${fetch_location}
}
EOF

echo "$ME: generated /etc/nginx/conf.d/httpsig-proxy.conf (upstream=${HTTPSIG_UPSTREAM})"
