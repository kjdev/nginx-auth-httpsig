#!/bin/sh
# Generates everything the demo stack needs under /run/secrets: a CA, the
# agent's HTTPS server certificate, and three Ed25519 signing keys (the
# current agent.bot.example key, its post-rotation replacement, and
# crawler.bot.example's key), plus the JWKS directory files that expose
# them. Re-run on every `up`; nothing here is meant to be stable across
# runs.
set -eu

OUT=/run/secrets
mkdir -p "$OUT/keys" "$OUT/agent.bot.example" "$OUT/crawler.bot.example"

jwk_x() {
    openssl pkey -in "$1" -pubout -outform DER | tail -c 32 \
        | openssl base64 -A | tr '+/' '-_' | tr -d '='
}

# RFC 7638 JWK thumbprint for an Ed25519 (OKP) key.
thumbprint() {
    x=$(jwk_x "$1")
    printf '{"crv":"Ed25519","kty":"OKP","x":"%s"}' "$x" \
        | openssl dgst -sha256 -binary | openssl base64 -A \
        | tr '+/' '-_' | tr -d '='
}

# --- CA ---
openssl genrsa -out "$OUT/ca.key" 2048 2>/dev/null
openssl req -x509 -new -key "$OUT/ca.key" -sha256 -days 3650 \
    -subj "/CN=httpsig-demo CA" -out "$OUT/ca.pem"

# --- agent's HTTPS server certificate (SAN covers both directory hosts) ---
openssl genrsa -out "$OUT/server.key" 2048 2>/dev/null
openssl req -new -key "$OUT/server.key" \
    -subj "/CN=agent.bot.example" -out "$OUT/server.csr"
printf 'subjectAltName=DNS:agent.bot.example,DNS:crawler.bot.example\n' \
    > "$OUT/server.ext"
openssl x509 -req -in "$OUT/server.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" \
    -CAcreateserial -days 3650 -sha256 -out "$OUT/server.crt" \
    -extfile "$OUT/server.ext"
rm -f "$OUT/server.csr" "$OUT/server.ext" "$OUT/ca.srl"

# --- Ed25519 signing keys ---
for name in agent agent-rotated crawler; do
    openssl genpkey -algorithm Ed25519 -out "$OUT/keys/$name.pem"
    thumbprint "$OUT/keys/$name.pem" > "$OUT/keys/$name.kid"
done

agent_kid=$(cat "$OUT/keys/agent.kid")
agent_x=$(jwk_x "$OUT/keys/agent.pem")
rotated_kid=$(cat "$OUT/keys/agent-rotated.kid")
rotated_x=$(jwk_x "$OUT/keys/agent-rotated.pem")
crawler_kid=$(cat "$OUT/keys/crawler.kid")
crawler_x=$(jwk_x "$OUT/keys/crawler.pem")

cat > "$OUT/agent.bot.example/directory.json" <<EOF
{"keys":[{"kty":"OKP","crv":"Ed25519","x":"$agent_x","kid":"$agent_kid"}]}
EOF

# Staged JWKS for the "rotate" scenario: demo.sh copies this over
# directory.json to simulate the agent publishing a new key.
cat > "$OUT/agent.bot.example/directory.json.rotated" <<EOF
{"keys":[{"kty":"OKP","crv":"Ed25519","x":"$rotated_x","kid":"$rotated_kid"}]}
EOF

cat > "$OUT/crawler.bot.example/directory.json" <<EOF
{"keys":[{"kty":"OKP","crv":"Ed25519","x":"$crawler_x","kid":"$crawler_kid"}]}
EOF

echo "gen-keys: generated CA, server cert, and 3 Ed25519 signing keys under $OUT" >&2
