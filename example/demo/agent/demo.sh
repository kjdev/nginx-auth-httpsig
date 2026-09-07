#!/bin/sh
# Scenario runner exec'd as `docker compose exec agent /demo/demo.sh <name>`.
# Each scenario sends one or more signed requests to the proxy and prints
# what to expect in `docker compose logs proxy`.
set -eu

SECRETS=/run/secrets
TARGET=${TARGET:-http://proxy:8080/}

req() {
    /demo/httpsig-request.pl "$@"
}

kid() {
    cat "$SECRETS/keys/$1.kid"
}

scenario_verify() {
    echo "--- signed request from agent.bot.example (expect verified=\"1\") ---" >&2
    req --agent https://agent.bot.example \
        --key "$SECRETS/keys/agent.pem" --keyid "$(kid agent)" \
        --target "$TARGET"
}

scenario_rotate() {
    cp "$SECRETS/agent.bot.example/directory.json.rotated" \
       "$SECRETS/agent.bot.example/directory.json"
    echo "rotate: agent.bot.example directory replaced with the rotated key; waiting for the cache TTL to expire..." >&2
    sleep 8

    echo "--- request signed with the pre-rotation key (expect error=\"unknown_keyid\") ---" >&2
    req --agent https://agent.bot.example \
        --key "$SECRETS/keys/agent.pem" --keyid "$(kid agent)" \
        --target "$TARGET"

    echo "--- request signed with the post-rotation key (expect verified=\"1\") ---" >&2
    req --agent https://agent.bot.example \
        --key "$SECRETS/keys/agent-rotated.pem" --keyid "$(kid agent-rotated)" \
        --target "$TARGET"
}

scenario_failopen() {
    echo "--- unsigned request (expect an empty verified field) ---" >&2
    req --unsigned --target "$TARGET"

    echo "--- tampered signature (expect verified=\"0\") ---" >&2
    req --agent https://agent.bot.example \
        --key "$SECRETS/keys/agent.pem" --keyid "$(kid agent)" \
        --tamper --target "$TARGET"

    echo "--- unregistered agent host (expect the fetch to be skipped) ---" >&2
    req --agent https://rogue.bot.example \
        --key "$SECRETS/keys/agent.pem" --keyid "$(kid agent)" \
        --target "$TARGET"
}

scenario_distribution() {
    i=0
    while [ "$i" -lt 5 ]; do
        req --agent https://agent.bot.example \
            --key "$SECRETS/keys/agent.pem" --keyid "$(kid agent)" \
            --target "$TARGET" >/dev/null
        i=$((i + 1))
    done
    i=0
    while [ "$i" -lt 3 ]; do
        req --agent https://crawler.bot.example \
            --key "$SECRETS/keys/crawler.pem" --keyid "$(kid crawler)" \
            --target "$TARGET" >/dev/null
        i=$((i + 1))
    done
    echo "distribution: sent 5 agent.bot.example + 3 crawler.bot.example requests; aggregate with:" >&2
    echo '  docker compose logs proxy | grep -oP '"'"'agent="\K[^"]*'"'"' | sort | uniq -c | sort -rn' >&2
}

case "${1:-}" in
    verify)        scenario_verify ;;
    rotate)        scenario_rotate ;;
    failopen)      scenario_failopen ;;
    distribution)  scenario_distribution ;;
    *)
        echo "usage: demo.sh {verify|rotate|failopen|distribution}" >&2
        exit 1
        ;;
esac
