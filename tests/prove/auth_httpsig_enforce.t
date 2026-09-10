use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/lib";

use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: enforce mode allows an unsigned request (fail-open without "require")
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode enforce;
        alias $TEST_NGINX_DATA_DIR/ok.txt;
    }
--- request
GET /t
--- error_code: 200



=== TEST 2: enforce mode rejects a tampered signature with the default invalid status
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode enforce;
        alias $TEST_NGINX_DATA_DIR/ok.txt;
    }
--- more_headers eval
use HttpSig qw(default_request sign tamper_signature);

my $req = default_request(
    target  => '/t',
    headers => [['Signature-Agent', '"https://bot.example.test"']],
);

my ($input, $sig) = sign(
    keyfile    => "$ENV{TEST_NGINX_DATA_DIR}/ed25519-key.pem",
    components => ['@target-uri', '@authority', 'signature-agent'],
    params     => [
        ['created', time(),       'integer'],
        ['expires', time() + 300, 'integer'],
        ['keyid',   'PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA', 'string'],
        ['tag',     'web-bot-auth', 'string'],
    ],
    req => $req,
);

$sig = tamper_signature($sig);

"Signature-Agent: \"https://bot.example.test\"\n"
    . "Signature-Input: $input\n"
    . "Signature: $sig\n"
--- request
GET /t
--- error_code: 403



=== TEST 3: enforce mode rejects a malformed Signature-Input with the default parse_error status
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode enforce;
        alias $TEST_NGINX_DATA_DIR/ok.txt;
    }
--- more_headers eval
use HttpSig qw(default_request sign);

my $req = default_request(
    target  => '/t',
    headers => [['Signature-Agent', '"https://bot.example.test"']],
);

my ($input, $sig) = sign(
    keyfile    => "$ENV{TEST_NGINX_DATA_DIR}/ed25519-key.pem",
    components => ['@target-uri', '@authority', 'signature-agent'],
    params     => [
        ['created', time(),       'integer'],
        ['expires', time() + 300, 'integer'],
        ['keyid',   'PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA', 'string'],
        ['tag',     'web-bot-auth', 'string'],
    ],
    req => $req,
);

"Signature-Agent: \"https://bot.example.test\"\n"
    . "Signature-Input: $input\n"
--- request
GET /t
--- error_code: 400



=== TEST 4: auth_httpsig_require rejects an unsigned request even in observe mode
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode observe;
        auth_httpsig_require on;
        alias $TEST_NGINX_DATA_DIR/ok.txt;
    }
--- request
GET /t
--- error_code: 403



=== TEST 5: auth_httpsig_require in observe mode does not reject a verification failure
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode observe;
        auth_httpsig_require on;
        alias $TEST_NGINX_DATA_DIR/ok.txt;
    }
--- more_headers eval
use HttpSig qw(default_request sign tamper_signature);

my $req = default_request(
    target  => '/t',
    headers => [['Signature-Agent', '"https://bot.example.test"']],
);

my ($input, $sig) = sign(
    keyfile    => "$ENV{TEST_NGINX_DATA_DIR}/ed25519-key.pem",
    components => ['@target-uri', '@authority', 'signature-agent'],
    params     => [
        ['created', time(),       'integer'],
        ['expires', time() + 300, 'integer'],
        ['keyid',   'PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA', 'string'],
        ['tag',     'web-bot-auth', 'string'],
    ],
    req => $req,
);

$sig = tamper_signature($sig);

"Signature-Agent: \"https://bot.example.test\"\n"
    . "Signature-Input: $input\n"
    . "Signature: $sig\n"
--- request
GET /t
--- error_code: 200



=== TEST 6: KEY_UNAVAILABLE (directory fetch rejected by the allowlist) still passes through under enforce
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
    auth_httpsig_key_cache_zone  httpsig_keys:1m;

    server {
        listen  127.0.0.1:18461;
        server_name  enforce-marker;

        location = /marker {
            default_type  text/plain;
            return 200 'ok';
        }
    }
--- config
    auth_httpsig_mode                   enforce;
    auth_httpsig_agent_allow            bot.example.com;
    auth_httpsig_key_directory_request  /httpsig_fetch;

    location /t {
        proxy_pass  http://127.0.0.1:18461/marker;
    }

    location = /httpsig_fetch {
        internal;
        auth_httpsig_mode                 off;
        auth_httpsig_agent_allow          off;
        resolver                          1.1.1.1;
        proxy_pass  https://$httpsig_directory_host/.well-known/http-message-signatures-directory;
    }
--- more_headers eval
use HttpSig qw(default_request sign);

my $req = default_request(
    target  => '/t',
    headers => [['Signature-Agent', '"https://evil.example.test"']],
);

my ($input, $sig) = sign(
    keyfile    => "$ENV{TEST_NGINX_DATA_DIR}/ed25519-key2.pem",
    components => ['@target-uri', '@authority', 'signature-agent'],
    params     => [
        ['created', time(),       'integer'],
        ['expires', time() + 300, 'integer'],
        ['keyid',   'ETcfa8hWhW-wlBzsJe5KvDD-ZfofYIfdTVyoIuVXwkc', 'string'],
        ['tag',     'web-bot-auth', 'string'],
    ],
    req => $req,
);

"Signature-Agent: \"https://evil.example.test\"\n"
    . "Signature-Input: $input\n"
    . "Signature: $sig\n"
--- request
GET /t
--- error_code: 200



=== TEST 7: overriding auth_httpsig_status_invalid changes the rejection code
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode enforce;
        auth_httpsig_status_invalid 418;
        alias $TEST_NGINX_DATA_DIR/ok.txt;
    }
--- more_headers eval
use HttpSig qw(default_request sign tamper_signature);

my $req = default_request(
    target  => '/t',
    headers => [['Signature-Agent', '"https://bot.example.test"']],
);

my ($input, $sig) = sign(
    keyfile    => "$ENV{TEST_NGINX_DATA_DIR}/ed25519-key.pem",
    components => ['@target-uri', '@authority', 'signature-agent'],
    params     => [
        ['created', time(),       'integer'],
        ['expires', time() + 300, 'integer'],
        ['keyid',   'PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA', 'string'],
        ['tag',     'web-bot-auth', 'string'],
    ],
    req => $req,
);

$sig = tamper_signature($sig);

"Signature-Agent: \"https://bot.example.test\"\n"
    . "Signature-Input: $input\n"
    . "Signature: $sig\n"
--- request
GET /t
--- error_code: 418



=== TEST 8: "satisfy any" clamps the default parse_error status (400) to 403
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode enforce;
        satisfy any;
        alias $TEST_NGINX_DATA_DIR/ok.txt;
    }
--- more_headers eval
use HttpSig qw(default_request sign);

my $req = default_request(
    target  => '/t',
    headers => [['Signature-Agent', '"https://bot.example.test"']],
);

my ($input, $sig) = sign(
    keyfile    => "$ENV{TEST_NGINX_DATA_DIR}/ed25519-key.pem",
    components => ['@target-uri', '@authority', 'signature-agent'],
    params     => [
        ['created', time(),       'integer'],
        ['expires', time() + 300, 'integer'],
        ['keyid',   'PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA', 'string'],
        ['tag',     'web-bot-auth', 'string'],
    ],
    req => $req,
);

"Signature-Agent: \"https://bot.example.test\"\n"
    . "Signature-Input: $input\n"
--- request
GET /t
--- error_code: 403



=== TEST 9: "satisfy any" with auth_basic prefers 401 over the clamped 403 when both fail
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode enforce;
        satisfy any;
        auth_basic          "restricted";
        auth_basic_user_file $TEST_NGINX_DATA_DIR/htpasswd;
        alias $TEST_NGINX_DATA_DIR/ok.txt;
    }
--- more_headers eval
use HttpSig qw(default_request sign tamper_signature);

my $req = default_request(
    target  => '/t',
    headers => [['Signature-Agent', '"https://bot.example.test"']],
);

my ($input, $sig) = sign(
    keyfile    => "$ENV{TEST_NGINX_DATA_DIR}/ed25519-key.pem",
    components => ['@target-uri', '@authority', 'signature-agent'],
    params     => [
        ['created', time(),       'integer'],
        ['expires', time() + 300, 'integer'],
        ['keyid',   'PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA', 'string'],
        ['tag',     'web-bot-auth', 'string'],
    ],
    req => $req,
);

$sig = tamper_signature($sig);

"Signature-Agent: \"https://bot.example.test\"\n"
    . "Signature-Input: $input\n"
    . "Signature: $sig\n"
--- request
GET /t
--- error_code: 401
--- response_headers_like
WWW-Authenticate: Basic realm="restricted"
