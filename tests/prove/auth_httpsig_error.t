use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/lib";

use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: an unsigned request leaves both variables unset
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode observe;
        return 200 "verified=[$httpsig_verified] error=[$httpsig_error]";
    }
--- request
GET /t
--- response_body chomp
verified=[] error=[]



=== TEST 2: a validly signed request leaves error unset
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode observe;
        return 200 "verified=[$httpsig_verified] error=[$httpsig_error]";
    }
--- more_headers eval
use HttpSig qw(default_request sign);

my $req = default_request(
    target  => '/t',
    headers => [['Signature-Agent', '"https://bot.example.test"']],
);

my ($input, $sig) = sign(
    keyfile    => 'tests/prove/data/ed25519-key.pem',
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
    . "Signature: $sig\n"
--- request
GET /t
--- response_body chomp
verified=[1] error=[]



=== TEST 3: a keyid absent from the configured JWKS reports unknown_keyid
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode observe;
        return 200 "verified=[$httpsig_verified] error=[$httpsig_error]";
    }
--- more_headers eval
use HttpSig qw(default_request sign);

my $req = default_request(
    target  => '/t',
    headers => [['Signature-Agent', '"https://bot.example.test"']],
);

my ($input, $sig) = sign(
    keyfile    => 'tests/prove/data/ed25519-key2.pem',
    components => ['@target-uri', '@authority', 'signature-agent'],
    params     => [
        ['created', time(),       'integer'],
        ['expires', time() + 300, 'integer'],
        ['keyid',   'ETcfa8hWhW-wlBzsJe5KvDD-ZfofYIfdTVyoIuVXwkc', 'string'],
        ['tag',     'web-bot-auth', 'string'],
    ],
    req => $req,
);

"Signature-Agent: \"https://bot.example.test\"\n"
    . "Signature-Input: $input\n"
    . "Signature: $sig\n"
--- request
GET /t
--- response_body chomp
verified=[0] error=[unknown_keyid]



=== TEST 4: a tampered signature reports signature_mismatch
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode observe;
        return 200 "verified=[$httpsig_verified] error=[$httpsig_error]";
    }
--- more_headers eval
use HttpSig qw(default_request sign tamper_signature);

my $req = default_request(
    target  => '/t',
    headers => [['Signature-Agent', '"https://bot.example.test"']],
);

my ($input, $sig) = sign(
    keyfile    => 'tests/prove/data/ed25519-key.pem',
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
--- response_body chomp
verified=[0] error=[signature_mismatch]



=== TEST 5: an expired signature reports expired
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode observe;
        return 200 "verified=[$httpsig_verified] error=[$httpsig_error]";
    }
--- more_headers eval
use HttpSig qw(default_request sign);

my $req = default_request(
    target  => '/t',
    headers => [['Signature-Agent', '"https://bot.example.test"']],
);

my ($input, $sig) = sign(
    keyfile    => 'tests/prove/data/ed25519-key.pem',
    components => ['@target-uri', '@authority', 'signature-agent'],
    params     => [
        ['created', time() - 200, 'integer'],
        ['expires', time() - 100, 'integer'],
        ['keyid',   'PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA', 'string'],
        ['tag',     'web-bot-auth', 'string'],
    ],
    req => $req,
);

"Signature-Agent: \"https://bot.example.test\"\n"
    . "Signature-Input: $input\n"
    . "Signature: $sig\n"
--- request
GET /t
--- response_body chomp
verified=[0] error=[expired]



=== TEST 6: a signature missing a required parameter reports profile_mismatch
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode observe;
        return 200 "verified=[$httpsig_verified] error=[$httpsig_error]";
    }
--- more_headers eval
use HttpSig qw(default_request sign);

my $req = default_request(
    target  => '/t',
    headers => [['Signature-Agent', '"https://bot.example.test"']],
);

my ($input, $sig) = sign(
    keyfile    => 'tests/prove/data/ed25519-key.pem',
    components => ['@target-uri', '@authority', 'signature-agent'],
    params     => [
        ['created', time(),       'integer'],
        ['keyid',   'PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA', 'string'],
        ['tag',     'web-bot-auth', 'string'],
    ],
    req => $req,
);

"Signature-Agent: \"https://bot.example.test\"\n"
    . "Signature-Input: $input\n"
    . "Signature: $sig\n"
--- request
GET /t
--- response_body chomp
verified=[0] error=[profile_mismatch]



=== TEST 7: a Signature-Input without a matching Signature field reports parse_error
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode observe;
        return 200 "verified=[$httpsig_verified] error=[$httpsig_error]";
    }
--- more_headers eval
use HttpSig qw(default_request sign);

my $req = default_request(
    target  => '/t',
    headers => [['Signature-Agent', '"https://bot.example.test"']],
);

my ($input, $sig) = sign(
    keyfile    => 'tests/prove/data/ed25519-key.pem',
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
--- response_body chomp
verified=[0] error=[parse_error]



=== TEST 8: a directory fetch rejected by the allowlist reports directory_not_allowed even when the keyid is also absent from the static JWKS
--- http_config
    auth_httpsig_jwks_file       $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile         web-bot-auth;
    auth_httpsig_key_cache_zone  httpsig_keys:1m;

    # $httpsig_* is only resolved once evaluate() runs; a plain "return" in
    # /t below compiles into a rewrite-phase script that finalizes the
    # request *before* the PREACCESS-phase directory fetch, so it would
    # always observe the pre-fetch value. Routing through a proxied marker
    # and a content-phase sub_filter defers the substitution until after
    # PREACCESS has run (same technique as auth_httpsig_directory_fetch.t).
    server {
        listen  127.0.0.1:18460;
        server_name  error-marker;

        location = /marker {
            default_type  text/plain;
            return 200 'RESPONSE_MARKER';
        }
    }
--- config
    auth_httpsig_mode                   observe;
    auth_httpsig_trusted_agent          bot.example.com;
    auth_httpsig_key_directory_request  /httpsig_fetch;

    location /t {
        default_type        text/plain;
        sub_filter_types     text/plain;
        sub_filter           'RESPONSE_MARKER'  'verified:$httpsig_verified error:$httpsig_error';
        sub_filter_once      on;
        proxy_pass  http://127.0.0.1:18460/marker;
    }

    location = /httpsig_fetch {
        internal;
        auth_httpsig_mode           off;
        auth_httpsig_trusted_agent  off;
        resolver                    1.1.1.1;
        proxy_pass  https://$httpsig_directory_host/.well-known/http-message-signatures-directory;
    }
--- more_headers eval
use HttpSig qw(default_request sign);

my $req = default_request(
    target  => '/t',
    headers => [['Signature-Agent', '"https://evil.example.test"']],
);

my ($input, $sig) = sign(
    keyfile    => 'tests/prove/data/ed25519-key2.pem',
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
--- response_body chomp
verified: error:directory_not_allowed
