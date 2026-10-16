use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/lib";

use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: a replayed nonce is rejected with the default replay status (SHM backend)
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
    auth_httpsig_nonce_store_zone httpsig_nonce:1m;
--- config
    location /t {
        auth_httpsig_mode enforce;
        auth_httpsig_nonce_store shm;
        alias $TEST_NGINX_DATA_DIR/ok.txt;
    }
--- pipelined_requests eval
["GET /t", "GET /t"]
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
        ['nonce',   'shm-replay-nonce-1', 'string'],
    ],
    req => $req,
);

my $hdr = "Signature-Agent: \"https://bot.example.test\"\n"
    . "Signature-Input: $input\n"
    . "Signature: $sig\n";

[$hdr, $hdr]
--- error_code eval
[200, 429]



=== TEST 2: an internal redirect does not consume the nonce a second time
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
    auth_httpsig_nonce_store_zone httpsig_nonce:1m;
--- config
    auth_httpsig_mode enforce;
    auth_httpsig_nonce_store shm;

    location /t {
        root $TEST_NGINX_DATA_DIR;
        try_files /nonexistent @fallback;
    }

    location @fallback {
        # "alias" is rejected in a named location; try_files with a fixed
        # target is a content-phase handler, so it runs after ACCESS
        # (auth_httpsig) on this pass rather than bypassing it.
        root $TEST_NGINX_DATA_DIR;
        try_files /ok.txt =404;
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
        ['nonce',   'shm-internal-redirect-nonce-1', 'string'],
    ],
    req => $req,
);

"Signature-Agent: \"https://bot.example.test\"\n"
    . "Signature-Input: $input\n"
    . "Signature: $sig\n"
--- request
GET /t
--- error_code: 200



=== TEST 3: an inherited nonce_store does not conflict with a block whose mode is off
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
    auth_httpsig_nonce_store_zone httpsig_nonce:1m;
    auth_httpsig_nonce_store shm;
--- config
    location /t {
        auth_httpsig_mode off;
        alias $TEST_NGINX_DATA_DIR/ok.txt;
    }
--- request
GET /t
--- error_code: 200


=== TEST 4: a nonce-less signature is rejected when nonce_required is on
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
    auth_httpsig_nonce_store_zone httpsig_nonce:1m;
--- config
    location /t {
        auth_httpsig_mode enforce;
        auth_httpsig_nonce_store shm;
        auth_httpsig_nonce_required on;
        alias $TEST_NGINX_DATA_DIR/ok.txt;
    }
--- request
GET /t
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
    . "Signature: $sig\n";
--- error_code: 403


=== TEST 5: a nonce-less signature passes when nonce_required is off (default)
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
    auth_httpsig_nonce_store_zone httpsig_nonce:1m;
--- config
    location /t {
        auth_httpsig_mode enforce;
        auth_httpsig_nonce_store shm;
        alias $TEST_NGINX_DATA_DIR/ok.txt;
    }
--- request
GET /t
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
    . "Signature: $sig\n";
--- error_code: 200


=== TEST 6: a nonce-less signature under nonce_required uses auth_httpsig_status_invalid
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
    auth_httpsig_nonce_store_zone httpsig_nonce:1m;
--- config
    location /t {
        auth_httpsig_mode enforce;
        auth_httpsig_nonce_store shm;
        auth_httpsig_nonce_required on;
        auth_httpsig_status_invalid 418;
        alias $TEST_NGINX_DATA_DIR/ok.txt;
    }
--- request
GET /t
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
    . "Signature: $sig\n";
--- error_code: 418


=== TEST 7: nonce_required on without a nonce store is a configuration error
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode enforce;
        auth_httpsig_nonce_required on;
        alias $TEST_NGINX_DATA_DIR/ok.txt;
    }
--- must_die
--- error_log eval
qr/"auth_httpsig_nonce_required" is "on" but "auth_httpsig_nonce_store" is "off"/



=== TEST 8: a nonce of exactly 256 bytes is accepted
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
    auth_httpsig_nonce_store_zone httpsig_nonce:1m;
--- config
    location /t {
        auth_httpsig_mode observe;
        auth_httpsig_nonce_store shm;
        return 200 "verified=[$httpsig_verified] error=[$httpsig_error]";
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
        ['nonce',   'n' x 256, 'string'],
    ],
    req => $req,
);

"Signature-Agent: \"https://bot.example.test\"\n"
    . "Signature-Input: $input\n"
    . "Signature: $sig\n"
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified=[1] error=[]



=== TEST 9: a nonce of 257 bytes is rejected as nonce_too_long
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
    auth_httpsig_nonce_store_zone httpsig_nonce:1m;
--- config
    location /t {
        auth_httpsig_mode observe;
        auth_httpsig_nonce_store shm;
        return 200 "verified=[$httpsig_verified] error=[$httpsig_error]";
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
        ['nonce',   'n' x 257, 'string'],
    ],
    req => $req,
);

"Signature-Agent: \"https://bot.example.test\"\n"
    . "Signature-Input: $input\n"
    . "Signature: $sig\n"
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified=[0] error=[nonce_too_long]
