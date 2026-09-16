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
