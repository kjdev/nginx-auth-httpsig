use strict;
use warnings;

BEGIN {
    if (!defined $ENV{NGX_AUTH_HTTPSIG_NONCE_REDIS}
        or $ENV{NGX_AUTH_HTTPSIG_NONCE_REDIS} eq '')
    {
        require Test::More;
        Test::More::plan(skip_all => "built without Redis nonce store support");
        exit 0;
    }
}

use FindBin;
use lib "$FindBin::Bin/lib";

use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: a replayed nonce is rejected with the default replay status (Redis backend)
--- init
system "redis-cli flushall"
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
    auth_httpsig_nonce_store_redis hostname=127.0.0.1 port=6379;
--- config
    location /t {
        auth_httpsig_mode enforce;
        auth_httpsig_nonce_store redis;
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
        ['nonce',   'redis-replay-nonce-1', 'string'],
    ],
    req => $req,
);

my $hdr = "Signature-Agent: \"https://bot.example.test\"\n"
    . "Signature-Input: $input\n"
    . "Signature: $sig\n";

[$hdr, $hdr]
--- error_code eval
[200, 429]



=== TEST 2: an unreachable Redis fails open and reports nonce_store_unavailable
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
    auth_httpsig_nonce_store_redis hostname=127.0.0.1 port=1 connect_timeout=1 command_timeout=1;
--- config
    location /t {
        auth_httpsig_mode observe;
        auth_httpsig_nonce_store redis;
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
        ['nonce',   'redis-unreachable-nonce-1', 'string'],
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
verified=[1] error=[nonce_store_unavailable]



=== TEST 3: an empty hostname= value is a configuration error
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
    auth_httpsig_nonce_store_redis hostname= port=6379;
--- config
    location /t {
        auth_httpsig_mode enforce;
        auth_httpsig_nonce_store redis;
        alias $TEST_NGINX_DATA_DIR/ok.txt;
    }
--- must_die
--- error_log eval
qr/auth_httpsig: invalid hostname value "hostname="/
