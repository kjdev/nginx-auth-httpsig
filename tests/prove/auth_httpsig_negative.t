use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/lib";

use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: a tampered signature is rejected
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode observe;
        return 200 "verified=[$httpsig_verified] keyid=[$httpsig_keyid] agent=[$httpsig_agent]";
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
verified=[0] keyid=[] agent=[]



=== TEST 2: a keyid absent from the configured JWKS is rejected
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode observe;
        return 200 "verified=[$httpsig_verified] keyid=[$httpsig_keyid] agent=[$httpsig_agent]";
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
verified=[0] keyid=[] agent=[]



=== TEST 3: an expired signature is rejected
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode observe;
        return 200 "verified=[$httpsig_verified] keyid=[$httpsig_keyid] agent=[$httpsig_agent]";
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
verified=[0] keyid=[] agent=[]
