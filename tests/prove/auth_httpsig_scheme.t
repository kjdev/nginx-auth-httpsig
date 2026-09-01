use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/lib";

use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: a signature over the real scheme verifies
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
    include $TEST_NGINX_CONF_DIR/scheme_map.conf;
--- config
    location /t {
        auth_httpsig_mode observe;
        return 200 "verified=[$httpsig_verified]";
    }
--- more_headers eval
use HttpSig qw(default_request sign);

my $req = default_request(
    scheme  => 'http',
    target  => '/t',
    headers => [['Signature-Agent', '"https://bot.example.test"']],
);

my ($input, $sig) = sign(
    keyfile    => "$ENV{TEST_NGINX_DATA_DIR}/ed25519-key.pem",
    components => ['@scheme', '@authority', 'signature-agent'],
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
verified=[1]



=== TEST 2: a proxy header claiming https does not change @scheme (ADR 0008)
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
    include $TEST_NGINX_CONF_DIR/scheme_map.conf;
--- config
    location /t {
        auth_httpsig_mode observe;
        return 200 "verified=[$httpsig_verified] naive_scheme=[$httpsig_test_naive_scheme]";
    }
--- more_headers eval
use HttpSig qw(default_request sign);

my $req = default_request(
    scheme  => 'https',
    target  => '/t',
    headers => [['Signature-Agent', '"https://bot.example.test"']],
);

my ($input, $sig) = sign(
    keyfile    => "$ENV{TEST_NGINX_DATA_DIR}/ed25519-key.pem",
    components => ['@scheme', '@authority', 'signature-agent'],
    params     => [
        ['created', time(),       'integer'],
        ['expires', time() + 300, 'integer'],
        ['keyid',   'PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA', 'string'],
        ['tag',     'web-bot-auth', 'string'],
    ],
    req => $req,
);

"X-Forwarded-Proto: https\n"
    . "Signature-Agent: \"https://bot.example.test\"\n"
    . "Signature-Input: $input\n"
    . "Signature: $sig\n"
--- request
GET /t
--- response_body chomp
verified=[0] naive_scheme=[https]



=== TEST 3: auth_httpsig_scheme_var repoints @scheme at a map-derived variable
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
    include $TEST_NGINX_CONF_DIR/scheme_map.conf;
--- config
    location /t {
        auth_httpsig_mode observe;
        auth_httpsig_scheme_var $httpsig_test_naive_scheme;
        return 200 "verified=[$httpsig_verified]";
    }
--- more_headers eval
use HttpSig qw(default_request sign);

my $req = default_request(
    scheme  => 'https',
    target  => '/t',
    headers => [['Signature-Agent', '"https://bot.example.test"']],
);

my ($input, $sig) = sign(
    keyfile    => "$ENV{TEST_NGINX_DATA_DIR}/ed25519-key.pem",
    components => ['@scheme', '@authority', 'signature-agent'],
    params     => [
        ['created', time(),       'integer'],
        ['expires', time() + 300, 'integer'],
        ['keyid',   'PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA', 'string'],
        ['tag',     'web-bot-auth', 'string'],
    ],
    req => $req,
);

"X-Forwarded-Proto: https\n"
    . "Signature-Agent: \"https://bot.example.test\"\n"
    . "Signature-Input: $input\n"
    . "Signature: $sig\n"
--- request
GET /t
--- response_body chomp
verified=[1]



=== TEST 4: a bare "$" is rejected as an empty variable name
--- config
    location /t {
        auth_httpsig_scheme_var $;
        return 200;
    }
--- must_die
--- error_log
auth_httpsig: invalid variable name "$"



=== TEST 5: a volatile map is re-evaluated after an internal redirect
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
    include $TEST_NGINX_CONF_DIR/scheme_map.conf;
--- config
    location /before {
        set $httpsig_test_snapshot $httpsig_test_volatile_scheme;
        rewrite ^ /after?scheme=https last;
    }

    location /after {
        auth_httpsig_mode observe;
        auth_httpsig_scheme_var $httpsig_test_volatile_scheme;
        return 200 "verified=[$httpsig_verified]";
    }
--- more_headers eval
use HttpSig qw(default_request sign);

my $req = default_request(
    scheme  => 'https',
    target  => '/after',
    headers => [['Signature-Agent', '"https://bot.example.test"']],
);

my ($input, $sig) = sign(
    keyfile    => "$ENV{TEST_NGINX_DATA_DIR}/ed25519-key.pem",
    components => ['@scheme', '@authority', 'signature-agent'],
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
GET /before?scheme=http
--- response_body chomp
verified=[1]
