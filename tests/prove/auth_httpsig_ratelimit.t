use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/lib";

use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: two requests from the same $httpsig_agent share one rate-limit bucket
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
    limit_req_zone $httpsig_agent zone=agent_zone:1m rate=1r/m;
--- config
    location /t {
        auth_httpsig_mode observe;
        limit_req zone=agent_zone nodelay;
        alias $TEST_NGINX_DATA_DIR/ratelimit-ok.txt;
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

my $hdr = "Signature-Agent: \"https://bot.example.test\"\n"
    . "Signature-Input: $input\n"
    . "Signature: $sig\n";

[$hdr, $hdr]
--- error_code eval
[200, 503]



=== TEST 2: requests from distinct $httpsig_agent values get independent buckets
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
    limit_req_zone $httpsig_agent zone=agent_zone:1m rate=1r/m;
--- config
    location /t {
        auth_httpsig_mode observe;
        limit_req zone=agent_zone nodelay;
        alias $TEST_NGINX_DATA_DIR/ratelimit-ok.txt;
    }
--- pipelined_requests eval
["GET /t", "GET /t"]
--- more_headers eval
use HttpSig qw(default_request sign);

my @hdrs;
for my $host (qw(bot-a.example.test bot-b.example.test)) {
    my $req = default_request(
        target  => '/t',
        headers => [['Signature-Agent', qq{"https://$host"}]],
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

    push @hdrs, "Signature-Agent: \"https://$host\"\n"
        . "Signature-Input: $input\n"
        . "Signature: $sig\n";
}

\@hdrs
--- error_code eval
[200, 200]
