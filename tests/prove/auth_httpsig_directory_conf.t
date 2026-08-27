use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/lib";

use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: the target dynamic key directory configuration starts
--- http_config
    auth_httpsig_key_cache_zone  httpsig_keys:1m;
--- config
    auth_httpsig_mode                   observe;
    auth_httpsig_trusted_agent          bot.example.com;
    auth_httpsig_key_directory_request  /httpsig_fetch;

    location /t {
        return 200 "ok";
    }

    location = /httpsig_fetch {
        internal;
        auth_httpsig_mode              off;
        auth_httpsig_trusted_agent     off;
        resolver                       1.1.1.1;
        subrequest_output_buffer_size  128k;
        proxy_ssl_verify                on;
        proxy_ssl_trusted_certificate   $TEST_NGINX_DATA_DIR/directory-cert.pem;
        proxy_ssl_server_name           on;
        proxy_ssl_name                  $httpsig_directory_host;
        proxy_set_header                Host $httpsig_directory_host;
        proxy_pass  https://$httpsig_directory_host/.well-known/http-message-signatures-directory;
    }
--- request
GET /t
--- error_code: 200
--- response_body chomp
ok



=== TEST 2: the static JWKS verification path is unaffected by the target configuration
--- http_config
    auth_httpsig_jwks_file       $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile         web-bot-auth;
    auth_httpsig_key_cache_zone  httpsig_keys:1m;
--- config
    auth_httpsig_mode                   observe;
    auth_httpsig_trusted_agent          bot.example.com;
    auth_httpsig_key_directory_request  /httpsig_fetch;

    location /t {
        add_header X-Httpsig-Verified $httpsig_verified always;
        return 200 "ok";
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
    . "Signature: $sig\n"
--- request
GET /t
--- error_code: 200
--- response_body chomp
ok
--- response_headers_like
X-Httpsig-Verified: 1



=== TEST 3: the target configuration starts with no static JWKS file configured
--- http_config
    auth_httpsig_key_cache_zone  httpsig_keys:1m;
--- config
    auth_httpsig_mode                   observe;
    auth_httpsig_trusted_agent          bot.example.com;
    auth_httpsig_key_directory_request  /httpsig_fetch;

    location /t {
        return 200 "ok";
    }

    location = /httpsig_fetch {
        internal;
        auth_httpsig_mode           off;
        auth_httpsig_trusted_agent  off;
        resolver                    1.1.1.1;
        proxy_pass  https://$httpsig_directory_host/.well-known/http-message-signatures-directory;
    }
--- request
GET /t
--- error_code: 200



=== TEST 4: a scheme-prefixed trusted_agent host is rejected
--- config
    auth_httpsig_trusted_agent  https://bot.example.com;

    location /t {
        return 200;
    }
--- must_die
--- error_log
invalid host "https://bot.example.com" in "auth_httpsig_trusted_agent"



=== TEST 5: a wildcard trusted_agent host is rejected
--- config
    auth_httpsig_trusted_agent  *.example.com;

    location /t {
        return 200;
    }
--- must_die
--- error_log
invalid host "*.example.com" in "auth_httpsig_trusted_agent"



=== TEST 6: a key_directory_request without a leading slash is rejected
--- config
    auth_httpsig_key_directory_request  fetch;

    location /t {
        return 200;
    }
--- must_die
--- error_log
"auth_httpsig_key_directory_request" must start with "/"



=== TEST 7: a key_directory_request containing a variable is rejected
--- config
    auth_httpsig_key_directory_request  /fetch$request_uri;

    location /t {
        return 200;
    }
--- must_die
--- error_log
"auth_httpsig_key_directory_request" must not contain variables



=== TEST 8: a key_cache_zone without a ":size" is rejected
--- http_config
    auth_httpsig_key_cache_zone  httpsig_keys;
--- config
    location /t {
        return 200;
    }
--- must_die
--- error_log
invalid zone size "httpsig_keys"



=== TEST 9: a key_cache_zone below the minimum size is rejected
--- http_config
    auth_httpsig_key_cache_zone  httpsig_keys:1k;
--- config
    location /t {
        return 200;
    }
--- must_die
--- error_log
zone "httpsig_keys:1k" is too small



=== TEST 10: a key_cache_min_ttl of 0 is rejected
--- config
    auth_httpsig_key_cache_min_ttl  0;

    location /t {
        return 200;
    }
--- must_die
--- error_log
"auth_httpsig_key_cache_min_ttl" must not be 0



=== TEST 11: a key_cache_max_ttl below key_cache_min_ttl is rejected
--- config
    auth_httpsig_key_cache_min_ttl  500;
    auth_httpsig_key_cache_max_ttl  100;

    location /t {
        return 200;
    }
--- must_die
--- error_log
"auth_httpsig_key_cache_max_ttl" must not be less than "auth_httpsig_key_cache_min_ttl"



=== TEST 12: a key_directory_max_size beyond the maximum JWKS size is rejected
--- config
    auth_httpsig_key_directory_max_size  1m;

    location /t {
        return 200;
    }
--- must_die
--- error_log
"auth_httpsig_key_directory_max_size" must not exceed



=== TEST 13: a trusted_agent without a key_directory_request is rejected
--- config
    auth_httpsig_trusted_agent  bot.example.com;

    location /t {
        return 200;
    }
--- must_die
--- error_log
"auth_httpsig_trusted_agent" is set but no "auth_httpsig_key_directory_request" is configured



=== TEST 14: a trusted_agent and key_directory_request without a key_cache_zone is rejected
--- config
    auth_httpsig_trusted_agent          bot.example.com;
    auth_httpsig_key_directory_request  /httpsig_fetch;

    location /t {
        return 200;
    }
--- must_die
--- error_log
"auth_httpsig_trusted_agent" is set but no "auth_httpsig_key_cache_zone" is configured



=== TEST 15: a mode other than off with no key source at all is rejected
--- config
    auth_httpsig_mode  observe;

    location /t {
        return 200;
    }
--- must_die
--- error_log
"auth_httpsig_mode" is not "off" but no "auth_httpsig_jwks_file" is configured
