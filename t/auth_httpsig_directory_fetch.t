use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/lib";

# Cache-reuse/TTL assertions below depend on the SHM zone surviving across
# blocks, which requires nginx to NOT restart between them. Test::Nginx
# restarts by default; since every block here shares the same http/main
# config text, disabling the forced restart makes it reconfig-only (no
# restart) instead.
BEGIN { $ENV{TEST_NGINX_FORCE_RESTART_ON_TEST} = 0; }

use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();

# Mock key-directory origins. Each gets its own loopback port (rather than
# SNI-based virtual hosting on one port) because the trusted-agent host is a
# literal IP:port -- normalize_host()/allowed() never invoke the resolver,
# so a symbolic server_name would need real DNS to reach the same origin.
our $HttpConfig = <<'_EOC_';
    auth_httpsig_key_cache_zone     httpsig_keys:1m;
    auth_httpsig_key_cache_min_ttl  2;
    auth_httpsig_key_cache_max_ttl  100;

    log_format directory_fetch '$server_port $request';

    server {
        listen  127.0.0.1:18443 ssl;
        server_name  directory-ok;

        ssl_certificate      $TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  $TEST_NGINX_DATA_DIR/directory-key.pem;

        access_log  $TEST_NGINX_SERVROOT/logs/error.log  directory_fetch;

        location = /.well-known/http-message-signatures-directory {
            default_type  application/http-message-signatures-directory+json;
            return 200 '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"xCpJVzjaTB6A8s8QGZO8OuhOsE7XVdsUw82inWca4f0","kid":"PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA"}]}';
        }
    }

    server {
        listen  127.0.0.1:18444 ssl;
        server_name  directory-redirect;

        ssl_certificate      $TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  $TEST_NGINX_DATA_DIR/directory-key.pem;

        location = /.well-known/http-message-signatures-directory {
            return 302 /elsewhere;
        }
    }

    server {
        listen  127.0.0.1:18445 ssl;
        server_name  directory-404;

        ssl_certificate      $TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  $TEST_NGINX_DATA_DIR/directory-key.pem;

        location = /.well-known/http-message-signatures-directory {
            return 404;
        }
    }

    server {
        listen  127.0.0.1:18446 ssl;
        server_name  directory-badtype;

        ssl_certificate      $TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  $TEST_NGINX_DATA_DIR/directory-key.pem;

        location = /.well-known/http-message-signatures-directory {
            default_type text/plain;
            return 200 '{"keys":[]}';
        }
    }

    server {
        listen  127.0.0.1:18447 ssl;
        server_name  directory-toolarge;

        ssl_certificate      $TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  $TEST_NGINX_DATA_DIR/directory-key.pem;

        location = /.well-known/http-message-signatures-directory {
            default_type application/json;
            alias  $TEST_NGINX_DATA_DIR/directory-oversized.json;
        }
    }

    server {
        listen  127.0.0.1:18448 ssl;
        server_name  directory-dedup;

        ssl_certificate      $TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  $TEST_NGINX_DATA_DIR/directory-key.pem;

        access_log  $TEST_NGINX_SERVROOT/logs/error.log  directory_fetch;

        location = /.well-known/http-message-signatures-directory {
            default_type  application/http-message-signatures-directory+json;
            return 200 '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"xCpJVzjaTB6A8s8QGZO8OuhOsE7XVdsUw82inWca4f0","kid":"PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA"}]}';
        }
    }

    server {
        listen  127.0.0.1:18450 ssl;
        server_name  directory-smallbuf;

        ssl_certificate      $TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  $TEST_NGINX_DATA_DIR/directory-key.pem;

        location = /.well-known/http-message-signatures-directory {
            default_type  application/http-message-signatures-directory+json;
            return 200 '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"xCpJVzjaTB6A8s8QGZO8OuhOsE7XVdsUw82inWca4f0","kid":"PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA"}]}';
        }
    }

    # /t below renders its body via proxy_pass + sub_filter (both content
    # filters, evaluated well after the PREACCESS phase). A `return` there
    # would compile into rewrite-phase script codes that run and finalize
    # the request *before* PREACCESS, so $httpsig_verified would always
    # observe its pre-fetch value; a try_files/named-location fallback
    # would reach the right phase but ngx_http_named_location() clears all
    # module contexts on the jump, discarding what PREACCESS just set.
    server {
        listen  127.0.0.1:18449;
        server_name  directory-marker;

        location = /marker {
            default_type  text/plain;
            return 200 'RESPONSE_MARKER';
        }
    }
_EOC_

our $MainConfig = <<'_EOC_';
    auth_httpsig_mode                   observe;
    auth_httpsig_key_directory_request  /httpsig_fetch;
    auth_httpsig_trusted_agent
        127.0.0.1:18443
        127.0.0.1:18444
        127.0.0.1:18445
        127.0.0.1:18446
        127.0.0.1:18447
        127.0.0.1:18448;

    location /t {
        default_type       text/plain;
        sub_filter_types    text/plain;
        sub_filter          'RESPONSE_MARKER'  'verified:$httpsig_verified error:$httpsig_error';
        sub_filter_once      on;
        proxy_pass  http://127.0.0.1:18449/marker;
    }

    location = /httpsig_fetch {
        internal;
        auth_httpsig_mode              off;
        auth_httpsig_trusted_agent     off;
        resolver                       1.1.1.1;
        subrequest_output_buffer_size  128k;
        proxy_ssl_verify                off;
        proxy_ssl_server_name           on;
        proxy_ssl_name                  $httpsig_directory_host;
        proxy_set_header                Host $httpsig_directory_host;
        proxy_pass  https://$httpsig_directory_host/.well-known/http-message-signatures-directory;
    }
_EOC_

# Same as $MainConfig, but with an additional trusted host and a
# subrequest_output_buffer_size below auth_httpsig_key_directory_max_size, to
# exercise the runtime buffer-size mismatch warning.
our $SmallBufferConfig = <<'_EOC_';
    auth_httpsig_mode                   observe;
    auth_httpsig_key_directory_request  /httpsig_fetch;
    auth_httpsig_trusted_agent
        127.0.0.1:18443
        127.0.0.1:18444
        127.0.0.1:18445
        127.0.0.1:18446
        127.0.0.1:18447
        127.0.0.1:18448
        127.0.0.1:18450;

    location /t {
        default_type       text/plain;
        sub_filter_types    text/plain;
        sub_filter          'RESPONSE_MARKER'  'verified:$httpsig_verified error:$httpsig_error';
        sub_filter_once      on;
        proxy_pass  http://127.0.0.1:18449/marker;
    }

    location = /httpsig_fetch {
        internal;
        auth_httpsig_mode              off;
        auth_httpsig_trusted_agent     off;
        resolver                       1.1.1.1;
        subrequest_output_buffer_size  1k;
        proxy_ssl_verify                off;
        proxy_ssl_server_name           on;
        proxy_ssl_name                  $httpsig_directory_host;
        proxy_set_header                Host $httpsig_directory_host;
        proxy_pass  https://$httpsig_directory_host/.well-known/http-message-signatures-directory;
    }
_EOC_

sub sign_headers {
    my ($agent_host, $target) = @_;
    $target //= '/t';

    my $req = HttpSig::default_request(
        target  => $target,
        headers => [['Signature-Agent', qq{"https://$agent_host"}]],
    );

    my ($input, $sig) = HttpSig::sign(
        keyfile    => 't/data/ed25519-key.pem',
        components => ['@target-uri', '@authority', 'signature-agent'],
        params     => [
            ['created', time(),       'integer'],
            ['expires', time() + 300, 'integer'],
            ['keyid',   'PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA', 'string'],
            ['tag',     'web-bot-auth', 'string'],
        ],
        req => $req,
    );

    return qq{Signature-Agent: "https://$agent_host"\n}
        . "Signature-Input: $input\n"
        . "Signature: $sig\n";
}

# Cache-TTL-reuse/refetch assertions depend on TEST 1/2/4/5/8/9/10/11 running
# in file order; Test::Nginx shuffles block order by default.
no_shuffle();

run_tests();

__DATA__

=== TEST 1: an allow-listed host with no cached keys is fetched and verified
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers('127.0.0.1:18443')
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified:1 error:
--- error_log
18443 GET /.well-known/http-message-signatures-directory



=== TEST 2: a second request within the cache TTL reuses the cached keys without refetching
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers('127.0.0.1:18443')
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified:1 error:
--- grep_error_log eval: qr/18443 GET \/\.well-known\/http-message-signatures-directory\S*/
--- grep_error_log_out
18443 GET /.well-known/http-message-signatures-directory



=== TEST 3: a host outside the trusted-agent allowlist is never fetched
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers('evil.example.test')
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified: error:directory_not_allowed



=== TEST 4: a redirect response is rejected without following it
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers('127.0.0.1:18444')
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified: error:directory_redirect



=== TEST 5: a retry within the negative-cache TTL after a failed fetch is rejected without refetching
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers('127.0.0.1:18444')
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified: error:directory_unavailable



=== TEST 6: a non-200 status is rejected
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers('127.0.0.1:18445')
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified: error:directory_status



=== TEST 7: a mismatched media type is rejected
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers('127.0.0.1:18446')
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified: error:directory_media_type



=== TEST 8: a response larger than the size limit is rejected
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers('127.0.0.1:18447')
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified: error:directory_too_large
--- wait: 2



=== TEST 9: a request after the cache TTL has elapsed triggers a fresh fetch
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers('127.0.0.1:18443')
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified:1 error:
--- grep_error_log eval: qr/18443 GET \/\.well-known\/http-message-signatures-directory\S*/
--- grep_error_log_out
18443 GET /.well-known/http-message-signatures-directory
18443 GET /.well-known/http-message-signatures-directory



=== TEST 10: concurrent requests for an uncached host both succeed without a crash or spurious rejection
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- pipelined_requests eval
["GET /t", "GET /t"]
--- more_headers eval
use HttpSig;
my $headers = main::sign_headers('127.0.0.1:18448');
[$headers, $headers]
--- error_code eval
[200, 200]
--- response_body eval
["verified:1 error:", "verified:1 error:"]



=== TEST 11: the concurrent requests in TEST 10 triggered only one fetch
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers('127.0.0.1:18443')
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified:1 error:
--- grep_error_log eval: qr/18448 GET \/\.well-known\/http-message-signatures-directory\S*/
--- grep_error_log_out
18448 GET /.well-known/http-message-signatures-directory



=== TEST 12: a subrequest_output_buffer_size below the key-directory max size logs a warning
--- http_config eval: $::HttpConfig
--- config eval: $::SmallBufferConfig
--- more_headers eval
use HttpSig;
main::sign_headers('127.0.0.1:18450')
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified:1 error:
--- error_log
auth_httpsig: "subrequest_output_buffer_size" (1024) in "/httpsig_fetch" is below "auth_httpsig_key_directory_max_size" (65536)
