use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/lib";
use File::Temp qw(tempdir);

# Cache-reuse/TTL assertions below depend on the SHM zone surviving across
# blocks, which requires nginx to NOT restart between them. Test::Nginx
# restarts by default; disabling the forced restart makes consecutive
# blocks with identical http/main config text reconfig-only (no restart).
#
# TEST 12 is the one exception: it uses $SmallBufferConfig, so nginx does
# restart around it and both caches are dropped. Any new cache-continuity
# assertion must stay inside a run of blocks that share one config text.
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

# Mutable key-directory fixture for the TTL-rotation test below: a plain
# file (not a `return` literal) so it can be rewritten between requests
# without changing the nginx config text -- changing the config would force
# Test::Nginx to restart the worker and defeat the point of testing
# worker-local generation invalidation within one running worker.
#
# The rewrite itself happens via a real PUT request (see the "directory
# rotate" location below), not a Perl side effect inside a --- more_headers
# or --- request eval block: Test::Base::blocks() runs every block's filters
# (which is what evaluates "eval" sections) up front, in file order, before
# run_tests() sends the first actual HTTP request for any block. A write
# performed from inside an eval section would therefore land before earlier
# blocks' requests go out, not between them.
our $RotateDir  = tempdir(CLEANUP => 1);
our $RotateFile = "$RotateDir/directory-rotate.json";

open(my $rotate_fh, '>', $RotateFile) or die "open $RotateFile: $!";
print $rotate_fh '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"xCpJVzjaTB6A8s8QGZO8OuhOsE7XVdsUw82inWca4f0","kid":"PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA"}]}';
close $rotate_fh;

$HttpConfig .= <<"_EOC_";
    server {
        listen  127.0.0.1:18451 ssl;
        server_name  directory-rotate;

        ssl_certificate      \$TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  \$TEST_NGINX_DATA_DIR/directory-key.pem;

        access_log  \$TEST_NGINX_SERVROOT/logs/error.log  directory_fetch;

        location = /.well-known/http-message-signatures-directory {
            default_type  application/http-message-signatures-directory+json;
            alias  $RotateFile;
        }
    }
_EOC_

# Two more mock origins for the location-scoping regression test below:
# both return the same valid, small JWKS body used by directory-ok,
# so the only variable between the two protected locations
# that use them is the auth_httpsig directive scoped to that location, not
# the response itself.
$HttpConfig .= <<'_EOC_';
    server {
        listen  127.0.0.1:18452 ssl;
        server_name  directory-locsize;

        ssl_certificate      $TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  $TEST_NGINX_DATA_DIR/directory-key.pem;

        location = /.well-known/http-message-signatures-directory {
            default_type  application/http-message-signatures-directory+json;
            return 200 '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"xCpJVzjaTB6A8s8QGZO8OuhOsE7XVdsUw82inWca4f0","kid":"PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA"}]}';
        }
    }

    server {
        listen  127.0.0.1:18453 ssl;
        server_name  directory-locttl;

        ssl_certificate      $TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  $TEST_NGINX_DATA_DIR/directory-key.pem;

        access_log  $TEST_NGINX_SERVROOT/logs/error.log  directory_fetch;

        location = /.well-known/http-message-signatures-directory {
            default_type  application/http-message-signatures-directory+json;
            return 200 '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"xCpJVzjaTB6A8s8QGZO8OuhOsE7XVdsUw82inWca4f0","kid":"PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA"}]}';
        }
    }
_EOC_

# Mock origins for the Signature-Agent Dictionary-format scenarios below.
# Each returns the same valid, small JWKS body used by
# directory-ok; what varies between scenarios is which of these get a
# Signature-Agent Dictionary entry pointing at them, and whether that entry
# is the one a verifier should actually pick. Ports that a scenario expects
# to NOT be fetched are still declared here (and trusted-agent-listed below)
# so that a wrong-entry-selection bug would show up as a spurious fetch log
# line instead of being masked behind an unrelated allowlist rejection.
$HttpConfig .= <<'_EOC_';
    server {
        listen  127.0.0.1:18454 ssl;
        server_name  directory-dictmatch;

        ssl_certificate      $TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  $TEST_NGINX_DATA_DIR/directory-key.pem;

        access_log  $TEST_NGINX_SERVROOT/logs/error.log  directory_fetch;

        location = /.well-known/http-message-signatures-directory {
            default_type  application/http-message-signatures-directory+json;
            return 200 '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"xCpJVzjaTB6A8s8QGZO8OuhOsE7XVdsUw82inWca4f0","kid":"PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA"}]}';
        }
    }

    server {
        listen  127.0.0.1:18455 ssl;
        server_name  directory-dictfallback;

        ssl_certificate      $TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  $TEST_NGINX_DATA_DIR/directory-key.pem;

        access_log  $TEST_NGINX_SERVROOT/logs/error.log  directory_fetch;

        location = /.well-known/http-message-signatures-directory {
            default_type  application/http-message-signatures-directory+json;
            return 200 '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"xCpJVzjaTB6A8s8QGZO8OuhOsE7XVdsUw82inWca4f0","kid":"PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA"}]}';
        }
    }

    server {
        listen  127.0.0.1:18456 ssl;
        server_name  directory-multiline-match;

        ssl_certificate      $TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  $TEST_NGINX_DATA_DIR/directory-key.pem;

        access_log  $TEST_NGINX_SERVROOT/logs/error.log  directory_fetch;

        location = /.well-known/http-message-signatures-directory {
            default_type  application/http-message-signatures-directory+json;
            return 200 '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"xCpJVzjaTB6A8s8QGZO8OuhOsE7XVdsUw82inWca4f0","kid":"PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA"}]}';
        }
    }

    server {
        listen  127.0.0.1:18457 ssl;
        server_name  directory-multiline-other;

        ssl_certificate      $TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  $TEST_NGINX_DATA_DIR/directory-key.pem;

        access_log  $TEST_NGINX_SERVROOT/logs/error.log  directory_fetch;

        location = /.well-known/http-message-signatures-directory {
            default_type  application/http-message-signatures-directory+json;
            return 200 '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"xCpJVzjaTB6A8s8QGZO8OuhOsE7XVdsUw82inWca4f0","kid":"PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA"}]}';
        }
    }

    server {
        listen  127.0.0.1:18458 ssl;
        server_name  directory-typeskip-unusable;

        ssl_certificate      $TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  $TEST_NGINX_DATA_DIR/directory-key.pem;

        access_log  $TEST_NGINX_SERVROOT/logs/error.log  directory_fetch;

        location = /.well-known/http-message-signatures-directory {
            default_type  application/http-message-signatures-directory+json;
            return 200 '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"xCpJVzjaTB6A8s8QGZO8OuhOsE7XVdsUw82inWca4f0","kid":"PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA"}]}';
        }
    }

    server {
        listen  127.0.0.1:18459 ssl;
        server_name  directory-typeskip-usable;

        ssl_certificate      $TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  $TEST_NGINX_DATA_DIR/directory-key.pem;

        access_log  $TEST_NGINX_SERVROOT/logs/error.log  directory_fetch;

        location = /.well-known/http-message-signatures-directory {
            default_type  application/http-message-signatures-directory+json;
            return 200 '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"xCpJVzjaTB6A8s8QGZO8OuhOsE7XVdsUw82inWca4f0","kid":"PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA"}]}';
        }
    }

    server {
        listen  127.0.0.1:18460 ssl;
        server_name  directory-diffkey-unusable;

        ssl_certificate      $TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  $TEST_NGINX_DATA_DIR/directory-key.pem;

        access_log  $TEST_NGINX_SERVROOT/logs/error.log  directory_fetch;

        location = /.well-known/http-message-signatures-directory {
            default_type  application/http-message-signatures-directory+json;
            return 200 '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"xCpJVzjaTB6A8s8QGZO8OuhOsE7XVdsUw82inWca4f0","kid":"PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA"}]}';
        }
    }

    server {
        listen  127.0.0.1:18461 ssl;
        server_name  directory-diffkey-fallback;

        ssl_certificate      $TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  $TEST_NGINX_DATA_DIR/directory-key.pem;

        access_log  $TEST_NGINX_SERVROOT/logs/error.log  directory_fetch;

        location = /.well-known/http-message-signatures-directory {
            default_type  application/http-message-signatures-directory+json;
            return 200 '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"xCpJVzjaTB6A8s8QGZO8OuhOsE7XVdsUw82inWca4f0","kid":"PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA"}]}';
        }
    }

    server {
        listen  127.0.0.1:18462 ssl;
        server_name  directory-tagmismatch;

        ssl_certificate      $TEST_NGINX_DATA_DIR/directory-cert.pem;
        ssl_certificate_key  $TEST_NGINX_DATA_DIR/directory-key.pem;

        access_log  $TEST_NGINX_SERVROOT/logs/error.log  directory_fetch;

        location = /.well-known/http-message-signatures-directory {
            default_type  application/http-message-signatures-directory+json;
            return 200 '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"xCpJVzjaTB6A8s8QGZO8OuhOsE7XVdsUw82inWca4f0","kid":"PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA"}]}';
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
        127.0.0.1:18448
        127.0.0.1:18451
        127.0.0.1:18454
        127.0.0.1:18455
        127.0.0.1:18456
        127.0.0.1:18457
        127.0.0.1:18458
        127.0.0.1:18459
        127.0.0.1:18460
        127.0.0.1:18461
        127.0.0.1:18462;

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

# Rewrites the "directory-rotate" origin's fixture (see $RotateFile above)
# via a real PUT request, so the rewrite happens exactly where it appears in
# the test file's request order instead of racing Test::Base's eval parsing.
# Requires nginx built with --with-http_dav_module (distro packages
# typically enable it; a minimal source build may not).
$MainConfig .= <<"_EOC_";
    location = /rotate {
        dav_methods  PUT;
        alias  $RotateFile;
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

# Same shape as $MainConfig, but auth_httpsig_key_directory_max_size and
# auth_httpsig_key_cache_min_ttl are each scoped to one protected location
# only, with the internal fetch location left on its inherited (smaller)
# http-level values. Regression coverage:
# these directives must be read from the protected location's config in
# ngx_http_auth_httpsig_directory_done(), not from whichever config the
# fetch subrequest's own find-config phase resolved for /httpsig_fetch.
our $LocScopeConfig = <<'_EOC_';
    auth_httpsig_mode                   observe;
    auth_httpsig_key_directory_request  /httpsig_fetch;
    auth_httpsig_trusted_agent
        127.0.0.1:18452
        127.0.0.1:18453;

    location /t_size {
        default_type                        text/plain;
        sub_filter_types                    text/plain;
        sub_filter    'RESPONSE_MARKER'  'verified:$httpsig_verified error:$httpsig_error';
        sub_filter_once                     on;
        auth_httpsig_key_directory_max_size 32;
        proxy_pass  http://127.0.0.1:18449/marker;
    }

    location /t_ttl {
        default_type                    text/plain;
        sub_filter_types                text/plain;
        sub_filter    'RESPONSE_MARKER'  'verified:$httpsig_verified error:$httpsig_error';
        sub_filter_once                 on;
        auth_httpsig_key_cache_min_ttl  30;
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

# $agent is either a bare host (legacy behavior: one line, quoted
# sf-string form, e.g. "127.0.0.1:18443") or an arrayref of raw
# Signature-Agent field values, one per header line, e.g.
# ['sig1="https://127.0.0.1:18443"', 'other="https://127.0.0.1:18448"']
# -- the Dictionary form real crawler traffic uses.
sub sign_headers {
    my ($agent, $target, $keyfile, $keyid, $label, $tag) = @_;
    $target //= '/t';
    $keyfile //= 'tests/prove/data/ed25519-key.pem';
    $keyid //= 'PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA';
    $label //= 'sig1';
    $tag //= 'web-bot-auth';

    my @agent_lines = ref($agent) eq 'ARRAY' ? @$agent : (qq{"https://$agent"});

    my $req = HttpSig::default_request(
        target  => $target,
        headers => [map { ['Signature-Agent', $_] } @agent_lines],
    );

    my ($input, $sig) = HttpSig::sign(
        label      => $label,
        keyfile    => $keyfile,
        components => ['@target-uri', '@authority', 'signature-agent'],
        params     => [
            ['created', time(),       'integer'],
            ['expires', time() + 300, 'integer'],
            ['keyid',   $keyid, 'string'],
            ['tag',     $tag, 'string'],
        ],
        req => $req,
    );

    my $agent_headers = join('', map { "Signature-Agent: $_\n" } @agent_lines);

    return $agent_headers
        . "Signature-Input: $input\n"
        . "Signature: $sig\n";
}

# Cache-TTL-reuse/refetch assertions depend on TEST
# 1/2/4/5/8/9/10/11/13/14/15/16 running in file order; Test::Nginx shuffles
# block order by default.
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



=== TEST 13: a fetch caches the current directory key
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers('127.0.0.1:18451')
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified:1 error:
--- grep_error_log eval: qr/18451 GET \/\.well-known\/http-message-signatures-directory\S*/
--- grep_error_log_out
18451 GET /.well-known/http-message-signatures-directory
--- wait: 2



=== TEST 14: a PUT request rotates the mock origin's directory key on disk
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- request
PUT /rotate
{"keys":[{"kty":"OKP","crv":"Ed25519","x":"y1f98y7aXG3ZAtYj85_YVsQib4MHknBtmiERGjF5T-I","kid":"ETcfa8hWhW-wlBzsJe5KvDD-ZfofYIfdTVyoIuVXwkc"}]}
--- error_code: 204



=== TEST 15: a TTL-triggered refetch of the rotated key invalidates the old one
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers('127.0.0.1:18451')
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified:0 error:unknown_keyid
--- grep_error_log eval: qr/18451 GET \/\.well-known\/http-message-signatures-directory\S*/
--- grep_error_log_out
18451 GET /.well-known/http-message-signatures-directory
18451 GET /.well-known/http-message-signatures-directory



=== TEST 16: the rotated key verifies without a further refetch
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers('127.0.0.1:18451', '/t',
    'tests/prove/data/ed25519-key2.pem', 'ETcfa8hWhW-wlBzsJe5KvDD-ZfofYIfdTVyoIuVXwkc')
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified:1 error:
--- grep_error_log eval: qr/18451 GET \/\.well-known\/http-message-signatures-directory\S*/
--- grep_error_log_out
18451 GET /.well-known/http-message-signatures-directory
18451 GET /.well-known/http-message-signatures-directory



=== TEST 17: auth_httpsig_key_directory_max_size scoped to the protected location is enforced, not the fetch location's inherited default
--- http_config eval: $::HttpConfig
--- config eval: $::LocScopeConfig
--- more_headers eval
use HttpSig;
main::sign_headers('127.0.0.1:18452', '/t_size')
--- request
GET /t_size
--- error_code: 200
--- response_body chomp
verified: error:directory_too_large



=== TEST 18: auth_httpsig_key_cache_min_ttl scoped to the protected location is honored, not the fetch location's inherited (shorter) default
--- http_config eval: $::HttpConfig
--- config eval: $::LocScopeConfig
--- more_headers eval
use HttpSig;
main::sign_headers('127.0.0.1:18453', '/t_ttl')
--- request
GET /t_ttl
--- error_code: 200
--- response_body chomp
verified:1 error:
--- grep_error_log eval: qr/18453 GET \/\.well-known\/http-message-signatures-directory\S*/
--- grep_error_log_out
18453 GET /.well-known/http-message-signatures-directory
--- wait: 3



=== TEST 19: the request in TEST 18 is still cached past the fetch location's inherited 2s TTL, because the effective TTL was the protected location's 30s
--- http_config eval: $::HttpConfig
--- config eval: $::LocScopeConfig
--- more_headers eval
use HttpSig;
main::sign_headers('127.0.0.1:18453', '/t_ttl')
--- request
GET /t_ttl
--- error_code: 200
--- response_body chomp
verified:1 error:
--- grep_error_log eval: qr/18453 GET \/\.well-known\/http-message-signatures-directory\S*/
--- grep_error_log_out
18453 GET /.well-known/http-message-signatures-directory



=== TEST 20: a Signature-Agent Dictionary entry keyed like the verified label is fetched (real crawler traffic shape)
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers(['sig1="https://127.0.0.1:18454"'])
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified:1 error:
--- grep_error_log eval: qr/18454 GET \/\.well-known\/http-message-signatures-directory\S*/
--- grep_error_log_out
18454 GET /.well-known/http-message-signatures-directory



=== TEST 21: a Signature-Agent Dictionary with no entry keyed like the verified label falls back to the first usable entry
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers(['g="https://127.0.0.1:18455"'])
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified:1 error:
--- grep_error_log eval: qr/18455 GET \/\.well-known\/http-message-signatures-directory\S*/
--- grep_error_log_out
18455 GET /.well-known/http-message-signatures-directory



=== TEST 22: only the labeled entry's host is fetched out of two Signature-Agent header lines naming different hosts
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers(['other="https://127.0.0.1:18457"', 'sig1="https://127.0.0.1:18456"'])
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified:1 error:
--- grep_error_log eval: qr/(?:18456|18457) GET \/\.well-known\/http-message-signatures-directory\S*/
--- grep_error_log_out
18456 GET /.well-known/http-message-signatures-directory



=== TEST 23: the same key repeated across lines with different "type" resolves to the line where "type" is absent
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers(['sig1="https://127.0.0.1:18458";type=jwks_uri', 'sig1="https://127.0.0.1:18459"'])
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified:1 error:
--- grep_error_log eval: qr/(?:18458|18459) GET \/\.well-known\/http-message-signatures-directory\S*/
--- grep_error_log_out
18459 GET /.well-known/http-message-signatures-directory



=== TEST 24: a labeled entry with an unsupported "type" is skipped in favor of a different key with no "type"
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers(['sig1="https://127.0.0.1:18460";type=jwks_uri, other="https://127.0.0.1:18461"'])
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified:1 error:
--- grep_error_log eval: qr/(?:18460|18461) GET \/\.well-known\/http-message-signatures-directory\S*/
--- grep_error_log_out
18461 GET /.well-known/http-message-signatures-directory



=== TEST 25: a Signature-Agent Dictionary whose only entry has an unsupported "type" is treated as having no usable entry
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers(['sig1="https://127.0.0.1:19999";type=cimd'])
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified: error:directory_not_allowed



=== TEST 26: a tag-mismatched signature never triggers a fetch, even with an otherwise-allowlisted Signature-Agent host
--- http_config eval: $::HttpConfig
--- config eval: $::MainConfig
--- more_headers eval
use HttpSig;
main::sign_headers('127.0.0.1:18462', '/t', undef, undef, undef, 'not-web-bot-auth')
--- request
GET /t
--- error_code: 200
--- response_body chomp
verified: error:
--- grep_error_log eval: qr/18462 GET \/\.well-known\/http-message-signatures-directory\S*/
--- grep_error_log_out
