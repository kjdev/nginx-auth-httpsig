use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/lib";

use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: an unsigned request passes through with empty variables
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode observe;
        return 200 "verified=[$httpsig_verified] keyid=[$httpsig_keyid] agent=[$httpsig_agent]";
    }
--- request
GET /t
--- response_body chomp
verified=[] keyid=[] agent=[]



=== TEST 2: a draft-cavage style Signature header is not RFC 9421 and is ignored
--- http_config
    auth_httpsig_jwks_file $TEST_NGINX_DATA_DIR/ed25519-jwks.json;
    auth_httpsig_profile   web-bot-auth;
--- config
    location /t {
        auth_httpsig_mode observe;
        return 200 "verified=[$httpsig_verified] keyid=[$httpsig_keyid] agent=[$httpsig_agent]";
    }
--- more_headers
Signature: keyId="PdxXhn7dNHVGUgmgckoHmbcG9hsWAnqedH8vCuwIxMA",algorithm="ed25519",headers="(request-target) host",signature="MTIz"
--- request
GET /t
--- response_body chomp
verified=[] keyid=[] agent=[]
