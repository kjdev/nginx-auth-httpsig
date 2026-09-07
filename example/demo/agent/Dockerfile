# Build context is the repository root (see ../compose.yaml) so this can
# reuse tests/prove/lib/HttpSig.pm instead of duplicating the signing code.
FROM nginx:alpine

RUN apk add --no-cache openssl perl curl

COPY tests/prove/lib/HttpSig.pm            /demo/lib/HttpSig.pm
COPY example/demo/agent/nginx.conf         /etc/nginx/nginx.conf
COPY example/demo/agent/gen-keys.sh        /demo/gen-keys.sh
COPY example/demo/agent/httpsig-request.pl /demo/httpsig-request.pl
COPY example/demo/agent/demo.sh            /demo/demo.sh

RUN chmod +x /demo/gen-keys.sh /demo/httpsig-request.pl /demo/demo.sh
