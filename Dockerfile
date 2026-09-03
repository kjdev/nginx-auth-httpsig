# syntax=docker/dockerfile:1

FROM nginx:alpine AS nginx

# [builder]
FROM nginx AS builder

WORKDIR /build
RUN --mount=type=cache,target=/var/cache/apk sh -ex <<'EOS'
apk upgrade
apk add \
  curl \
  gcc \
  jansson-dev \
  linux-headers \
  make \
  musl-dev \
  openssl-dev \
  pcre2-dev \
  zlib-dev
nginx_version=$(nginx -v 2>&1 | sed 's/^[^0-9]*//')
curl -sL -o nginx-${nginx_version}.tar.gz https://nginx.org/download/nginx-${nginx_version}.tar.gz
tar -xf nginx-${nginx_version}.tar.gz
mv nginx-${nginx_version} nginx
EOS

COPY config /build/
COPY src/ /build/src/
COPY nxe-json/ /build/nxe-json/
COPY nxe-jwx/ /build/nxe-jwx/
COPY nxe-phase/ /build/nxe-phase/

WORKDIR /build/nginx
RUN sh -ex <<'EOS'
opt=$(nginx -V 2>&1 | tail -1 | sed -e 's/configure arguments://' -e 's| --add-dynamic-module=[^ ]*||g')
with_cc_opt=$(echo "${opt}" | grep -e "--with-cc-opt='[^']*'" -o | sed -e "s/^--with-cc-opt='//" -e "s/'$//")
with_ld_opt=$(echo "${opt}" | grep -e "--with-ld-opt='[^']*'" -o | sed -e "s/^--with-ld-opt='//" -e "s/'$//")
opt=$(echo "${opt}" | sed -e "s|--with-cc-opt='[^']*'||" -e "s|--with-ld-opt='[^']*'||" -e 's/--without-engine//')
./configure \
  ${opt} \
  --with-cc-opt="${with_cc_opt} -DNGX_HTTP_HEADERS" \
  --with-ld-opt="${with_ld_opt}" \
  --add-dynamic-module=..
make -j
cp objs/ngx_http_auth_httpsig_module.so /usr/lib/nginx/modules/
EOS

# [nginx]
FROM nginx AS module

RUN --mount=type=cache,target=/var/cache/apk sh -ex <<'EOS'
apk upgrade
apk add jansson
# load module: ngx_http_auth_httpsig_module.so
sed -i '/events {/i load_module "/usr/lib/nginx/modules/ngx_http_auth_httpsig_module.so";' /etc/nginx/nginx.conf
EOS

COPY --from=builder /usr/lib/nginx/modules/ngx_http_auth_httpsig_module.so /usr/lib/nginx/modules/ngx_http_auth_httpsig_module.so

# [proxy]
FROM module AS proxy

RUN --mount=type=cache,target=/var/cache/apk sh -ex <<'EOS'
apk add ca-certificates
EOS

COPY docker/25-httpsig-conf.sh /docker-entrypoint.d/25-httpsig-conf.sh
RUN chmod +x /docker-entrypoint.d/25-httpsig-conf.sh
