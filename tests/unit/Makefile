CC       = cc
CFLAGS   = -std=c99 -Wall -Wextra -Wpedantic -Wshadow -Wformat=2
CFLAGS  += -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes
CFLAGS  += -Wno-unused-parameter -Wno-format
CFLAGS  += -I ngx_compat -I ../../src -I ../../nxe-json/src -I ../../nxe-jwx/src
CFLAGS  += $(shell pkg-config --cflags jansson)
CFLAGS  += $(shell pkg-config --cflags openssl 2>/dev/null)
LDFLAGS  = $(shell pkg-config --libs jansson)
LDFLAGS += $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

SRCS = test_main.c \
       test_sfv.c \
       test_sfv_httpwg.c \
       test_base.c \
       test_keys.c \
       test_verify.c \
       test_profile.c \
       test_directory.c \
       test_cache.c \
       test_keys_cache.c \
       test_crypto.c \
       ngx_compat/ngx_stub.c \
       ngx_compat/ngx_rbtree.c \
       ../../src/ngx_auth_httpsig_sfv.c \
       ../../src/ngx_auth_httpsig_base.c \
       ../../src/ngx_auth_httpsig_keys.c \
       ../../src/ngx_auth_httpsig_verify.c \
       ../../src/ngx_auth_httpsig_profile.c \
       ../../src/ngx_auth_httpsig_directory.c \
       ../../src/ngx_auth_httpsig_cache.c \
       ../../src/ngx_auth_httpsig_keys_cache.c \
       ../../nxe-json/src/nxe_json.c \
       ../../nxe-jwx/src/nxe_jwx_jwks.c \
       ../../nxe-jwx/src/nxe_jwx_jws.c \
       ../../nxe-jwx/src/nxe_jwx_decode.c \
       ../../nxe-jwx/src/nxe_jwx_thumbprint.c

# Not compiled directly, but every SRCS file transitively includes one
# of these; listing them as prerequisites forces a relink when only a
# header changes (SRCS timestamps alone would otherwise look current).
HDRS = test.h \
       test_crypto.h \
       ngx_compat/ngx_config.h \
       ngx_compat/ngx_core.h \
       ngx_compat/ngx_stub.h \
       ngx_compat/ngx_rbtree.h \
       ../../src/ngx_auth_httpsig_sfv.h \
       ../../src/ngx_auth_httpsig_str.h \
       ../../src/ngx_auth_httpsig_base.h \
       ../../src/ngx_auth_httpsig_keys.h \
       ../../src/ngx_auth_httpsig_verify.h \
       ../../src/ngx_auth_httpsig_profile.h \
       ../../src/ngx_auth_httpsig_directory.h \
       ../../src/ngx_auth_httpsig_cache.h \
       ../../src/ngx_auth_httpsig_keys_cache.h \
       ../../nxe-json/src/nxe_json.h \
       ../../nxe-jwx/src/nxe_jwx.h \
       ../../nxe-jwx/src/nxe_jwx_jwks.h \
       ../../nxe-jwx/src/nxe_jwx_jws.h \
       ../../nxe-jwx/src/nxe_jwx_internal.h

test_runner: $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

test_runner_asan: $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -fsanitize=address -fno-omit-frame-pointer -g \
		-o $@ $(SRCS) $(LDFLAGS) -fsanitize=address

test_runner_cov: $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) --coverage -g -O0 -o $@ $(SRCS) $(LDFLAGS) --coverage

test: test_runner
	./test_runner

test-asan: test_runner_asan
	./test_runner_asan

test-cov: test_runner_cov
	@rm -f *.gcda
	./test_runner_cov
	@echo ""
	@echo "=== Coverage Summary (src/) ==="
	@LC_ALL=C gcov -n *ngx_auth_httpsig*.gcda 2>/dev/null \
		| awk '/^File.*\.\.\/\.\.\/src\// { file=$$0 } \
		       /^Lines executed:/ && file { print file; print $$0; file="" }'

clean:
	rm -f test_runner test_runner_asan test_runner_cov *.gcno *.gcda *.gcov

.PHONY: test test-asan test-cov clean
