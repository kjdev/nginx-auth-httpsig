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
       ngx_compat/ngx_stub.c \
       ../../src/ngx_auth_httpsig_sfv.c \
       ../../src/ngx_auth_httpsig_base.c \
       ../../nxe-json/src/nxe_json.c

# Not compiled directly, but every SRCS file transitively includes one
# of these; listing them as prerequisites forces a relink when only a
# header changes (SRCS timestamps alone would otherwise look current).
HDRS = test.h \
       ngx_compat/ngx_config.h \
       ngx_compat/ngx_core.h \
       ngx_compat/ngx_stub.h \
       ../../src/ngx_auth_httpsig_sfv.h \
       ../../src/ngx_auth_httpsig_base.h \
       ../../nxe-json/src/nxe_json.h

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
