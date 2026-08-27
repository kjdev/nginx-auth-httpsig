/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_stub.c - implementation of the minimal nginx stub used by the
 * auth_httpsig unit tests.  All allocations are tracked so
 * ngx_destroy_pool can release them at teardown.
 */

#include "ngx_stub.h"

#include <stdarg.h>
#include <stdlib.h>


ngx_pool_t *
ngx_create_pool(size_t size, ngx_log_t *log)
{
    ngx_pool_t *pool;

    (void) size;

    pool = malloc(sizeof(ngx_pool_t));
    if (pool == NULL) {
        return NULL;
    }

    pool->large = NULL;
    pool->cleanup = NULL;
    pool->log = log;

    return pool;
}


void
ngx_destroy_pool(ngx_pool_t *pool)
{
    ngx_pool_large_t *l, *next;
    ngx_pool_cleanup_t *c, *cnext;

    if (pool == NULL) {
        return;
    }

    /* Run cleanup handlers in LIFO order, like nginx core. */
    for (c = pool->cleanup; c != NULL; c = cnext) {
        cnext = c->next;
        if (c->handler != NULL) {
            c->handler(c->data);
        }
        free(c);
    }

    for (l = pool->large; l != NULL; l = next) {
        next = l->next;
        free(l->alloc);
        free(l);
    }

    free(pool);
}


ngx_pool_cleanup_t *
ngx_pool_cleanup_add(ngx_pool_t *pool, size_t size)
{
    ngx_pool_cleanup_t *c;

    if (pool == NULL) {
        return NULL;
    }

    c = malloc(sizeof(ngx_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    if (size > 0) {
        c->data = malloc(size);
        if (c->data == NULL) {
            free(c);
            return NULL;
        }
    } else {
        c->data = NULL;
    }

    c->handler = NULL;
    c->next = pool->cleanup;
    pool->cleanup = c;

    return c;
}


void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    void *p;
    ngx_pool_large_t *large;

    p = malloc(size);
    if (p == NULL) {
        return NULL;
    }

    large = malloc(sizeof(ngx_pool_large_t));
    if (large == NULL) {
        free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}


void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    return ngx_palloc(pool, size);
}


void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    void *p;

    p = ngx_palloc(pool, size);
    if (p != NULL) {
        ngx_memzero(p, size);
    }

    return p;
}


ngx_int_t
ngx_pfree(ngx_pool_t *pool, void *p)
{
    ngx_pool_large_t *l, **prev;

    if (pool == NULL) {
        return NGX_ERROR;
    }

    prev = &pool->large;
    for (l = pool->large; l != NULL; l = l->next) {
        if (l->alloc == p) {
            *prev = l->next;
            free(l->alloc);
            free(l);
            return NGX_OK;
        }
        prev = &l->next;
    }

    return NGX_ERROR;
}


/*
 * The shim pool has no bump-allocator tail to extend in place (unlike
 * nginx core's ngx_array_push), so growth always allocates a fresh,
 * doubled buffer and copies the live elements into it. The old buffer
 * is left tracked in the pool's large list and freed at
 * ngx_destroy_pool, same as any other ngx_palloc.
 */
ngx_int_t
ngx_array_init(ngx_array_t *array, ngx_pool_t *pool, ngx_uint_t n,
    size_t size)
{
    array->nelts = 0;
    array->size = size;
    array->nalloc = n;
    array->pool = pool;

    array->elts = ngx_palloc(pool, n * size);
    if (array->elts == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_array_t *
ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size)
{
    ngx_array_t *a;

    a = ngx_palloc(p, sizeof(ngx_array_t));
    if (a == NULL) {
        return NULL;
    }

    if (ngx_array_init(a, p, n, size) != NGX_OK) {
        return NULL;
    }

    return a;
}


void
ngx_array_destroy(ngx_array_t *a)
{
    ngx_pfree(a->pool, a->elts);
    ngx_pfree(a->pool, a);
}


void *
ngx_array_push_n(ngx_array_t *a, ngx_uint_t n)
{
    void *elt, *new;
    ngx_uint_t nalloc;

    if (a->nelts + n > a->nalloc) {
        nalloc = 2 * ((n >= a->nalloc) ? a->nelts + n : a->nalloc);

        new = ngx_palloc(a->pool, nalloc * a->size);
        if (new == NULL) {
            return NULL;
        }

        ngx_memcpy(new, a->elts, a->nelts * a->size);

        a->elts = new;
        a->nalloc = nalloc;
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts += n;

    return elt;
}


void *
ngx_array_push(ngx_array_t *a)
{
    return ngx_array_push_n(a, 1);
}


ngx_int_t
ngx_strcasecmp(u_char *s1, u_char *s2)
{
    ngx_uint_t c1, c2;

    for ( ;; ) {
        c1 = (ngx_uint_t) *s1++;
        c2 = (ngx_uint_t) *s2++;

        c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
        c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;

        if (c1 == c2) {
            if (c1) {
                continue;
            }
            return 0;
        }

        return c1 - c2;
    }
}


ngx_int_t
ngx_strncasecmp(u_char *s1, u_char *s2, size_t n)
{
    ngx_uint_t c1, c2;

    while (n) {
        c1 = (ngx_uint_t) *s1++;
        c2 = (ngx_uint_t) *s2++;

        c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
        c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;

        if (c1 == c2) {
            if (c1 == 0) {
                return 0;
            }
            n--;
            continue;
        }

        return c1 - c2;
    }

    return 0;
}


time_t
ngx_time(void)
{
    return time(NULL);
}


static int
ngx_stub_b64url_char(u_char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}


/*
 * base64url decoder.  Mirrors the production ngx_decode_base64_internal():
 * scans only up to the first '=' (or the end of input) and validates
 * just that prefix, silently ignoring everything from the first '='
 * onward -- including further '=' or other bytes -- and rejects a
 * dangling one-character group (len % 4 == 1).  Callers that must
 * reject '=' outside a trailing pad (e.g. the SFV byte sequence
 * parser) validate that themselves before calling this.
 */
ngx_int_t
ngx_decode_base64url(ngx_str_t *dst, ngx_str_t *src)
{
    size_t i, len;
    int v;
    u_char *out;
    unsigned int bits = 0;
    unsigned int buf = 0;

    for (len = 0; len < src->len && src->data[len] != '='; len++) {
        if (ngx_stub_b64url_char(src->data[len]) < 0) {
            return NGX_ERROR;
        }
    }

    if (len % 4 == 1) {
        return NGX_ERROR;
    }

    out = dst->data;

    for (i = 0; i < len; i++) {
        v = ngx_stub_b64url_char(src->data[i]);
        buf = (buf << 6) | (unsigned int) v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            *out++ = (u_char) ((buf >> bits) & 0xff);
            buf &= (1u << bits) - 1;
        }
    }

    dst->len = (size_t) (out - dst->data);
    return NGX_OK;
}


/*
 * base64url encoder.  URL-safe alphabet, no '=' padding -- matches the
 * production ngx_encode_base64url (basis64url, padding disabled), which
 * is the form JWS compact serialization expects.
 */
void
ngx_encode_base64url(ngx_str_t *dst, ngx_str_t *src)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    u_char *s = src->data;
    u_char *d = dst->data;
    size_t len = src->len;

    while (len >= 3) {
        *d++ = (u_char) alphabet[s[0] >> 2];
        *d++ = (u_char) alphabet[((s[0] & 0x03) << 4) | (s[1] >> 4)];
        *d++ = (u_char) alphabet[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
        *d++ = (u_char) alphabet[s[2] & 0x3f];
        s += 3;
        len -= 3;
    }

    if (len) {
        *d++ = (u_char) alphabet[s[0] >> 2];
        if (len == 1) {
            *d++ = (u_char) alphabet[(s[0] & 0x03) << 4];
        } else {
            *d++ = (u_char) alphabet[((s[0] & 0x03) << 4) | (s[1] >> 4)];
            *d++ = (u_char) alphabet[(s[1] & 0x0f) << 2];
        }
    }

    dst->len = (size_t) (d - dst->data);
}


static int
ngx_stub_b64_char(u_char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}


/*
 * base64 decoder (standard '+'/'/' alphabet).  Mirrors the production
 * ngx_decode_base64_internal(): see ngx_decode_base64url() above for
 * the exact semantics this reproduces, in particular that everything
 * from the first '=' onward is ignored rather than merely skipped.
 */
ngx_int_t
ngx_decode_base64(ngx_str_t *dst, ngx_str_t *src)
{
    size_t i, len;
    int v;
    u_char *out;
    unsigned int bits = 0;
    unsigned int buf = 0;

    for (len = 0; len < src->len && src->data[len] != '='; len++) {
        if (ngx_stub_b64_char(src->data[len]) < 0) {
            return NGX_ERROR;
        }
    }

    if (len % 4 == 1) {
        return NGX_ERROR;
    }

    out = dst->data;

    for (i = 0; i < len; i++) {
        v = ngx_stub_b64_char(src->data[i]);
        buf = (buf << 6) | (unsigned int) v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            *out++ = (u_char) ((buf >> bits) & 0xff);
            buf &= (1u << bits) - 1;
        }
    }

    dst->len = (size_t) (out - dst->data);
    return NGX_OK;
}


/*
 * base64 (standard alphabet, '+'/'/' with '=' padding). Not used by
 * auth_httpsig itself, but kept for parity with the nxe-jwx shim this
 * file was copied from, in case a future test needs it.
 */
void
ngx_encode_base64(ngx_str_t *dst, ngx_str_t *src)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    u_char *s = src->data;
    u_char *d = dst->data;
    size_t len = src->len;

    while (len >= 3) {
        *d++ = (u_char) alphabet[s[0] >> 2];
        *d++ = (u_char) alphabet[((s[0] & 0x03) << 4) | (s[1] >> 4)];
        *d++ = (u_char) alphabet[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
        *d++ = (u_char) alphabet[s[2] & 0x3f];
        s += 3;
        len -= 3;
    }

    if (len) {
        *d++ = (u_char) alphabet[s[0] >> 2];
        if (len == 1) {
            *d++ = (u_char) alphabet[(s[0] & 0x03) << 4];
            *d++ = '=';
        } else {
            *d++ = (u_char) alphabet[((s[0] & 0x03) << 4) | (s[1] >> 4)];
            *d++ = (u_char) alphabet[(s[1] & 0x0f) << 2];
        }
        *d++ = '=';
    }

    dst->len = (size_t) (d - dst->data);
}


/* --- ngx_cycle (minimal, log-only) --- */

static ngx_log_t ngx_stub_default_log = { NGX_LOG_WARN };
static ngx_cycle_t ngx_stub_default_cycle = { &ngx_stub_default_log };
volatile ngx_cycle_t *ngx_cycle = &ngx_stub_default_cycle;


/* --- ngx_shmtx_t (single-threaded no-op) --- */

void
ngx_shmtx_lock(ngx_shmtx_t *mtx)
{
    mtx->lock_calls++;
    mtx->locked = 1;
}


void
ngx_shmtx_unlock(ngx_shmtx_t *mtx)
{
    mtx->unlock_calls++;
    mtx->locked = 0;
}


/* --- ngx_slab_pool_t (malloc-backed, byte-budget capped) --- */

static void *
ngx_stub_slab_do_alloc(ngx_slab_pool_t *pool, size_t size)
{
    ngx_stub_slab_block_t *block;

    if (pool == NULL) {
        return NULL;
    }

    if (pool->used + size > pool->budget) {
        return NULL;
    }

    block = malloc(sizeof(ngx_stub_slab_block_t) + size);
    if (block == NULL) {
        return NULL;
    }

    block->size = size;
    block->prev = NULL;
    block->next = pool->blocks;

    if (pool->blocks != NULL) {
        pool->blocks->prev = block;
    }

    pool->blocks = block;
    pool->used += size;

    return (void *) (block + 1);
}


void *
ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size)
{
    return ngx_stub_slab_do_alloc(pool, size);
}


void *
ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size)
{
    return ngx_stub_slab_do_alloc(pool, size);
}


void
ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p)
{
    ngx_stub_slab_block_t *block;

    if (pool == NULL || p == NULL) {
        return;
    }

    block = ((ngx_stub_slab_block_t *) p) - 1;

    if (block->prev != NULL) {
        block->prev->next = block->next;
    } else {
        pool->blocks = block->next;
    }

    if (block->next != NULL) {
        block->next->prev = block->prev;
    }

    pool->used -= block->size;

    free(block);
}


ngx_slab_pool_t *
ngx_stub_slab_create(size_t budget, ngx_log_t *log)
{
    ngx_slab_pool_t *pool;

    (void) log;

    pool = malloc(sizeof(ngx_slab_pool_t));
    if (pool == NULL) {
        return NULL;
    }

    ngx_memzero(pool, sizeof(ngx_slab_pool_t));
    pool->budget = budget;

    return pool;
}


/*
 * Frees every allocation still tracked in the slab's block list, which
 * covers cache nodes, jwks payloads and the log_ctx string alike -- all
 * of them went through ngx_slab_alloc(_locked), so a single walk is
 * enough to leave ASAN with nothing outstanding.
 */
void
ngx_stub_slab_destroy(ngx_slab_pool_t *pool)
{
    ngx_stub_slab_block_t *block, *next;

    if (pool == NULL) {
        return;
    }

    for (block = pool->blocks; block != NULL; block = next) {
        next = block->next;
        free(block);
    }

    free(pool);
}


/* --- ngx_crc32_short --- */

static uint32_t ngx_stub_crc32_table16[] = {
    0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
    0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
    0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
    0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c
};


uint32_t
ngx_crc32_short(u_char *p, size_t len)
{
    u_char c;
    uint32_t crc;

    crc = 0xffffffff;

    while (len--) {
        c = *p++;
        crc = ngx_stub_crc32_table16[(crc ^ (c & 0xf)) & 0xf] ^ (crc >> 4);
        crc = ngx_stub_crc32_table16[(crc ^ (c >> 4)) & 0xf] ^ (crc >> 4);
    }

    return crc ^ 0xffffffff;
}


/* --- ngx_memn2cmp --- */

ngx_int_t
ngx_memn2cmp(u_char *s1, u_char *s2, size_t n1, size_t n2)
{
    size_t n;
    ngx_int_t m, z;

    if (n1 <= n2) {
        n = n1;
        z = -1;

    } else {
        n = n2;
        z = 1;
    }

    m = ngx_memcmp(s1, s2, n);

    if (m || n1 == n2) {
        return m;
    }

    return z;
}


/* --- ngx_sprintf (minimal: "%V" and "%Z" only) --- */

u_char *ngx_cdecl
ngx_sprintf(u_char *buf, const char *fmt, ...)
{
    va_list args;
    const char *p;
    ngx_str_t *value;

    va_start(args, fmt);

    for (p = fmt; *p != '\0'; p++) {
        if (*p != '%') {
            *buf++ = (u_char) *p;
            continue;
        }

        p++;

        switch (*p) {
        case 'V':
            value = va_arg(args, ngx_str_t *);
            buf = ngx_cpymem(buf, value->data, value->len);
            break;

        case 'Z':
            *buf++ = '\0';
            break;

        default:
            *buf++ = (u_char) *p;
            break;
        }
    }

    va_end(args);

    return buf;
}
