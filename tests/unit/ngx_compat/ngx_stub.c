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


void
ngx_strlow(u_char *dst, u_char *src, size_t n)
{
    while (n) {
        *dst = ngx_tolower(*src);
        dst++;
        src++;
        n--;
    }
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


/* --- ngx_crc32_long ---
 *
 * Table verbatim from nginx's src/core/ngx_crc32.c (ngx_crc32_table256):
 * the SHM nonce store hashes rbtree keys with the real ngx_crc32_long, so
 * this stub must produce byte-identical hashes to it, not merely "a"
 * CRC32 variant.
 */

static uint32_t ngx_stub_crc32_table256[] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
    0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
    0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
    0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
    0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
    0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
    0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
    0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
    0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
    0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
    0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
    0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
    0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
    0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
    0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
    0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
    0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
    0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
    0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
    0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
    0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
    0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};


uint32_t
ngx_crc32_long(u_char *p, size_t len)
{
    uint32_t crc;

    crc = 0xffffffff;

    while (len--) {
        crc = ngx_stub_crc32_table256[(crc ^ *p++) & 0xff] ^ (crc >> 8);
    }

    return crc ^ 0xffffffff;
}


/* --- ngx_crc32_short ---
 *
 * Same CRC-32 as ngx_crc32_long (nginx's table16 variant only trades the
 * table size for two lookups per byte), so it delegates.
 */

uint32_t
ngx_crc32_short(u_char *p, size_t len)
{
    return ngx_crc32_long(p, len);
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
