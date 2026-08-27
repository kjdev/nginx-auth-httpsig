/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_stub.h - minimal nginx core surface for the auth_httpsig unit
 * tests.
 *
 * Provides the types and macros used by src/ngx_auth_httpsig_*.c.
 * Memory is tracked in a simple linked list inside ngx_pool_t so the
 * test harness can free everything at teardown.
 */

#ifndef NGX_STUB_H
#define NGX_STUB_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define ngx_cdecl


/* --- basic types --- */

typedef unsigned char u_char;
typedef intptr_t ngx_int_t;
typedef uintptr_t ngx_uint_t;
typedef intptr_t ngx_flag_t;
typedef intptr_t ngx_msec_t;

#define NGX_OK          0
#define NGX_ERROR       (-1)
#define NGX_DECLINED    (-5)

#define NGX_MAX_INT_T_VALUE  INTPTR_MAX

#ifndef NULL
#define NULL ((void *) 0)
#endif

#define ngx_inline  inline

#define NGX_CONF_UNSET       (-1)
#define NGX_CONF_UNSET_UINT  ((ngx_uint_t) -1)
#define NGX_CONF_UNSET_PTR   ((void *) -1)
#define NGX_CONF_UNSET_SIZE  ((size_t) -1)
#define NGX_CONF_UNSET_MSEC  ((ngx_msec_t) -1)

#define ngx_min(val1, val2)  ((val1 > val2) ? (val2) : (val1))
#define ngx_max(val1, val2)  ((val1 < val2) ? (val2) : (val1))

#include "ngx_rbtree.h"


/* --- ngx_str_t --- */

typedef struct {
    size_t  len;
    u_char *data;
} ngx_str_t;

#define ngx_string(str)     { sizeof(str) - 1, (u_char *) str }
#define ngx_null_string     { 0, NULL }

#define ngx_str_set(str, text)                                               \
        (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text

#define ngx_str_null(str)   (str)->len = 0; (str)->data = NULL


/* --- forward declarations --- */

typedef struct ngx_pool_s ngx_pool_t;
typedef struct ngx_log_s ngx_log_t;
typedef struct ngx_pool_large_s ngx_pool_large_t;


/* --- ngx_log_t (minimal) --- */

#define NGX_LOG_STDERR  0
#define NGX_LOG_EMERG   1
#define NGX_LOG_ALERT   2
#define NGX_LOG_CRIT    3
#define NGX_LOG_ERR     4
#define NGX_LOG_WARN    5
#define NGX_LOG_NOTICE  6
#define NGX_LOG_INFO    7
#define NGX_LOG_DEBUG   8

struct ngx_log_s {
    ngx_uint_t  log_level;
};

#define ngx_log_error(level, log, err, ...)                                  \
        do {                                                                 \
            (void) (err);                                                    \
            if ((log) != NULL                                                \
                && (ngx_uint_t) (level) <= (log)->log_level)                 \
            {                                                                \
                fprintf(stderr, "[auth_httpsig_stub] ");                     \
                fprintf(stderr, __VA_ARGS__);                                \
                fprintf(stderr, "\n");                                       \
            }                                                                \
        } while (0)


/* --- ngx_pool_t (malloc-backed) --- */

typedef struct ngx_pool_cleanup_s ngx_pool_cleanup_t;
typedef void (*ngx_pool_cleanup_pt)(void *data);

struct ngx_pool_cleanup_s {
    ngx_pool_cleanup_pt  handler;
    void                *data;
    ngx_pool_cleanup_t  *next;
};

struct ngx_pool_large_s {
    ngx_pool_large_t *next;
    void             *alloc;
};

struct ngx_pool_s {
    ngx_pool_large_t   *large;
    ngx_pool_cleanup_t *cleanup;
    ngx_log_t          *log;
};

ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);
void        ngx_destroy_pool(ngx_pool_t *pool);

void *ngx_palloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
ngx_int_t  ngx_pfree(ngx_pool_t *pool, void *p);

ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *pool, size_t size);


/* --- ngx_array_t (malloc-backed, grows by doubling) --- */

typedef struct {
    void       *elts;
    ngx_uint_t  nelts;
    size_t      size;
    ngx_uint_t  nalloc;
    ngx_pool_t *pool;
} ngx_array_t;

ngx_array_t *ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size);
void ngx_array_destroy(ngx_array_t *a);
void *ngx_array_push(ngx_array_t *a);
void *ngx_array_push_n(ngx_array_t *a, ngx_uint_t n);

ngx_int_t ngx_array_init(ngx_array_t *array, ngx_pool_t *pool, ngx_uint_t n,
    size_t size);


/* --- memory / string macros --- */

#define ngx_memcmp(s1, s2, n)   memcmp(s1, s2, n)
#define ngx_memcpy(dst, src, n) memcpy(dst, src, n)
#define ngx_memzero(buf, n)     memset(buf, 0, n)
#define ngx_memset(buf, c, n)   memset(buf, c, n)
#define ngx_cpymem(dst, src, n) (((u_char *) memcpy(dst, src, n)) + (n))
#define ngx_copy(dst, src, n)   ngx_cpymem(dst, src, n)
#define ngx_strlen(s)           strlen((const char *) (s))
#define ngx_strncmp(s1, s2, n)  strncmp((const char *) (s1),                 \
                                        (const char *) (s2), n)
#define ngx_strcmp(s1, s2)      strcmp((const char *) (s1),                  \
                                       (const char *) (s2))

#define ngx_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define ngx_toupper(c)      (u_char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)

ngx_int_t ngx_strcasecmp(u_char *s1, u_char *s2);
ngx_int_t ngx_strncasecmp(u_char *s1, u_char *s2, size_t n);
void ngx_strlow(u_char *dst, u_char *src, size_t n);


/* --- time --- */

time_t ngx_time(void);


/* --- base64 / base64url --- */

#define ngx_base64_decoded_length(len) (((len + 3) / 4) * 3)
#define ngx_base64_encoded_length(len) (((len) + 2) / 3 * 4)

ngx_int_t ngx_decode_base64url(ngx_str_t *dst, ngx_str_t *src);
void ngx_encode_base64url(ngx_str_t *dst, ngx_str_t *src);
ngx_int_t ngx_decode_base64(ngx_str_t *dst, ngx_str_t *src);
void ngx_encode_base64(ngx_str_t *dst, ngx_str_t *src);


/* --- ngx_shm_t / ngx_shm_zone_t --- */

typedef struct {
    u_char     *addr;
    size_t      size;
    ngx_str_t   name;
    ngx_log_t  *log;
    ngx_uint_t  exists;
} ngx_shm_t;

typedef struct ngx_shm_zone_s  ngx_shm_zone_t;
typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

struct ngx_shm_zone_s {
    void                  *data;
    ngx_shm_t              shm;
    ngx_shm_zone_init_pt   init;
    void                  *tag;
    void                  *sync;
    ngx_uint_t             noreuse;
};


/* --- ngx_cycle_t (minimal) --- */

typedef struct {
    ngx_log_t  *log;
} ngx_cycle_t;

extern volatile ngx_cycle_t *ngx_cycle;


/* --- ngx_shmtx_t (single-threaded no-op, counts lock/unlock calls) --- */

typedef struct {
    ngx_uint_t  locked;
    ngx_uint_t  lock_calls;
    ngx_uint_t  unlock_calls;
} ngx_shmtx_t;

void ngx_shmtx_lock(ngx_shmtx_t *mtx);
void ngx_shmtx_unlock(ngx_shmtx_t *mtx);


/* --- ngx_slab_pool_t (malloc-backed, byte-budget capped) --- */

typedef struct ngx_stub_slab_block_s ngx_stub_slab_block_t;

struct ngx_stub_slab_block_s {
    ngx_stub_slab_block_t *next;
    ngx_stub_slab_block_t *prev;
    size_t                  size;
};

typedef struct {
    ngx_shmtx_t             mutex;
    void                   *data;
    u_char                 *log_ctx;
    unsigned                log_nomem:1;

    size_t                  budget;
    size_t                  used;
    ngx_stub_slab_block_t  *blocks;
} ngx_slab_pool_t;

void *ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size);
void  ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p);

ngx_slab_pool_t *ngx_stub_slab_create(size_t budget, ngx_log_t *log);
void ngx_stub_slab_destroy(ngx_slab_pool_t *pool);


/* --- ngx_crc32_short / ngx_memn2cmp --- */

uint32_t ngx_crc32_short(u_char *p, size_t len);
ngx_int_t ngx_memn2cmp(u_char *s1, u_char *s2, size_t n1, size_t n2);


/* --- ngx_sprintf (minimal: "%V" and "%Z" only) --- */

u_char *ngx_cdecl ngx_sprintf(u_char *buf, const char *fmt, ...);


#endif /* NGX_STUB_H */
