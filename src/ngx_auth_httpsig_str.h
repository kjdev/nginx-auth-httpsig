/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_str.h - ngx_str_t equality helper shared across the
 * sfv/base/profile/directory layers.
 */

#ifndef NGX_AUTH_HTTPSIG_STR_H
#define NGX_AUTH_HTTPSIG_STR_H


#include <ngx_config.h>
#include <ngx_core.h>


static ngx_inline ngx_flag_t
ngx_auth_httpsig_str_eq(const ngx_str_t *a, const ngx_str_t *b)
{
    return a->len == b->len && ngx_memcmp(a->data, b->data, a->len) == 0;
}


#endif /* NGX_AUTH_HTTPSIG_STR_H */
