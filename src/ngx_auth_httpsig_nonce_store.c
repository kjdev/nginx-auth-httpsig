/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_nonce_store.h"


ngx_int_t
ngx_auth_httpsig_nonce_store_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    return NGX_OK;
}
