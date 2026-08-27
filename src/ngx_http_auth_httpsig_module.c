/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_auth_httpsig_base.h"
#include "ngx_auth_httpsig_cache.h"
#include "ngx_auth_httpsig_directory.h"
#include "ngx_auth_httpsig_keys.h"
#include "ngx_auth_httpsig_keys_cache.h"
#include "ngx_auth_httpsig_profile.h"
#include "ngx_auth_httpsig_verify.h"


#define NGX_HTTP_AUTH_HTTPSIG_MODE_OFF       0
#define NGX_HTTP_AUTH_HTTPSIG_MODE_OBSERVE   1


typedef struct {
    ngx_str_t                file;
    ngx_auth_httpsig_keys_t *keys;
} ngx_http_auth_httpsig_jwks_conf_t;

typedef struct {
    const ngx_auth_httpsig_profile_t *def;
    ngx_str_t                         name;
    ngx_array_t                      *algs;    /* ngx_str_t, validated only */
    time_t                            expires_max;
    time_t                            max_skew;
} ngx_http_auth_httpsig_profile_conf_t;

typedef struct {
    ngx_array_t *trusted_agents; /* ngx_str_t normalized.
                                  * NULL = undeclared, nelts == 0 = explicit
                                  * "off". */
    ngx_str_t    request_uri;
    size_t       max_size;
    time_t       cache_min_ttl;
    time_t       cache_max_ttl;
    ngx_flag_t   enabled;        /* derived at merge */
} ngx_http_auth_httpsig_directory_conf_t;

typedef struct {
    ngx_uint_t                              mode;
    ngx_http_auth_httpsig_jwks_conf_t       jwks;
    ngx_http_auth_httpsig_profile_conf_t    profile;
    ngx_http_auth_httpsig_directory_conf_t  directory;
} ngx_http_auth_httpsig_loc_conf_t;

typedef struct {
    ngx_shm_zone_t                *shm_zone;
    ngx_flag_t                     dynamic;  /* true if the dynamic key
                                              * directory is enabled
                                              * anywhere in the whole
                                              * config */
    ngx_auth_httpsig_keys_cache_t *local_keys;  /* NULL unless dynamic */
} ngx_http_auth_httpsig_main_conf_t;

/* done == 1 means "already evaluated this request" (memoizes evaluation
 * across the get_handler calls of the $httpsig_* variables); keyid/agent
 * are only ever set from the RESULT_OK branch of
 * ngx_http_auth_httpsig_evaluate(), so a failed verification always
 * leaves them empty. directory_host/directory_done/claimed/
 * keys_unavailable/directory_reason/jwks/directory_generation are set by
 * the dynamic key-directory phase handler, not by evaluate():
 * directory_done marks that the fetch dance (hit / declined /
 * claimed-and-fetched) has run to completion for this request, claimed
 * marks that this worker currently holds the SHM fetch right for
 * directory_host and must release it, keys_unavailable records that a
 * fetch was attempted but did not yield usable keys (allow-list miss,
 * cache miss while another worker fetches, or a rejected/unparsable
 * response), which evaluate() maps to
 * NGX_AUTH_HTTPSIG_RESULT_KEY_UNAVAILABLE instead of
 * NGX_AUTH_HTTPSIG_RESULT_UNKNOWN_KEYID, and directory_reason records why
 * (only meaningful alongside keys_unavailable). jwks/directory_generation
 * identify the fetched document (bytes and SHM generation, respectively)
 * without parsing it; evaluate() resolves them into a keyset through the
 * worker-local parse cache, so no parsed-keys pointer is carried in this
 * struct across the PREACCESS/content boundary (see
 * ngx_http_auth_httpsig_resolve_keys()). internal_error is set by
 * evaluate() itself, for the NGX_ERROR cases that leave ctx->result at
 * NOT_SIGNED (fail-open) but still deserve a distinct $httpsig_error
 * token from "not signed". */
typedef struct {
    unsigned                         done:1;
    unsigned                         directory_done:1;
    unsigned                         claimed:1;
    unsigned                         keys_unavailable:1;
    unsigned                         internal_error:1;
    ngx_auth_httpsig_result_t        result;
    ngx_auth_httpsig_fetch_reason_t  directory_reason;
    ngx_str_t                        keyid;
    ngx_str_t                        agent;
    ngx_str_t                        directory_host;
    ngx_str_t                        jwks;           /* fetched body,
                                                      * r->pool */
    ngx_uint_t                       directory_generation;
} ngx_http_auth_httpsig_ctx_t;

/* Backstop for ngx_http_auth_httpsig_directory_handler(): if the request
 * ends (client abort, internal error) while ctx->claimed is still set --
 * meaning the ordinary release path in
 * ngx_http_auth_httpsig_directory_done() never ran -- this releases the
 * SHM fetch right so the host does not stay stuck BUSY forever. */
typedef struct {
    ngx_http_auth_httpsig_ctx_t  *ctx;
    ngx_auth_httpsig_cache_ctx_t *cache;
    ngx_str_t                     host;
    time_t                        retry_ttl;
} ngx_http_auth_httpsig_directory_cleanup_t;


static ngx_int_t ngx_http_auth_httpsig_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_httpsig_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_httpsig_init_process(ngx_cycle_t *cycle);
static void *ngx_http_auth_httpsig_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_auth_httpsig_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_httpsig_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_auth_httpsig_set_jwks_file(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_httpsig_set_profile(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_httpsig_set_alg(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_httpsig_set_trusted_agent(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_httpsig_set_key_directory_request(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_httpsig_set_key_cache_zone(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static void ngx_http_auth_httpsig_cleanup_keys(void *data);

static ngx_int_t ngx_http_auth_httpsig_variable_verified(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_auth_httpsig_variable_keyid(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_auth_httpsig_variable_agent(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_auth_httpsig_variable_directory_host(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_auth_httpsig_variable_error(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_auth_httpsig_directory_handler(
    ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_httpsig_directory_fail_open(
    ngx_http_auth_httpsig_ctx_t *ctx, ngx_auth_httpsig_fetch_reason_t reason);
static ngx_int_t ngx_http_auth_httpsig_directory_fail_open_release(
    ngx_http_auth_httpsig_ctx_t *ctx, ngx_auth_httpsig_cache_ctx_t *cache,
    time_t retry_ttl, ngx_auth_httpsig_fetch_reason_t reason);
static ngx_int_t ngx_http_auth_httpsig_directory_done(ngx_http_request_t *sr,
    void *data, ngx_int_t rc);
static void ngx_http_auth_httpsig_directory_cleanup(void *data);
static ngx_int_t ngx_http_auth_httpsig_evaluate(ngx_http_request_t *r,
    ngx_http_auth_httpsig_ctx_t **out);
static ngx_auth_httpsig_keys_t *ngx_http_auth_httpsig_resolve_keys(
    ngx_http_request_t *r, ngx_http_auth_httpsig_ctx_t *ctx);
static ngx_table_elt_t *ngx_http_auth_httpsig_find_header(
    ngx_list_t *list, const char *name, size_t len);
static ngx_int_t ngx_http_auth_httpsig_build_request(ngx_http_request_t *r,
    ngx_auth_httpsig_request_t *req);


static ngx_conf_enum_t ngx_http_auth_httpsig_mode[] = {
    { ngx_string("off"),     NGX_HTTP_AUTH_HTTPSIG_MODE_OFF },
    { ngx_string("observe"), NGX_HTTP_AUTH_HTTPSIG_MODE_OBSERVE },
    { ngx_null_string, 0 }
};

static ngx_command_t ngx_http_auth_httpsig_commands[] = {

    { ngx_string("auth_httpsig_mode"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_httpsig_loc_conf_t, mode),
      &ngx_http_auth_httpsig_mode },

    { ngx_string("auth_httpsig_jwks_file"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_http_auth_httpsig_set_jwks_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_httpsig_profile"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_http_auth_httpsig_set_profile,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_httpsig_alg"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_1MORE,
      ngx_http_auth_httpsig_set_alg,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_httpsig_expires_max"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_httpsig_loc_conf_t, profile.expires_max),
      NULL },

    { ngx_string("auth_httpsig_max_skew"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_httpsig_loc_conf_t, profile.max_skew),
      NULL },

    { ngx_string("auth_httpsig_trusted_agent"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_1MORE,
      ngx_http_auth_httpsig_set_trusted_agent,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_httpsig_key_directory_request"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_http_auth_httpsig_set_key_directory_request,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_httpsig_key_directory_max_size"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_httpsig_loc_conf_t, directory.max_size),
      NULL },

    { ngx_string("auth_httpsig_key_cache_min_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_httpsig_loc_conf_t, directory.cache_min_ttl),
      NULL },

    { ngx_string("auth_httpsig_key_cache_max_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_httpsig_loc_conf_t, directory.cache_max_ttl),
      NULL },

    { ngx_string("auth_httpsig_key_cache_zone"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_http_auth_httpsig_set_key_cache_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_auth_httpsig_module_ctx = {
    ngx_http_auth_httpsig_add_variables,    /* preconfiguration */
    ngx_http_auth_httpsig_init,             /* postconfiguration */

    ngx_http_auth_httpsig_create_main_conf, /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_auth_httpsig_create_loc_conf, /* create location configuration */
    ngx_http_auth_httpsig_merge_loc_conf   /* merge location configuration */
};


ngx_module_t ngx_http_auth_httpsig_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_httpsig_module_ctx,     /* module context */
    ngx_http_auth_httpsig_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_auth_httpsig_init_process,    /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t ngx_http_auth_httpsig_variables[] = {

    { ngx_string("httpsig_verified"), NULL,
      ngx_http_auth_httpsig_variable_verified,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("httpsig_keyid"), NULL,
      ngx_http_auth_httpsig_variable_keyid,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("httpsig_agent"), NULL,
      ngx_http_auth_httpsig_variable_agent,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("httpsig_directory_host"), NULL,
      ngx_http_auth_httpsig_variable_directory_host,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("httpsig_error"), NULL,
      ngx_http_auth_httpsig_variable_error,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    ngx_http_null_variable
};


static ngx_int_t
ngx_http_auth_httpsig_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *v, *var;

    for (v = ngx_http_auth_httpsig_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


/*
 * nginx's phase handlers are a per-cycle array shared across every
 * location, so this cannot be scoped to only the locations that declare
 * "auth_httpsig_trusted_agent". Instead, the whole config is checked once
 * here: if no location anywhere enabled dynamic key fetching, the handler
 * is never registered and static-JWKS-only configs pay nothing (ADR
 * 0013). Once registered, every request pays one indirect call plus the
 * r != r->main / directory.enabled checks inside the handler.
 */
static ngx_int_t
ngx_http_auth_httpsig_init(ngx_conf_t *cf)
{
    ngx_http_auth_httpsig_main_conf_t *mcf;
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt *h;

    mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_auth_httpsig_module);

    if (!mcf->dynamic) {
        return NGX_OK;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_httpsig_directory_handler;

    return NGX_OK;
}


/*
 * Mirrors the ngx_http_auth_httpsig_init() gate: a worker-local parse
 * cache is only useful where the dynamic key directory is enabled, so
 * static-JWKS-only configs allocate nothing here either.
 */
static ngx_int_t
ngx_http_auth_httpsig_init_process(ngx_cycle_t *cycle)
{
    ngx_http_auth_httpsig_main_conf_t *mcf;

    mcf = ngx_http_cycle_get_module_main_conf(cycle,
                                              ngx_http_auth_httpsig_module);
    if (mcf == NULL || !mcf->dynamic) {
        return NGX_OK;
    }

    mcf->local_keys = ngx_auth_httpsig_keys_cache_create(cycle->pool);
    if (mcf->local_keys == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void *
ngx_http_auth_httpsig_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_auth_httpsig_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_httpsig_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static void *
ngx_http_auth_httpsig_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_httpsig_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_httpsig_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->mode = NGX_CONF_UNSET_UINT;
    conf->profile.algs = NGX_CONF_UNSET_PTR;
    conf->profile.expires_max = NGX_CONF_UNSET;
    conf->profile.max_skew = NGX_CONF_UNSET;

    /* directory.trusted_agents is deliberately left NULL (not
     * NGX_CONF_UNSET_PTR): NULL/empty/non-empty are three distinct
     * states (undeclared/explicit "off"/real list), not one. */
    conf->directory.max_size = NGX_CONF_UNSET_SIZE;
    conf->directory.cache_min_ttl = NGX_CONF_UNSET;
    conf->directory.cache_max_ttl = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_auth_httpsig_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_httpsig_loc_conf_t *prev = parent;
    ngx_http_auth_httpsig_loc_conf_t *conf = child;
    ngx_http_auth_httpsig_main_conf_t *mcf;
    ngx_str_t default_name = ngx_string("web-bot-auth");
    ngx_flag_t declared;

    ngx_conf_merge_uint_value(conf->mode, prev->mode,
                              NGX_HTTP_AUTH_HTTPSIG_MODE_OFF);

    if (conf->jwks.keys == NULL) {
        conf->jwks.keys = prev->jwks.keys;
        conf->jwks.file = prev->jwks.file;
    }

    if (conf->profile.def == NULL) {
        conf->profile.def = prev->profile.def;
        conf->profile.name = prev->profile.name;
    }

    if (conf->profile.def == NULL) {
        conf->profile.def = ngx_auth_httpsig_profile_get(&default_name);
        conf->profile.name = default_name;

        if (conf->profile.def == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_httpsig: unknown default profile \"%V\"",
                               &default_name);
            return NGX_CONF_ERROR;
        }
    }

    ngx_conf_merge_ptr_value(conf->profile.algs, prev->profile.algs, NULL);

    ngx_conf_merge_sec_value(conf->profile.expires_max,
                             prev->profile.expires_max,
                             conf->profile.def->expires_max);
    ngx_conf_merge_sec_value(conf->profile.max_skew,
                             prev->profile.max_skew,
                             conf->profile.def->max_skew);

    /* Override, not accumulate: a block that declares its own
     * "auth_httpsig_trusted_agent" (including "off") discards whatever
     * the parent inherited, rather than adding to it (ADR 0013). */
    declared = (conf->directory.trusted_agents != NULL);

    if (!declared) {
        conf->directory.trusted_agents = prev->directory.trusted_agents;
    }

    if (conf->directory.request_uri.len == 0) {
        conf->directory.request_uri = prev->directory.request_uri;
    }

    ngx_conf_merge_size_value(conf->directory.max_size,
                              prev->directory.max_size, 65536);
    ngx_conf_merge_sec_value(conf->directory.cache_min_ttl,
                             prev->directory.cache_min_ttl, 300);
    ngx_conf_merge_sec_value(conf->directory.cache_max_ttl,
                             prev->directory.cache_max_ttl, 3600);

    conf->directory.enabled = (conf->directory.trusted_agents != NULL
                               && conf->directory.trusted_agents->nelts > 0
                               && conf->directory.request_uri.len > 0);

    if (conf->directory.cache_min_ttl == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_httpsig: \"auth_httpsig_key_cache_min_ttl\" "
                           "must not be 0");
        return NGX_CONF_ERROR;
    }

    if (conf->directory.cache_max_ttl < conf->directory.cache_min_ttl) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_httpsig: \"auth_httpsig_key_cache_max_ttl\" "
                           "must not be less than "
                           "\"auth_httpsig_key_cache_min_ttl\"");
        return NGX_CONF_ERROR;
    }

    if (conf->directory.max_size > NGX_AUTH_HTTPSIG_MAX_JWKS_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_httpsig: \"auth_httpsig_key_directory_max_size\" "
                           "must not exceed %d bytes",
                           NGX_AUTH_HTTPSIG_MAX_JWKS_SIZE);
        return NGX_CONF_ERROR;
    }

    /* Gate on "declared", not on the merged value: a config that puts
     * "auth_httpsig_trusted_agent" on the server block and
     * "auth_httpsig_key_directory_request" only on some of its
     * locations is valid (the other locations inherit both), and must
     * not be rejected just because this specific block's merged
     * request_uri came from the parent. */
    if (declared && conf->directory.trusted_agents->nelts > 0) {
        if (conf->directory.request_uri.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_httpsig: \"auth_httpsig_trusted_agent\" is "
                               "set but no "
                               "\"auth_httpsig_key_directory_request\" is "
                               "configured");
            return NGX_CONF_ERROR;
        }

        mcf = ngx_http_conf_get_module_main_conf(cf,
                                                 ngx_http_auth_httpsig_module);

        if (mcf->shm_zone == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_httpsig: \"auth_httpsig_trusted_agent\" is "
                               "set but no \"auth_httpsig_key_cache_zone\" is "
                               "configured");
            return NGX_CONF_ERROR;
        }
    }

    if (conf->mode != NGX_HTTP_AUTH_HTTPSIG_MODE_OFF
        && conf->jwks.keys == NULL
        && !conf->directory.enabled)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_httpsig: \"auth_httpsig_mode\" is not \"off\" but no "
                           "\"auth_httpsig_jwks_file\" is configured");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void
ngx_http_auth_httpsig_cleanup_keys(void *data)
{
    ngx_auth_httpsig_keys_free(data);
}


static char *
ngx_http_auth_httpsig_set_jwks_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_auth_httpsig_loc_conf_t *lcf = conf;
    ngx_str_t *value, path, content;
    ngx_fd_t fd;
    ngx_file_t file;
    ngx_file_info_t fi;
    ngx_pool_cleanup_t *cln;

    if (lcf->jwks.file.len) {
        return "is duplicate";
    }

    value = cf->args->elts;
    path = value[1];

    if (ngx_conf_full_name(cf->cycle, &path, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    fd = ngx_open_file(path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%V\" failed", &path);
        return NGX_CONF_ERROR;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_fd_info_n " \"%V\" failed", &path);
        ngx_close_file(fd);
        return NGX_CONF_ERROR;
    }

    if (ngx_file_size(&fi) > NGX_AUTH_HTTPSIG_MAX_JWKS_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_httpsig: \"%V\" exceeds the maximum JWKS size of %d bytes",
                           &path, NGX_AUTH_HTTPSIG_MAX_JWKS_SIZE);
        ngx_close_file(fd);
        return NGX_CONF_ERROR;
    }

    content.len = ngx_file_size(&fi);
    content.data = ngx_pnalloc(cf->pool, content.len);
    if (content.data == NULL) {
        ngx_close_file(fd);
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.fd = fd;
    file.name = path;
    file.log = cf->log;

    if ((size_t) ngx_read_file(&file, content.data, content.len, 0)
        != content.len)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_read_file_n " \"%V\" failed", &path);
        ngx_close_file(fd);
        return NGX_CONF_ERROR;
    }

    ngx_close_file(fd);

    if (ngx_auth_httpsig_keys_load_jwks(cf->pool, &content, &path,
                                        NGX_LOG_EMERG, &lcf->jwks.keys)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_http_auth_httpsig_cleanup_keys;
    cln->data = lcf->jwks.keys;

    lcf->jwks.file = path;

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_httpsig_set_profile(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_auth_httpsig_loc_conf_t *lcf = conf;
    ngx_str_t *value;
    const ngx_auth_httpsig_profile_t *def;

    if (lcf->profile.def != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    def = ngx_auth_httpsig_profile_get(&value[1]);
    if (def == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_httpsig: unknown profile \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    lcf->profile.def = def;
    lcf->profile.name = value[1];

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_httpsig_set_alg(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_httpsig_loc_conf_t *lcf = conf;
    ngx_str_t *value, *alg;
    ngx_array_t *algs;
    ngx_uint_t i;

    if (lcf->profile.algs != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    algs = ngx_array_create(cf->pool, cf->args->nelts - 1, sizeof(ngx_str_t));
    if (algs == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len != sizeof("ed25519") - 1
            || ngx_strncasecmp(value[i].data, (u_char *) "ed25519",
                               sizeof("ed25519") - 1) != 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_httpsig: unsupported algorithm \"%V\", only "
                               "\"ed25519\" is accepted", &value[i]);
            return NGX_CONF_ERROR;
        }

        alg = ngx_array_push(algs);
        if (alg == NULL) {
            return NGX_CONF_ERROR;
        }

        *alg = value[i];
    }

    lcf->profile.algs = algs;

    return NGX_CONF_OK;
}


/*
 * "off" is a single-argument form that allocates an empty array to mean
 * "explicitly discard whatever the parent block would otherwise
 * inherit" (ADR 0013); it must not be mixed with hostnames, either as
 * arguments to one invocation or across repeated invocations in the
 * same block, since either combination as a boolean is deceptive: a
 * host list with an "off" in it either allowed those hosts (surprising)
 * or ignored them (silently, which is worse).
 *
 * Repeated invocations with real hostnames accumulate (push) rather
 * than erroring, matching directives like "allow"/"deny".
 */
static char *
ngx_http_auth_httpsig_set_trusted_agent(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_auth_httpsig_loc_conf_t *lcf = conf;
    ngx_http_auth_httpsig_main_conf_t *mcf;
    ngx_str_t *value, *entry, normalized;
    ngx_auth_httpsig_host_reason_t reason;
    ngx_uint_t i;
    ngx_flag_t is_off;

    value = cf->args->elts;

    is_off = (cf->args->nelts == 2
              && value[1].len == sizeof("off") - 1
              && ngx_strncasecmp(value[1].data, (u_char *) "off",
                                 sizeof("off") - 1) == 0);

    if (!is_off) {
        for (i = 1; i < cf->args->nelts; i++) {
            if (value[i].len == sizeof("off") - 1
                && ngx_strncasecmp(value[i].data, (u_char *) "off",
                                   sizeof("off") - 1) == 0)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "auth_httpsig: \"off\" cannot be "
                                   "combined with hostnames in "
                                   "\"auth_httpsig_trusted_agent\"");
                return NGX_CONF_ERROR;
            }
        }
    }

    if (lcf->directory.trusted_agents != NULL
        && (is_off || lcf->directory.trusted_agents->nelts == 0))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_httpsig: \"auth_httpsig_trusted_agent off\" "
                           "cannot be combined with other "
                           "\"auth_httpsig_trusted_agent\" directives in "
                           "the same block");
        return NGX_CONF_ERROR;
    }

    if (lcf->directory.trusted_agents == NULL) {
        lcf->directory.trusted_agents = ngx_array_create(cf->pool,
                                                         is_off ? 0
                                                    : cf->args->nelts - 1,
                                                         sizeof(ngx_str_t));
        if (lcf->directory.trusted_agents == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (is_off) {
        return NGX_CONF_OK;
    }

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_auth_httpsig_directory_normalize_host(cf->pool, &value[i],
                                                      &normalized, &reason)
            != NGX_OK)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_httpsig: invalid host \"%V\" in "
                               "\"auth_httpsig_trusted_agent\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        entry = ngx_array_push(lcf->directory.trusted_agents);
        if (entry == NULL) {
            return NGX_CONF_ERROR;
        }

        *entry = normalized;
    }

    mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_auth_httpsig_module);
    mcf->dynamic = 1;

    return NGX_CONF_OK;
}


/*
 * Rejecting "$" is a structural guarantee, not a style preference:
 * unlike auth_httpsig_jwks_file (a startup-time path) or nginx-auth-jwt
 * (which does allow "$var" in its equivalent directive), this URI is
 * used at request time, so a variable here would be the one path by
 * which client-influenced data could reach the internal fetch location.
 * The host is instead threaded through separately, via
 * $httpsig_directory_host.
 */
static char *
ngx_http_auth_httpsig_set_key_directory_request(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_httpsig_loc_conf_t *lcf = conf;
    ngx_str_t *value;
    ngx_uint_t i;

    if (lcf->directory.request_uri.len) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len == 0 || value[1].data[0] != '/') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_httpsig: \"auth_httpsig_key_directory_request\" "
                           "must start with \"/\"");
        return NGX_CONF_ERROR;
    }

    for (i = 0; i < value[1].len; i++) {
        if (value[1].data[i] == '$') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "auth_httpsig: \"auth_httpsig_key_directory_request\" "
                               "must not contain variables");
            return NGX_CONF_ERROR;
        }
    }

    lcf->directory.request_uri = value[1];

    return NGX_CONF_OK;
}


/*
 * "<name>:<size>" follows the same syntax and 8-page floor as
 * limit_req_zone's "zone=" parameter; zone-name collisions across
 * "auth_httpsig_key_cache_zone" and other modules' shared-memory zones
 * are already caught by ngx_shared_memory_add(), so no separate check is
 * needed here.
 */
static char *
ngx_http_auth_httpsig_set_key_cache_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_auth_httpsig_main_conf_t *mcf = conf;
    u_char *p;
    ssize_t size;
    ngx_str_t *value, name, s;
    ngx_shm_zone_t *shm_zone;

    if (mcf->shm_zone) {
        return "is duplicate";
    }

    value = cf->args->elts;

    p = (u_char *) ngx_strchr(value[1].data, ':');
    if (p == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_httpsig: invalid zone size \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    name.data = value[1].data;
    name.len = p - name.data;

    s.data = p + 1;
    s.len = value[1].data + value[1].len - s.data;

    size = ngx_parse_size(&s);
    if (size == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_httpsig: invalid zone size \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    if (size < (ssize_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_httpsig: zone \"%V\" is too small",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_auth_httpsig_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_auth_httpsig_cache_init_zone;

    shm_zone->data = ngx_pcalloc(cf->pool,
                                 sizeof(ngx_auth_httpsig_cache_ctx_t));
    if (shm_zone->data == NULL) {
        return NGX_CONF_ERROR;
    }

    mcf->shm_zone = shm_zone;

    return NGX_CONF_OK;
}


static ngx_table_elt_t *
ngx_http_auth_httpsig_find_header(ngx_list_t *list, const char *name,
    size_t len)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *header;
    ngx_uint_t i;

    part = &list->part;
    header = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].key.len == len
            && ngx_strncasecmp(header[i].key.data, (u_char *) name, len) == 0)
        {
            return &header[i];
        }
    }

    return NULL;
}


/*
 * @scheme must come from the "scheme" variable, not r->schema directly:
 * a map-based rewrite of $scheme (the operator's trust-boundary decision
 * for TLS-terminating load balancers) would otherwise be bypassed.
 */
static ngx_int_t
ngx_http_auth_httpsig_build_request(ngx_http_request_t *r,
    ngx_auth_httpsig_request_t *req)
{
    static ngx_str_t scheme_name = ngx_string("scheme");
    ngx_http_variable_value_t *vv;
    ngx_str_t host;
    u_char *qmark;
    ngx_list_part_t *part;
    ngx_table_elt_t *header;
    ngx_uint_t i, n, p;
    ngx_auth_httpsig_header_t *h;

    static const struct {
        const char *scheme;
        size_t      scheme_len;
        const char *suffix;
        size_t      suffix_len;
    } default_ports[] = {
        { "http",  sizeof("http") - 1, ":80",  sizeof(":80") - 1 },
        { "https", sizeof("https") - 1, ":443", sizeof(":443") - 1 },
    };

    ngx_memzero(req, sizeof(ngx_auth_httpsig_request_t));

    req->method = r->method_name;

    vv = ngx_http_get_variable(r, &scheme_name,
                               ngx_hash_key(scheme_name.data,
                                            scheme_name.len));
    if (vv == NULL || vv->not_found) {
        return NGX_ERROR;
    }

    req->scheme.len = vv->len;
    req->scheme.data = vv->data;

    host = r->headers_in.host ? r->headers_in.host->value
                               : r->headers_in.server;

    req->authority.data = ngx_pnalloc(r->pool, host.len);
    if (req->authority.data == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(req->authority.data, host.data, host.len);
    req->authority.len = host.len;

    for (p = 0; p < sizeof(default_ports) / sizeof(default_ports[0]); p++) {
        if (req->scheme.len == default_ports[p].scheme_len
            && ngx_strncasecmp(req->scheme.data,
                               (u_char *) default_ports[p].scheme,
                               default_ports[p].scheme_len) == 0
            && req->authority.len > default_ports[p].suffix_len
            && ngx_memcmp(req->authority.data
                          + req->authority.len - default_ports[p].suffix_len,
                          default_ports[p].suffix,
                          default_ports[p].suffix_len) == 0)
        {
            req->authority.len -= default_ports[p].suffix_len;
            break;
        }
    }

    req->request_target = r->unparsed_uri;

    if (r->method == NGX_HTTP_CONNECT
        || (r->unparsed_uri.len == 1 && r->unparsed_uri.data[0] == '*'))
    {
        req->target_defined = 0;

    } else {
        req->target_defined = 1;

        qmark = ngx_strlchr(r->unparsed_uri.data,
                            r->unparsed_uri.data + r->unparsed_uri.len, '?');

        if (qmark != NULL) {
            req->has_query = 1;
            req->path.data = r->unparsed_uri.data;
            req->path.len = qmark - r->unparsed_uri.data;
            req->query.data = qmark + 1;
            req->query.len = r->unparsed_uri.data + r->unparsed_uri.len
                             - (qmark + 1);

        } else {
            req->path = r->unparsed_uri;
        }
    }

    n = 0;
    for (part = &r->headers_in.headers.part; part; part = part->next) {
        n += part->nelts;
    }

    req->headers = ngx_array_create(r->pool, n,
                                    sizeof(ngx_auth_httpsig_header_t));
    if (req->headers == NULL) {
        return NGX_ERROR;
    }

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        h = ngx_array_push(req->headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->name.len = header[i].key.len;
        h->name.data = ngx_pnalloc(r->pool, header[i].key.len);
        if (h->name.data == NULL) {
            return NGX_ERROR;
        }

        ngx_strlow(h->name.data, header[i].key.data, header[i].key.len);

        h->value = header[i].value;

        while (h->value.len > 0
               && (h->value.data[0] == ' ' || h->value.data[0] == '\t'))
        {
            h->value.data++;
            h->value.len--;
        }

        while (h->value.len > 0
               && (h->value.data[h->value.len - 1] == ' '
                   || h->value.data[h->value.len - 1] == '\t'))
        {
            h->value.len--;
        }
    }

    return NGX_OK;
}


/*
 * Fail-open helpers for ngx_http_auth_httpsig_directory_handler(): every
 * path that cannot complete the key-directory fetch marks
 * ctx->keys_unavailable (so ngx_http_auth_httpsig_evaluate() later reports
 * KEY_UNAVAILABLE instead of aborting the request) and ctx->directory_done
 * (so the phase engine does not re-enter this handler), then declines.
 */
static ngx_int_t
ngx_http_auth_httpsig_directory_fail_open(ngx_http_auth_httpsig_ctx_t *ctx,
    ngx_auth_httpsig_fetch_reason_t reason)
{
    ctx->keys_unavailable = 1;
    ctx->directory_reason = reason;
    ctx->directory_done = 1;

    return NGX_DECLINED;
}


/*
 * Same as above, but for the paths that already hold the SHM fetch right
 * (ctx->claimed) and must release it first. ctx->claimed is cleared
 * before cache_release() runs so that
 * ngx_http_auth_httpsig_directory_cleanup(), which checks claimed to
 * avoid a double release, does not also release this host.
 */
static ngx_int_t
ngx_http_auth_httpsig_directory_fail_open_release(
    ngx_http_auth_httpsig_ctx_t *ctx, ngx_auth_httpsig_cache_ctx_t *cache,
    time_t retry_ttl, ngx_auth_httpsig_fetch_reason_t reason)
{
    ctx->claimed = 0;
    ngx_auth_httpsig_cache_release(cache, &ctx->directory_host,
                                   ngx_time() + retry_ttl);

    return ngx_http_auth_httpsig_directory_fail_open(ctx, reason);
}


/*
 * Lazily evaluates the request against the configured profile, at most
 * once per request: the ctx is allocated and done=1 is set before any
 * other work, so re-entrancy (this being called again while it is
 * already running) is structurally impossible.
 *
 * Steps up to selecting a tag-matching Signature-Input label are
 * fail-open ("not signed", ctx->result stays NOT_SIGNED); every step
 * after that is fail-closed (an ordinary declined result). Internal
 * errors also fail open rather than aborting the request: this module
 * verifies an optional signature, it never causes a 500.
 */
/*
 * r != r->main is checked first, before anything else: the fetch
 * subrequest issued below runs through this same phase, and without this
 * guard it would recurse into itself. ctx is created (but never marked
 * done) as soon as Signature-Input/Signature-Agent are both present, so
 * ngx_http_auth_httpsig_evaluate() -- which may run first if some other
 * module reads $httpsig_* earlier in the phase chain -- can tell "not yet
 * evaluated" (ctx present, done == 0) from "no ctx at all".
 *
 * Returns NGX_AGAIN only once a fetch subrequest has actually been
 * posted; every other outcome (disabled, not eligible, cache hit/miss,
 * allocation failure) is NGX_DECLINED, per this module's fail-open
 * design -- a directory fetch that cannot happen simply leaves
 * ctx->keys_unavailable set, which ngx_http_auth_httpsig_evaluate() later
 * turns into NGX_AUTH_HTTPSIG_RESULT_KEY_UNAVAILABLE instead of aborting
 * the request.
 */
static ngx_int_t
ngx_http_auth_httpsig_directory_handler(ngx_http_request_t *r)
{
    ngx_http_auth_httpsig_loc_conf_t *lcf;
    ngx_http_auth_httpsig_main_conf_t *mcf;
    ngx_http_auth_httpsig_ctx_t *ctx;
    ngx_auth_httpsig_cache_ctx_t *cache;
    ngx_http_auth_httpsig_directory_cleanup_t *cln_data;
    ngx_pool_cleanup_t *cln;
    ngx_http_post_subrequest_t *ps;
    ngx_http_request_t *sr;
    ngx_table_elt_t *sig_input, *sig_agent;
    ngx_str_t agent_host, host, jwks;
    ngx_auth_httpsig_host_reason_t host_reason;
    ngx_auth_httpsig_cache_status_t status;
    time_t retry_ttl;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_httpsig_module);

    if (lcf->mode == NGX_HTTP_AUTH_HTTPSIG_MODE_OFF
        || !lcf->directory.enabled)
    {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_httpsig_module);

    if (ctx != NULL) {
        if (ctx->directory_done) {
            return NGX_DECLINED;
        }

        if (ctx->claimed) {
            /* the fetch subrequest is still in flight; this is a
             * spurious re-entry, not the normal post-subrequest resume
             * (that path always sets directory_done before returning
             * control to the phase engine). */
            return NGX_AGAIN;
        }

        if (ctx->done) {
            /* $httpsig_* was already evaluated by something earlier in
             * the phase chain; a fetch now would never be consumed. */
            ctx->directory_done = 1;
            return NGX_DECLINED;
        }

    } else {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_httpsig_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_auth_httpsig_module);
    }

    sig_input = ngx_http_auth_httpsig_find_header(&r->headers_in.headers,
                                                  "signature-input",
                                                  sizeof("signature-input") -
                                                  1);
    sig_agent = ngx_http_auth_httpsig_find_header(&r->headers_in.headers,
                                                  "signature-agent",
                                                  sizeof("signature-agent") -
                                                  1);

    if (sig_input == NULL || sig_agent == NULL) {
        /* Signature-Agent alone must not trigger a fetch: an
         * unauthenticated client could otherwise use it to amplify
         * traffic toward an allow-listed host. */
        ctx->directory_done = 1;
        return NGX_DECLINED;
    }

    ngx_auth_httpsig_profile_agent_authority(r->pool, &sig_agent->value,
                                             &agent_host);

    if (agent_host.len == 0
        || ngx_auth_httpsig_directory_normalize_host(r->pool, &agent_host,
                                                     &host, &host_reason)
        != NGX_OK
        || !ngx_auth_httpsig_directory_allowed(lcf->directory.trusted_agents,
                                               &host))
    {
        return ngx_http_auth_httpsig_directory_fail_open(ctx,
                                                         NGX_AUTH_HTTPSIG_FETCH_NOT_ALLOWED);
    }

    ctx->directory_host = host;

    mcf = ngx_http_get_module_main_conf(r, ngx_http_auth_httpsig_module);
    cache = mcf->shm_zone->data;

    if (ngx_auth_httpsig_cache_lookup(cache, r->pool, &host, ngx_time(),
                                      &jwks, &status,
                                      &ctx->directory_generation)
        != NGX_OK)
    {
        return ngx_http_auth_httpsig_directory_fail_open(ctx,
                                                         NGX_AUTH_HTTPSIG_FETCH_FAILED);
    }

    switch (status) {

    case NGX_AUTH_HTTPSIG_CACHE_HIT:
        /* Parsing is deferred to evaluate(), which resolves ctx->jwks
         * through the worker-local parse cache keyed on
         * ctx->directory_generation instead of reparsing it here on
         * every request. */
        ctx->jwks = jwks;
        ctx->directory_done = 1;
        return NGX_DECLINED;

    case NGX_AUTH_HTTPSIG_CACHE_BUSY:
        return ngx_http_auth_httpsig_directory_fail_open(ctx,
                                                         NGX_AUTH_HTTPSIG_FETCH_BUSY);

    case NGX_AUTH_HTTPSIG_CACHE_NEGATIVE:
        return ngx_http_auth_httpsig_directory_fail_open(ctx,
                                                         NGX_AUTH_HTTPSIG_FETCH_UNAVAILABLE);

    case NGX_AUTH_HTTPSIG_CACHE_UNAVAILABLE:
        return ngx_http_auth_httpsig_directory_fail_open(ctx,
                                                         NGX_AUTH_HTTPSIG_FETCH_UNAVAILABLE);

    default: /* NGX_AUTH_HTTPSIG_CACHE_CLAIMED */
        break;
    }

    /* This worker now holds the SHM fetch right for host and must
     * eventually call cache_store() or cache_release(). The pool
     * cleanup backstop is registered before anything else below can
     * fail, so any failure from here on still releases the right
     * instead of leaving host BUSY until the cache entry ages out. */
    ctx->claimed = 1;
    retry_ttl = lcf->directory.cache_min_ttl;

    cln = ngx_pool_cleanup_add(r->pool,
                               sizeof(ngx_http_auth_httpsig_directory_cleanup_t));
    if (cln == NULL) {
        return ngx_http_auth_httpsig_directory_fail_open_release(ctx, cache,
                                                                 retry_ttl,
                                                                 NGX_AUTH_HTTPSIG_FETCH_FAILED);
    }

    cln->handler = ngx_http_auth_httpsig_directory_cleanup;
    cln_data = cln->data;
    cln_data->ctx = ctx;
    cln_data->cache = cache;
    cln_data->host = host;
    cln_data->retry_ttl = retry_ttl;

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return ngx_http_auth_httpsig_directory_fail_open_release(ctx, cache,
                                                                 retry_ttl,
                                                                 NGX_AUTH_HTTPSIG_FETCH_FAILED);
    }

    ps->handler = ngx_http_auth_httpsig_directory_done;
    ps->data = ctx;

    if (ngx_http_subrequest(r, &lcf->directory.request_uri, NULL, &sr, ps,
                            NGX_HTTP_SUBREQUEST_IN_MEMORY
                            | NGX_HTTP_SUBREQUEST_WAITED)
        != NGX_OK)
    {
        return ngx_http_auth_httpsig_directory_fail_open_release(ctx, cache,
                                                                 retry_ttl,
                                                                 NGX_AUTH_HTTPSIG_FETCH_FAILED);
    }

    /* From here on the subrequest is posted and its post_subrequest
     * handler will run to completion (releasing the fetch right and
     * setting directory_done) regardless of what happens next in this
     * function, so every remaining failure mode falls through to
     * NGX_AGAIN rather than declining. */

    sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));

    return NGX_AGAIN;
}


/*
 * post_subrequest handler for the key-directory fetch. Classifies the
 * response, copies out what is needed before the subrequest's pool is
 * torn down, loads it into a keyset on success, and always releases the
 * SHM fetch right claimed by ngx_http_auth_httpsig_directory_handler()
 * before returning -- this is the only ordinary (non-backstop) release
 * path.
 *
 * sr->upstream->schema is "<scheme>://" (e.g. "https://"), while
 * ngx_auth_httpsig_directory_check_response() expects a bare scheme (e.g.
 * "https"); the trailing "://" is stripped before the call.
 *
 * The response body lands in sr->out->buf (a single link), not in
 * sr->upstream->buffer -- NGX_HTTP_SUBREQUEST_IN_MEMORY routes output
 * through ngx_http_postpone_filter_in_memory(), which accumulates into
 * the subrequest's own output chain.
 */
static ngx_int_t
ngx_http_auth_httpsig_directory_done(ngx_http_request_t *sr, void *data,
    ngx_int_t rc)
{
    ngx_http_auth_httpsig_ctx_t *ctx = data;
    ngx_http_auth_httpsig_loc_conf_t *lcf;
    ngx_http_auth_httpsig_main_conf_t *mcf;
    ngx_http_core_loc_conf_t *clcf;
    ngx_auth_httpsig_cache_ctx_t *cache;
    ngx_str_t schema, content_type, body, cache_control;
    ngx_table_elt_t *h, *age_header;
    ngx_uint_t status;
    time_t now, age, ttl;
    size_t len;
    u_char *p;
    ngx_flag_t accepted;
    ngx_auth_httpsig_fetch_reason_t reason;
    ngx_auth_httpsig_keys_t *validated;

    lcf = ngx_http_get_module_loc_conf(sr, ngx_http_auth_httpsig_module);
    mcf = ngx_http_get_module_main_conf(sr, ngx_http_auth_httpsig_module);
    cache = mcf->shm_zone->data;

    /* sr's location is resolved by now (its own phase engine ran the
     * find-config phase before this post_subrequest handler fires), so
     * clcf reflects the fetch location's own directive, not the
     * requesting location's. */
    clcf = ngx_http_get_module_loc_conf(sr, ngx_http_core_module);

    if (clcf->subrequest_output_buffer_size < lcf->directory.max_size) {
        ngx_log_error(NGX_LOG_WARN, sr->connection->log, 0,
                      "auth_httpsig: \"subrequest_output_buffer_size\" "
                      "(%uz) in \"%V\" is below "
                      "\"auth_httpsig_key_directory_max_size\" (%uz); "
                      "nginx will reject a larger key-directory response "
                      "before this module sees it",
                      clcf->subrequest_output_buffer_size,
                      &lcf->directory.request_uri, lcf->directory.max_size);
    }

    accepted = 0;
    ngx_str_null(&body);
    ngx_str_null(&cache_control);
    age = 0;

    if (rc == NGX_OK && sr->upstream != NULL) {
        schema = sr->upstream->schema;

        if (schema.len >= 3
            && ngx_memcmp(schema.data + schema.len - 3, "://", 3) == 0)
        {
            schema.len -= 3;
        }

        status = sr->headers_out.status;

        content_type.len = 0;
        content_type.data = NULL;

        if (sr->headers_out.content_type.len) {
            content_type = sr->headers_out.content_type;
        }

        if (sr->out != NULL) {
            body.data = sr->out->buf->pos;
            body.len = sr->out->buf->last - sr->out->buf->pos;
        }

        if (sr->upstream->headers_in.cache_control != NULL) {
            len = 0;

            for (h = sr->upstream->headers_in.cache_control; h != NULL;
                 h = h->next)
            {
                len += h->value.len + (h->next != NULL ? 2 : 0);
            }

            p = ngx_pnalloc(sr->parent->pool, len);

            if (p != NULL) {
                cache_control.data = p;

                for (h = sr->upstream->headers_in.cache_control; h != NULL;
                     h = h->next)
                {
                    p = ngx_cpymem(p, h->value.data, h->value.len);

                    if (h->next != NULL) {
                        *p++ = ',';
                        *p++ = ' ';
                    }
                }

                cache_control.len = p - cache_control.data;
            }
        }

        age_header = ngx_http_auth_httpsig_find_header(
            &sr->upstream->headers_in.headers, "age", sizeof("age") - 1);

        if (age_header != NULL) {
            age = ngx_atotm(age_header->value.data, age_header->value.len);

            if (age == (time_t) NGX_ERROR) {
                age = 0;
            }
        }

        if (ngx_auth_httpsig_directory_check_response(&schema, status,
                                                      &content_type,
                                                      &lcf->profile.def->
                                                      directory_media_type,
                                                      body.len,
                                                      lcf->directory.max_size,
                                                      &reason)
            == NGX_OK)
        {
            accepted = 1;

        } else {
            ngx_log_error(NGX_LOG_INFO, sr->connection->log, 0,
                          "auth_httpsig: key directory fetch for \"%V\" "
                          "rejected, reason=%s, status=%ui",
                          &ctx->directory_host,
                          ngx_auth_httpsig_directory_reason_name(reason),
                          status);
        }

    } else {
        reason = NGX_AUTH_HTTPSIG_FETCH_FAILED;

        ngx_log_error(NGX_LOG_INFO, sr->connection->log, 0,
                      "auth_httpsig: key directory fetch for \"%V\" "
                      "failed, rc=%i", &ctx->directory_host, rc);
    }

    now = ngx_time();

    if (accepted) {
        ctx->jwks.data = ngx_pnalloc(sr->parent->pool, body.len);

        if (ctx->jwks.data != NULL) {
            ngx_memcpy(ctx->jwks.data, body.data, body.len);
            ctx->jwks.len = body.len;

            /* Parsed here only to gate the SHM store against a
             * malformed document; the parsed keyset itself is
             * discarded -- evaluate() re-resolves ctx->jwks through
             * the worker-local parse cache, keyed on the generation
             * cache_store() assigns below, rather than reusing this
             * pointer (see ngx_http_auth_httpsig_resolve_keys()). */
            if (ngx_auth_httpsig_keys_load_jwks(sr->parent->pool, &ctx->jwks,
                                                &ctx->directory_host,
                                                NGX_LOG_WARN, &validated)
                == NGX_OK)
            {
                ttl = ngx_auth_httpsig_directory_ttl(&cache_control, age,
                                                     lcf->directory.
                                                     cache_min_ttl,
                                                     lcf->directory.
                                                     cache_max_ttl);

                ngx_auth_httpsig_cache_store(cache, &ctx->directory_host,
                                             &ctx->jwks, now + ttl,
                                             &ctx->directory_generation);

            } else {
                accepted = 0;
                reason = NGX_AUTH_HTTPSIG_FETCH_INVALID;
            }

        } else {
            accepted = 0;
            reason = NGX_AUTH_HTTPSIG_FETCH_FAILED;
        }
    }

    if (!accepted) {
        ctx->keys_unavailable = 1;
        ctx->directory_reason = reason;
        ngx_auth_httpsig_cache_release(cache, &ctx->directory_host,
                                       now + lcf->directory.cache_min_ttl);
    }

    ctx->claimed = 0;
    ctx->directory_done = 1;

    return NGX_OK;
}


/*
 * Backstop for ngx_http_auth_httpsig_directory_handler(): runs whenever
 * r->pool is destroyed, whether or not
 * ngx_http_auth_httpsig_directory_done() ran to completion first. If
 * ctx->claimed is still set here, the ordinary release path never ran
 * (client abort, worker shutdown mid-fetch, ...), so this releases the
 * SHM fetch right for host instead of leaving it stuck BUSY until some
 * other worker's fetching_since staleness check reclaims it.
 */
static void
ngx_http_auth_httpsig_directory_cleanup(void *data)
{
    ngx_http_auth_httpsig_directory_cleanup_t *cln = data;

    if (cln->ctx->claimed) {
        cln->ctx->claimed = 0;
        ngx_auth_httpsig_cache_release(cln->cache, &cln->host,
                                       ngx_time() + cln->retry_ttl);
    }
}


/*
 * Resolves ctx->jwks -- the key-directory document the PREACCESS phase
 * handler fetched or found cached, identified only by bytes and SHM
 * generation -- into a parsed keyset for this request. Prefers the
 * worker-local parse cache (mcf->local_keys) over reparsing, falling
 * back to a direct parse into r->pool when the cache is unavailable or
 * generation is 0 (dynamic directory not enabled, or nothing fetched).
 *
 * The returned pointer is borrowed from either mcf->local_keys or
 * r->pool; ngx_http_auth_httpsig_evaluate() uses it up synchronously in
 * its call into ngx_auth_httpsig_profile_verify() and never stores it
 * in ctx, so no reference to worker-local memory survives past this
 * call chain (see ngx_auth_httpsig_keys_cache.c's module comment for
 * why that matters).
 *
 * Returns NULL if ctx->jwks is empty (nothing was fetched) or the
 * document could not be parsed at all.
 */
static ngx_auth_httpsig_keys_t *
ngx_http_auth_httpsig_resolve_keys(ngx_http_request_t *r,
    ngx_http_auth_httpsig_ctx_t *ctx)
{
    ngx_http_auth_httpsig_main_conf_t *mcf;
    ngx_auth_httpsig_keys_t *keys;

    if (ctx->jwks.len == 0) {
        return NULL;
    }

    mcf = ngx_http_get_module_main_conf(r, ngx_http_auth_httpsig_module);

    if (mcf->local_keys != NULL && ctx->directory_generation != 0) {
        keys = ngx_auth_httpsig_keys_cache_get(mcf->local_keys,
                                               &ctx->directory_host,
                                               ctx->directory_generation);
        if (keys != NULL) {
            return keys;
        }

        if (ngx_auth_httpsig_keys_cache_put(mcf->local_keys,
                                            &ctx->directory_host, &ctx->jwks,
                                            ctx->directory_generation,
                                            r->connection->log, &keys)
            == NGX_OK)
        {
            return keys;
        }
    }

    if (ngx_auth_httpsig_keys_load_jwks(r->pool, &ctx->jwks,
                                        &ctx->directory_host, NGX_LOG_WARN,
                                        &keys)
        != NGX_OK)
    {
        return NULL;
    }

    return keys;
}


static ngx_int_t
ngx_http_auth_httpsig_evaluate(ngx_http_request_t *r,
    ngx_http_auth_httpsig_ctx_t **out)
{
    ngx_http_auth_httpsig_loc_conf_t *lcf;
    ngx_http_auth_httpsig_ctx_t *ctx;
    ngx_auth_httpsig_request_t req;
    ngx_auth_httpsig_signature_t sig;
    ngx_auth_httpsig_profile_ctx_t pctx;
    ngx_auth_httpsig_result_t result;
    ngx_auth_httpsig_keys_t *dynamic_keys;
    ngx_int_t rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_httpsig_module);

    if (lcf->mode == NGX_HTTP_AUTH_HTTPSIG_MODE_OFF) {
        *out = NULL;
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_httpsig_module);

    if (ctx != NULL && ctx->done) {
        *out = ctx;
        return NGX_OK;
    }

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_httpsig_ctx_t));
        if (ctx == NULL) {
            *out = NULL;
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_auth_httpsig_module);
    }

    ctx->done = 1;
    ctx->result = NGX_AUTH_HTTPSIG_RESULT_NOT_SIGNED;
    *out = ctx;

    if (ngx_http_auth_httpsig_find_header(&r->headers_in.headers,
                                          "signature-input",
                                          sizeof("signature-input") - 1)
        == NULL)
    {
        return NGX_OK;
    }

    if (ngx_http_auth_httpsig_build_request(r, &req) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_httpsig: failed to build the request snapshot");
        ctx->internal_error = 1;
        return NGX_OK;
    }

    ngx_memzero(&sig, sizeof(ngx_auth_httpsig_signature_t));

    pctx.profile = lcf->profile.def;

    dynamic_keys = ngx_http_auth_httpsig_resolve_keys(r, ctx);

    if (dynamic_keys == NULL && ctx->jwks.len != 0) {
        ctx->keys_unavailable = 1;
        ctx->directory_reason = NGX_AUTH_HTTPSIG_FETCH_INVALID;
    }

    pctx.keys = ngx_auth_httpsig_keys_chain(r->pool, dynamic_keys,
                                            lcf->jwks.keys);

    pctx.expires_max = lcf->profile.expires_max;
    pctx.max_skew = lcf->profile.max_skew;
    pctx.now = 0;

    rc = ngx_auth_httpsig_profile_verify(r->pool, &pctx, &req, &sig, &result);

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_httpsig: verification failed internally");
        ctx->internal_error = 1;
        return NGX_OK;
    }

    if (result == NGX_AUTH_HTTPSIG_RESULT_UNKNOWN_KEYID
        && ctx->keys_unavailable)
    {
        result = NGX_AUTH_HTTPSIG_RESULT_KEY_UNAVAILABLE;
    }

    ctx->result = result;

    if (result != NGX_AUTH_HTTPSIG_RESULT_OK
        && result != NGX_AUTH_HTTPSIG_RESULT_NOT_SIGNED)
    {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "auth_httpsig: verification declined: %s, "
                      "keyid=\"%V\", tag=\"%V\"",
                      ngx_auth_httpsig_result_name(result), &sig.keyid,
                      &sig.tag);
    }

    if (result == NGX_AUTH_HTTPSIG_RESULT_OK) {
        ctx->keyid = sig.keyid;
        ctx->agent = sig.agent_host;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_httpsig_variable_verified(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_auth_httpsig_ctx_t *ctx;

    if (ngx_http_auth_httpsig_evaluate(r, &ctx) != NGX_OK || ctx == NULL
        || ctx->result == NGX_AUTH_HTTPSIG_RESULT_NOT_SIGNED
        || ctx->result == NGX_AUTH_HTTPSIG_RESULT_KEY_UNAVAILABLE)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = (ctx->result == NGX_AUTH_HTTPSIG_RESULT_OK)
              ? (u_char *) "1" : (u_char *) "0";
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_httpsig_variable_keyid(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_auth_httpsig_ctx_t *ctx;

    if (ngx_http_auth_httpsig_evaluate(r, &ctx) != NGX_OK || ctx == NULL
        || ctx->result != NGX_AUTH_HTTPSIG_RESULT_OK)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->keyid.data;
    v->len = ctx->keyid.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_httpsig_variable_agent(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_auth_httpsig_ctx_t *ctx;

    if (ngx_http_auth_httpsig_evaluate(r, &ctx) != NGX_OK || ctx == NULL
        || ctx->result != NGX_AUTH_HTTPSIG_RESULT_OK
        || ctx->agent.len == 0)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->agent.data;
    v->len = ctx->agent.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


/*
 * Reads r->main's ctx, not r's: a subrequest shares its parent's
 * r->variables array (ngx_http_subrequest() sets sr->variables =
 * r->variables) but gets a fresh, pcalloc'd sr->ctx, so the internal
 * fetch location's proxy_set_header/proxy_pass -- which evaluate this
 * variable on the subrequest -- would otherwise always see it unset.
 *
 * Deliberately does not call ngx_http_auth_httpsig_evaluate(): doing so
 * would run signature verification while a directory-fetch subrequest
 * is in flight, breaking the lazy-evaluation premise that evaluate()
 * runs at most once per (main) request.
 */
static ngx_int_t
ngx_http_auth_httpsig_variable_directory_host(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_auth_httpsig_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r->main, ngx_http_auth_httpsig_module);

    if (ctx == NULL || ctx->directory_host.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->directory_host.data;
    v->len = ctx->directory_host.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


/*
 * A single lowercase token, distinct from $httpsig_verified (which stays
 * pinned to "1"/"0"/unset for fail-open compatibility, ADR 0016):
 * internal errors and directory-fetch failures both leave ctx->result at
 * NOT_SIGNED or KEY_UNAVAILABLE, so this reads ctx->internal_error and
 * ctx->directory_reason to recover the finer-grained reason.
 */
static ngx_int_t
ngx_http_auth_httpsig_variable_error(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_auth_httpsig_ctx_t *ctx;
    const char *name;

    if (ngx_http_auth_httpsig_evaluate(r, &ctx) != NGX_OK || ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ctx->internal_error) {
        name = "internal";

    } else if (ctx->result == NGX_AUTH_HTTPSIG_RESULT_OK
               || ctx->result == NGX_AUTH_HTTPSIG_RESULT_NOT_SIGNED)
    {
        v->not_found = 1;
        return NGX_OK;

    } else if (ctx->result == NGX_AUTH_HTTPSIG_RESULT_KEY_UNAVAILABLE
               && ctx->directory_reason != NGX_AUTH_HTTPSIG_FETCH_OK)
    {
        name = ngx_auth_httpsig_directory_reason_name(ctx->directory_reason);

    } else {
        name = ngx_auth_httpsig_result_name(ctx->result);
    }

    v->data = (u_char *) name;
    v->len = ngx_strlen(name);
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}
