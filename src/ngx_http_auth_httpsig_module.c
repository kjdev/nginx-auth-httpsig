/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_auth_httpsig_base.h"
#include "ngx_auth_httpsig_directory.h"
#include "ngx_auth_httpsig_keys.h"
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
    ngx_shm_zone_t *shm_zone;
    ngx_flag_t      dynamic; /* true if the dynamic key directory is
                              * enabled anywhere in the whole config */
} ngx_http_auth_httpsig_main_conf_t;

/* done == 1 means "already evaluated this request" (memoizes evaluation
 * across the get_handler calls of the $httpsig_* variables); keyid/agent
 * are only ever set from the RESULT_OK branch of
 * ngx_http_auth_httpsig_evaluate(), so a failed verification always
 * leaves them empty. directory_host is set by the dynamic key-directory
 * phase handler, not by evaluate(). */
typedef struct {
    unsigned                   done:1;
    ngx_auth_httpsig_result_t  result;
    ngx_str_t                  keyid;
    ngx_str_t                  agent;
    ngx_str_t                  directory_host;
} ngx_http_auth_httpsig_ctx_t;


static ngx_int_t ngx_http_auth_httpsig_add_variables(ngx_conf_t *cf);
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
static void ngx_http_auth_httpsig_cleanup_keys(void *data);

static ngx_int_t ngx_http_auth_httpsig_variable_verified(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_auth_httpsig_variable_keyid(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_auth_httpsig_variable_agent(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_auth_httpsig_variable_directory_host(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_auth_httpsig_evaluate(ngx_http_request_t *r,
    ngx_http_auth_httpsig_ctx_t **out);
static ngx_table_elt_t *ngx_http_auth_httpsig_find_header(
    ngx_http_request_t *r, const char *name, size_t len);
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

    ngx_null_command
};


static ngx_http_module_t ngx_http_auth_httpsig_module_ctx = {
    ngx_http_auth_httpsig_add_variables,    /* preconfiguration */
    NULL,                                   /* postconfiguration */

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
    NULL,                                  /* init process */
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
                                        &lcf->jwks.keys) != NGX_OK)
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


static ngx_table_elt_t *
ngx_http_auth_httpsig_find_header(ngx_http_request_t *r, const char *name,
    size_t len)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *header;
    ngx_uint_t i;

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
    ngx_uint_t i, n;
    ngx_auth_httpsig_header_t *h;

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

    if (req->scheme.len == sizeof("http") - 1
        && ngx_strncasecmp(req->scheme.data, (u_char *) "http",
                           sizeof("http") - 1) == 0
        && req->authority.len > sizeof(":80") - 1
        && ngx_memcmp(req->authority.data
                      + req->authority.len - (sizeof(":80") - 1),
                      ":80", sizeof(":80") - 1) == 0)
    {
        req->authority.len -= sizeof(":80") - 1;

    } else if (req->scheme.len == sizeof("https") - 1
               && ngx_strncasecmp(req->scheme.data, (u_char *) "https",
                                  sizeof("https") - 1) == 0
               && req->authority.len > sizeof(":443") - 1
               && ngx_memcmp(req->authority.data
                             + req->authority.len - (sizeof(":443") - 1),
                             ":443", sizeof(":443") - 1) == 0)
    {
        req->authority.len -= sizeof(":443") - 1;
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
    ngx_int_t rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_httpsig_module);

    if (lcf->mode == NGX_HTTP_AUTH_HTTPSIG_MODE_OFF) {
        *out = NULL;
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_httpsig_module);
    if (ctx != NULL) {
        *out = ctx;
        return NGX_OK;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_httpsig_ctx_t));
    if (ctx == NULL) {
        *out = NULL;
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_auth_httpsig_module);

    ctx->done = 1;
    ctx->result = NGX_AUTH_HTTPSIG_RESULT_NOT_SIGNED;
    *out = ctx;

    if (ngx_http_auth_httpsig_find_header(r, "signature-input",
                                          sizeof("signature-input") - 1)
        == NULL)
    {
        return NGX_OK;
    }

    if (ngx_http_auth_httpsig_build_request(r, &req) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_httpsig: failed to build the request snapshot");
        return NGX_OK;
    }

    ngx_memzero(&sig, sizeof(ngx_auth_httpsig_signature_t));

    pctx.profile = lcf->profile.def;
    pctx.keys = lcf->jwks.keys;
    pctx.expires_max = lcf->profile.expires_max;
    pctx.max_skew = lcf->profile.max_skew;
    pctx.now = 0;

    rc = ngx_auth_httpsig_profile_verify(r->pool, &pctx, &req, &sig, &result);

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_httpsig: verification failed internally");
        return NGX_OK;
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
        || ctx->result == NGX_AUTH_HTTPSIG_RESULT_NOT_SIGNED)
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
