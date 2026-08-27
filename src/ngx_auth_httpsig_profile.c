/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_auth_httpsig_profile.c - implements the profile table and the
 * step-by-step judgment that matches a request against it (tag
 * selection, required parameters/components, time window, signature
 * verification).
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_profile.h"
#include "ngx_auth_httpsig_str.h"


#define NGX_AUTH_HTTPSIG_NELTS(a)  (sizeof(a) / sizeof((a)[0]))


static const ngx_auth_httpsig_profile_t ngx_auth_httpsig_profiles[] = {

    {
        ngx_string("web-bot-auth"),
        ngx_string("web-bot-auth"),
        NGX_AUTH_HTTPSIG_PARAM_CREATED | NGX_AUTH_HTTPSIG_PARAM_EXPIRES
        | NGX_AUTH_HTTPSIG_PARAM_KEYID | NGX_AUTH_HTTPSIG_PARAM_TAG,
        NGX_AUTH_HTTPSIG_COMP_TARGET_URI | NGX_AUTH_HTTPSIG_COMP_AUTHORITY,
        0,
        1,
        86400,
        60,
        ngx_string("ed25519"),
        ngx_string("/.well-known/http-message-signatures-directory"),
        ngx_string("application/http-message-signatures-directory+json")
    }

};


/* Maps a covered-component identifier to the bit it sets in
 * ngx_auth_httpsig_signature_t.covered. Components with no bit (an
 * arbitrary HTTP field) simply never match this table. */
static const struct {
    ngx_str_t   name;
    ngx_uint_t  bit;
} ngx_auth_httpsig_profile_components[] = {

    { ngx_string("@method"),          NGX_AUTH_HTTPSIG_COMP_METHOD },
    { ngx_string("@target-uri"),      NGX_AUTH_HTTPSIG_COMP_TARGET_URI },
    { ngx_string("@authority"),       NGX_AUTH_HTTPSIG_COMP_AUTHORITY },
    { ngx_string("@scheme"),          NGX_AUTH_HTTPSIG_COMP_SCHEME },
    { ngx_string("@request-target"),  NGX_AUTH_HTTPSIG_COMP_REQUEST_TARGET },
    { ngx_string("@path"),            NGX_AUTH_HTTPSIG_COMP_PATH },
    { ngx_string("@query"),           NGX_AUTH_HTTPSIG_COMP_QUERY },
    { ngx_string("signature-agent"),  NGX_AUTH_HTTPSIG_COMP_SIGNATURE_AGENT }

};


static ngx_auth_httpsig_sfv_dict_entry_t *ngx_auth_httpsig_profile_select(
    const ngx_auth_httpsig_sfv_dictionary_t *dict, const ngx_str_t *tag);
static ngx_int_t ngx_auth_httpsig_profile_extract_params(
    const ngx_array_t *params, ngx_auth_httpsig_signature_t *sig);
static ngx_uint_t ngx_auth_httpsig_profile_covered_components(
    const ngx_array_t *items);
static ngx_int_t ngx_auth_httpsig_profile_agent_bounds(ngx_pool_t *pool,
    const ngx_str_t *raw, u_char **host_start, u_char **host_end,
    u_char **authority_end);
static void ngx_auth_httpsig_profile_agent_copy(ngx_pool_t *pool,
    u_char *start, u_char *end, ngx_str_t *out);


const ngx_auth_httpsig_profile_t *
ngx_auth_httpsig_profile_get(const ngx_str_t *name)
{
    ngx_uint_t i;

    if (name == NULL) {
        return NULL;
    }

    for (i = 0; i < NGX_AUTH_HTTPSIG_NELTS(ngx_auth_httpsig_profiles); i++) {
        if (ngx_auth_httpsig_str_eq(&ngx_auth_httpsig_profiles[i].name, name)) {
            return &ngx_auth_httpsig_profiles[i];
        }
    }

    return NULL;
}


ngx_int_t
ngx_auth_httpsig_profile_match(const ngx_auth_httpsig_profile_t *profile,
    const ngx_auth_httpsig_signature_t *sig,
    ngx_auth_httpsig_result_t *result)
{
    if (profile == NULL || sig == NULL || result == NULL) {
        return NGX_ERROR;
    }

    if ((sig->present & profile->required_params) != profile->required_params) {
        *result = NGX_AUTH_HTTPSIG_RESULT_PROFILE_MISMATCH;
        return NGX_DECLINED;
    }

    if ((sig->present & NGX_AUTH_HTTPSIG_PARAM_ALG) && profile->alg.len > 0
        && (sig->alg.len != profile->alg.len
            || ngx_strncasecmp(sig->alg.data, profile->alg.data,
                               profile->alg.len)
            != 0))
    {
        *result = NGX_AUTH_HTTPSIG_RESULT_PROFILE_MISMATCH;
        return NGX_DECLINED;
    }

    if (profile->any_of_components != 0
        && (sig->covered & profile->any_of_components) == 0)
    {
        *result = NGX_AUTH_HTTPSIG_RESULT_PROFILE_MISMATCH;
        return NGX_DECLINED;
    }

    if ((sig->covered & profile->all_of_components)
        != profile->all_of_components)
    {
        *result = NGX_AUTH_HTTPSIG_RESULT_PROFILE_MISMATCH;
        return NGX_DECLINED;
    }

    *result = NGX_AUTH_HTTPSIG_RESULT_OK;
    return NGX_OK;
}


ngx_int_t
ngx_auth_httpsig_profile_verify(ngx_pool_t *pool,
    const ngx_auth_httpsig_profile_ctx_t *pctx,
    const ngx_auth_httpsig_request_t *req,
    ngx_auth_httpsig_signature_t *sig, ngx_auth_httpsig_result_t *result)
{
    static const ngx_str_t signature_input_name
        = ngx_string("signature-input");
    static const ngx_str_t signature_name = ngx_string("signature");
    static const ngx_str_t signature_agent_name
        = ngx_string("signature-agent");

    const ngx_auth_httpsig_profile_t *profile;
    ngx_auth_httpsig_sfv_dictionary_t *input_dict, *sig_dict;
    ngx_auth_httpsig_sfv_dict_entry_t *entry;
    const ngx_auth_httpsig_sfv_value_t *sig_value;
    ngx_auth_httpsig_base_reason_t base_reason;
    ngx_str_t input_raw, sig_raw, base, agent_raw;
    ngx_int_t rc;
    ngx_flag_t agent_present;
    time_t now;

    if (pool == NULL || pctx == NULL || pctx->profile == NULL || req == NULL
        || sig == NULL || result == NULL)
    {
        return NGX_ERROR;
    }

    profile = pctx->profile;
    ngx_memzero(sig, sizeof(ngx_auth_httpsig_signature_t));

    /* Step 1: signature-input field present. */
    rc = ngx_auth_httpsig_base_field_value(pool, req, &signature_input_name,
                                           &input_raw);
    if (rc == NGX_DECLINED) {
        *result = NGX_AUTH_HTTPSIG_RESULT_NOT_SIGNED;
        return NGX_DECLINED;
    }
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    /* Step 2: signature field present. */
    rc = ngx_auth_httpsig_base_field_value(pool, req, &signature_name,
                                           &sig_raw);
    if (rc == NGX_DECLINED) {
        *result = NGX_AUTH_HTTPSIG_RESULT_PARSE_ERROR;
        return NGX_DECLINED;
    }
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    /* Step 3: both parse as Dictionaries. */
    rc = ngx_auth_httpsig_sfv_parse_dictionary(pool, &input_raw, &input_dict,
                                               NULL);
    if (rc == NGX_DECLINED) {
        *result = NGX_AUTH_HTTPSIG_RESULT_PARSE_ERROR;
        return NGX_DECLINED;
    }
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    rc = ngx_auth_httpsig_sfv_parse_dictionary(pool, &sig_raw, &sig_dict,
                                               NULL);
    if (rc == NGX_DECLINED) {
        *result = NGX_AUTH_HTTPSIG_RESULT_PARSE_ERROR;
        return NGX_DECLINED;
    }
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    /* Step 4: no duplicate labels in either dictionary. */
    if (input_dict->duplicate_keys || sig_dict->duplicate_keys) {
        *result = NGX_AUTH_HTTPSIG_RESULT_PARSE_ERROR;
        return NGX_DECLINED;
    }

    /* Step 5: first Signature-Input label tagged for this profile. */
    entry = ngx_auth_httpsig_profile_select(input_dict, &profile->tag);
    if (entry == NULL) {
        *result = NGX_AUTH_HTTPSIG_RESULT_NOT_SIGNED;
        return NGX_DECLINED;
    }

    /* Step 6: the selected value is an Inner List. */
    if (entry->value.type != NGX_AUTH_HTTPSIG_SFV_MEMBER_INNER_LIST) {
        *result = NGX_AUTH_HTTPSIG_RESULT_PARSE_ERROR;
        return NGX_DECLINED;
    }

    sig->label = entry->key;
    sig->components = &entry->value.inner_list;

    if (ngx_auth_httpsig_profile_extract_params(entry->value.inner_list.params,
                                                sig)
        != NGX_OK)
    {
        *result = NGX_AUTH_HTTPSIG_RESULT_PARSE_ERROR;
        return NGX_DECLINED;
    }

    sig->covered = ngx_auth_httpsig_profile_covered_components(
        entry->value.inner_list.items);

    /* Steps 7-9: required params, alg, and covered components. */
    if (ngx_auth_httpsig_profile_match(profile, sig, result) != NGX_OK) {
        return NGX_DECLINED;
    }

    /* Step 10: if the request carries Signature-Agent, it must be
     * covered, when the profile requires it. */
    rc = ngx_auth_httpsig_base_field_value(pool, req, &signature_agent_name,
                                           &agent_raw);
    if (rc != NGX_OK && rc != NGX_DECLINED) {
        return NGX_ERROR;
    }

    agent_present = (rc == NGX_OK);

    if (profile->require_agent_covered && agent_present
        && !(sig->covered & NGX_AUTH_HTTPSIG_COMP_SIGNATURE_AGENT))
    {
        *result = NGX_AUTH_HTTPSIG_RESULT_PROFILE_MISMATCH;
        return NGX_DECLINED;
    }

    /* Step 11: time window. */
    now = (pctx->now != 0) ? pctx->now : ngx_time();

    if ((sig->present & NGX_AUTH_HTTPSIG_PARAM_CREATED)
        && sig->created > (int64_t) now + (int64_t) pctx->max_skew)
    {
        *result = NGX_AUTH_HTTPSIG_RESULT_EXPIRED;
        return NGX_DECLINED;
    }

    if (sig->present & NGX_AUTH_HTTPSIG_PARAM_EXPIRES) {
        if (sig->expires < (int64_t) now - (int64_t) pctx->max_skew) {
            *result = NGX_AUTH_HTTPSIG_RESULT_EXPIRED;
            return NGX_DECLINED;
        }

        if ((sig->present & NGX_AUTH_HTTPSIG_PARAM_CREATED)
            && sig->expires - sig->created > (int64_t) pctx->expires_max)
        {
            *result = NGX_AUTH_HTTPSIG_RESULT_EXPIRED;
            return NGX_DECLINED;
        }
    }

    /* Step 12: the matching Signature label is a Byte Sequence. */
    sig_value = ngx_auth_httpsig_sfv_dict_get(sig_dict, &sig->label);
    if (sig_value == NULL
        || sig_value->type != NGX_AUTH_HTTPSIG_SFV_MEMBER_ITEM
        || sig_value->item.bare.type != NGX_AUTH_HTTPSIG_SFV_BYTE_SEQUENCE)
    {
        *result = NGX_AUTH_HTTPSIG_RESULT_PARSE_ERROR;
        return NGX_DECLINED;
    }

    sig->signature = sig_value->item.bare.value;

    /* Step 13: reconstruct the signature base string. */
    rc = ngx_auth_httpsig_base_build(pool, req, sig->components, &base,
                                     &base_reason);
    if (rc == NGX_DECLINED) {
        *result = NGX_AUTH_HTTPSIG_RESULT_PARSE_ERROR;
        return NGX_DECLINED;
    }
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    /* Step 14: verify. */
    rc = ngx_auth_httpsig_verify_ed25519(pool, pctx->keys, &sig->keyid, &base,
                                         &sig->signature, result);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Step 15: only on success, extract the Signature-Agent host. */
    if (agent_present) {
        ngx_auth_httpsig_profile_agent_host(pool, &agent_raw,
                                            &sig->agent_host);
    }

    return NGX_OK;
}


/*
 * Returns the first Signature-Input entry whose "tag" parameter equals
 * `tag`, or NULL if none match. The first matching label wins; later
 * ones with the same tag are ignored.
 */
static ngx_auth_httpsig_sfv_dict_entry_t *
ngx_auth_httpsig_profile_select(const ngx_auth_httpsig_sfv_dictionary_t *dict,
    const ngx_str_t *tag)
{
    ngx_auth_httpsig_sfv_dict_entry_t *entry;
    const ngx_array_t *params;
    const ngx_auth_httpsig_sfv_bare_t *found;
    ngx_uint_t i;

    entry = dict->entries->elts;

    for (i = 0; i < dict->entries->nelts; i++) {
        params = (entry[i].value.type == NGX_AUTH_HTTPSIG_SFV_MEMBER_INNER_LIST)
                     ? entry[i].value.inner_list.params
                     : entry[i].value.item.params;

        found = ngx_auth_httpsig_sfv_param_get(params, "tag");

        if (found != NULL && found->type == NGX_AUTH_HTTPSIG_SFV_STRING
            && ngx_auth_httpsig_str_eq(&found->value, tag))
        {
            return &entry[i];
        }
    }

    return NULL;
}


typedef enum {
    NGX_AUTH_HTTPSIG_PROFILE_PARAM_INTEGER,
    NGX_AUTH_HTTPSIG_PROFILE_PARAM_STRING
} ngx_auth_httpsig_profile_param_kind_t;

typedef struct {
    const char                            *name;
    ngx_auth_httpsig_profile_param_kind_t  kind;
    size_t                                 offset;
    ngx_uint_t                             bit;
} ngx_auth_httpsig_profile_param_t;

static const ngx_auth_httpsig_profile_param_t
    ngx_auth_httpsig_profile_params[] =
{
    { "created", NGX_AUTH_HTTPSIG_PROFILE_PARAM_INTEGER,
      offsetof(ngx_auth_httpsig_signature_t, created),
      NGX_AUTH_HTTPSIG_PARAM_CREATED },

    { "expires", NGX_AUTH_HTTPSIG_PROFILE_PARAM_INTEGER,
      offsetof(ngx_auth_httpsig_signature_t, expires),
      NGX_AUTH_HTTPSIG_PARAM_EXPIRES },

    { "keyid", NGX_AUTH_HTTPSIG_PROFILE_PARAM_STRING,
      offsetof(ngx_auth_httpsig_signature_t, keyid),
      NGX_AUTH_HTTPSIG_PARAM_KEYID },

    { "alg", NGX_AUTH_HTTPSIG_PROFILE_PARAM_STRING,
      offsetof(ngx_auth_httpsig_signature_t, alg),
      NGX_AUTH_HTTPSIG_PARAM_ALG },

    { "nonce", NGX_AUTH_HTTPSIG_PROFILE_PARAM_STRING,
      offsetof(ngx_auth_httpsig_signature_t, nonce),
      NGX_AUTH_HTTPSIG_PARAM_NONCE },

    { "tag", NGX_AUTH_HTTPSIG_PROFILE_PARAM_STRING,
      offsetof(ngx_auth_httpsig_signature_t, tag),
      NGX_AUTH_HTTPSIG_PARAM_TAG }
};


/* Reads the parameters a profile might require out of a selected
 * Signature-Input Inner List's Parameters, setting the matching
 * `present` bit for each one found. NGX_DECLINED if a parameter is
 * present with the wrong bare type. */
static ngx_int_t
ngx_auth_httpsig_profile_extract_params(const ngx_array_t *params,
    ngx_auth_httpsig_signature_t *sig)
{
    u_char *field;
    ngx_uint_t i;
    const ngx_auth_httpsig_sfv_bare_t *v;
    const ngx_auth_httpsig_profile_param_t *p;

    for (i = 0; i < NGX_AUTH_HTTPSIG_NELTS(ngx_auth_httpsig_profile_params);
         i++)
    {
        p = &ngx_auth_httpsig_profile_params[i];

        v = ngx_auth_httpsig_sfv_param_get(params, p->name);
        if (v == NULL) {
            continue;
        }

        field = (u_char *) sig + p->offset;

        if (p->kind == NGX_AUTH_HTTPSIG_PROFILE_PARAM_INTEGER) {
            if (v->type != NGX_AUTH_HTTPSIG_SFV_INTEGER) {
                return NGX_DECLINED;
            }
            *(int64_t *) field = v->integer;

        } else {
            if (v->type != NGX_AUTH_HTTPSIG_SFV_STRING) {
                return NGX_DECLINED;
            }
            *(ngx_str_t *) field = v->value;
        }

        sig->present |= p->bit;
    }

    return NGX_OK;
}


/* Maps the covered-components Inner List's items to the
 * NGX_AUTH_HTTPSIG_COMP_* bits they set; a component not in the table
 * (an arbitrary HTTP field) contributes no bit. */
static ngx_uint_t
ngx_auth_httpsig_profile_covered_components(const ngx_array_t *items)
{
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_uint_t i, j, covered;

    covered = 0;
    item = items->elts;

    for (i = 0; i < items->nelts; i++) {
        if (item[i].bare.type != NGX_AUTH_HTTPSIG_SFV_STRING) {
            continue;
        }

        for (j = 0;
             j < NGX_AUTH_HTTPSIG_NELTS(ngx_auth_httpsig_profile_components);
             j++)
        {
            if (ngx_auth_httpsig_str_eq(&item[i].bare.value,
                                        &ngx_auth_httpsig_profile_components[j].
                                        name))
            {
                covered |= ngx_auth_httpsig_profile_components[j].bit;
                break;
            }
        }
    }

    return covered;
}


/*
 * Signature-Agent is carried as a bare sf-string in some web-bot-auth
 * draft revisions and as an Item in others; parsing it as an Item
 * covers both, since a bare quoted string also parses as an Item.
 * Either way, the reconstructed signature base string uses the raw
 * field value unchanged, so this ambiguity never affects verification
 * -- only $httpsig_agent / key-directory host extraction.
 *
 * Locates the host and authority (host, plus ":<port>" if present)
 * spans within `raw`'s underlying https URL, leaving all three
 * pointers unset unless it parses as such. Shared by
 * ngx_auth_httpsig_profile_agent_host() (host only, for
 * $httpsig_agent) and ngx_auth_httpsig_profile_agent_authority() (full
 * authority, for key-directory allow-list matching and dialing).
 */
static ngx_int_t
ngx_auth_httpsig_profile_agent_bounds(ngx_pool_t *pool,
    const ngx_str_t *raw, u_char **host_start, u_char **host_end,
    u_char **authority_end)
{
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_auth_httpsig_sfv_error_t err;
    ngx_str_t url;
    u_char *start, *end_of_authority, *end, *p;

    if (ngx_auth_httpsig_sfv_parse_item(pool, raw, &item, &err) == NGX_OK
        && item->bare.type == NGX_AUTH_HTTPSIG_SFV_STRING)
    {
        url = item->bare.value;
    } else {
        url = *raw;
    }

    if (url.len < 8
        || ngx_strncasecmp(url.data, (u_char *) "https://", 8) != 0)
    {
        return NGX_DECLINED;
    }

    end = url.data + url.len;
    start = url.data + 8;
    end_of_authority = start;

    while (end_of_authority < end && *end_of_authority != '/'
           && *end_of_authority != '?' && *end_of_authority != '#')
    {
        end_of_authority++;
    }

    /* strip userinfo: host starts after the last '@' in the authority */
    for (p = end_of_authority; p > start; p--) {
        if (*(p - 1) == '@') {
            start = p;
            break;
        }
    }

    if (start >= end_of_authority) {
        return NGX_DECLINED;
    }

    *host_start = start;

    if (*start == '[') {
        /* bracketed IPv6 literal: host runs up to the matching ']' */
        *host_end = start + 1;

        while (*host_end < end_of_authority && **host_end != ']') {
            if (!((**host_end >= '0' && **host_end <= '9')
                  || (**host_end >= 'a' && **host_end <= 'f')
                  || (**host_end >= 'A' && **host_end <= 'F')
                  || **host_end == ':'))
            {
                return NGX_DECLINED;
            }

            (*host_end)++;
        }

        if (*host_end >= end_of_authority || *host_end == start + 1) {
            return NGX_DECLINED;
        }

        (*host_end)++;

    } else {
        *host_end = start;

        while (*host_end < end_of_authority && **host_end != ':') {
            if (!((**host_end >= 'a' && **host_end <= 'z')
                  || (**host_end >= 'A' && **host_end <= 'Z')
                  || (**host_end >= '0' && **host_end <= '9')
                  || **host_end == '-' || **host_end == '.'))
            {
                return NGX_DECLINED;
            }

            (*host_end)++;
        }
    }

    if (*host_end < end_of_authority) {
        if (**host_end != ':' || *host_end + 1 == end_of_authority) {
            return NGX_DECLINED;
        }

        for (p = *host_end + 1; p < end_of_authority; p++) {
            if (*p < '0' || *p > '9') {
                return NGX_DECLINED;
            }
        }
    }

    if (*host_end == *host_start) {
        return NGX_DECLINED;
    }

    *authority_end = end_of_authority;

    return NGX_OK;
}


/* Lowercases [start, end) into a freshly allocated `out`. */
static void
ngx_auth_httpsig_profile_agent_copy(ngx_pool_t *pool, u_char *start,
    u_char *end, ngx_str_t *out)
{
    ngx_str_t value;
    ngx_uint_t i;

    value.len = (size_t) (end - start);

    value.data = ngx_pnalloc(pool, value.len);
    if (value.data == NULL) {
        return;
    }

    for (i = 0; i < value.len; i++) {
        value.data[i] = ngx_tolower(start[i]);
    }

    *out = value;
}


void
ngx_auth_httpsig_profile_agent_host(ngx_pool_t *pool,
    const ngx_str_t *raw, ngx_str_t *out)
{
    u_char *host_start, *host_end, *authority_end;

    out->len = 0;
    out->data = NULL;

    if (ngx_auth_httpsig_profile_agent_bounds(pool, raw, &host_start,
                                              &host_end, &authority_end)
        != NGX_OK)
    {
        return;
    }

    ngx_auth_httpsig_profile_agent_copy(pool, host_start, host_end, out);
}


void
ngx_auth_httpsig_profile_agent_authority(ngx_pool_t *pool,
    const ngx_str_t *raw, ngx_str_t *out)
{
    u_char *host_start, *host_end, *authority_end;

    out->len = 0;
    out->data = NULL;

    if (ngx_auth_httpsig_profile_agent_bounds(pool, raw, &host_start,
                                              &host_end, &authority_end)
        != NGX_OK)
    {
        return;
    }

    ngx_auth_httpsig_profile_agent_copy(pool, host_start, authority_end,
                                        out);
}
