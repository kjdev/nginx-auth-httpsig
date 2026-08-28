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
typedef struct {
    ngx_str_t   name;
    ngx_uint_t  bit;
} ngx_auth_httpsig_profile_component_t;

static const ngx_auth_httpsig_profile_component_t
    ngx_auth_httpsig_profile_components[] = {

    { ngx_string("@method"),          NGX_AUTH_HTTPSIG_COMP_METHOD },
    { ngx_string("@target-uri"),      NGX_AUTH_HTTPSIG_COMP_TARGET_URI },
    { ngx_string("@authority"),       NGX_AUTH_HTTPSIG_COMP_AUTHORITY },
    { ngx_string("@scheme"),          NGX_AUTH_HTTPSIG_COMP_SCHEME },
    { ngx_string("@request-target"),  NGX_AUTH_HTTPSIG_COMP_REQUEST_TARGET },
    { ngx_string("@path"),            NGX_AUTH_HTTPSIG_COMP_PATH },
    { ngx_string("@query"),           NGX_AUTH_HTTPSIG_COMP_QUERY },
    { ngx_string("signature-agent"),  NGX_AUTH_HTTPSIG_COMP_SIGNATURE_AGENT }

};


static ngx_auth_httpsig_sfv_dict_entry_t *
ngx_auth_httpsig_profile_select_entry(
    const ngx_auth_httpsig_sfv_dictionary_t *dict, const ngx_str_t *tag);
static ngx_int_t ngx_auth_httpsig_profile_extract_params(
    const ngx_array_t *params, ngx_auth_httpsig_signature_t *sig);
static ngx_uint_t ngx_auth_httpsig_profile_covered_components(
    const ngx_array_t *items);
static ngx_int_t ngx_auth_httpsig_profile_collect(ngx_pool_t *pool,
    const ngx_auth_httpsig_request_t *req, const ngx_str_t *name,
    ngx_array_t **out);
static ngx_int_t ngx_auth_httpsig_profile_join_lines(ngx_pool_t *pool,
    const ngx_array_t *raws, ngx_str_t *out);
static ngx_flag_t ngx_auth_httpsig_profile_agent_type_ok(
    const ngx_array_t *params);
static void ngx_auth_httpsig_profile_agent_entry(
    const ngx_auth_httpsig_sfv_dictionary_t *dict, const ngx_str_t *label,
    const ngx_str_t **match, const ngx_str_t **fallback);
static ngx_int_t ngx_auth_httpsig_profile_agent_url(ngx_pool_t *pool,
    const ngx_array_t *raws, const ngx_str_t *label, ngx_str_t *url);
static ngx_int_t ngx_auth_httpsig_profile_agent_bounds(const ngx_str_t *url,
    u_char **host_start, u_char **host_end, u_char **authority_end);
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
    ngx_str_t input_raw, sig_raw, base;
    ngx_array_t *agent_raws;
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
    entry = ngx_auth_httpsig_profile_select_entry(input_dict, &profile->tag);
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
     * covered, when the profile requires it. Collected as separate
     * lines, not joined, so the later host extraction can apply ADR
     * 0022's per-line resolution. */
    if (ngx_auth_httpsig_profile_collect(pool, req, &signature_agent_name,
                                         &agent_raws)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    agent_present = (agent_raws->nelts > 0);

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
        ngx_auth_httpsig_profile_agent_host(pool, agent_raws, &sig->label,
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
ngx_auth_httpsig_profile_select_entry(
    const ngx_auth_httpsig_sfv_dictionary_t *dict, const ngx_str_t *tag)
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


/* Concatenates `raws` (in order) with ", " between lines, the standard
 * combination for repeated HTTP field lines (RFC 9651 §3.1). Used only
 * for Signature-Input: unlike Signature-Agent, its labels are unique
 * keys, so joining before parsing is safe and matches how
 * ngx_auth_httpsig_base_field_value() folds the same field for
 * ngx_auth_httpsig_profile_verify() itself. */
static ngx_int_t
ngx_auth_httpsig_profile_join_lines(ngx_pool_t *pool,
    const ngx_array_t *raws, ngx_str_t *out)
{
    ngx_str_t *line;
    ngx_uint_t i;
    size_t len;
    u_char *data, *p;

    line = raws->elts;
    len = 0;

    for (i = 0; i < raws->nelts; i++) {
        if (i > 0) {
            len += 2;   /* ", " */
        }

        len += line[i].len;
    }

    data = ngx_pnalloc(pool, len);
    if (data == NULL) {
        return NGX_ERROR;
    }

    p = data;

    for (i = 0; i < raws->nelts; i++) {
        if (i > 0) {
            *p++ = ',';
            *p++ = ' ';
        }

        p = ngx_cpymem(p, line[i].data, line[i].len);
    }

    out->len = len;
    out->data = data;

    return NGX_OK;
}


ngx_int_t
ngx_auth_httpsig_profile_select_label(ngx_pool_t *pool,
    const ngx_auth_httpsig_profile_t *profile,
    const ngx_array_t *signature_input, ngx_str_t *label)
{
    ngx_auth_httpsig_sfv_dictionary_t *dict;
    ngx_auth_httpsig_sfv_dict_entry_t *entry;
    ngx_auth_httpsig_signature_t sig;
    ngx_auth_httpsig_result_t result;
    ngx_str_t joined;
    ngx_int_t rc;

    if (pool == NULL || profile == NULL || signature_input == NULL
        || label == NULL)
    {
        return NGX_ERROR;
    }

    label->len = 0;
    label->data = NULL;

    if (signature_input->nelts == 0) {
        return NGX_DECLINED;
    }

    if (ngx_auth_httpsig_profile_join_lines(pool, signature_input, &joined)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    rc = ngx_auth_httpsig_sfv_parse_dictionary(pool, &joined, &dict, NULL);
    if (rc == NGX_DECLINED) {
        return NGX_DECLINED;
    }
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    if (dict->duplicate_keys) {
        return NGX_DECLINED;
    }

    entry = ngx_auth_httpsig_profile_select_entry(dict, &profile->tag);
    if (entry == NULL) {
        return NGX_DECLINED;
    }

    if (entry->value.type != NGX_AUTH_HTTPSIG_SFV_MEMBER_INNER_LIST) {
        return NGX_DECLINED;
    }

    /* A tag match alone isn't enough: an Inner List missing required
     * parameters or covered components would fail
     * ngx_auth_httpsig_profile_verify() anyway, so triggering a fetch
     * for it would only ever waste a subrequest. */
    ngx_memzero(&sig, sizeof(ngx_auth_httpsig_signature_t));

    if (ngx_auth_httpsig_profile_extract_params(entry->value.inner_list.params,
                                                &sig)
        != NGX_OK)
    {
        return NGX_DECLINED;
    }

    sig.covered = ngx_auth_httpsig_profile_covered_components(
        entry->value.inner_list.items);

    if (ngx_auth_httpsig_profile_match(profile, &sig, &result) != NGX_OK) {
        return NGX_DECLINED;
    }

    *label = entry->key;

    return NGX_OK;
}


/* Collects every occurrence of `name` (in receipt order) out of
 * `req->headers`, unjoined -- unlike
 * ngx_auth_httpsig_base_field_value(), which combines them with ", ".
 * Signature-Agent must be walked line by line (ADR 0022), so its
 * caller needs the individual values, not a folded string. */
static ngx_int_t
ngx_auth_httpsig_profile_collect(ngx_pool_t *pool,
    const ngx_auth_httpsig_request_t *req, const ngx_str_t *name,
    ngx_array_t **out)
{
    ngx_auth_httpsig_header_t *headers;
    ngx_array_t *arr;
    ngx_str_t *v;
    ngx_uint_t i, n;

    arr = ngx_array_create(pool, 1, sizeof(ngx_str_t));
    if (arr == NULL) {
        return NGX_ERROR;
    }

    headers = req->headers->elts;
    n = req->headers->nelts;

    for (i = 0; i < n; i++) {
        if (!ngx_auth_httpsig_str_eq(&headers[i].name, name)) {
            continue;
        }

        v = ngx_array_push(arr);
        if (v == NULL) {
            return NGX_ERROR;
        }

        *v = headers[i].value;
    }

    *out = arr;

    return NGX_OK;
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
    const ngx_auth_httpsig_profile_component_t *comp;
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
            comp = &ngx_auth_httpsig_profile_components[j];

            if (ngx_auth_httpsig_str_eq(&item[i].bare.value, &comp->name)) {
                covered |= comp->bit;
                break;
            }
        }
    }

    return covered;
}


/*
 * A dictionary member is a usable Signature-Agent entry only when its
 * `type` is absent (default "directory") or the Token "directory";
 * the draft requires verifiers to ignore members whose type they
 * don't support, rather than rejecting the whole field.
 */
static ngx_flag_t
ngx_auth_httpsig_profile_agent_type_ok(const ngx_array_t *params)
{
    static const ngx_str_t directory = ngx_string("directory");
    const ngx_auth_httpsig_sfv_bare_t *type;

    type = ngx_auth_httpsig_sfv_param_get(params, "type");
    if (type == NULL) {
        return 1;
    }

    return type->type == NGX_AUTH_HTTPSIG_SFV_TOKEN
           && ngx_auth_httpsig_str_eq(&type->value, &directory);
}


/*
 * Scans one parsed Signature-Agent dictionary for usable entries
 * (String item, type-filtered) and records at most one match per
 * output: `*match` for the entry keyed like `label`, `*fallback` for
 * the first usable entry regardless of key. Both are set only if
 * still NULL on entry, so a caller folding several header lines keeps
 * whichever line's entry it saw first -- the label match takes
 * priority over the fallback across the whole set of lines.
 */
static void
ngx_auth_httpsig_profile_agent_entry(
    const ngx_auth_httpsig_sfv_dictionary_t *dict, const ngx_str_t *label,
    const ngx_str_t **match, const ngx_str_t **fallback)
{
    ngx_auth_httpsig_sfv_dict_entry_t *entry;
    ngx_uint_t i;

    entry = dict->entries->elts;

    for (i = 0; i < dict->entries->nelts; i++) {
        if (entry[i].value.type != NGX_AUTH_HTTPSIG_SFV_MEMBER_ITEM
            || entry[i].value.item.bare.type != NGX_AUTH_HTTPSIG_SFV_STRING
            || !ngx_auth_httpsig_profile_agent_type_ok(
                entry[i].value.item.params))
        {
            continue;
        }

        if (*fallback == NULL) {
            *fallback = &entry[i].value.item.bare.value;
        }

        if (*match == NULL && label != NULL && label->len > 0
            && ngx_auth_httpsig_str_eq(&entry[i].key, label))
        {
            *match = &entry[i].value.item.bare.value;
        }
    }
}


/*
 * Signature-Agent is carried as a Dictionary per the current
 * web-bot-auth draft, and as a bare sf-string Item in earlier
 * revisions still seen in real crawler traffic. Resolves `raws` (its
 * header lines, in receipt order, unjoined per ADR 0022) to the
 * https URL it carries, trying each line as: a Dictionary (label
 * match preferred, else first type-ok entry, across all lines), then
 * an sf-string Item, then the raw field bytes unchanged. A line that
 * parses as a well-formed Dictionary is never re-interpreted as a
 * lower form, even if it has no usable entry.
 *
 * Either way, the reconstructed signature base string uses the raw
 * field value unchanged, so this ambiguity never affects verification
 * -- only $httpsig_agent / key-directory host extraction.
 *
 * The raw-value fallback bypasses SFV parsing, so it would otherwise
 * skip the length limit that ngx_auth_httpsig_sfv_parse_item()
 * enforces internally; apply the same limit here up front so all
 * paths are bounded identically.
 */
static ngx_int_t
ngx_auth_httpsig_profile_agent_url(ngx_pool_t *pool,
    const ngx_array_t *raws, const ngx_str_t *label, ngx_str_t *url)
{
    ngx_str_t *line;
    ngx_auth_httpsig_sfv_dictionary_t *dict;
    ngx_auth_httpsig_sfv_item_t *item;
    const ngx_str_t *match, *fallback;
    ngx_uint_t i;

    match = NULL;
    fallback = NULL;

    line = raws->elts;

    for (i = 0; i < raws->nelts; i++) {
        if (line[i].len == 0 || line[i].len > NGX_AUTH_HTTPSIG_MAX_SFV_LENGTH) {
            continue;
        }

        if (ngx_auth_httpsig_sfv_parse_dictionary(pool, &line[i], &dict, NULL)
            == NGX_OK)
        {
            ngx_auth_httpsig_profile_agent_entry(dict, label, &match,
                                                 &fallback);

            if (match != NULL) {
                break;
            }

            continue;
        }

        if (ngx_auth_httpsig_sfv_parse_item(pool, &line[i], &item, NULL)
            == NGX_OK && item->bare.type == NGX_AUTH_HTTPSIG_SFV_STRING)
        {
            if (fallback == NULL) {
                fallback = &item->bare.value;
            }

            continue;
        }

        if (fallback == NULL) {
            fallback = &line[i];
        }
    }

    if (match != NULL) {
        *url = *match;
        return NGX_OK;
    }

    if (fallback != NULL) {
        *url = *fallback;
        return NGX_OK;
    }

    return NGX_DECLINED;
}


/*
 * Locates the host and authority (host, plus ":<port>" if present)
 * spans within `url`'s underlying https URL. The output pointers are
 * only set when this returns NGX_OK.  Shared by
 * ngx_auth_httpsig_profile_agent_host() (host only, for
 * $httpsig_agent) and ngx_auth_httpsig_profile_agent_authority() (full
 * authority, for key-directory allow-list matching and dialing).
 */
static ngx_int_t
ngx_auth_httpsig_profile_agent_bounds(const ngx_str_t *url,
    u_char **host_start, u_char **host_end, u_char **authority_end)
{
    u_char *start, *end_of_authority, *end, *p, *host_begin, *host_stop;

    if (url->len < 8
        || ngx_strncasecmp(url->data, (u_char *) "https://", 8) != 0)
    {
        return NGX_DECLINED;
    }

    end = url->data + url->len;
    start = url->data + 8;
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

    host_begin = start;

    if (*start == '[') {
        /* bracketed IPv6 literal: host runs up to the matching ']' */
        p = start + 1;

        while (p < end_of_authority && *p != ']') {
            if (!((*p >= '0' && *p <= '9')
                  || (*p >= 'a' && *p <= 'f')
                  || (*p >= 'A' && *p <= 'F')
                  || *p == ':'))
            {
                return NGX_DECLINED;
            }

            p++;
        }

        if (p >= end_of_authority || p == start + 1) {
            return NGX_DECLINED;
        }

        p++;

    } else {
        p = start;

        while (p < end_of_authority && *p != ':') {
            if (!((*p >= 'a' && *p <= 'z')
                  || (*p >= 'A' && *p <= 'Z')
                  || (*p >= '0' && *p <= '9')
                  || *p == '-' || *p == '.'))
            {
                return NGX_DECLINED;
            }

            p++;
        }
    }

    host_stop = p;

    if (host_stop < end_of_authority) {
        if (*host_stop != ':' || host_stop + 1 == end_of_authority) {
            return NGX_DECLINED;
        }

        for (p = host_stop + 1; p < end_of_authority; p++) {
            if (*p < '0' || *p > '9') {
                return NGX_DECLINED;
            }
        }
    }

    if (host_stop == host_begin) {
        return NGX_DECLINED;
    }

    *host_start = host_begin;
    *host_end = host_stop;
    *authority_end = end_of_authority;

    return NGX_OK;
}


/* Lowercases [start, end) into a freshly allocated `out`. */
static void
ngx_auth_httpsig_profile_agent_copy(ngx_pool_t *pool, u_char *start,
    u_char *end, ngx_str_t *out)
{
    ngx_str_t value;

    value.len = (size_t) (end - start);

    value.data = ngx_pnalloc(pool, value.len);
    if (value.data == NULL) {
        return;
    }

    ngx_strlow(value.data, start, value.len);

    *out = value;
}


void
ngx_auth_httpsig_profile_agent_host(ngx_pool_t *pool,
    const ngx_array_t *raws, const ngx_str_t *label, ngx_str_t *out)
{
    ngx_str_t url;
    u_char *host_start, *host_end, *authority_end;

    out->len = 0;
    out->data = NULL;

    if (raws == NULL
        || ngx_auth_httpsig_profile_agent_url(pool, raws, label, &url)
        != NGX_OK
        || ngx_auth_httpsig_profile_agent_bounds(&url, &host_start,
                                                 &host_end, &authority_end)
        != NGX_OK)
    {
        return;
    }

    ngx_auth_httpsig_profile_agent_copy(pool, host_start, host_end, out);
}


void
ngx_auth_httpsig_profile_agent_authority(ngx_pool_t *pool,
    const ngx_array_t *raws, const ngx_str_t *label, ngx_str_t *out)
{
    ngx_str_t url;
    u_char *host_start, *host_end, *authority_end;

    out->len = 0;
    out->data = NULL;

    if (raws == NULL
        || ngx_auth_httpsig_profile_agent_url(pool, raws, label, &url)
        != NGX_OK
        || ngx_auth_httpsig_profile_agent_bounds(&url, &host_start,
                                                 &host_end, &authority_end)
        != NGX_OK)
    {
        return;
    }

    ngx_auth_httpsig_profile_agent_copy(pool, host_start, authority_end,
                                        out);
}
