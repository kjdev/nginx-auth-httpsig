/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * test_profile.c - coverage for the web-bot-auth profile checks.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_profile.h"
#include "test.h"
#include "test_crypto.h"

#include <nxe_jwx.h>

#include <stdarg.h>
#include <stdio.h>


/* A fixed clock so time-window checks are deterministic. */
#define TEST_NOW  1700000000


typedef struct {
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_keys_t    *keys;
    ngx_str_t                   thumbprint;
    EVP_PKEY                   *pkey;
} profile_fixture_t;


static ngx_str_t
str(const char *s)
{
    ngx_str_t v;

    v.data = (u_char *) s;
    v.len = ngx_strlen(v.data);

    return v;
}


static ngx_str_t
fmt(ngx_pool_t *pool, const char *format, ...)
{
    va_list args;
    int n;
    ngx_str_t out;

    va_start(args, format);
    n = vsnprintf(NULL, 0, format, args);
    va_end(args);

    out.len = (size_t) n;
    out.data = ngx_pnalloc(pool, out.len + 1);

    va_start(args, format);
    vsnprintf((char *) out.data, out.len + 1, format, args);
    va_end(args);

    return out;
}


static void
push_header(ngx_pool_t *pool, ngx_array_t *headers, const ngx_str_t *name,
    const ngx_str_t *value)
{
    ngx_auth_httpsig_header_t *h;

    h = ngx_array_push(headers);
    h->name = *name;
    h->value = *value;
}


/*
 * Builds an ngx_array_t of ngx_str_t out of a NULL-terminated list of
 * C strings, one per Signature-Agent / Signature-Input header line --
 * the shape ngx_auth_httpsig_profile_agent_host(),
 * ngx_auth_httpsig_profile_agent_authority(), and
 * ngx_auth_httpsig_profile_select_label() take.
 */
static ngx_array_t *
lines(ngx_pool_t *pool, ...)
{
    va_list args;
    ngx_array_t *arr;
    const char *s;
    ngx_str_t *v;

    arr = ngx_array_create(pool, 1, sizeof(ngx_str_t));

    va_start(args, pool);

    for (;;) {
        s = va_arg(args, const char *);
        if (s == NULL) {
            break;
        }

        v = ngx_array_push(arr);
        *v = str(s);
    }

    va_end(args);

    return arr;
}


static ngx_int_t
build_fixture(ngx_pool_t *pool, profile_fixture_t *fx)
{
    ngx_str_t jwk, jwks_json;
    nxe_jwx_jwks_t *ref;

    fx->pkey = test_gen_ed25519();
    if (fx->pkey == NULL) {
        return NGX_ERROR;
    }

    jwk = test_jwk_okp(fx->pkey, "Ed25519", 32, NULL, NULL, pool);
    if (jwk.data == NULL) {
        return NGX_ERROR;
    }

    jwks_json = test_jwks_build(&jwk, 1, pool);
    if (jwks_json.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_auth_httpsig_keys_load_jwks(pool, &jwks_json, NULL, NGX_LOG_EMERG,
                                        &fx->keys)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ref = nxe_jwx_jwks_parse(&jwks_json, pool);
    if (ref == NULL) {
        return NGX_ERROR;
    }

    if (nxe_jwx_jwks_thumbprint(ref, 0, &fx->thumbprint) != NGX_OK) {
        return NGX_ERROR;
    }

    fx->req = ngx_pcalloc(pool, sizeof(ngx_auth_httpsig_request_t));

    fx->req->method = str("GET");
    fx->req->scheme = str("https");
    fx->req->authority = str("example.com");
    fx->req->path = str("/foo");
    fx->req->has_query = 0;
    fx->req->request_target = str("/foo");
    fx->req->target_defined = 1;
    fx->req->headers = ngx_array_create(pool, 4,
                                        sizeof(ngx_auth_httpsig_header_t));

    return NGX_OK;
}


/*
 * Reconstructs the signature base string for `label` out of
 * `input_text` (a full Signature-Input dictionary value), signs it
 * with `fx->pkey`, and returns a Signature dictionary value carrying
 * just that one label - the only label ngx_auth_httpsig_profile_verify()
 * ever looks up.
 */
static ngx_str_t
sign_label(ngx_pool_t *pool, profile_fixture_t *fx, const ngx_str_t *input_text,
    const char *label)
{
    ngx_auth_httpsig_sfv_dictionary_t *dict;
    const ngx_auth_httpsig_sfv_value_t *value;
    ngx_auth_httpsig_sfv_error_t err;
    ngx_auth_httpsig_sfv_item_t sig_item;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_str_t label_str, base, serialized;
    u_char *sig;
    size_t sig_len;

    label_str = str(label);

    if (ngx_auth_httpsig_sfv_parse_dictionary(pool, input_text, &dict, &err)
        != NGX_OK)
    {
        return str("");
    }

    value = ngx_auth_httpsig_sfv_dict_get(dict, &label_str);
    if (value == NULL
        || value->type != NGX_AUTH_HTTPSIG_SFV_MEMBER_INNER_LIST)
    {
        return str("");
    }

    if (ngx_auth_httpsig_base_build(pool, fx->req, &value->inner_list, &base,
                                    &reason)
        != NGX_OK)
    {
        return str("");
    }

    if (test_sign(fx->pkey, base.data, base.len, &sig, &sig_len, pool)
        != NGX_OK)
    {
        return str("");
    }

    sig_item.bare.type = NGX_AUTH_HTTPSIG_SFV_BYTE_SEQUENCE;
    sig_item.bare.value.data = sig;
    sig_item.bare.value.len = sig_len;
    sig_item.bare.integer = 0;
    sig_item.params = ngx_array_create(pool, 1,
                                       sizeof(ngx_auth_httpsig_sfv_param_t));

    if (ngx_auth_httpsig_sfv_serialize_item(pool, &sig_item, &serialized)
        != NGX_OK)
    {
        return str("");
    }

    return fmt(pool, "%s=%.*s", label, (int) serialized.len,
               (char *) serialized.data);
}


static void
attach_signature(ngx_pool_t *pool, profile_fixture_t *fx,
    const ngx_str_t *input_text, const char *signed_label)
{
    ngx_str_t sig_text;

    sig_text = sign_label(pool, fx, input_text, signed_label);

    push_header(pool, fx->req->headers,
                &(ngx_str_t) ngx_string("signature-input"),
                input_text);
    push_header(pool, fx->req->headers, &(ngx_str_t) ngx_string("signature"),
                &sig_text);
}


static ngx_auth_httpsig_profile_ctx_t
build_ctx(profile_fixture_t *fx)
{
    ngx_auth_httpsig_profile_ctx_t pctx;
    ngx_str_t name;

    name = str("web-bot-auth");

    pctx.profile = ngx_auth_httpsig_profile_get(&name);
    pctx.keys = fx->keys;
    pctx.expires_max = pctx.profile->expires_max;
    pctx.max_skew = pctx.profile->max_skew;
    pctx.now = TEST_NOW;

    return pctx;
}


TEST(profile_verify_success){
    profile_fixture_t fx;
    ngx_auth_httpsig_profile_ctx_t pctx;
    ngx_auth_httpsig_signature_t sig;
    ngx_auth_httpsig_result_t result;
    ngx_str_t input_text;

    ASSERT_EQ_INT(NGX_OK, build_fixture(pool, &fx));

    input_text = fmt(pool,
                     "sig1=(\"@target-uri\" \"@authority\");created=%d;expires=%d;"
                     "keyid=\"%.*s\";tag=\"web-bot-auth\"",
                     TEST_NOW - 5, TEST_NOW + 55,
                     (int) fx.thumbprint.len, (char *) fx.thumbprint.data);

    attach_signature(pool, &fx, &input_text, "sig1");

    pctx = build_ctx(&fx);

    ASSERT_EQ_INT(NGX_OK,
                  ngx_auth_httpsig_profile_verify(pool, &pctx, fx.req, &sig,
                                                  &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_OK, result);
    ASSERT_EQ_INT(0,
                  sig.label.len != 4 || ngx_memcmp(sig.label.data, "sig1", 4));
    ASSERT_EQ_INT(0, sig.agent_host.len);

    ngx_auth_httpsig_keys_free(fx.keys);
    EVP_PKEY_free(fx.pkey);

    return 0;
}


TEST(profile_agent_host_extracts_valid_host){
    profile_fixture_t fx;
    ngx_auth_httpsig_profile_ctx_t pctx;
    ngx_auth_httpsig_signature_t sig;
    ngx_auth_httpsig_result_t result;
    ngx_str_t input_text, agent;

    ASSERT_EQ_INT(NGX_OK, build_fixture(pool, &fx));

    agent = str("\"https://Example.COM:443/agents/1\"");
    push_header(pool, fx.req->headers,
                &(ngx_str_t) ngx_string("signature-agent"), &agent);

    input_text = fmt(pool,
                     "sig1=(\"@target-uri\" \"@authority\" \"signature-agent\");"
                     "created=%d;expires=%d;keyid=\"%.*s\";tag=\"web-bot-auth\"",
                     TEST_NOW - 5, TEST_NOW + 55,
                     (int) fx.thumbprint.len, (char *) fx.thumbprint.data);

    attach_signature(pool, &fx, &input_text, "sig1");

    pctx = build_ctx(&fx);

    ASSERT_EQ_INT(NGX_OK,
                  ngx_auth_httpsig_profile_verify(pool, &pctx, fx.req, &sig,
                                                  &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_OK, result);
    ASSERT_STR_EQ(sig.agent_host, "example.com");

    ngx_auth_httpsig_keys_free(fx.keys);
    EVP_PKEY_free(fx.pkey);

    return 0;
}


TEST(profile_agent_host_rejects_invalid_bytes){
    profile_fixture_t fx;
    ngx_auth_httpsig_profile_ctx_t pctx;
    ngx_auth_httpsig_signature_t sig;
    ngx_auth_httpsig_result_t result;
    ngx_str_t input_text, agent;

    ASSERT_EQ_INT(NGX_OK, build_fixture(pool, &fx));

    agent = str("\"https://a.test,evil\"");
    push_header(pool, fx.req->headers,
                &(ngx_str_t) ngx_string("signature-agent"), &agent);

    input_text = fmt(pool,
                     "sig1=(\"@target-uri\" \"@authority\" \"signature-agent\");"
                     "created=%d;expires=%d;keyid=\"%.*s\";tag=\"web-bot-auth\"",
                     TEST_NOW - 5, TEST_NOW + 55,
                     (int) fx.thumbprint.len, (char *) fx.thumbprint.data);

    attach_signature(pool, &fx, &input_text, "sig1");

    pctx = build_ctx(&fx);

    ASSERT_EQ_INT(NGX_OK,
                  ngx_auth_httpsig_profile_verify(pool, &pctx, fx.req, &sig,
                                                  &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_OK, result);
    ASSERT_EQ_INT(0, sig.agent_host.len);

    ngx_auth_httpsig_keys_free(fx.keys);
    EVP_PKEY_free(fx.pkey);

    return 0;
}


TEST(profile_agent_host_rejects_oversized_raw_fallback){
    profile_fixture_t fx;
    ngx_auth_httpsig_profile_ctx_t pctx;
    ngx_auth_httpsig_signature_t sig;
    ngx_auth_httpsig_result_t result;
    ngx_str_t input_text, agent, filler;

    ASSERT_EQ_INT(NGX_OK, build_fixture(pool, &fx));

    /*
     * Oversized and unquoted, so it fails to parse as an sf-string and
     * falls back to the raw header bytes. That fallback must still be
     * bounded by NGX_AUTH_HTTPSIG_MAX_SFV_LENGTH rather than relying on
     * nginx's own header size limits.
     */
    filler.len = NGX_AUTH_HTTPSIG_MAX_SFV_LENGTH + 1;
    filler.data = ngx_pnalloc(pool, filler.len);
    ngx_memset(filler.data, 'a', filler.len);

    agent = fmt(pool, "https://%.*s.test/",
                (int) filler.len, (char *) filler.data);
    push_header(pool, fx.req->headers,
                &(ngx_str_t) ngx_string("signature-agent"), &agent);

    input_text = fmt(pool,
                     "sig1=(\"@target-uri\" \"@authority\" \"signature-agent\");"
                     "created=%d;expires=%d;keyid=\"%.*s\";tag=\"web-bot-auth\"",
                     TEST_NOW - 5, TEST_NOW + 55,
                     (int) fx.thumbprint.len, (char *) fx.thumbprint.data);

    attach_signature(pool, &fx, &input_text, "sig1");

    pctx = build_ctx(&fx);

    ASSERT_EQ_INT(NGX_OK,
                  ngx_auth_httpsig_profile_verify(pool, &pctx, fx.req, &sig,
                                                  &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_OK, result);
    ASSERT_EQ_INT(0, sig.agent_host.len);

    ngx_auth_httpsig_keys_free(fx.keys);
    EVP_PKEY_free(fx.pkey);

    return 0;
}


TEST(profile_agent_host_extracts_bracketed_ipv6){
    profile_fixture_t fx;
    ngx_auth_httpsig_profile_ctx_t pctx;
    ngx_auth_httpsig_signature_t sig;
    ngx_auth_httpsig_result_t result;
    ngx_str_t input_text, agent;

    ASSERT_EQ_INT(NGX_OK, build_fixture(pool, &fx));

    agent = str("\"https://[2001:DB8::1]:443/agents/1\"");
    push_header(pool, fx.req->headers,
                &(ngx_str_t) ngx_string("signature-agent"), &agent);

    input_text = fmt(pool,
                     "sig1=(\"@target-uri\" \"@authority\" \"signature-agent\");"
                     "created=%d;expires=%d;keyid=\"%.*s\";tag=\"web-bot-auth\"",
                     TEST_NOW - 5, TEST_NOW + 55,
                     (int) fx.thumbprint.len, (char *) fx.thumbprint.data);

    attach_signature(pool, &fx, &input_text, "sig1");

    pctx = build_ctx(&fx);

    ASSERT_EQ_INT(NGX_OK,
                  ngx_auth_httpsig_profile_verify(pool, &pctx, fx.req, &sig,
                                                  &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_OK, result);
    ASSERT_STR_EQ(sig.agent_host, "[2001:db8::1]");

    ngx_auth_httpsig_keys_free(fx.keys);
    EVP_PKEY_free(fx.pkey);

    return 0;
}


TEST(profile_agent_host_rejects_invalid_bracketed_bytes){
    profile_fixture_t fx;
    ngx_auth_httpsig_profile_ctx_t pctx;
    ngx_auth_httpsig_signature_t sig;
    ngx_auth_httpsig_result_t result;
    ngx_str_t input_text, agent;

    ASSERT_EQ_INT(NGX_OK, build_fixture(pool, &fx));

    agent = str("\"https://[not,ipv6]/\"");
    push_header(pool, fx.req->headers,
                &(ngx_str_t) ngx_string("signature-agent"), &agent);

    input_text = fmt(pool,
                     "sig1=(\"@target-uri\" \"@authority\" \"signature-agent\");"
                     "created=%d;expires=%d;keyid=\"%.*s\";tag=\"web-bot-auth\"",
                     TEST_NOW - 5, TEST_NOW + 55,
                     (int) fx.thumbprint.len, (char *) fx.thumbprint.data);

    attach_signature(pool, &fx, &input_text, "sig1");

    pctx = build_ctx(&fx);

    ASSERT_EQ_INT(NGX_OK,
                  ngx_auth_httpsig_profile_verify(pool, &pctx, fx.req, &sig,
                                                  &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_OK, result);
    ASSERT_EQ_INT(0, sig.agent_host.len);

    ngx_auth_httpsig_keys_free(fx.keys);
    EVP_PKEY_free(fx.pkey);

    return 0;
}


TEST(profile_agent_authority_keeps_port){
    ngx_array_t *raws;
    ngx_str_t authority;

    raws = lines(pool, "\"https://Example.COM:443/agents/1\"", NULL);

    ngx_auth_httpsig_profile_agent_authority(pool, raws, NULL, &authority);

    ASSERT_STR_EQ(authority, "example.com:443");

    return 0;
}


TEST(profile_agent_authority_omits_absent_port){
    ngx_array_t *raws;
    ngx_str_t authority;

    raws = lines(pool, "\"https://Example.COM/agents/1\"", NULL);

    ngx_auth_httpsig_profile_agent_authority(pool, raws, NULL, &authority);

    ASSERT_STR_EQ(authority, "example.com");

    return 0;
}


TEST(profile_agent_authority_keeps_bracketed_ipv6_port){
    ngx_array_t *raws;
    ngx_str_t authority;

    raws = lines(pool, "\"https://[2001:DB8::1]:8443/agents/1\"", NULL);

    ngx_auth_httpsig_profile_agent_authority(pool, raws, NULL, &authority);

    ASSERT_STR_EQ(authority, "[2001:db8::1]:8443");

    return 0;
}


TEST(profile_agent_authority_rejects_non_https){
    ngx_array_t *raws;
    ngx_str_t authority;

    raws = lines(pool, "\"http://example.com\"", NULL);

    ngx_auth_httpsig_profile_agent_authority(pool, raws, NULL, &authority);

    ASSERT_EQ_INT(0, authority.len);

    return 0;
}


TEST(profile_agent_host_dictionary_single_entry){
    ngx_array_t *raws;
    ngx_str_t host;

    raws = lines(pool, "g=\"https://agent.bot.goog\"", NULL);

    ngx_auth_httpsig_profile_agent_host(pool, raws, NULL, &host);

    ASSERT_STR_EQ(host, "agent.bot.goog");

    return 0;
}


TEST(profile_agent_host_dictionary_label_priority){
    ngx_array_t *raws;
    ngx_str_t host, label;

    raws = lines(pool, "a=\"https://a.example\", g=\"https://g.example\"",
                 NULL);
    label = str("g");

    ngx_auth_httpsig_profile_agent_host(pool, raws, &label, &host);

    ASSERT_STR_EQ(host, "g.example");

    return 0;
}


TEST(profile_agent_host_dictionary_no_label_falls_back_to_first){
    ngx_array_t *raws;
    ngx_str_t host;

    raws = lines(pool, "a=\"https://a.example\", g=\"https://g.example\"",
                 NULL);

    ngx_auth_httpsig_profile_agent_host(pool, raws, NULL, &host);

    ASSERT_STR_EQ(host, "a.example");

    return 0;
}


TEST(profile_agent_host_dictionary_type_directory_matches){
    ngx_array_t *raws;
    ngx_str_t host;

    raws = lines(pool, "g=\"https://g.example\";type=directory", NULL);

    ngx_auth_httpsig_profile_agent_host(pool, raws, NULL, &host);

    ASSERT_STR_EQ(host, "g.example");

    return 0;
}


TEST(profile_agent_host_dictionary_type_jwks_uri_is_skipped){
    ngx_array_t *raws;
    ngx_str_t host;

    raws = lines(pool,
                 "g=\"https://g.example\";type=jwks_uri, "
                 "h=\"https://h.example\"",
                 NULL);

    ngx_auth_httpsig_profile_agent_host(pool, raws, NULL, &host);

    ASSERT_STR_EQ(host, "h.example");

    return 0;
}


TEST(profile_agent_host_dictionary_only_unsupported_type_is_empty){
    ngx_array_t *raws;
    ngx_str_t host;

    raws = lines(pool, "g=\"https://g.example\";type=jwks_uri", NULL);

    ngx_auth_httpsig_profile_agent_host(pool, raws, NULL, &host);

    ASSERT_EQ_INT(0, host.len);

    return 0;
}


TEST(profile_agent_host_dictionary_label_match_wrong_type_falls_through){
    ngx_array_t *raws;
    ngx_str_t host, label;

    raws = lines(pool,
                 "g=\"https://g.example\";type=jwks_uri, "
                 "h=\"https://h.example\"",
                 NULL);
    label = str("g");

    ngx_auth_httpsig_profile_agent_host(pool, raws, &label, &host);

    ASSERT_STR_EQ(host, "h.example");

    return 0;
}


TEST(profile_agent_host_dictionary_type_not_token_is_ignored){
    ngx_array_t *raws;
    ngx_str_t host;

    raws = lines(pool, "g=\"https://g.example\";type=\"directory\"", NULL);

    ngx_auth_httpsig_profile_agent_host(pool, raws, NULL, &host);

    ASSERT_EQ_INT(0, host.len);

    return 0;
}


TEST(profile_agent_host_dictionary_lines_not_joined){
    ngx_array_t *raws;
    ngx_str_t host, label;

    /*
     * Two separate header lines, each its own well-formed dictionary
     * keyed "g". Joining them with ", " before parsing would collapse
     * into a single dictionary where the second line's "g" overwrites
     * the first (SFV duplicate-key semantics); walking lines
     * separately must instead let the first line's match win.
     */
    raws = lines(pool, "g=\"https://one.example\"", "g=\"https://two.example\"",
                 NULL);
    label = str("g");

    ngx_auth_httpsig_profile_agent_host(pool, raws, &label, &host);

    ASSERT_STR_EQ(host, "one.example");

    return 0;
}


TEST(profile_agent_host_dictionary_inner_list_member_is_skipped){
    ngx_array_t *raws;
    ngx_str_t host;

    raws = lines(pool, "g=(\"x\" \"y\"), h=\"https://h.example\"", NULL);

    ngx_auth_httpsig_profile_agent_host(pool, raws, NULL, &host);

    ASSERT_STR_EQ(host, "h.example");

    return 0;
}


TEST(profile_select_label_picks_first_tagged_entry){
    ngx_auth_httpsig_profile_t profile;
    ngx_array_t *raws;
    ngx_str_t label;

    ngx_memzero(&profile, sizeof(profile));
    profile.tag = str("web-bot-auth");

    raws = lines(pool,
                 "sig0=(\"@method\");tag=\"other-tag\", "
                 "sig1=(\"@target-uri\");tag=\"web-bot-auth\", "
                 "sig2=(\"@target-uri\");tag=\"web-bot-auth\"",
                 NULL);

    ASSERT_EQ_INT(NGX_OK,
                  ngx_auth_httpsig_profile_select_label(pool, &profile, raws,
                                                        &label));
    ASSERT_STR_EQ(label, "sig1");

    return 0;
}


TEST(profile_select_label_declines_on_tag_mismatch){
    ngx_auth_httpsig_profile_t profile;
    ngx_array_t *raws;
    ngx_str_t label;

    ngx_memzero(&profile, sizeof(profile));
    profile.tag = str("web-bot-auth");

    raws = lines(pool, "sig0=(\"@method\");tag=\"other-tag\"", NULL);

    ASSERT_EQ_INT(NGX_DECLINED,
                  ngx_auth_httpsig_profile_select_label(pool, &profile, raws,
                                                        &label));
    ASSERT_EQ_INT(0, label.len);

    return 0;
}


TEST(profile_select_label_declines_on_malformed_input){
    ngx_auth_httpsig_profile_t profile;
    ngx_array_t *raws;
    ngx_str_t label;

    ngx_memzero(&profile, sizeof(profile));
    profile.tag = str("web-bot-auth");

    raws = lines(pool, "sig1=(unterminated", NULL);

    ASSERT_EQ_INT(NGX_DECLINED,
                  ngx_auth_httpsig_profile_select_label(pool, &profile, raws,
                                                        &label));

    return 0;
}


TEST(profile_select_label_declines_on_duplicate_label){
    ngx_auth_httpsig_profile_t profile;
    ngx_array_t *raws;
    ngx_str_t label;

    ngx_memzero(&profile, sizeof(profile));
    profile.tag = str("web-bot-auth");

    raws = lines(pool,
                 "sig1=(\"@method\");tag=\"web-bot-auth\", "
                 "sig1=(\"@target-uri\");tag=\"web-bot-auth\"",
                 NULL);

    ASSERT_EQ_INT(NGX_DECLINED,
                  ngx_auth_httpsig_profile_select_label(pool, &profile, raws,
                                                        &label));

    return 0;
}


TEST(profile_select_label_declines_on_non_inner_list_entry){
    ngx_auth_httpsig_profile_t profile;
    ngx_array_t *raws;
    ngx_str_t label;

    ngx_memzero(&profile, sizeof(profile));
    profile.tag = str("web-bot-auth");

    raws = lines(pool, "sig1=\"x\";tag=\"web-bot-auth\"", NULL);

    ASSERT_EQ_INT(NGX_DECLINED,
                  ngx_auth_httpsig_profile_select_label(pool, &profile, raws,
                                                        &label));
    ASSERT_EQ_INT(0, label.len);

    return 0;
}


TEST(profile_select_label_declines_on_profile_mismatch){
    ngx_auth_httpsig_profile_t profile;
    ngx_array_t *raws;
    ngx_str_t label;

    ngx_memzero(&profile, sizeof(profile));
    profile.tag = str("web-bot-auth");
    profile.required_params = NGX_AUTH_HTTPSIG_PARAM_KEYID;
    profile.all_of_components = NGX_AUTH_HTTPSIG_COMP_TARGET_URI;

    raws = lines(pool, "sig1=();tag=\"web-bot-auth\"", NULL);

    ASSERT_EQ_INT(NGX_DECLINED,
                  ngx_auth_httpsig_profile_select_label(pool, &profile, raws,
                                                        &label));
    ASSERT_EQ_INT(0, label.len);

    return 0;
}


TEST(profile_tag_mismatch_is_not_signed){
    profile_fixture_t fx;
    ngx_auth_httpsig_profile_ctx_t pctx;
    ngx_auth_httpsig_signature_t sig;
    ngx_auth_httpsig_result_t result;
    ngx_str_t input_text;

    ASSERT_EQ_INT(NGX_OK, build_fixture(pool, &fx));

    input_text = fmt(pool,
                     "sig1=(\"@target-uri\" \"@authority\");created=%d;expires=%d;"
                     "keyid=\"%.*s\";tag=\"other-tag\"",
                     TEST_NOW - 5, TEST_NOW + 55,
                     (int) fx.thumbprint.len, (char *) fx.thumbprint.data);

    attach_signature(pool, &fx, &input_text, "sig1");

    pctx = build_ctx(&fx);

    ASSERT_EQ_INT(NGX_DECLINED,
                  ngx_auth_httpsig_profile_verify(pool, &pctx, fx.req, &sig,
                                                  &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_NOT_SIGNED, result);

    ngx_auth_httpsig_keys_free(fx.keys);
    EVP_PKEY_free(fx.pkey);

    return 0;
}


TEST(profile_missing_required_param_is_mismatch){
    profile_fixture_t fx;
    ngx_auth_httpsig_profile_ctx_t pctx;
    ngx_auth_httpsig_signature_t sig;
    ngx_auth_httpsig_result_t result;
    ngx_str_t input_text;

    ASSERT_EQ_INT(NGX_OK, build_fixture(pool, &fx));

    /* Missing "expires". */
    input_text = fmt(pool,
                     "sig1=(\"@target-uri\" \"@authority\");created=%d;"
                     "keyid=\"%.*s\";tag=\"web-bot-auth\"",
                     TEST_NOW - 5,
                     (int) fx.thumbprint.len, (char *) fx.thumbprint.data);

    attach_signature(pool, &fx, &input_text, "sig1");

    pctx = build_ctx(&fx);

    ASSERT_EQ_INT(NGX_DECLINED,
                  ngx_auth_httpsig_profile_verify(pool, &pctx, fx.req, &sig,
                                                  &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_PROFILE_MISMATCH, result);

    ngx_auth_httpsig_keys_free(fx.keys);
    EVP_PKEY_free(fx.pkey);

    return 0;
}


TEST(profile_missing_authority_and_target_uri_is_mismatch){
    profile_fixture_t fx;
    ngx_auth_httpsig_profile_ctx_t pctx;
    ngx_auth_httpsig_signature_t sig;
    ngx_auth_httpsig_result_t result;
    ngx_str_t input_text;

    ASSERT_EQ_INT(NGX_OK, build_fixture(pool, &fx));

    input_text = fmt(pool,
                     "sig1=(\"@method\");created=%d;expires=%d;"
                     "keyid=\"%.*s\";tag=\"web-bot-auth\"",
                     TEST_NOW - 5, TEST_NOW + 55,
                     (int) fx.thumbprint.len, (char *) fx.thumbprint.data);

    attach_signature(pool, &fx, &input_text, "sig1");

    pctx = build_ctx(&fx);

    ASSERT_EQ_INT(NGX_DECLINED,
                  ngx_auth_httpsig_profile_verify(pool, &pctx, fx.req, &sig,
                                                  &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_PROFILE_MISMATCH, result);

    ngx_auth_httpsig_keys_free(fx.keys);
    EVP_PKEY_free(fx.pkey);

    return 0;
}


TEST(profile_alg_mismatch_is_mismatch){
    profile_fixture_t fx;
    ngx_auth_httpsig_profile_ctx_t pctx;
    ngx_auth_httpsig_signature_t sig;
    ngx_auth_httpsig_result_t result;
    ngx_str_t input_text;

    ASSERT_EQ_INT(NGX_OK, build_fixture(pool, &fx));

    input_text = fmt(pool,
                     "sig1=(\"@target-uri\" \"@authority\");created=%d;expires=%d;"
                     "keyid=\"%.*s\";alg=\"hmac-sha256\";tag=\"web-bot-auth\"",
                     TEST_NOW - 5, TEST_NOW + 55,
                     (int) fx.thumbprint.len, (char *) fx.thumbprint.data);

    attach_signature(pool, &fx, &input_text, "sig1");

    pctx = build_ctx(&fx);

    ASSERT_EQ_INT(NGX_DECLINED,
                  ngx_auth_httpsig_profile_verify(pool, &pctx, fx.req, &sig,
                                                  &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_PROFILE_MISMATCH, result);

    ngx_auth_httpsig_keys_free(fx.keys);
    EVP_PKEY_free(fx.pkey);

    return 0;
}


TEST(profile_created_skew_boundary_passes){
    profile_fixture_t fx;
    ngx_auth_httpsig_profile_ctx_t pctx;
    ngx_auth_httpsig_signature_t sig;
    ngx_auth_httpsig_result_t result;
    ngx_str_t input_text;

    ASSERT_EQ_INT(NGX_OK, build_fixture(pool, &fx));

    /* created == now + max_skew exactly: must still pass. */
    input_text = fmt(pool,
                     "sig1=(\"@target-uri\" \"@authority\");created=%d;expires=%d;"
                     "keyid=\"%.*s\";tag=\"web-bot-auth\"",
                     TEST_NOW + 60, TEST_NOW + 70,
                     (int) fx.thumbprint.len, (char *) fx.thumbprint.data);

    attach_signature(pool, &fx, &input_text, "sig1");

    pctx = build_ctx(&fx);

    ASSERT_EQ_INT(NGX_OK,
                  ngx_auth_httpsig_profile_verify(pool, &pctx, fx.req, &sig,
                                                  &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_OK, result);

    ngx_auth_httpsig_keys_free(fx.keys);
    EVP_PKEY_free(fx.pkey);

    return 0;
}


TEST(profile_created_skew_boundary_fails_beyond){
    profile_fixture_t fx;
    ngx_auth_httpsig_profile_ctx_t pctx;
    ngx_auth_httpsig_signature_t sig;
    ngx_auth_httpsig_result_t result;
    ngx_str_t input_text;

    ASSERT_EQ_INT(NGX_OK, build_fixture(pool, &fx));

    /* created == now + max_skew + 1: one second beyond must fail. */
    input_text = fmt(pool,
                     "sig1=(\"@target-uri\" \"@authority\");created=%d;expires=%d;"
                     "keyid=\"%.*s\";tag=\"web-bot-auth\"",
                     TEST_NOW + 61, TEST_NOW + 71,
                     (int) fx.thumbprint.len, (char *) fx.thumbprint.data);

    attach_signature(pool, &fx, &input_text, "sig1");

    pctx = build_ctx(&fx);

    ASSERT_EQ_INT(NGX_DECLINED,
                  ngx_auth_httpsig_profile_verify(pool, &pctx, fx.req, &sig,
                                                  &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_EXPIRED, result);

    ngx_auth_httpsig_keys_free(fx.keys);
    EVP_PKEY_free(fx.pkey);

    return 0;
}


TEST(profile_expires_past_beyond_skew_is_expired){
    profile_fixture_t fx;
    ngx_auth_httpsig_profile_ctx_t pctx;
    ngx_auth_httpsig_signature_t sig;
    ngx_auth_httpsig_result_t result;
    ngx_str_t input_text;

    ASSERT_EQ_INT(NGX_OK, build_fixture(pool, &fx));

    /* expires == now - max_skew - 1: one second beyond must fail. */
    input_text = fmt(pool,
                     "sig1=(\"@target-uri\" \"@authority\");created=%d;expires=%d;"
                     "keyid=\"%.*s\";tag=\"web-bot-auth\"",
                     TEST_NOW - 100, TEST_NOW - 61,
                     (int) fx.thumbprint.len, (char *) fx.thumbprint.data);

    attach_signature(pool, &fx, &input_text, "sig1");

    pctx = build_ctx(&fx);

    ASSERT_EQ_INT(NGX_DECLINED,
                  ngx_auth_httpsig_profile_verify(pool, &pctx, fx.req, &sig,
                                                  &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_EXPIRED, result);

    ngx_auth_httpsig_keys_free(fx.keys);
    EVP_PKEY_free(fx.pkey);

    return 0;
}


TEST(profile_expires_created_window_too_wide_is_expired){
    profile_fixture_t fx;
    ngx_auth_httpsig_profile_ctx_t pctx;
    ngx_auth_httpsig_signature_t sig;
    ngx_auth_httpsig_result_t result;
    ngx_str_t input_text;

    ASSERT_EQ_INT(NGX_OK, build_fixture(pool, &fx));

    /* expires - created (86500) exceeds expires_max (86400). */
    input_text = fmt(pool,
                     "sig1=(\"@target-uri\" \"@authority\");created=%d;expires=%d;"
                     "keyid=\"%.*s\";tag=\"web-bot-auth\"",
                     TEST_NOW - 10, TEST_NOW - 10 + 86500,
                     (int) fx.thumbprint.len, (char *) fx.thumbprint.data);

    attach_signature(pool, &fx, &input_text, "sig1");

    pctx = build_ctx(&fx);

    ASSERT_EQ_INT(NGX_DECLINED,
                  ngx_auth_httpsig_profile_verify(pool, &pctx, fx.req, &sig,
                                                  &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_EXPIRED, result);

    ngx_auth_httpsig_keys_free(fx.keys);
    EVP_PKEY_free(fx.pkey);

    return 0;
}


TEST(profile_first_matching_tag_label_wins){
    profile_fixture_t fx;
    ngx_auth_httpsig_profile_ctx_t pctx;
    ngx_auth_httpsig_signature_t sig;
    ngx_auth_httpsig_result_t result;
    ngx_str_t input_text;

    ASSERT_EQ_INT(NGX_OK, build_fixture(pool, &fx));

    /*
     * sig0 does not match the tag. sig1 matches and is well-formed
     * (the entry that gets signed and must be selected). sig2 also
     * matches the tag but is missing "expires" - it must never be
     * consulted, since ADR 0009 picks the first matching label.
     */
    input_text = fmt(pool,
                     "sig0=(\"@method\");created=%d;expires=%d;keyid=\"%.*s\";"
                     "tag=\"other-tag\", "
                     "sig1=(\"@target-uri\" \"@authority\");created=%d;expires=%d;"
                     "keyid=\"%.*s\";tag=\"web-bot-auth\", "
                     "sig2=(\"@target-uri\" \"@authority\");created=%d;"
                     "keyid=\"%.*s\";tag=\"web-bot-auth\"",
                     TEST_NOW - 5, TEST_NOW + 55,
                     (int) fx.thumbprint.len, (char *) fx.thumbprint.data,
                     TEST_NOW - 5, TEST_NOW + 55,
                     (int) fx.thumbprint.len, (char *) fx.thumbprint.data,
                     TEST_NOW - 5,
                     (int) fx.thumbprint.len, (char *) fx.thumbprint.data);

    attach_signature(pool, &fx, &input_text, "sig1");

    pctx = build_ctx(&fx);

    ASSERT_EQ_INT(NGX_OK,
                  ngx_auth_httpsig_profile_verify(pool, &pctx, fx.req, &sig,
                                                  &result));
    ASSERT_EQ_INT(NGX_AUTH_HTTPSIG_RESULT_OK, result);
    ASSERT_EQ_INT(0,
                  sig.label.len != 4 || ngx_memcmp(sig.label.data, "sig1", 4));

    ngx_auth_httpsig_keys_free(fx.keys);
    EVP_PKEY_free(fx.pkey);

    return 0;
}


TEST_SUITE(profile){
    RUN(profile_verify_success);
    RUN(profile_agent_host_extracts_valid_host);
    RUN(profile_agent_host_rejects_invalid_bytes);
    RUN(profile_agent_host_rejects_oversized_raw_fallback);
    RUN(profile_agent_host_extracts_bracketed_ipv6);
    RUN(profile_agent_host_rejects_invalid_bracketed_bytes);
    RUN(profile_agent_authority_keeps_port);
    RUN(profile_agent_authority_omits_absent_port);
    RUN(profile_agent_authority_keeps_bracketed_ipv6_port);
    RUN(profile_agent_authority_rejects_non_https);
    RUN(profile_agent_host_dictionary_single_entry);
    RUN(profile_agent_host_dictionary_label_priority);
    RUN(profile_agent_host_dictionary_no_label_falls_back_to_first);
    RUN(profile_agent_host_dictionary_type_directory_matches);
    RUN(profile_agent_host_dictionary_type_jwks_uri_is_skipped);
    RUN(profile_agent_host_dictionary_only_unsupported_type_is_empty);
    RUN(profile_agent_host_dictionary_label_match_wrong_type_falls_through);
    RUN(profile_agent_host_dictionary_type_not_token_is_ignored);
    RUN(profile_agent_host_dictionary_lines_not_joined);
    RUN(profile_agent_host_dictionary_inner_list_member_is_skipped);
    RUN(profile_select_label_picks_first_tagged_entry);
    RUN(profile_select_label_declines_on_tag_mismatch);
    RUN(profile_select_label_declines_on_malformed_input);
    RUN(profile_select_label_declines_on_duplicate_label);
    RUN(profile_select_label_declines_on_non_inner_list_entry);
    RUN(profile_select_label_declines_on_profile_mismatch);
    RUN(profile_tag_mismatch_is_not_signed);
    RUN(profile_missing_required_param_is_mismatch);
    RUN(profile_missing_authority_and_target_uri_is_mismatch);
    RUN(profile_alg_mismatch_is_mismatch);
    RUN(profile_created_skew_boundary_passes);
    RUN(profile_created_skew_boundary_fails_beyond);
    RUN(profile_expires_past_beyond_skew_is_expired);
    RUN(profile_expires_created_window_too_wide_is_expired);
    RUN(profile_first_matching_tag_label_wins);
}
