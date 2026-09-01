/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * test_base.c - coverage for signature base string reconstruction
 * (RFC 9421 section 2.5), including a byte-exact check against the
 * ed25519 example in Appendix B.2.6.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_base.h"
#include "ngx_auth_httpsig_sfv.h"
#include "test.h"


static ngx_str_t
sfv_str(const char *s)
{
    ngx_str_t v;

    v.data = (u_char *) s;
    v.len = ngx_strlen(v.data);

    return v;
}


static void
push_header(ngx_pool_t *pool, ngx_array_t *headers, const char *name,
    const char *value)
{
    ngx_auth_httpsig_header_t *h;

    h = ngx_array_push(headers);
    h->name = sfv_str(name);
    h->value = sfv_str(value);
}


/* Builds the request state for RFC 9421's `test-request` fixture. */
static ngx_auth_httpsig_request_t *
build_test_request(ngx_pool_t *pool)
{
    ngx_auth_httpsig_request_t *req;

    req = ngx_pcalloc(pool, sizeof(ngx_auth_httpsig_request_t));

    req->method = sfv_str("POST");
    req->scheme = sfv_str("https");
    req->authority = sfv_str("example.com");
    req->path = sfv_str("/foo");
    req->query = sfv_str("param=Value&Pet=dog");
    req->has_query = 1;
    req->request_target = sfv_str("/foo?param=Value&Pet=dog");
    req->target_defined = 1;

    req->headers = ngx_array_create(pool, 8,
                                     sizeof(ngx_auth_httpsig_header_t));

    push_header(pool, req->headers, "host", "example.com");
    push_header(pool, req->headers, "date",
                "Tue, 20 Apr 2021 02:07:55 GMT");
    push_header(pool, req->headers, "content-type", "application/json");
    push_header(pool, req->headers, "content-digest",
                "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+T"
                "aPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:");
    push_header(pool, req->headers, "content-length", "18");

    return req;
}


/* Parses `s` as a top-level SFV List and returns the first member's
 * Inner List, mirroring how a Signature-Input dictionary value is
 * handed to the base layer. */
static const ngx_auth_httpsig_sfv_inner_list_t *
parse_covered(ngx_pool_t *pool, const char *s)
{
    ngx_str_t input;
    ngx_auth_httpsig_sfv_list_t *list;
    ngx_auth_httpsig_sfv_error_t err;
    ngx_auth_httpsig_sfv_value_t *members;
    ngx_int_t rc;

    input = sfv_str(s);
    rc = ngx_auth_httpsig_sfv_parse_list(pool, &input, &list, &err);

    if (rc != NGX_OK || list->members->nelts == 0) {
        return NULL;
    }

    members = list->members->elts;

    return &members[0].inner_list;
}


static ngx_auth_httpsig_sfv_item_t
build_component(ngx_pool_t *pool, const char *name)
{
    ngx_auth_httpsig_sfv_item_t item;

    item.bare.type = NGX_AUTH_HTTPSIG_SFV_STRING;
    item.bare.value = sfv_str(name);
    item.bare.integer = 0;
    item.params = ngx_array_create(pool, 1,
                                    sizeof(ngx_auth_httpsig_sfv_param_t));

    return item;
}


static void
push_param(ngx_pool_t *pool, ngx_auth_httpsig_sfv_item_t *item,
    const char *key, const char *value)
{
    ngx_auth_httpsig_sfv_param_t *p;

    p = ngx_array_push(item->params);
    p->key = sfv_str(key);
    p->value.type = NGX_AUTH_HTTPSIG_SFV_STRING;
    p->value.value = sfv_str(value);
    p->value.integer = 0;
}


static ngx_auth_httpsig_sfv_inner_list_t
build_covered(ngx_pool_t *pool, const char **names, ngx_uint_t n)
{
    ngx_auth_httpsig_sfv_inner_list_t list;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_uint_t i;

    list.items = ngx_array_create(pool, n,
                                   sizeof(ngx_auth_httpsig_sfv_item_t));
    list.params = ngx_array_create(pool, 1,
                                    sizeof(ngx_auth_httpsig_sfv_param_t));

    for (i = 0; i < n; i++) {
        item = ngx_array_push(list.items);
        *item = build_component(pool, names[i]);
    }

    return list;
}


TEST(rfc9421_appendix_b26_byte_exact)
{
    ngx_auth_httpsig_request_t *req;
    const ngx_auth_httpsig_sfv_inner_list_t *covered;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);

    covered = parse_covered(pool,
        "(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" "
        "\"content-length\");created=1618884473;keyid=\"test-key-ed25519\"");
    ASSERT(covered != NULL);

    rc = ngx_auth_httpsig_base_build(pool, req, covered, &out, &reason);
    ASSERT_EQ_INT(rc, NGX_OK);

    ASSERT_STR_EQ(out,
        "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n"
        "\"@method\": POST\n"
        "\"@path\": /foo\n"
        "\"@authority\": example.com\n"
        "\"content-type\": application/json\n"
        "\"content-length\": 18\n"
        "\"@signature-params\": (\"date\" \"@method\" \"@path\" "
        "\"@authority\" \"content-type\" \"content-length\")"
        ";created=1618884473;keyid=\"test-key-ed25519\"");

    return 0;
}


TEST(query_always_has_question_mark)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_item_t component;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    req->query = sfv_str("");
    req->has_query = 0;

    component = build_component(pool, "@query");

    rc = ngx_auth_httpsig_base_derive_component(pool, req, &component, &out,
                                                 &reason);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_STR_EQ(out, "?");

    return 0;
}


TEST(path_empty_becomes_root)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_item_t component;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    req->path = sfv_str("");

    component = build_component(pool, "@path");

    rc = ngx_auth_httpsig_base_derive_component(pool, req, &component, &out,
                                                 &reason);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_STR_EQ(out, "/");

    return 0;
}


TEST(target_uri_reconstruction)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_item_t component;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);

    component = build_component(pool, "@target-uri");

    rc = ngx_auth_httpsig_base_derive_component(pool, req, &component, &out,
                                                 &reason);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_STR_EQ(out, "https://example.com/foo?param=Value&Pet=dog");

    return 0;
}


TEST(field_value_joins_multiple_occurrences)
{
    ngx_auth_httpsig_request_t *req;
    ngx_str_t name, out;
    ngx_int_t rc;

    req = build_test_request(pool);
    push_header(pool, req->headers, "x-multi", "b");
    push_header(pool, req->headers, "x-multi", "c");

    /* Ensure the join covers occurrences beyond the first two as well. */
    {
        ngx_auth_httpsig_header_t *h;

        h = ngx_array_push(req->headers);
        h->name = sfv_str("x-multi");
        h->value = sfv_str("a");
    }

    name = sfv_str("x-multi");
    rc = ngx_auth_httpsig_base_field_value(pool, req, &name, &out);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_STR_EQ(out, "b, c, a");

    return 0;
}


TEST(field_value_joins_empty_first_occurrence)
{
    ngx_auth_httpsig_request_t *req;
    ngx_str_t name, out;
    ngx_int_t rc;

    req = build_test_request(pool);
    push_header(pool, req->headers, "x-empty", "");
    push_header(pool, req->headers, "x-empty", "b");

    name = sfv_str("x-empty");
    rc = ngx_auth_httpsig_base_field_value(pool, req, &name, &out);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_STR_EQ(out, ", b");

    return 0;
}


TEST(field_value_missing_returns_declined)
{
    ngx_auth_httpsig_request_t *req;
    ngx_str_t name, out;
    ngx_int_t rc;

    req = build_test_request(pool);

    name = sfv_str("x-absent");
    rc = ngx_auth_httpsig_base_field_value(pool, req, &name, &out);
    ASSERT_EQ_INT(rc, NGX_DECLINED);

    return 0;
}


TEST(derive_component_unknown_at_prefix)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_item_t component;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    component = build_component(pool, "@status");

    rc = ngx_auth_httpsig_base_derive_component(pool, req, &component, &out,
                                                 &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_UNKNOWN_COMPONENT);

    return 0;
}


TEST(derive_component_undefined_target)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_item_t component;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    req->target_defined = 0;

    component = build_component(pool, "@target-uri");
    rc = ngx_auth_httpsig_base_derive_component(pool, req, &component, &out,
                                                 &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_UNDEFINED_TARGET);

    component = build_component(pool, "@request-target");
    rc = ngx_auth_httpsig_base_derive_component(pool, req, &component, &out,
                                                 &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_UNDEFINED_TARGET);

    /* @path/@query must also fail closed for CONNECT authority-form and
     * OPTIONS * asterisk-form requests, not silently fall back to "/"
     * and "?": that would make the base string indistinguishable from
     * a real request for the root path. */
    component = build_component(pool, "@path");
    rc = ngx_auth_httpsig_base_derive_component(pool, req, &component, &out,
                                                 &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_UNDEFINED_TARGET);

    component = build_component(pool, "@query");
    rc = ngx_auth_httpsig_base_derive_component(pool, req, &component, &out,
                                                 &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_UNDEFINED_TARGET);

    return 0;
}


TEST(derive_component_rejects_params)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_item_t component;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    component = build_component(pool, "@method");
    push_param(pool, &component, "bs", "");

    rc = ngx_auth_httpsig_base_derive_component(pool, req, &component, &out,
                                                 &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_UNSUPPORTED_PARAM);

    return 0;
}


TEST(query_param_extracts_and_decodes)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_item_t component;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    req->query = sfv_str("greeting=hello%20world&Pet=dog");

    component = build_component(pool, "@query-param");
    push_param(pool, &component, "name", "greeting");

    rc = ngx_auth_httpsig_base_derive_component(pool, req, &component, &out,
                                                 &reason);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_STR_EQ(out, "hello+world");

    return 0;
}


TEST(query_param_name_matches_percent_encoded_key)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_item_t component;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    req->query = sfv_str("gree%74ing=hi");

    component = build_component(pool, "@query-param");
    push_param(pool, &component, "name", "greeting");

    rc = ngx_auth_httpsig_base_derive_component(pool, req, &component, &out,
                                                 &reason);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_STR_EQ(out, "hi");

    return 0;
}


TEST(query_param_value_plus_decodes_to_space)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_item_t component;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    req->query = sfv_str("greeting=hello+world");

    component = build_component(pool, "@query-param");
    push_param(pool, &component, "name", "greeting");

    rc = ngx_auth_httpsig_base_derive_component(pool, req, &component, &out,
                                                 &reason);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_STR_EQ(out, "hello+world");

    return 0;
}


TEST(query_param_name_matches_plus_encoded_space)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_item_t component;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    req->query = sfv_str("a+b=x");

    component = build_component(pool, "@query-param");
    push_param(pool, &component, "name", "a+b");

    rc = ngx_auth_httpsig_base_derive_component(pool, req, &component, &out,
                                                 &reason);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_STR_EQ(out, "x");

    return 0;
}


TEST(query_param_value_underscore_stays_unescaped)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_item_t component;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    req->query = sfv_str("greeting=token_a");

    component = build_component(pool, "@query-param");
    push_param(pool, &component, "name", "greeting");

    rc = ngx_auth_httpsig_base_derive_component(pool, req, &component, &out,
                                                 &reason);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_STR_EQ(out, "token_a");

    return 0;
}


TEST(query_param_duplicate_name_is_declined)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_item_t component;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    req->query = sfv_str("role=user&role=admin");

    component = build_component(pool, "@query-param");
    push_param(pool, &component, "name", "role");

    rc = ngx_auth_httpsig_base_derive_component(pool, req, &component, &out,
                                                 &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_MISSING_FIELD);

    return 0;
}


TEST(query_param_empty_value_is_empty_string)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_item_t component;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    req->query = sfv_str("empty=&other=x");

    component = build_component(pool, "@query-param");
    push_param(pool, &component, "name", "empty");

    rc = ngx_auth_httpsig_base_derive_component(pool, req, &component, &out,
                                                 &reason);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_EQ_INT(out.len, 0);

    return 0;
}


TEST(query_param_missing_returns_missing_field)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_item_t component;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);

    component = build_component(pool, "@query-param");
    push_param(pool, &component, "name", "absent");

    rc = ngx_auth_httpsig_base_derive_component(pool, req, &component, &out,
                                                 &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_MISSING_FIELD);

    return 0;
}


TEST(query_param_requires_name)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_item_t component;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);

    component = build_component(pool, "@query-param");

    rc = ngx_auth_httpsig_base_derive_component(pool, req, &component, &out,
                                                 &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_UNKNOWN_COMPONENT);

    return 0;
}


TEST(build_rejects_duplicate_component)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_inner_list_t covered;
    const char *names[2] = { "@method", "@method" };
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    covered = build_covered(pool, names, 2);

    rc = ngx_auth_httpsig_base_build(pool, req, &covered, &out, &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_DUPLICATE_COMPONENT);

    return 0;
}


TEST(build_rejects_uppercase_field_name)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_inner_list_t covered;
    const char *names[1] = { "Content-Type" };
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    covered = build_covered(pool, names, 1);

    rc = ngx_auth_httpsig_base_build(pool, req, &covered, &out, &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_UNKNOWN_COMPONENT);

    return 0;
}


TEST(build_rejects_unsupported_field_param)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_inner_list_t covered;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);

    covered.items = ngx_array_create(pool, 1,
                                      sizeof(ngx_auth_httpsig_sfv_item_t));
    covered.params = ngx_array_create(pool, 1,
                                       sizeof(ngx_auth_httpsig_sfv_param_t));

    item = ngx_array_push(covered.items);
    *item = build_component(pool, "content-type");
    push_param(pool, item, "sf", "");

    rc = ngx_auth_httpsig_base_build(pool, req, &covered, &out, &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_UNSUPPORTED_PARAM);

    return 0;
}


TEST(build_missing_field_fails)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_inner_list_t covered;
    const char *names[1] = { "x-absent" };
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    covered = build_covered(pool, names, 1);

    rc = ngx_auth_httpsig_base_build(pool, req, &covered, &out, &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_MISSING_FIELD);

    return 0;
}


TEST(build_too_long)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_inner_list_t covered;
    const char *names[1] = { "x-long" };
    ngx_str_t out, huge;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);

    huge.len = NGX_AUTH_HTTPSIG_MAX_BASE_LENGTH + 1;
    huge.data = ngx_pnalloc(pool, huge.len);
    ngx_memset(huge.data, 'a', huge.len);

    {
        ngx_auth_httpsig_header_t *h;

        h = ngx_array_push(req->headers);
        h->name = sfv_str("x-long");
        h->value = huge;
    }

    covered = build_covered(pool, names, 1);

    rc = ngx_auth_httpsig_base_build(pool, req, &covered, &out, &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_TOO_LONG);

    return 0;
}


TEST(agent_key_item_member_is_extracted)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_inner_list_t covered;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    push_header(pool, req->headers, "signature-agent",
                "g=\"https://agent.bot.goog\"");

    covered.items = ngx_array_create(pool, 1,
                                      sizeof(ngx_auth_httpsig_sfv_item_t));
    covered.params = ngx_array_create(pool, 1,
                                       sizeof(ngx_auth_httpsig_sfv_param_t));

    item = ngx_array_push(covered.items);
    *item = build_component(pool, "signature-agent");
    push_param(pool, item, "key", "g");

    rc = ngx_auth_httpsig_base_build(pool, req, &covered, &out, &reason);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_STR_EQ(out,
                  "\"signature-agent\";key=\"g\": "
                  "\"https://agent.bot.goog\"\n"
                  "\"@signature-params\": (\"signature-agent\";key=\"g\")");

    return 0;
}


TEST(agent_key_inner_list_member_is_extracted)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_inner_list_t covered;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    push_header(pool, req->headers, "signature-agent", "g=(1 2)");

    covered.items = ngx_array_create(pool, 1,
                                      sizeof(ngx_auth_httpsig_sfv_item_t));
    covered.params = ngx_array_create(pool, 1,
                                       sizeof(ngx_auth_httpsig_sfv_param_t));

    item = ngx_array_push(covered.items);
    *item = build_component(pool, "signature-agent");
    push_param(pool, item, "key", "g");

    rc = ngx_auth_httpsig_base_build(pool, req, &covered, &out, &reason);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_STR_EQ(out,
                  "\"signature-agent\";key=\"g\": (1 2)\n"
                  "\"@signature-params\": (\"signature-agent\";key=\"g\")");

    return 0;
}


TEST(agent_key_absent_named_key_declines)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_inner_list_t covered;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    push_header(pool, req->headers, "signature-agent",
                "h=\"https://bot.example.test\"");

    covered.items = ngx_array_create(pool, 1,
                                      sizeof(ngx_auth_httpsig_sfv_item_t));
    covered.params = ngx_array_create(pool, 1,
                                       sizeof(ngx_auth_httpsig_sfv_param_t));

    item = ngx_array_push(covered.items);
    *item = build_component(pool, "signature-agent");
    push_param(pool, item, "key", "g");

    rc = ngx_auth_httpsig_base_build(pool, req, &covered, &out, &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_MISSING_FIELD);

    return 0;
}


TEST(agent_key_non_dictionary_field_declines)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_inner_list_t covered;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    push_header(pool, req->headers, "signature-agent",
                "\"https://bot.example.test\"");

    covered.items = ngx_array_create(pool, 1,
                                      sizeof(ngx_auth_httpsig_sfv_item_t));
    covered.params = ngx_array_create(pool, 1,
                                       sizeof(ngx_auth_httpsig_sfv_param_t));

    item = ngx_array_push(covered.items);
    *item = build_component(pool, "signature-agent");
    push_param(pool, item, "key", "g");

    rc = ngx_auth_httpsig_base_build(pool, req, &covered, &out, &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_MISSING_FIELD);

    return 0;
}


TEST(agent_key_field_absent_declines)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_inner_list_t covered;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);

    covered.items = ngx_array_create(pool, 1,
                                      sizeof(ngx_auth_httpsig_sfv_item_t));
    covered.params = ngx_array_create(pool, 1,
                                       sizeof(ngx_auth_httpsig_sfv_param_t));

    item = ngx_array_push(covered.items);
    *item = build_component(pool, "signature-agent");
    push_param(pool, item, "key", "g");

    rc = ngx_auth_httpsig_base_build(pool, req, &covered, &out, &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_MISSING_FIELD);

    return 0;
}


TEST(agent_key_wrong_bare_type_falls_through_to_unsupported_param)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_inner_list_t covered;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_auth_httpsig_sfv_param_t *param;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    push_header(pool, req->headers, "signature-agent",
                "g=\"https://agent.bot.goog\"");

    covered.items = ngx_array_create(pool, 1,
                                      sizeof(ngx_auth_httpsig_sfv_item_t));
    covered.params = ngx_array_create(pool, 1,
                                       sizeof(ngx_auth_httpsig_sfv_param_t));

    item = ngx_array_push(covered.items);
    *item = build_component(pool, "signature-agent");
    push_param(pool, item, "key", "g");

    /* "key" must name a Dictionary member (a String), not merely be a
     * bare String parameter value: a Token spelled the same way falls
     * through to the generic, unconditional param rejection instead of
     * being silently accepted. */
    param = item->params->elts;
    param[0].value.type = NGX_AUTH_HTTPSIG_SFV_TOKEN;

    rc = ngx_auth_httpsig_base_build(pool, req, &covered, &out, &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_UNSUPPORTED_PARAM);

    return 0;
}


TEST(agent_key_with_redundant_sf_flag_is_accepted)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_inner_list_t covered;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_auth_httpsig_sfv_param_t *param;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    push_header(pool, req->headers, "signature-agent",
                "g=\"https://agent.bot.goog\"");

    covered.items = ngx_array_create(pool, 1,
                                      sizeof(ngx_auth_httpsig_sfv_item_t));
    covered.params = ngx_array_create(pool, 1,
                                       sizeof(ngx_auth_httpsig_sfv_param_t));

    item = ngx_array_push(covered.items);
    *item = build_component(pool, "signature-agent");
    push_param(pool, item, "key", "g");
    push_param(pool, item, "sf", "");

    /* "sf" is a Boolean flag (RFC 9421 section 2.1); its bare value is
     * never spelled as a String in the SFV grammar. */
    param = item->params->elts;
    param[1].value.type = NGX_AUTH_HTTPSIG_SFV_BOOLEAN;
    param[1].value.integer = 1;

    rc = ngx_auth_httpsig_base_build(pool, req, &covered, &out, &reason);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_STR_EQ(out,
                  "\"signature-agent\";key=\"g\";sf: "
                  "\"https://agent.bot.goog\"\n"
                  "\"@signature-params\": (\"signature-agent\";key=\"g\";sf)");

    return 0;
}


TEST(agent_key_with_false_sf_falls_through_to_unsupported_param)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_inner_list_t covered;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_auth_httpsig_sfv_param_t *param;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    push_header(pool, req->headers, "signature-agent",
                "g=\"https://agent.bot.goog\"");

    covered.items = ngx_array_create(pool, 1,
                                      sizeof(ngx_auth_httpsig_sfv_item_t));
    covered.params = ngx_array_create(pool, 1,
                                       sizeof(ngx_auth_httpsig_sfv_param_t));

    item = ngx_array_push(covered.items);
    *item = build_component(pool, "signature-agent");
    push_param(pool, item, "key", "g");
    push_param(pool, item, "sf", "");

    /* "sf=?0" does not request strict serialization at all, so it must
     * not be tolerated as the redundant-with-"key" case above. */
    param = item->params->elts;
    param[1].value.type = NGX_AUTH_HTTPSIG_SFV_BOOLEAN;
    param[1].value.integer = 0;

    rc = ngx_auth_httpsig_base_build(pool, req, &covered, &out, &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_UNSUPPORTED_PARAM);

    return 0;
}


TEST(agent_key_extra_param_falls_through_to_unsupported_param)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_inner_list_t covered;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);
    push_header(pool, req->headers, "signature-agent",
                "g=\"https://agent.bot.goog\"");

    covered.items = ngx_array_create(pool, 1,
                                      sizeof(ngx_auth_httpsig_sfv_item_t));
    covered.params = ngx_array_create(pool, 1,
                                       sizeof(ngx_auth_httpsig_sfv_param_t));

    item = ngx_array_push(covered.items);
    *item = build_component(pool, "signature-agent");
    push_param(pool, item, "key", "g");
    push_param(pool, item, "name", "extra");

    rc = ngx_auth_httpsig_base_build(pool, req, &covered, &out, &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_UNSUPPORTED_PARAM);

    return 0;
}


TEST(agent_key_scope_limited_to_signature_agent)
{
    ngx_auth_httpsig_request_t *req;
    ngx_auth_httpsig_sfv_inner_list_t covered;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_str_t out;
    ngx_auth_httpsig_base_reason_t reason;
    ngx_int_t rc;

    req = build_test_request(pool);

    covered.items = ngx_array_create(pool, 1,
                                      sizeof(ngx_auth_httpsig_sfv_item_t));
    covered.params = ngx_array_create(pool, 1,
                                       sizeof(ngx_auth_httpsig_sfv_param_t));

    item = ngx_array_push(covered.items);
    *item = build_component(pool, "content-type");
    push_param(pool, item, "key", "g");

    rc = ngx_auth_httpsig_base_build(pool, req, &covered, &out, &reason);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT_EQ_INT(reason, NGX_AUTH_HTTPSIG_BASE_UNSUPPORTED_PARAM);

    return 0;
}


TEST_SUITE(base)
{
    RUN(rfc9421_appendix_b26_byte_exact);
    RUN(query_always_has_question_mark);
    RUN(path_empty_becomes_root);
    RUN(target_uri_reconstruction);
    RUN(field_value_joins_multiple_occurrences);
    RUN(field_value_joins_empty_first_occurrence);
    RUN(field_value_missing_returns_declined);
    RUN(derive_component_unknown_at_prefix);
    RUN(derive_component_undefined_target);
    RUN(derive_component_rejects_params);
    RUN(query_param_extracts_and_decodes);
    RUN(query_param_name_matches_percent_encoded_key);
    RUN(query_param_value_plus_decodes_to_space);
    RUN(query_param_name_matches_plus_encoded_space);
    RUN(query_param_value_underscore_stays_unescaped);
    RUN(query_param_duplicate_name_is_declined);
    RUN(query_param_empty_value_is_empty_string);
    RUN(query_param_missing_returns_missing_field);
    RUN(query_param_requires_name);
    RUN(build_rejects_duplicate_component);
    RUN(build_rejects_uppercase_field_name);
    RUN(build_rejects_unsupported_field_param);
    RUN(build_missing_field_fails);
    RUN(build_too_long);
    RUN(agent_key_item_member_is_extracted);
    RUN(agent_key_inner_list_member_is_extracted);
    RUN(agent_key_absent_named_key_declines);
    RUN(agent_key_non_dictionary_field_declines);
    RUN(agent_key_field_absent_declines);
    RUN(agent_key_wrong_bare_type_falls_through_to_unsupported_param);
    RUN(agent_key_with_redundant_sf_flag_is_accepted);
    RUN(agent_key_with_false_sf_falls_through_to_unsupported_param);
    RUN(agent_key_extra_param_falls_through_to_unsupported_param);
    RUN(agent_key_scope_limited_to_signature_agent);
}
