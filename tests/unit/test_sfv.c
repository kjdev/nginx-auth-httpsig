/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * test_sfv.c - hand-written coverage for the Structured Fields parser and
 * serializer: DoS limits, Integer/Decimal boundaries, duplicate-key
 * folding, the three top-level forms, and serialization round trips.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_sfv.h"
#include "test.h"

#include <stdio.h>


static ngx_str_t
sfv_str(const char *s)
{
    ngx_str_t v;

    v.data = (u_char *) s;
    v.len = ngx_strlen(v.data);

    return v;
}


static ngx_str_t
build_item_list(ngx_pool_t *pool, ngx_uint_t count)
{
    ngx_str_t out;
    u_char *p;
    ngx_uint_t i;

    out.data = ngx_pnalloc(pool, count * 3);
    p = out.data;

    for (i = 0; i < count; i++) {
        if (i > 0) {
            *p++ = ',';
            *p++ = ' ';
        }
        *p++ = 'a';
    }

    out.len = (size_t) (p - out.data);

    return out;
}


static ngx_str_t
build_inner_list(ngx_pool_t *pool, ngx_uint_t count)
{
    ngx_str_t out;
    u_char *p;
    ngx_uint_t i;

    out.data = ngx_pnalloc(pool, count * 2 + 2);
    p = out.data;
    *p++ = '(';

    for (i = 0; i < count; i++) {
        if (i > 0) {
            *p++ = ' ';
        }
        *p++ = 'a';
    }

    *p++ = ')';
    out.len = (size_t) (p - out.data);

    return out;
}


static ngx_str_t
build_dict(ngx_pool_t *pool, ngx_uint_t count)
{
    ngx_str_t out;
    u_char *p;
    ngx_uint_t i;
    char numbuf[16];
    int n;

    out.data = ngx_pnalloc(pool, count * 24);
    p = out.data;

    for (i = 0; i < count; i++) {
        if (i > 0) {
            *p++ = ',';
            *p++ = ' ';
        }

        *p++ = 'k';
        n = snprintf(numbuf, sizeof(numbuf), "%u", (unsigned int) i);
        ngx_memcpy(p, numbuf, (size_t) n);
        p += n;
        *p++ = '=';
        *p++ = '1';
    }

    out.len = (size_t) (p - out.data);

    return out;
}


static ngx_str_t
build_params(ngx_pool_t *pool, ngx_uint_t count)
{
    ngx_str_t out;
    u_char *p;
    ngx_uint_t i;
    char numbuf[16];
    int n;

    out.data = ngx_pnalloc(pool, 1 + count * 8);
    p = out.data;
    *p++ = 'a';

    for (i = 0; i < count; i++) {
        *p++ = ';';
        *p++ = 'p';
        n = snprintf(numbuf, sizeof(numbuf), "%u", (unsigned int) i);
        ngx_memcpy(p, numbuf, (size_t) n);
        p += n;
    }

    out.len = (size_t) (p - out.data);

    return out;
}


TEST(length_limit)
{
    ngx_str_t input;
    ngx_auth_httpsig_sfv_dictionary_t *dict;
    ngx_auth_httpsig_sfv_error_t err;
    ngx_int_t rc;

    input.len = NGX_AUTH_HTTPSIG_MAX_SFV_LENGTH + 1;
    input.data = ngx_pnalloc(pool, input.len);
    ngx_memset(input.data, 'a', input.len);

    rc = ngx_auth_httpsig_sfv_parse_dictionary(pool, &input, &dict, &err);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT(ngx_strcmp((u_char *) err.reason, (u_char *) "input too long")
           == 0);

    return 0;
}


TEST(too_many_dictionary_entries)
{
    ngx_str_t input;
    ngx_auth_httpsig_sfv_dictionary_t *dict;
    ngx_auth_httpsig_sfv_error_t err;
    ngx_int_t rc;

    input = build_dict(pool, NGX_AUTH_HTTPSIG_MAX_SFV_ITEMS + 1);

    rc = ngx_auth_httpsig_sfv_parse_dictionary(pool, &input, &dict, &err);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT(ngx_strcmp((u_char *) err.reason,
                      (u_char *) "too many dictionary entries") == 0);

    input = build_dict(pool, NGX_AUTH_HTTPSIG_MAX_SFV_ITEMS);
    rc = ngx_auth_httpsig_sfv_parse_dictionary(pool, &input, &dict, &err);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_EQ_INT(dict->entries->nelts, NGX_AUTH_HTTPSIG_MAX_SFV_ITEMS);

    return 0;
}


TEST(too_many_list_members)
{
    ngx_str_t input;
    ngx_auth_httpsig_sfv_list_t *list;
    ngx_auth_httpsig_sfv_error_t err;
    ngx_int_t rc;

    input = build_item_list(pool, NGX_AUTH_HTTPSIG_MAX_SFV_ITEMS + 1);

    rc = ngx_auth_httpsig_sfv_parse_list(pool, &input, &list, &err);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT(ngx_strcmp((u_char *) err.reason,
                      (u_char *) "too many list members") == 0);

    input = build_item_list(pool, NGX_AUTH_HTTPSIG_MAX_SFV_ITEMS);
    rc = ngx_auth_httpsig_sfv_parse_list(pool, &input, &list, &err);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_EQ_INT(list->members->nelts, NGX_AUTH_HTTPSIG_MAX_SFV_ITEMS);

    return 0;
}


TEST(too_many_inner_list_items)
{
    ngx_str_t input;
    ngx_auth_httpsig_sfv_list_t *list;
    ngx_auth_httpsig_sfv_error_t err;
    ngx_int_t rc;

    input = build_inner_list(pool, NGX_AUTH_HTTPSIG_MAX_SFV_ITEMS + 1);

    rc = ngx_auth_httpsig_sfv_parse_list(pool, &input, &list, &err);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT(ngx_strcmp((u_char *) err.reason,
                      (u_char *) "too many inner list items") == 0);

    return 0;
}


TEST(too_many_parameters)
{
    ngx_str_t input;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_auth_httpsig_sfv_error_t err;
    ngx_int_t rc;

    input = build_params(pool, NGX_AUTH_HTTPSIG_MAX_SFV_PARAMS + 1);

    rc = ngx_auth_httpsig_sfv_parse_item(pool, &input, &item, &err);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT(ngx_strcmp((u_char *) err.reason, (u_char *) "too many parameters")
           == 0);

    input = build_params(pool, NGX_AUTH_HTTPSIG_MAX_SFV_PARAMS);
    rc = ngx_auth_httpsig_sfv_parse_item(pool, &input, &item, &err);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_EQ_INT(item->params->nelts, NGX_AUTH_HTTPSIG_MAX_SFV_PARAMS);

    return 0;
}


TEST(integer_boundaries)
{
    ngx_str_t input;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_auth_httpsig_sfv_error_t err;
    ngx_int_t rc;

    input = sfv_str("999999999999999");
    rc = ngx_auth_httpsig_sfv_parse_item(pool, &input, &item, &err);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_EQ_INT(item->bare.type, NGX_AUTH_HTTPSIG_SFV_INTEGER);
    ASSERT_EQ_INT(item->bare.integer, 999999999999999LL);

    input = sfv_str("9999999999999999");
    rc = ngx_auth_httpsig_sfv_parse_item(pool, &input, &item, &err);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT(ngx_strcmp((u_char *) err.reason, (u_char *) "number too long")
           == 0);

    return 0;
}


TEST(decimal_boundaries)
{
    ngx_str_t input;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_auth_httpsig_sfv_error_t err;
    ngx_int_t rc;

    input = sfv_str("123456789012.123");
    rc = ngx_auth_httpsig_sfv_parse_item(pool, &input, &item, &err);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_EQ_INT(item->bare.type, NGX_AUTH_HTTPSIG_SFV_DECIMAL);
    ASSERT_EQ_INT(item->bare.integer, 123456789012123LL);

    input = sfv_str("1234567890123.1");
    rc = ngx_auth_httpsig_sfv_parse_item(pool, &input, &item, &err);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT(ngx_strcmp((u_char *) err.reason,
                      (u_char *) "decimal integer part too long") == 0);

    input = sfv_str("1.1234");
    rc = ngx_auth_httpsig_sfv_parse_item(pool, &input, &item, &err);
    ASSERT_EQ_INT(rc, NGX_DECLINED);
    ASSERT(ngx_strcmp((u_char *) err.reason,
                      (u_char *) "decimal fraction too long") == 0);

    return 0;
}


TEST(duplicate_keys)
{
    ngx_str_t input;
    ngx_auth_httpsig_sfv_dictionary_t *dict;
    ngx_auth_httpsig_sfv_error_t err;
    ngx_int_t rc;
    ngx_auth_httpsig_sfv_dict_entry_t *entries;

    input = sfv_str("a=1, b=2, a=3");
    rc = ngx_auth_httpsig_sfv_parse_dictionary(pool, &input, &dict, &err);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_EQ_INT(dict->duplicate_keys, 1);
    ASSERT_EQ_INT(dict->entries->nelts, 2);

    entries = dict->entries->elts;
    ASSERT_STR_EQ(entries[0].key, "a");
    ASSERT_EQ_INT(entries[0].value.item.bare.integer, 3);
    ASSERT_STR_EQ(entries[1].key, "b");
    ASSERT_EQ_INT(entries[1].value.item.bare.integer, 2);

    return 0;
}


TEST(parse_dictionary_real)
{
    ngx_str_t input;
    ngx_auth_httpsig_sfv_dictionary_t *dict;
    ngx_auth_httpsig_sfv_error_t err;
    ngx_int_t rc;
    ngx_str_t key;
    const ngx_auth_httpsig_sfv_value_t *v;
    const ngx_auth_httpsig_sfv_bare_t *p;

    input = sfv_str("a=1, b=2.5, c=?1, d=?0, e=\"hello\", "
                     "f=:aGVsbG8=:, g=(1 2 3);p=1, h");
    rc = ngx_auth_httpsig_sfv_parse_dictionary(pool, &input, &dict, &err);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_EQ_INT(dict->duplicate_keys, 0);
    ASSERT_EQ_INT(dict->entries->nelts, 8);

    key = sfv_str("a");
    v = ngx_auth_httpsig_sfv_dict_get(dict, &key);
    ASSERT(v != NULL);
    ASSERT_EQ_INT(v->type, NGX_AUTH_HTTPSIG_SFV_MEMBER_ITEM);
    ASSERT_EQ_INT(v->item.bare.type, NGX_AUTH_HTTPSIG_SFV_INTEGER);
    ASSERT_EQ_INT(v->item.bare.integer, 1);

    key = sfv_str("b");
    v = ngx_auth_httpsig_sfv_dict_get(dict, &key);
    ASSERT(v != NULL);
    ASSERT_EQ_INT(v->item.bare.type, NGX_AUTH_HTTPSIG_SFV_DECIMAL);
    ASSERT_EQ_INT(v->item.bare.integer, 2500);

    key = sfv_str("c");
    v = ngx_auth_httpsig_sfv_dict_get(dict, &key);
    ASSERT(v != NULL);
    ASSERT_EQ_INT(v->item.bare.type, NGX_AUTH_HTTPSIG_SFV_BOOLEAN);
    ASSERT_EQ_INT(v->item.bare.integer, 1);

    key = sfv_str("d");
    v = ngx_auth_httpsig_sfv_dict_get(dict, &key);
    ASSERT(v != NULL);
    ASSERT_EQ_INT(v->item.bare.type, NGX_AUTH_HTTPSIG_SFV_BOOLEAN);
    ASSERT_EQ_INT(v->item.bare.integer, 0);

    key = sfv_str("e");
    v = ngx_auth_httpsig_sfv_dict_get(dict, &key);
    ASSERT(v != NULL);
    ASSERT_EQ_INT(v->item.bare.type, NGX_AUTH_HTTPSIG_SFV_STRING);
    ASSERT_STR_EQ(v->item.bare.value, "hello");

    key = sfv_str("f");
    v = ngx_auth_httpsig_sfv_dict_get(dict, &key);
    ASSERT(v != NULL);
    ASSERT_EQ_INT(v->item.bare.type, NGX_AUTH_HTTPSIG_SFV_BYTE_SEQUENCE);
    ASSERT_STR_EQ(v->item.bare.value, "hello");

    key = sfv_str("g");
    v = ngx_auth_httpsig_sfv_dict_get(dict, &key);
    ASSERT(v != NULL);
    ASSERT_EQ_INT(v->type, NGX_AUTH_HTTPSIG_SFV_MEMBER_INNER_LIST);
    ASSERT_EQ_INT(v->inner_list.items->nelts, 3);
    p = ngx_auth_httpsig_sfv_param_get(v->inner_list.params, "p");
    ASSERT(p != NULL);
    ASSERT_EQ_INT(p->integer, 1);

    key = sfv_str("h");
    v = ngx_auth_httpsig_sfv_dict_get(dict, &key);
    ASSERT(v != NULL);
    ASSERT_EQ_INT(v->item.bare.type, NGX_AUTH_HTTPSIG_SFV_BOOLEAN);
    ASSERT_EQ_INT(v->item.bare.integer, 1);

    return 0;
}


TEST(parse_list_real)
{
    ngx_str_t input;
    ngx_auth_httpsig_sfv_list_t *list;
    ngx_auth_httpsig_sfv_error_t err;
    ngx_int_t rc;
    ngx_auth_httpsig_sfv_value_t *members;
    const ngx_auth_httpsig_sfv_bare_t *p;

    input = sfv_str("1, 2.5, \"hi\", token123, :aGVsbG8=:, ?1, (1 2);p");
    rc = ngx_auth_httpsig_sfv_parse_list(pool, &input, &list, &err);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_EQ_INT(list->members->nelts, 7);

    members = list->members->elts;

    ASSERT_EQ_INT(members[0].item.bare.type, NGX_AUTH_HTTPSIG_SFV_INTEGER);
    ASSERT_EQ_INT(members[0].item.bare.integer, 1);

    ASSERT_EQ_INT(members[1].item.bare.type, NGX_AUTH_HTTPSIG_SFV_DECIMAL);
    ASSERT_EQ_INT(members[1].item.bare.integer, 2500);

    ASSERT_EQ_INT(members[2].item.bare.type, NGX_AUTH_HTTPSIG_SFV_STRING);
    ASSERT_STR_EQ(members[2].item.bare.value, "hi");

    ASSERT_EQ_INT(members[3].item.bare.type, NGX_AUTH_HTTPSIG_SFV_TOKEN);
    ASSERT_STR_EQ(members[3].item.bare.value, "token123");

    ASSERT_EQ_INT(members[4].item.bare.type,
                  NGX_AUTH_HTTPSIG_SFV_BYTE_SEQUENCE);
    ASSERT_STR_EQ(members[4].item.bare.value, "hello");

    ASSERT_EQ_INT(members[5].item.bare.type, NGX_AUTH_HTTPSIG_SFV_BOOLEAN);
    ASSERT_EQ_INT(members[5].item.bare.integer, 1);

    ASSERT_EQ_INT(members[6].type, NGX_AUTH_HTTPSIG_SFV_MEMBER_INNER_LIST);
    ASSERT_EQ_INT(members[6].inner_list.items->nelts, 2);
    p = ngx_auth_httpsig_sfv_param_get(members[6].inner_list.params, "p");
    ASSERT(p != NULL);
    ASSERT_EQ_INT(p->type, NGX_AUTH_HTTPSIG_SFV_BOOLEAN);
    ASSERT_EQ_INT(p->integer, 1);

    return 0;
}


TEST(parse_item_real)
{
    ngx_str_t input;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_auth_httpsig_sfv_error_t err;
    ngx_int_t rc;
    const ngx_auth_httpsig_sfv_bare_t *p;

    input = sfv_str("foo;a=1;b=2");
    rc = ngx_auth_httpsig_sfv_parse_item(pool, &input, &item, &err);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_EQ_INT(item->bare.type, NGX_AUTH_HTTPSIG_SFV_TOKEN);
    ASSERT_STR_EQ(item->bare.value, "foo");
    ASSERT_EQ_INT(item->params->nelts, 2);

    p = ngx_auth_httpsig_sfv_param_get(item->params, "a");
    ASSERT(p != NULL);
    ASSERT_EQ_INT(p->integer, 1);

    p = ngx_auth_httpsig_sfv_param_get(item->params, "b");
    ASSERT(p != NULL);
    ASSERT_EQ_INT(p->integer, 2);

    return 0;
}


TEST(serialize_round_trip)
{
    ngx_str_t input, out;
    ngx_auth_httpsig_sfv_item_t *item;
    ngx_auth_httpsig_sfv_error_t err;
    ngx_int_t rc;

    input = sfv_str("foo;a;b=2");
    rc = ngx_auth_httpsig_sfv_parse_item(pool, &input, &item, &err);
    ASSERT_EQ_INT(rc, NGX_OK);
    rc = ngx_auth_httpsig_sfv_serialize_item(pool, item, &out);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_STR_EQ(out, "foo;a;b=2");

    input = sfv_str("1.500");
    rc = ngx_auth_httpsig_sfv_parse_item(pool, &input, &item, &err);
    ASSERT_EQ_INT(rc, NGX_OK);
    rc = ngx_auth_httpsig_sfv_serialize_item(pool, item, &out);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_STR_EQ(out, "1.5");

    input = sfv_str("2.000");
    rc = ngx_auth_httpsig_sfv_parse_item(pool, &input, &item, &err);
    ASSERT_EQ_INT(rc, NGX_OK);
    rc = ngx_auth_httpsig_sfv_serialize_item(pool, item, &out);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_STR_EQ(out, "2.0");

    input = sfv_str(":aGVsbG8=:");
    rc = ngx_auth_httpsig_sfv_parse_item(pool, &input, &item, &err);
    ASSERT_EQ_INT(rc, NGX_OK);
    rc = ngx_auth_httpsig_sfv_serialize_item(pool, item, &out);
    ASSERT_EQ_INT(rc, NGX_OK);
    ASSERT_STR_EQ(out, ":aGVsbG8=:");

    return 0;
}


TEST_SUITE(sfv)
{
    RUN(length_limit);
    RUN(too_many_dictionary_entries);
    RUN(too_many_list_members);
    RUN(too_many_inner_list_items);
    RUN(too_many_parameters);
    RUN(integer_boundaries);
    RUN(decimal_boundaries);
    RUN(duplicate_keys);
    RUN(parse_dictionary_real);
    RUN(parse_list_real);
    RUN(parse_item_real);
    RUN(serialize_round_trip);
}
