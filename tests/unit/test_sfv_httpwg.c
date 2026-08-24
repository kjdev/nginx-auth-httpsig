/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * test_sfv_httpwg.c - runs the Structured Fields parser against the
 * httpwg/structured-field-tests vendor suite (tests/unit/vendor/).
 *
 * Each JSON file holds an array of cases. A case's "raw" field lines
 * are combined with ", " per RFC 8941 SS3.2 before parsing. "must_fail"
 * cases must be rejected; otherwise the parse result is compared
 * against "expected", and -- for Item cases only, since the SFV module
 * does not expose a List/Dictionary serializer -- re-serialized and
 * compared against "canonical", or against "raw" itself when a case
 * has no "canonical" (the suite's documented fallback).
 *
 * large-generated.json is intentionally excluded: it exists to probe
 * implementation scalability (a single 1024-entry dictionary) and
 * collides with this module's own DoS limit (MAX_SFV_ITEMS), which is
 * an implementation choice, not an RFC 8941 requirement. date.json and
 * display-string.json cover RFC 9651 types this module does not
 * implement. The serialisation-tests directory is excluded because
 * those cases have no "raw" field -- they build a value directly from
 * "expected" and serialize it, which needs a constructor API this
 * module does not expose (ngx_auth_httpsig_sfv_serialize_item() only
 * ever receives values that already parsed successfully). If the
 * vendor submodule has not been checked out, every file is reported
 * missing and the suite is skipped rather than failed.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_auth_httpsig_sfv.h"
#include "nxe_json.h"
#include "test.h"

#include <jansson.h>
#include <stdio.h>


static int
b32_val(u_char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }

    if (c >= '2' && c <= '7') {
        return c - '2' + 26;
    }

    return -1;
}


/* RFC 4648 base32 (standard alphabet), used to decode "expected" byte
 * sequences in the vendor suite. Our own parser decodes base64
 * (RFC 4648 sec 4) for the wire format; base32 only appears here as the
 * suite's JSON-safe encoding for raw bytes. */
static ngx_int_t
base32_decode(ngx_pool_t *pool, const ngx_str_t *in, ngx_str_t *out)
{
    size_t i;
    int bits, v;
    unsigned int buf;
    u_char *o;

    out->data = ngx_pnalloc(pool, in->len * 5 / 8 + 8);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    o = out->data;
    bits = 0;
    buf = 0;

    for (i = 0; i < in->len; i++) {
        if (in->data[i] == '=') {
            continue;
        }

        v = b32_val(in->data[i]);
        if (v < 0) {
            return NGX_ERROR;
        }

        buf = (buf << 5) | (unsigned int) v;
        bits += 5;

        if (bits >= 8) {
            bits -= 8;
            *o++ = (u_char) ((buf >> bits) & 0xff);
        }
    }

    out->len = (size_t) (o - out->data);

    return NGX_OK;
}


static int
compare_bare(ngx_pool_t *pool, nxe_json_t *jbare,
    const ngx_auth_httpsig_sfv_bare_t *bare)
{
    nxe_json_type_t t;
    ngx_str_t s, type_s, b32;
    int64_t iv;
    double dv;
    ngx_flag_t bv;
    nxe_json_t *type_j, *val_j;

    t = nxe_json_type(jbare);

    switch (bare->type) {

    case NGX_AUTH_HTTPSIG_SFV_INTEGER:
        if (t != NXE_JSON_INTEGER
            || nxe_json_integer(jbare, &iv) != NGX_OK)
        {
            return -1;
        }
        return iv == bare->integer ? 0 : -1;

    case NGX_AUTH_HTTPSIG_SFV_DECIMAL:
        if (t != NXE_JSON_REAL || nxe_json_real(jbare, &dv) != NGX_OK) {
            return -1;
        }
        return ((int64_t) (dv * 1000.0 + (dv >= 0 ? 0.5 : -0.5)))
                == bare->integer ? 0 : -1;

    case NGX_AUTH_HTTPSIG_SFV_STRING:
        if (t != NXE_JSON_STRING || nxe_json_string(jbare, &s) != NGX_OK) {
            return -1;
        }
        return (s.len == bare->value.len
                && ngx_memcmp(s.data, bare->value.data, s.len) == 0)
                ? 0 : -1;

    case NGX_AUTH_HTTPSIG_SFV_TOKEN:
        if (t != NXE_JSON_OBJECT) {
            return -1;
        }
        type_j = nxe_json_object_get(jbare, "__type");
        if (type_j == NULL || nxe_json_string(type_j, &type_s) != NGX_OK
            || type_s.len != 5 || ngx_memcmp(type_s.data, "token", 5) != 0)
        {
            return -1;
        }
        val_j = nxe_json_object_get(jbare, "value");
        if (val_j == NULL || nxe_json_string(val_j, &s) != NGX_OK) {
            return -1;
        }
        return (s.len == bare->value.len
                && ngx_memcmp(s.data, bare->value.data, s.len) == 0)
                ? 0 : -1;

    case NGX_AUTH_HTTPSIG_SFV_BYTE_SEQUENCE:
        if (t != NXE_JSON_OBJECT) {
            return -1;
        }
        type_j = nxe_json_object_get(jbare, "__type");
        if (type_j == NULL || nxe_json_string(type_j, &type_s) != NGX_OK
            || type_s.len != 6 || ngx_memcmp(type_s.data, "binary", 6) != 0)
        {
            return -1;
        }
        val_j = nxe_json_object_get(jbare, "value");
        if (val_j == NULL || nxe_json_string(val_j, &b32) != NGX_OK) {
            return -1;
        }
        if (base32_decode(pool, &b32, &s) != NGX_OK) {
            return -1;
        }
        return (s.len == bare->value.len
                && ngx_memcmp(s.data, bare->value.data, s.len) == 0)
                ? 0 : -1;

    case NGX_AUTH_HTTPSIG_SFV_BOOLEAN:
        if (t != NXE_JSON_BOOLEAN || nxe_json_boolean(jbare, &bv) != NGX_OK) {
            return -1;
        }
        return ((bv ? 1 : 0) == (bare->integer ? 1 : 0)) ? 0 : -1;
    }

    return -1;
}


static int
compare_params(ngx_pool_t *pool, nxe_json_t *jparams,
    const ngx_array_t *params)
{
    size_t n, i;
    ngx_auth_httpsig_sfv_param_t *p;
    nxe_json_t *pair, *jkey, *jval;
    ngx_str_t key;

    if (nxe_json_type(jparams) != NXE_JSON_ARRAY) {
        return -1;
    }

    n = nxe_json_array_size(jparams);

    if (params == NULL) {
        return n == 0 ? 0 : -1;
    }

    if (n != (size_t) params->nelts) {
        return -1;
    }

    p = params->elts;

    for (i = 0; i < n; i++) {
        pair = nxe_json_array_get(jparams, i);
        if (nxe_json_type(pair) != NXE_JSON_ARRAY
            || nxe_json_array_size(pair) != 2)
        {
            return -1;
        }

        jkey = nxe_json_array_get(pair, 0);
        jval = nxe_json_array_get(pair, 1);

        if (nxe_json_string(jkey, &key) != NGX_OK) {
            return -1;
        }

        if (key.len != p[i].key.len
            || ngx_memcmp(key.data, p[i].key.data, key.len) != 0)
        {
            return -1;
        }

        if (compare_bare(pool, jval, &p[i].value) != 0) {
            return -1;
        }
    }

    return 0;
}


static int
compare_item_tuple(ngx_pool_t *pool, nxe_json_t *jtuple,
    const ngx_auth_httpsig_sfv_item_t *item)
{
    nxe_json_t *jbare, *jparams;

    if (nxe_json_type(jtuple) != NXE_JSON_ARRAY
        || nxe_json_array_size(jtuple) != 2)
    {
        return -1;
    }

    jbare = nxe_json_array_get(jtuple, 0);
    jparams = nxe_json_array_get(jtuple, 1);

    if (compare_bare(pool, jbare, &item->bare) != 0) {
        return -1;
    }

    return compare_params(pool, jparams, item->params);
}


static int
compare_member_tuple(ngx_pool_t *pool, nxe_json_t *jtuple,
    const ngx_auth_httpsig_sfv_value_t *value)
{
    nxe_json_t *jfirst, *jparams;
    size_t n, i;
    ngx_auth_httpsig_sfv_item_t *items;

    if (nxe_json_type(jtuple) != NXE_JSON_ARRAY
        || nxe_json_array_size(jtuple) != 2)
    {
        return -1;
    }

    jfirst = nxe_json_array_get(jtuple, 0);
    jparams = nxe_json_array_get(jtuple, 1);

    if (nxe_json_type(jfirst) == NXE_JSON_ARRAY) {
        if (value->type != NGX_AUTH_HTTPSIG_SFV_MEMBER_INNER_LIST) {
            return -1;
        }

        n = nxe_json_array_size(jfirst);
        if (n != (size_t) value->inner_list.items->nelts) {
            return -1;
        }

        items = value->inner_list.items->elts;

        for (i = 0; i < n; i++) {
            if (compare_item_tuple(pool, nxe_json_array_get(jfirst, i),
                                   &items[i])
                != 0)
            {
                return -1;
            }
        }

        return compare_params(pool, jparams, value->inner_list.params);
    }

    if (value->type != NGX_AUTH_HTTPSIG_SFV_MEMBER_ITEM) {
        return -1;
    }

    if (compare_bare(pool, jfirst, &value->item.bare) != 0) {
        return -1;
    }

    return compare_params(pool, jparams, value->item.params);
}


static int
compare_list(ngx_pool_t *pool, nxe_json_t *jexpected,
    const ngx_auth_httpsig_sfv_list_t *list)
{
    size_t n, i;
    ngx_auth_httpsig_sfv_value_t *members;

    if (nxe_json_type(jexpected) != NXE_JSON_ARRAY) {
        return -1;
    }

    n = nxe_json_array_size(jexpected);
    if (n != (size_t) list->members->nelts) {
        return -1;
    }

    members = list->members->elts;

    for (i = 0; i < n; i++) {
        if (compare_member_tuple(pool, nxe_json_array_get(jexpected, i),
                                 &members[i])
            != 0)
        {
            return -1;
        }
    }

    return 0;
}


static int
compare_dictionary(ngx_pool_t *pool, nxe_json_t *jexpected,
    const ngx_auth_httpsig_sfv_dictionary_t *dict)
{
    size_t n, i;
    ngx_auth_httpsig_sfv_dict_entry_t *entries;
    nxe_json_t *pair, *jkey, *jvalue;
    ngx_str_t key;

    if (nxe_json_type(jexpected) != NXE_JSON_ARRAY) {
        return -1;
    }

    n = nxe_json_array_size(jexpected);
    if (n != (size_t) dict->entries->nelts) {
        return -1;
    }

    entries = dict->entries->elts;

    for (i = 0; i < n; i++) {
        pair = nxe_json_array_get(jexpected, i);
        if (nxe_json_type(pair) != NXE_JSON_ARRAY
            || nxe_json_array_size(pair) != 2)
        {
            return -1;
        }

        jkey = nxe_json_array_get(pair, 0);
        jvalue = nxe_json_array_get(pair, 1);

        if (nxe_json_string(jkey, &key) != NGX_OK) {
            return -1;
        }

        if (key.len != entries[i].key.len
            || ngx_memcmp(key.data, entries[i].key.data, key.len) != 0)
        {
            return -1;
        }

        if (compare_member_tuple(pool, jvalue, &entries[i].value) != 0) {
            return -1;
        }
    }

    return 0;
}


static ngx_int_t
read_file(ngx_pool_t *pool, const char *path, ngx_str_t *out)
{
    FILE *f;
    long size;

    f = fopen(path, "rb");
    if (f == NULL) {
        return NGX_DECLINED;
    }

    if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0
        || fseek(f, 0, SEEK_SET) != 0)
    {
        fclose(f);
        return NGX_ERROR;
    }

    out->data = ngx_pnalloc(pool, (size_t) size);
    if (out->data == NULL) {
        fclose(f);
        return NGX_ERROR;
    }

    if (size > 0 && fread(out->data, 1, (size_t) size, f) != (size_t) size) {
        fclose(f);
        return NGX_ERROR;
    }

    fclose(f);
    out->len = (size_t) size;

    return NGX_OK;
}


static int
join_raw(ngx_pool_t *pool, nxe_json_t *jraw, ngx_str_t *out)
{
    size_t n, i, total;
    u_char *p;
    ngx_str_t line;

    if (nxe_json_type(jraw) != NXE_JSON_ARRAY) {
        return -1;
    }

    n = nxe_json_array_size(jraw);
    total = 0;

    for (i = 0; i < n; i++) {
        if (nxe_json_string(nxe_json_array_get(jraw, i), &line) != NGX_OK) {
            return -1;
        }
        total += line.len;
        if (i > 0) {
            total += 2;
        }
    }

    out->data = ngx_pnalloc(pool, total ? total : 1);
    if (out->data == NULL) {
        return -1;
    }

    p = out->data;

    for (i = 0; i < n; i++) {
        nxe_json_string(nxe_json_array_get(jraw, i), &line);
        if (i > 0) {
            *p++ = ',';
            *p++ = ' ';
        }
        ngx_memcpy(p, line.data, line.len);
        p += line.len;
    }

    out->len = total;

    return 0;
}


static int
process_case(ngx_pool_t *pool, nxe_json_t *jcase, const char *file,
    size_t idx)
{
    nxe_json_t *jraw, *jname, *jtype, *jflag, *jexpected, *jcanonical;
    ngx_str_t name, header_type, input, out, expected_line;
    ngx_flag_t must_fail, can_fail;
    ngx_int_t rc;
    ngx_auth_httpsig_sfv_error_t err;

    ngx_str_null(&name);

    jname = nxe_json_object_get(jcase, "name");
    if (jname != NULL) {
        nxe_json_string(jname, &name);
    }

    jraw = nxe_json_object_get(jcase, "raw");
    if (jraw == NULL || join_raw(pool, jraw, &input) != 0) {
        fprintf(stderr, "  FAIL  %s#%zu %.*s: missing/invalid raw\n", file,
                idx, (int) name.len, name.data);
        return -1;
    }

    jtype = nxe_json_object_get(jcase, "header_type");
    if (jtype == NULL || nxe_json_string(jtype, &header_type) != NGX_OK) {
        fprintf(stderr, "  FAIL  %s#%zu %.*s: missing header_type\n", file,
                idx, (int) name.len, name.data);
        return -1;
    }

    must_fail = 0;
    jflag = nxe_json_object_get(jcase, "must_fail");
    if (jflag != NULL) {
        nxe_json_boolean(jflag, &must_fail);
    }

    can_fail = 0;
    jflag = nxe_json_object_get(jcase, "can_fail");
    if (jflag != NULL) {
        nxe_json_boolean(jflag, &can_fail);
    }

    jexpected = nxe_json_object_get(jcase, "expected");
    jcanonical = nxe_json_object_get(jcase, "canonical");

    if (header_type.len == 4 && ngx_memcmp(header_type.data, "item", 4) == 0)
    {
        ngx_auth_httpsig_sfv_item_t *item;

        rc = ngx_auth_httpsig_sfv_parse_item(pool, &input, &item, &err);

        if (must_fail) {
            if (rc == NGX_OK) {
                fprintf(stderr, "  FAIL  %s#%zu %.*s: expected parse "
                        "failure\n", file, idx, (int) name.len, name.data);
                return -1;
            }
            return 0;
        }

        if (rc != NGX_OK) {
            if (can_fail) {
                return 0;
            }
            fprintf(stderr, "  FAIL  %s#%zu %.*s: parse failed: %s\n", file,
                    idx, (int) name.len, name.data, err.reason);
            return -1;
        }

        if (jexpected != NULL
            && compare_item_tuple(pool, jexpected, item) != 0)
        {
            fprintf(stderr, "  FAIL  %s#%zu %.*s: value mismatch\n", file,
                    idx, (int) name.len, name.data);
            return -1;
        }

        /*
         * Per the httpwg test suite README, the expected serialization
         * is "canonical" if present, or "raw" (already joined into
         * `input`) otherwise -- there is no case where neither applies.
         */
        if (jcanonical != NULL) {
            if (join_raw(pool, jcanonical, &expected_line) != 0) {
                fprintf(stderr, "  FAIL  %s#%zu %.*s: invalid canonical\n",
                        file, idx, (int) name.len, name.data);
                return -1;
            }

        } else {
            expected_line = input;
        }

        if (ngx_auth_httpsig_sfv_serialize_item(pool, item, &out) != NGX_OK)
        {
            fprintf(stderr, "  FAIL  %s#%zu %.*s: serialize failed\n",
                    file, idx, (int) name.len, name.data);
            return -1;
        }

        if (out.len != expected_line.len
            || ngx_memcmp(out.data, expected_line.data, out.len) != 0)
        {
            fprintf(stderr, "  FAIL  %s#%zu %.*s: canonical mismatch\n",
                    file, idx, (int) name.len, name.data);
            return -1;
        }

        return 0;
    }

    if (header_type.len == 4 && ngx_memcmp(header_type.data, "list", 4) == 0)
    {
        ngx_auth_httpsig_sfv_list_t *list;

        rc = ngx_auth_httpsig_sfv_parse_list(pool, &input, &list, &err);

        if (must_fail) {
            if (rc == NGX_OK) {
                fprintf(stderr, "  FAIL  %s#%zu %.*s: expected parse "
                        "failure\n", file, idx, (int) name.len, name.data);
                return -1;
            }
            return 0;
        }

        if (rc != NGX_OK) {
            if (can_fail) {
                return 0;
            }
            fprintf(stderr, "  FAIL  %s#%zu %.*s: parse failed: %s\n", file,
                    idx, (int) name.len, name.data, err.reason);
            return -1;
        }

        if (jexpected != NULL && compare_list(pool, jexpected, list) != 0) {
            fprintf(stderr, "  FAIL  %s#%zu %.*s: value mismatch\n", file,
                    idx, (int) name.len, name.data);
            return -1;
        }

        return 0;
    }

    if (header_type.len == 10
        && ngx_memcmp(header_type.data, "dictionary", 10) == 0)
    {
        ngx_auth_httpsig_sfv_dictionary_t *dict;

        rc = ngx_auth_httpsig_sfv_parse_dictionary(pool, &input, &dict,
                                                    &err);

        if (must_fail) {
            if (rc == NGX_OK) {
                fprintf(stderr, "  FAIL  %s#%zu %.*s: expected parse "
                        "failure\n", file, idx, (int) name.len, name.data);
                return -1;
            }
            return 0;
        }

        if (rc != NGX_OK) {
            if (can_fail) {
                return 0;
            }
            fprintf(stderr, "  FAIL  %s#%zu %.*s: parse failed: %s\n", file,
                    idx, (int) name.len, name.data, err.reason);
            return -1;
        }

        if (jexpected != NULL
            && compare_dictionary(pool, jexpected, dict) != 0)
        {
            fprintf(stderr, "  FAIL  %s#%zu %.*s: value mismatch\n", file,
                    idx, (int) name.len, name.data);
            return -1;
        }

        return 0;
    }

    fprintf(stderr, "  FAIL  %s#%zu %.*s: unknown header_type\n", file, idx,
            (int) name.len, name.data);
    return -1;
}


/*
 * nxe_json_parse() does not pass JSON_ALLOW_NUL, so it rejects any
 * JSON string that decodes to a value containing an embedded NUL --
 * which some generated vendor cases use to exercise NUL handling.
 * Retry with jansson directly in that case; the resulting json_t is
 * safe to hand to the nxe_json_* accessors, since nxe_json_t is
 * jansson's json_t under an opaque name.
 */
static nxe_json_t *
parse_allow_nul(ngx_str_t *data)
{
    json_error_t error;

    return (nxe_json_t *) json_loadb((const char *) data->data, data->len,
                                     JSON_DECODE_ANY | JSON_REJECT_DUPLICATES
                                     | JSON_ALLOW_NUL, &error);
}


static int
run_httpwg_file(ngx_pool_t *pool, const char *path)
{
    ngx_str_t data;
    nxe_json_t *root;
    size_t n, i;
    int failed;
    ngx_int_t rc;

    rc = read_file(pool, path, &data);
    if (rc == NGX_DECLINED) {
        return 1;
    }

    if (rc != NGX_OK) {
        fprintf(stderr, "  FAIL  %s: cannot read file\n", path);
        return -1;
    }

    root = nxe_json_parse(&data, NULL);
    if (root == NULL) {
        root = parse_allow_nul(&data);
    }

    if (root == NULL || nxe_json_type(root) != NXE_JSON_ARRAY) {
        fprintf(stderr, "  FAIL  %s: invalid JSON\n", path);
        nxe_json_free(root);
        return -1;
    }

    failed = 0;
    n = nxe_json_array_size(root);

    for (i = 0; i < n; i++) {
        if (process_case(pool, nxe_json_array_get(root, i), path, i) != 0) {
            failed = 1;
        }
    }

    nxe_json_free(root);

    return failed ? -1 : 0;
}


TEST(httpwg)
{
    static const char *files[] = {
        "vendor/structured-field-tests/boolean.json",
        "vendor/structured-field-tests/token.json",
        "vendor/structured-field-tests/token-generated.json",
        "vendor/structured-field-tests/key-generated.json",
        "vendor/structured-field-tests/string.json",
        "vendor/structured-field-tests/string-generated.json",
        "vendor/structured-field-tests/number.json",
        "vendor/structured-field-tests/number-generated.json",
        "vendor/structured-field-tests/binary.json",
        "vendor/structured-field-tests/item.json",
        "vendor/structured-field-tests/list.json",
        "vendor/structured-field-tests/listlist.json",
        "vendor/structured-field-tests/dictionary.json",
        "vendor/structured-field-tests/param-dict.json",
        "vendor/structured-field-tests/param-list.json",
        "vendor/structured-field-tests/param-listlist.json",
        "vendor/structured-field-tests/examples.json",
    };
    size_t i;
    int rc, present, failed;

    present = 0;
    failed = 0;

    for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        rc = run_httpwg_file(pool, files[i]);
        if (rc == 1) {
            continue;
        }
        present = 1;
        if (rc != 0) {
            failed = 1;
        }
    }

    if (!present) {
        fprintf(stderr, "  SKIP  structured-field-tests submodule not "
                "checked out\n");
        return 0;
    }

    return failed ? -1 : 0;
}


TEST_SUITE(sfv_httpwg)
{
    RUN(httpwg);
}
