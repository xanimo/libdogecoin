/*

 The MIT License (MIT)

 Copyright (c) 2026 bluezr
 Copyright (c) 2026 The Dogecoin Foundation

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/

#include <string.h>

#include <test/utest.h>

#include <dogecoin/golomb.h>
#include <dogecoin/mem.h>
#include <dogecoin/serialize.h>

static void cstr_free_cb(void *p) { cstr_free((cstring *)p, true); }

/* ================================================================ */
/*  Bitwriter / Bitreader                                          */
/* ================================================================ */

static void test_bitwriter_basic(void)
{
    gcs_bitwriter w;
    gcs_bitwriter_init(&w, 4);

    /* Write 10 bits: 1 0 1 1 0 0 1 0  1 1
     * First byte  = 10110010 = 0xB2
     * Second byte = 11xxxxxx → after flush = 0xC0 */
    gcs_bitwriter_write_bit(&w, 1);
    gcs_bitwriter_write_bit(&w, 0);
    gcs_bitwriter_write_bit(&w, 1);
    gcs_bitwriter_write_bit(&w, 1);
    gcs_bitwriter_write_bit(&w, 0);
    gcs_bitwriter_write_bit(&w, 0);
    gcs_bitwriter_write_bit(&w, 1);
    gcs_bitwriter_write_bit(&w, 0); /* byte boundary → 0xB2 written */
    gcs_bitwriter_write_bit(&w, 1);
    gcs_bitwriter_write_bit(&w, 1);
    gcs_bitwriter_flush(&w);

    u_assert_uint32_eq(w.data->len, 2);
    u_assert_uint32_eq((uint8_t)w.data->str[0], 0xB2);
    u_assert_uint32_eq((uint8_t)w.data->str[1], 0xC0);

    cstr_free(w.data, true);
}

static void test_bitwriter_write_bits_be(void)
{
    /* write_bits_be(22, 5): value=22=0b10110, 5 bits MSB-first
     * bit order: 1,0,1,1,0 → packed byte: 10110000 = 0xB0 */
    gcs_bitwriter w;
    gcs_bitwriter_init(&w, 4);
    gcs_bitwriter_write_bits_be(&w, 22, 5);
    gcs_bitwriter_flush(&w);

    u_assert_uint32_eq(w.data->len, 1);
    u_assert_uint32_eq((uint8_t)w.data->str[0], 0xB0);
    cstr_free(w.data, true);
}

static void test_bitreader_roundtrip(void)
{
    /* Write a known 5-bit value and read it back */
    gcs_bitwriter w;
    gcs_bitwriter_init(&w, 4);
    gcs_bitwriter_write_bits_be(&w, 22, 5);
    gcs_bitwriter_flush(&w);

    gcs_bitreader r;
    gcs_bitreader_init(&r, w.data->str, w.data->len);

    uint64_t out = 0;
    u_assert_true(gcs_bitreader_read_bits_be(&r, 5, &out));
    u_assert_uint64_eq(out, 22);

    cstr_free(w.data, true);
}

static void test_bitreader_individual_bits(void)
{
    /* Write 0xB2 and read each bit */
    uint8_t byte = 0xB2; /* 10110010 */
    gcs_bitreader r;
    gcs_bitreader_init(&r, &byte, 1);

    u_assert_int_eq(gcs_bitreader_read_bit(&r), 1);
    u_assert_int_eq(gcs_bitreader_read_bit(&r), 0);
    u_assert_int_eq(gcs_bitreader_read_bit(&r), 1);
    u_assert_int_eq(gcs_bitreader_read_bit(&r), 1);
    u_assert_int_eq(gcs_bitreader_read_bit(&r), 0);
    u_assert_int_eq(gcs_bitreader_read_bit(&r), 0);
    u_assert_int_eq(gcs_bitreader_read_bit(&r), 1);
    u_assert_int_eq(gcs_bitreader_read_bit(&r), 0);

    /* Buffer exhausted — next read returns -1 */
    u_assert_int_eq(gcs_bitreader_read_bit(&r), -1);
}

/* ================================================================ */
/*  Golomb-Rice codec                                               */
/* ================================================================ */

static void test_golomb_rice_roundtrip_p3(void)
{
    int P = 3;
    uint64_t values[] = {0, 1, 7, 8, 9, 15, 100, 255, 1023, 65535};
    size_t n = sizeof(values) / sizeof(values[0]);
    size_t i;

    for (i = 0; i < n; i++) {
        gcs_bitwriter w;
        gcs_bitwriter_init(&w, 16);
        golomb_rice_encode(&w, values[i], P);
        gcs_bitwriter_flush(&w);

        gcs_bitreader r;
        gcs_bitreader_init(&r, w.data->str, w.data->len);
        uint64_t decoded = 0;
        u_assert_true(golomb_rice_decode(&r, P, &decoded));
        u_assert_uint64_eq(decoded, values[i]);

        cstr_free(w.data, true);
    }
}

static void test_golomb_rice_roundtrip_p19(void)
{
    /* P=19 is the actual BIP158 parameter */
    int P = GCS_BASIC_FILTER_P;
    uint64_t values[] = {
        0,
        1,
        (1ULL << 19) - 1,   /* max remainder with P=19 */
        (1ULL << 19),        /* first value needing quotient=1 */
        (1ULL << 19) + 42,
        (uint64_t)GCS_BASIC_FILTER_M, /* ~784931 */
        (uint64_t)GCS_BASIC_FILTER_M * 5
    };
    size_t n = sizeof(values) / sizeof(values[0]);
    size_t i;

    for (i = 0; i < n; i++) {
        gcs_bitwriter w;
        gcs_bitwriter_init(&w, 32);
        golomb_rice_encode(&w, values[i], P);
        gcs_bitwriter_flush(&w);

        gcs_bitreader r;
        gcs_bitreader_init(&r, w.data->str, w.data->len);
        uint64_t decoded = 0;
        u_assert_true(golomb_rice_decode(&r, P, &decoded));
        u_assert_uint64_eq(decoded, values[i]);

        cstr_free(w.data, true);
    }
}

static void test_golomb_rice_known_encoding(void)
{
    /* value=5, P=3: quotient=0, remainder=5
     * bits: 0(term) 1 0 1 → 4 bits → 0101xxxx → 0x50 after flush */
    gcs_bitwriter w;
    gcs_bitwriter_init(&w, 4);
    golomb_rice_encode(&w, 5, 3);
    gcs_bitwriter_flush(&w);

    u_assert_uint32_eq(w.data->len, 1);
    u_assert_uint32_eq((uint8_t)w.data->str[0], 0x50);
    cstr_free(w.data, true);

    /* value=0, P=3: quotient=0, remainder=0
     * bits: 0(term) 0 0 0 → 4 bits → 0000xxxx → 0x00 after flush */
    gcs_bitwriter_init(&w, 4);
    golomb_rice_encode(&w, 0, 3);
    gcs_bitwriter_flush(&w);

    u_assert_uint32_eq(w.data->len, 1);
    u_assert_uint32_eq((uint8_t)w.data->str[0], 0x00);
    cstr_free(w.data, true);
}

/* ================================================================ */
/*  GCS filter: build and match                                     */
/* ================================================================ */

static void test_gcs_filter_empty(void)
{
    gcs_filter *f = gcs_filter_new();
    u_assert_not_null(f);
    u_assert_uint32_eq(f->filter_type, GCS_BASIC_FILTER_TYPE);
    u_assert_uint32_eq(f->N, 0);

    uint8_t blockhash[32];
    memset(blockhash, 0, 32);
    vector_t *elements = vector_new(0, cstr_free_cb);

    u_assert_true(gcs_filter_build(f, GCS_BASIC_FILTER_TYPE, blockhash, elements));
    u_assert_uint32_eq(f->N, 0);
    u_assert_not_null(f->encoded);
    u_assert_uint32_eq(f->encoded->len, 0);

    u_assert_true(!gcs_filter_match(f, (const uint8_t *)"test", 4));

    gcs_filter_free(f);
    vector_free(elements, true);
}

static void test_gcs_filter_build_and_match(void)
{
    gcs_filter *f = gcs_filter_new();
    u_assert_not_null(f);

    uint8_t blockhash[32];
    memset(blockhash, 0xAB, 32);

    /* Three known script pubkeys */
    const uint8_t s0[] = {0x76, 0xa9, 0x14, 0x01, 0x02, 0x03};
    const uint8_t s1[] = {0x76, 0xa9, 0x14, 0x04, 0x05, 0x06};
    const uint8_t s2[] = {0x00, 0x14, 0x07, 0x08, 0x09, 0x0a};

    vector_t *elements = vector_new(3, cstr_free_cb);
    vector_add(elements, cstr_new_buf((const char *)s0, sizeof(s0)));
    vector_add(elements, cstr_new_buf((const char *)s1, sizeof(s1)));
    vector_add(elements, cstr_new_buf((const char *)s2, sizeof(s2)));

    u_assert_true(gcs_filter_build(f, GCS_BASIC_FILTER_TYPE, blockhash, elements));
    u_assert_uint32_eq(f->N, 3);
    u_assert_not_null(f->encoded);

    /* All inserted elements must match */
    u_assert_true(gcs_filter_match(f, s0, sizeof(s0)));
    u_assert_true(gcs_filter_match(f, s1, sizeof(s1)));
    u_assert_true(gcs_filter_match(f, s2, sizeof(s2)));

    /* An element that was not inserted should not match (FP rate ~1/784931) */
    const uint8_t nonmember[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    u_assert_true(!gcs_filter_match(f, nonmember, sizeof(nonmember)));

    gcs_filter_free(f);
    vector_free(elements, true);
}

static void test_gcs_filter_match_any(void)
{
    gcs_filter *f = gcs_filter_new();
    uint8_t blockhash[32];
    memset(blockhash, 0xCC, 32);

    const uint8_t s0[] = {0x76, 0xa9, 0x14, 0xDE, 0xAD, 0xBE};
    const uint8_t s1[] = {0x76, 0xa9, 0x14, 0xCA, 0xFE, 0x00};

    vector_t *elements = vector_new(2, cstr_free_cb);
    vector_add(elements, cstr_new_buf((const char *)s0, sizeof(s0)));
    vector_add(elements, cstr_new_buf((const char *)s1, sizeof(s1)));

    u_assert_true(gcs_filter_build(f, GCS_BASIC_FILTER_TYPE, blockhash, elements));

    /* Query set containing one matching element */
    vector_t *mixed = vector_new(3, cstr_free_cb);
    vector_add(mixed, cstr_new_buf("\x00\x00\x00\x00", 4)); /* non-member */
    vector_add(mixed, cstr_new_buf((const char *)s1, sizeof(s1))); /* member */
    u_assert_true(gcs_filter_match_any(f, mixed));

    /* Query set with no matching elements */
    vector_t *none = vector_new(2, cstr_free_cb);
    vector_add(none, cstr_new_buf("\x00\x00\x00\x00", 4));
    vector_add(none, cstr_new_buf("\xFF\xFF\xFF\xFF", 4));
    u_assert_true(!gcs_filter_match_any(f, none));

    /* Empty query set */
    vector_t *empty = vector_new(0, cstr_free_cb);
    u_assert_true(!gcs_filter_match_any(f, empty));

    gcs_filter_free(f);
    vector_free(elements, true);
    vector_free(mixed, true);
    vector_free(none, true);
    vector_free(empty, true);
}

/* ================================================================ */
/*  GCS filter: serialization round-trip                            */
/* ================================================================ */

static void test_gcs_filter_serialize_deser(void)
{
    gcs_filter *f = gcs_filter_new();
    uint8_t blockhash[32];
    memset(blockhash, 0x11, 32);

    const uint8_t s0[] = {0x76, 0xa9, 0x14, 0xDE, 0xAD, 0xBE, 0xEF};
    const uint8_t s1[] = {0x00, 0x14, 0x01, 0x23, 0x45, 0x67};

    vector_t *elements = vector_new(2, cstr_free_cb);
    vector_add(elements, cstr_new_buf((const char *)s0, sizeof(s0)));
    vector_add(elements, cstr_new_buf((const char *)s1, sizeof(s1)));

    u_assert_true(gcs_filter_build(f, GCS_BASIC_FILTER_TYPE, blockhash, elements));

    /* Serialize */
    cstring *serialized = cstr_new_sz(64);
    gcs_filter_serialize(f, serialized);
    u_assert_true(serialized->len > 0);

    /* Deserialize */
    gcs_filter *f2 = gcs_filter_new();
    struct const_buffer buf = {(const uint8_t *)serialized->str, serialized->len};
    u_assert_true(gcs_filter_deserialize(f2, GCS_BASIC_FILTER_TYPE, blockhash, &buf));
    u_assert_uint32_eq(f2->N, f->N);
    u_assert_uint32_eq(f2->encoded->len, f->encoded->len);
    u_assert_mem_eq(f2->encoded->str, f->encoded->str, f->encoded->len);

    /* Deserialized filter must still match inserted elements */
    u_assert_true(gcs_filter_match(f2, s0, sizeof(s0)));
    u_assert_true(gcs_filter_match(f2, s1, sizeof(s1)));

    gcs_filter_free(f);
    gcs_filter_free(f2);
    cstr_free(serialized, true);
    vector_free(elements, true);
}

/* ================================================================ */
/*  GCS filter header chaining                                      */
/* ================================================================ */

static void test_gcs_filter_header(void)
{
    uint8_t blockhash[32];
    memset(blockhash, 0, 32);

    gcs_filter *f1 = gcs_filter_new();
    vector_t *e1 = vector_new(1, cstr_free_cb);
    vector_add(e1, cstr_new("script_one"));
    u_assert_true(gcs_filter_build(f1, GCS_BASIC_FILTER_TYPE, blockhash, e1));

    uint8_t prev[32], h1[32], h2[32];
    memset(prev, 0, 32);
    u_assert_true(gcs_filter_compute_header(f1, prev, h1));

    /* Second filter chains from h1 */
    gcs_filter *f2 = gcs_filter_new();
    vector_t *e2 = vector_new(1, cstr_free_cb);
    vector_add(e2, cstr_new("script_two"));
    u_assert_true(gcs_filter_build(f2, GCS_BASIC_FILTER_TYPE, blockhash, e2));
    u_assert_true(gcs_filter_compute_header(f2, h1, h2));

    /* Headers must differ from each other and from the zero-hash */
    uint8_t zeros[32];
    memset(zeros, 0, 32);
    u_assert_mem_not_eq(h1, zeros, 32);
    u_assert_mem_not_eq(h2, zeros, 32);
    u_assert_mem_not_eq(h1, h2, 32);

    /* Same inputs reproduce the same header */
    uint8_t h1_again[32];
    u_assert_true(gcs_filter_compute_header(f1, prev, h1_again));
    u_assert_mem_eq(h1, h1_again, 32);

    gcs_filter_free(f1);
    gcs_filter_free(f2);
    vector_free(e1, true);
    vector_free(e2, true);
}

/* ================================================================ */
/*  GCS key derivation                                              */
/* ================================================================ */

static void test_gcs_derive_key(void)
{
    uint8_t blockhash[32];
    uint8_t key[GCS_SIPHASH_KEY_SIZE];
    uint32_t i;

    for (i = 0; i < 32; i++) blockhash[i] = (uint8_t)i;

    gcs_derive_key(blockhash, key);

    /* Key must be the first 16 bytes of the block hash */
    u_assert_mem_eq(key, blockhash, GCS_SIPHASH_KEY_SIZE);
}

/* ================================================================ */
/*  Public test entry point                                         */
/* ================================================================ */

void test_golomb(void)
{
    test_bitwriter_basic();
    test_bitwriter_write_bits_be();
    test_bitreader_roundtrip();
    test_bitreader_individual_bits();
    test_golomb_rice_roundtrip_p3();
    test_golomb_rice_roundtrip_p19();
    test_golomb_rice_known_encoding();
    test_gcs_filter_empty();
    test_gcs_filter_build_and_match();
    test_gcs_filter_match_any();
    test_gcs_filter_serialize_deser();
    test_gcs_filter_header();
    test_gcs_derive_key();
}
