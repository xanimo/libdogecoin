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

#include <dogecoin/chainparams.h>
#include <dogecoin/compact_filter.h>
#include <dogecoin/mem.h>
#include <dogecoin/serialize.h>
#include <dogecoin/utils.h>

/* ================================================================ */
/*  State lifecycle                                                 */
/* ================================================================ */

static void test_compact_filter_state_lifecycle(void)
{
    dogecoin_compact_filter_state *state = dogecoin_compact_filter_state_new();
    u_assert_not_null(state);
    u_assert_true(state->enabled == false);
    u_assert_uint32_eq(state->filter_type, GCS_BASIC_FILTER_TYPE);
    u_assert_uint32_eq(state->cfheaders_tip_height, 0);
    u_assert_uint32_eq(state->filters_tip_height, 0);
    u_assert_true(state->awaiting_response == false);
    u_assert_not_null(state->filter_headers);
    u_assert_not_null(state->checkpoints);
    u_assert_not_null(state->watched_scripts);
    u_assert_not_null(state->matched_block_hashes);

    /* reset clears tip height and awaiting flag, preserves watched_scripts */
    state->cfheaders_tip_height = 42;
    state->awaiting_response = true;
    dogecoin_compact_filter_state_reset(state);
    u_assert_uint32_eq(state->cfheaders_tip_height, 0);
    u_assert_true(state->awaiting_response == false);
    u_assert_not_null(state->watched_scripts);

    dogecoin_compact_filter_state_free(state);
}

/* ================================================================ */
/*  Request message serialization                                   */
/* ================================================================ */

static void test_getcfilters_ser(void)
{
    dogecoin_getcfilters_msg msg;
    msg.filter_type = GCS_BASIC_FILTER_TYPE;
    msg.start_height = 0x01020304;
    uint8_t stop_hash[32];
    uint32_t i;
    for (i = 0; i < 32; i++) stop_hash[i] = (uint8_t)(i * 2 + 1);
    memcpy(msg.stop_hash, stop_hash, 32);

    cstring *buf = cstr_new_sz(64);
    dogecoin_p2p_msg_getcfilters_ser(&msg, buf);

    /* 1 (filter_type) + 4 (start_height LE) + 32 (stop_hash) = 37 */
    u_assert_uint32_eq(buf->len, 37);
    u_assert_uint32_eq((uint8_t)buf->str[0], GCS_BASIC_FILTER_TYPE);
    /* start_height 0x01020304 in LE: 04 03 02 01 */
    u_assert_uint32_eq((uint8_t)buf->str[1], 0x04);
    u_assert_uint32_eq((uint8_t)buf->str[2], 0x03);
    u_assert_uint32_eq((uint8_t)buf->str[3], 0x02);
    u_assert_uint32_eq((uint8_t)buf->str[4], 0x01);
    u_assert_mem_eq(buf->str + 5, stop_hash, 32);
    cstr_free(buf, true);
}

static void test_getcfheaders_ser(void)
{
    dogecoin_getcfheaders_msg msg;
    msg.filter_type = GCS_BASIC_FILTER_TYPE;
    msg.start_height = 1000;
    memset(msg.stop_hash, 0xAB, 32);

    cstring *buf = cstr_new_sz(64);
    dogecoin_p2p_msg_getcfheaders_ser(&msg, buf);

    u_assert_uint32_eq(buf->len, 37);
    u_assert_uint32_eq((uint8_t)buf->str[0], GCS_BASIC_FILTER_TYPE);
    /* start_height 1000 = 0x3E8 in LE: E8 03 00 00 */
    u_assert_uint32_eq((uint8_t)buf->str[1], 0xE8);
    u_assert_uint32_eq((uint8_t)buf->str[2], 0x03);
    u_assert_uint32_eq((uint8_t)buf->str[3], 0x00);
    u_assert_uint32_eq((uint8_t)buf->str[4], 0x00);
    cstr_free(buf, true);
}

static void test_getcfcheckpt_ser(void)
{
    dogecoin_getcfcheckpt_msg msg;
    msg.filter_type = GCS_BASIC_FILTER_TYPE;
    memset(msg.stop_hash, 0x55, 32);

    cstring *buf = cstr_new_sz(64);
    dogecoin_p2p_msg_getcfcheckpt_ser(&msg, buf);

    /* 1 (filter_type) + 32 (stop_hash) = 33 */
    u_assert_uint32_eq(buf->len, 33);
    u_assert_uint32_eq((uint8_t)buf->str[0], GCS_BASIC_FILTER_TYPE);
    uint8_t expected[32];
    memset(expected, 0x55, 32);
    u_assert_mem_eq(buf->str + 1, expected, 32);
    cstr_free(buf, true);
}

/* ================================================================ */
/*  Response message deserialization                                */
/* ================================================================ */

static void test_cfilter_deser(void)
{
    /* Dogecoin Core wire format: block_hash(32) | filter_type(1) | varint(len) | data */
    uint8_t block_hash[32];
    uint32_t i;
    for (i = 0; i < 32; i++) block_hash[i] = (uint8_t)i;
    const uint8_t filter_bytes[] = {0xDE, 0xAD, 0xBE, 0xEF};

    cstring *wire = cstr_new_sz(64);
    ser_bytes(wire, block_hash, 32);
    uint8_t ft = GCS_BASIC_FILTER_TYPE;
    ser_bytes(wire, &ft, 1);
    ser_varlen(wire, sizeof(filter_bytes));
    ser_bytes(wire, filter_bytes, sizeof(filter_bytes));

    struct const_buffer buf = {(const uint8_t *)wire->str, wire->len};
    dogecoin_cfilter_msg msg;
    dogecoin_cfilter_msg_init(&msg);

    u_assert_true(dogecoin_p2p_msg_cfilter_deser(&msg, &buf));
    u_assert_mem_eq(msg.block_hash, block_hash, 32);
    u_assert_uint32_eq(msg.filter_type, GCS_BASIC_FILTER_TYPE);
    u_assert_not_null(msg.filter_data);
    u_assert_uint32_eq(msg.filter_data->len, sizeof(filter_bytes));
    u_assert_mem_eq(msg.filter_data->str, filter_bytes, sizeof(filter_bytes));
    u_assert_uint32_eq(buf.len, 0); /* fully consumed */

    dogecoin_cfilter_msg_free(&msg);
    cstr_free(wire, true);
}

static void test_cfilter_deser_truncated(void)
{
    /* Truncated message should fail cleanly */
    uint8_t short_buf[10];
    memset(short_buf, 0, sizeof(short_buf));
    struct const_buffer buf = {short_buf, sizeof(short_buf)};
    dogecoin_cfilter_msg msg;
    dogecoin_cfilter_msg_init(&msg);
    /* Only 10 bytes — not enough for 32-byte block_hash */
    u_assert_true(!dogecoin_p2p_msg_cfilter_deser(&msg, &buf));
    dogecoin_cfilter_msg_free(&msg);
}

static void test_cfheaders_deser(void)
{
    /* Wire: filter_type(1) | stop_hash(32) | prev_filter_header(32) | varint(N) | N×32 hashes */
    uint8_t stop_hash[32], prev_header[32], hash1[32], hash2[32];
    memset(stop_hash, 0x11, 32);
    memset(prev_header, 0x22, 32);
    memset(hash1, 0xAA, 32);
    memset(hash2, 0xBB, 32);

    cstring *wire = cstr_new_sz(128);
    uint8_t ft = GCS_BASIC_FILTER_TYPE;
    ser_bytes(wire, &ft, 1);
    ser_bytes(wire, stop_hash, 32);
    ser_bytes(wire, prev_header, 32);
    ser_varlen(wire, 2);
    ser_bytes(wire, hash1, 32);
    ser_bytes(wire, hash2, 32);

    struct const_buffer buf = {(const uint8_t *)wire->str, wire->len};
    dogecoin_cfheaders_msg msg;
    dogecoin_cfheaders_msg_init(&msg);

    u_assert_true(dogecoin_p2p_msg_cfheaders_deser(&msg, &buf));
    u_assert_uint32_eq(msg.filter_type, GCS_BASIC_FILTER_TYPE);
    u_assert_mem_eq(msg.stop_hash, stop_hash, 32);
    u_assert_mem_eq(msg.prev_filter_header, prev_header, 32);
    u_assert_not_null(msg.filter_hashes);
    u_assert_uint32_eq((uint32_t)msg.filter_hashes->len, 2);
    u_assert_mem_eq(vector_idx(msg.filter_hashes, 0), hash1, 32);
    u_assert_mem_eq(vector_idx(msg.filter_hashes, 1), hash2, 32);
    u_assert_uint32_eq(buf.len, 0);

    dogecoin_cfheaders_msg_free(&msg);
    cstr_free(wire, true);
}

static void test_cfcheckpt_deser(void)
{
    /* Wire: filter_type(1) | stop_hash(32) | varint(N) | N×32 filter headers */
    uint8_t stop_hash[32], cp1[32], cp2[32], cp3[32];
    memset(stop_hash, 0x55, 32);
    memset(cp1, 0x01, 32);
    memset(cp2, 0x02, 32);
    memset(cp3, 0x03, 32);

    cstring *wire = cstr_new_sz(160);
    uint8_t ft = GCS_BASIC_FILTER_TYPE;
    ser_bytes(wire, &ft, 1);
    ser_bytes(wire, stop_hash, 32);
    ser_varlen(wire, 3);
    ser_bytes(wire, cp1, 32);
    ser_bytes(wire, cp2, 32);
    ser_bytes(wire, cp3, 32);

    struct const_buffer buf = {(const uint8_t *)wire->str, wire->len};
    dogecoin_cfcheckpt_msg msg;
    dogecoin_cfcheckpt_msg_init(&msg);

    u_assert_true(dogecoin_p2p_msg_cfcheckpt_deser(&msg, &buf));
    u_assert_uint32_eq(msg.filter_type, GCS_BASIC_FILTER_TYPE);
    u_assert_mem_eq(msg.stop_hash, stop_hash, 32);
    u_assert_not_null(msg.filter_headers);
    u_assert_uint32_eq((uint32_t)msg.filter_headers->len, 3);
    u_assert_mem_eq(vector_idx(msg.filter_headers, 0), cp1, 32);
    u_assert_mem_eq(vector_idx(msg.filter_headers, 1), cp2, 32);
    u_assert_mem_eq(vector_idx(msg.filter_headers, 2), cp3, 32);
    u_assert_uint32_eq(buf.len, 0);

    dogecoin_cfcheckpt_msg_free(&msg);
    cstr_free(wire, true);
}

/* ================================================================ */
/*  Filter header computation and validation                        */
/* ================================================================ */

static void test_filter_header_compute(void)
{
    const char *data_str = "hello world";
    cstring *filter_data = cstr_new(data_str);

    uint8_t prev[32], header[32];
    memset(prev, 0, 32);

    dogecoin_compact_filter_compute_header(filter_data, prev, header);

    /* The header must not be all zeros */
    uint8_t zeros[32];
    memset(zeros, 0, 32);
    u_assert_mem_not_eq(header, zeros, 32);

    /* Validation with the correct expected header must pass */
    u_assert_true(dogecoin_compact_filter_validate(filter_data, prev, header));

    /* Different prev_filter_header yields a different header */
    uint8_t other_prev[32], other_header[32];
    memset(other_prev, 0xFF, 32);
    dogecoin_compact_filter_compute_header(filter_data, other_prev, other_header);
    u_assert_mem_not_eq(header, other_header, 32);

    /* Cross-validation must fail */
    u_assert_true(!dogecoin_compact_filter_validate(filter_data, prev, other_header));
    u_assert_true(!dogecoin_compact_filter_validate(filter_data, other_prev, header));

    /* NULL filter_data returns false */
    u_assert_true(!dogecoin_compact_filter_validate(NULL, prev, header));

    /* Chaining: header2 = SHA256d(filter_hash2 || header1) */
    cstring *filter_data2 = cstr_new("next block filter");
    uint8_t header2[32];
    dogecoin_compact_filter_compute_header(filter_data2, header, header2);
    u_assert_mem_not_eq(header2, header, 32);
    u_assert_true(dogecoin_compact_filter_validate(filter_data2, header, header2));

    cstr_free(filter_data, true);
    cstr_free(filter_data2, true);
}

/* ================================================================ */
/*  Hardcoded checkpoint helpers                                    */
/* ================================================================ */

static void test_cf_checkpoints_get(void)
{
    size_t count = 0;
    const dogecoin_cf_checkpoint *arr = dogecoin_cf_get_checkpoints(&dogecoin_chainparams_main, &count);
    u_assert_not_null(arr);
    u_assert_true(count > 0);
    /* First checkpoint is at height 1000 (Dogecoin Core convention) */
    u_assert_uint32_eq(arr[0].height, 1000);
    u_assert_not_null(arr[0].filter_header);

    /* Testnet and regtest currently have no checkpoints — function returns true (nothing to verify) */
    const dogecoin_cf_checkpoint *tarr = dogecoin_cf_get_checkpoints(&dogecoin_chainparams_test, &count);
    (void)tarr;
    /* count may be 0; that's expected */
}

static void test_cf_checkpoints_load(void)
{
    dogecoin_compact_filter_state *state = dogecoin_compact_filter_state_new();
    size_t loaded = dogecoin_cf_load_hardcoded_checkpoints(state, &dogecoin_chainparams_main);
    u_assert_true(loaded > 0);

    /* The checkpoints vector must have at least as many slots as loaded entries */
    u_assert_true((uint32_t)state->checkpoints->len >= (uint32_t)loaded);

    /* cp_idx 0 corresponds to height 1000; it must not be all-zero */
    uint8_t zeros[32];
    memset(zeros, 0, 32);
    u_assert_mem_not_eq(vector_idx(state->checkpoints, 0), zeros, 32);

    dogecoin_compact_filter_state_free(state);
}

static void test_cf_checkpoints_validate(void)
{
    size_t count = 0;
    const dogecoin_cf_checkpoint *arr = dogecoin_cf_get_checkpoints(&dogecoin_chainparams_main, &count);

    /* Empty peer list — every hardcoded checkpoint is skipped (peer chain is "shorter") */
    vector_t *peer = vector_new(4, dogecoin_free);
    u_assert_true(dogecoin_cf_validate_checkpoints(&dogecoin_chainparams_main, peer));

    /* Correct checkpoint at cp_idx 0 (height 1000) */
    uint256_t *cp0 = dogecoin_calloc(1, sizeof(uint256_t));
    utils_uint256_sethex((char *)arr[0].filter_header, *cp0);
    vector_add(peer, cp0);
    u_assert_true(dogecoin_cf_validate_checkpoints(&dogecoin_chainparams_main, peer));

    /* Corrupt cp_idx 0 — validation must fail */
    (*cp0)[0] ^= 0xFF;
    u_assert_true(!dogecoin_cf_validate_checkpoints(&dogecoin_chainparams_main, peer));

    vector_free(peer, true);
}

/* ================================================================ */
/*  Public test entry point                                         */
/* ================================================================ */

void test_compact_filter(void)
{
    test_compact_filter_state_lifecycle();
    test_getcfilters_ser();
    test_getcfheaders_ser();
    test_getcfcheckpt_ser();
    test_cfilter_deser();
    test_cfilter_deser_truncated();
    test_cfheaders_deser();
    test_cfcheckpt_deser();
    test_filter_header_compute();
    test_cf_checkpoints_get();
    test_cf_checkpoints_load();
    test_cf_checkpoints_validate();
}
