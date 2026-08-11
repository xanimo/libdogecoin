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

    /* cfheaders_base_height must start at 1 (default) */
    u_assert_uint32_eq(state->cfheaders_base_height, 1);

    /* reset clears tip height and awaiting flag, preserves watched_scripts */
    state->cfheaders_tip_height = 42;
    state->cfheaders_base_height = 6238060;
    state->awaiting_response = true;
    dogecoin_compact_filter_state_reset(state);
    u_assert_uint32_eq(state->cfheaders_tip_height, 0);
    u_assert_uint32_eq(state->cfheaders_base_height, 1);
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
    /* BIP157 wire format: filter_type(1) | block_hash(32) | varint(len) | data */
    uint8_t block_hash[32];
    uint32_t i;
    for (i = 0; i < 32; i++) block_hash[i] = (uint8_t)i;
    const uint8_t filter_bytes[] = {0xDE, 0xAD, 0xBE, 0xEF};

    cstring *wire = cstr_new_sz(64);
    uint8_t ft = GCS_BASIC_FILTER_TYPE;
    ser_bytes(wire, &ft, 1);
    ser_bytes(wire, block_hash, 32);
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
    /* Only 10 bytes — not enough for filter_type(1) + block_hash(32) */
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

    /* The attack this function exists to stop: a peer that serves altered
     * filter bytes for a block whose filter header is already committed to by
     * the cfheaders chain. Flipping any single bit of the payload must fail
     * validation against the header computed from the original -- otherwise a
     * peer could strip a transaction out of a filter and the client would
     * silently skip the block that pays it. */
    {
        size_t probe;
        for (probe = 0; probe < filter_data->len; probe++) {
            cstring *tampered = cstr_new_buf(filter_data->str, filter_data->len);
            tampered->str[probe] ^= 0x01;
            u_assert_true(!dogecoin_compact_filter_validate(tampered, prev, header));
            cstr_free(tampered, true);
        }
        /* Truncation and extension must be rejected on the same grounds. */
        cstring *shorter = cstr_new_buf(filter_data->str, filter_data->len - 1);
        u_assert_true(!dogecoin_compact_filter_validate(shorter, prev, header));
        cstr_free(shorter, true);

        cstring *longer = cstr_new_buf(filter_data->str, filter_data->len);
        cstr_append_c(longer, 0x00);
        u_assert_true(!dogecoin_compact_filter_validate(longer, prev, header));
        cstr_free(longer, true);
    }

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
/*  cfheaders_base_height cfilter indexing                         */
/* ================================================================ */

/* Verify cfilter validation indexing when cfheaders start at a height > 1.
 * With checkpoint-based header sync, cfheaders_base_height is set to chainbottom
 * (e.g. 6,238,060), not 1.  filter_headers[i] = filter header for block at
 * (cfheaders_base_height + i), so the vector index is (filter_height - base). */
static void test_cfilter_indexing_with_base_height(void)
{
    dogecoin_compact_filter_state *state = dogecoin_compact_filter_state_new();
    u_assert_not_null(state);

    const uint32_t base = 6238060; /* simulated chainbottom */
    state->cfheaders_base_height = base;
    state->cfheaders_tip_height  = base - 1;
    state->filters_tip_height    = base - 1;

    /* Synthetic genesis_filter_header: the filter header at height (base-1). */
    uint256_t genesis_fh;
    memset(genesis_fh, 0xAB, 32);
    memcpy(state->genesis_filter_header, genesis_fh, 32);

    /* Build 3 consecutive filter data strings (empty GCS filters). */
    cstring *fd[3];
    fd[0] = cstr_new_sz(0); /* height base   */
    fd[1] = cstr_new_sz(0); /* height base+1 */
    fd[2] = cstr_new_sz(0); /* height base+2 */

    /* Compute chained filter headers. */
    uint256_t fh[3];
    dogecoin_compact_filter_compute_header(fd[0], genesis_fh,  fh[0]);
    dogecoin_compact_filter_compute_header(fd[1], fh[0],       fh[1]);
    dogecoin_compact_filter_compute_header(fd[2], fh[1],       fh[2]);

    /* Populate filter_headers as if cfheaders download completed. */
    uint32_t k;
    for (k = 0; k < 3; k++) {
        uint256_t *h = dogecoin_calloc(1, sizeof(uint256_t));
        memcpy(*h, fh[k], 32);
        vector_add(state->filter_headers, h);
    }
    state->cfheaders_tip_height = base + 2;

    /* ------ cfilter at height (base) ------
     * vec_idx = filter_height - base = 0
     * prev_fh = genesis_filter_header  (filter_height <= base) */
    {
        uint32_t filter_height = base;
        uint32_t vec_idx = filter_height - base;
        u_assert_uint32_eq(vec_idx, 0);
        u_assert_true(vec_idx < state->filter_headers->len);

        uint256_t prev_fh;
        memcpy(prev_fh, state->genesis_filter_header, 32);
        u_assert_mem_eq(prev_fh, genesis_fh, 32);

        uint256_t *expected = (uint256_t *)vector_idx(state->filter_headers, vec_idx);
        u_assert_mem_eq(*expected, fh[0], 32);
        u_assert_true(dogecoin_compact_filter_validate(fd[0], prev_fh, *expected));
    }

    /* ------ cfilter at height (base+1) ------
     * vec_idx = 1, prev_fh = filter_headers[0] */
    {
        uint32_t filter_height = base + 1;
        uint32_t vec_idx = filter_height - base;
        u_assert_uint32_eq(vec_idx, 1);
        u_assert_true(vec_idx < state->filter_headers->len);

        uint32_t prev_idx = filter_height - base - 1; /* = 0 */
        uint256_t prev_fh;
        memcpy(prev_fh, vector_idx(state->filter_headers, prev_idx), 32);
        u_assert_mem_eq(prev_fh, fh[0], 32);

        uint256_t *expected = (uint256_t *)vector_idx(state->filter_headers, vec_idx);
        u_assert_mem_eq(*expected, fh[1], 32);
        u_assert_true(dogecoin_compact_filter_validate(fd[1], prev_fh, *expected));
    }

    /* ------ wrong prev_fh must fail ------
     * Using genesis_fh as prev for height base+1 is incorrect. */
    {
        uint256_t *expected = (uint256_t *)vector_idx(state->filter_headers, 1);
        u_assert_true(!dogecoin_compact_filter_validate(fd[1], genesis_fh, *expected));
    }

    uint32_t j;
    for (j = 0; j < 3; j++) cstr_free(fd[j], true);
    dogecoin_compact_filter_state_free(state);
}

/* ================================================================ */
/*  Unbounded-allocation regressions (CWE-400)                      */
/* ================================================================ */

/* A cfheaders/cfcheckpt message declares a hash count as a compact_size read
 * straight off the wire. The count fed vector_new() directly, which reserves a
 * power-of-two number of pointers -- 0xFFFFFFFF became a ~34 GB calloc before a
 * single hash was read, so a ~10-byte message from any peer was a memory
 * exhaustion DoS. Same class as the getheaders locator-count fix. Each entry is
 * a 32-byte hash, so a count the remaining buffer cannot hold must be rejected. */
static void test_cfheaders_deser_unbounded_count(void)
{
    /* filter_type(1) + stop_hash(32) + prev_filter_header(32), then
     * varint 0xFFFFFFFF claiming 429496729 hashes, then nothing. */
    uint8_t bad[1 + 32 + 32 + 5];
    memset(bad, 0, sizeof(bad));
    bad[65] = 0xfe;                       /* compact_size: uint32 follows */
    bad[66] = 0xff; bad[67] = 0xff;
    bad[68] = 0xff; bad[69] = 0xff;       /* 0xFFFFFFFF */

    struct const_buffer buf = { bad, sizeof(bad) };
    dogecoin_cfheaders_msg msg;
    dogecoin_cfheaders_msg_init(&msg);
    u_assert_true(!dogecoin_p2p_msg_cfheaders_deser(&msg, &buf));
    dogecoin_cfheaders_msg_free(&msg);

    /* A count above BIP157's 2000-hash cap must also be refused even when the
     * buffer is large enough to make it look plausible. */
    size_t big_len = 1 + 32 + 32 + 3 + (size_t)2001 * 32;
    uint8_t *big = dogecoin_calloc(1, big_len);
    big[65] = 0xfd;                       /* compact_size: uint16 follows */
    big[66] = (uint8_t)(2001 & 0xff);
    big[67] = (uint8_t)((2001 >> 8) & 0xff);
    struct const_buffer bigbuf = { big, big_len };
    dogecoin_cfheaders_msg msg2;
    dogecoin_cfheaders_msg_init(&msg2);
    u_assert_true(!dogecoin_p2p_msg_cfheaders_deser(&msg2, &bigbuf));
    dogecoin_cfheaders_msg_free(&msg2);
    dogecoin_free(big);
}

static void test_cfcheckpt_deser_unbounded_count(void)
{
    /* filter_type(1) + stop_hash(32), then varint 0xFFFFFFFF, then nothing. */
    uint8_t bad[1 + 32 + 5];
    memset(bad, 0, sizeof(bad));
    bad[33] = 0xfe;
    bad[34] = 0xff; bad[35] = 0xff;
    bad[36] = 0xff; bad[37] = 0xff;

    struct const_buffer buf = { bad, sizeof(bad) };
    dogecoin_cfcheckpt_msg msg;
    dogecoin_cfcheckpt_msg_init(&msg);
    u_assert_true(!dogecoin_p2p_msg_cfcheckpt_deser(&msg, &buf));
    dogecoin_cfcheckpt_msg_free(&msg);
}

/* ================================================================ */
/*  Public test entry point                                         */
/* ================================================================ */

/* The compiled-in table is what cfheaders are anchored against, so the lookup has
   to answer correctly for every real height and refuse everything else. A false
   positive would anchor a header against the wrong block; a false negative would
   silently drop an anchor. */
static void test_cf_hardcoded_checkpoint_lookup(void)
{
    uint256_t got, want;

    size_t count = 0;
    const dogecoin_cf_checkpoint *cps =
        dogecoin_cf_get_checkpoints(&dogecoin_chainparams_main, &count);
    u_assert_true(cps != NULL);
    u_assert_true(count > 0);

    /* Every entry, so an ordering fault anywhere in 6k+ rows is caught rather
       than only wherever a handful of probes happen to land. */
    size_t i;
    for (i = 0; i < count; i++) {
        u_assert_true(dogecoin_cf_hardcoded_checkpoint_at(&dogecoin_chainparams_main,
                                                          cps[i].height, got));
        utils_uint256_sethex((char *)cps[i].filter_header, want);
        u_assert_int_eq(memcmp(got, want, 32), 0);
        if (i > 0) u_assert_true(cps[i].height > cps[i - 1].height);
    }

    /* Absent: between entries, below the first, above the last, and zero. */
    u_assert_true(!dogecoin_cf_hardcoded_checkpoint_at(&dogecoin_chainparams_main,
                                                       cps[0].height - 1, got));
    u_assert_true(!dogecoin_cf_hardcoded_checkpoint_at(&dogecoin_chainparams_main,
                                                       cps[0].height + 1, got));
    u_assert_true(!dogecoin_cf_hardcoded_checkpoint_at(&dogecoin_chainparams_main,
                                                       cps[count - 1].height + 1, got));
    u_assert_true(!dogecoin_cf_hardcoded_checkpoint_at(&dogecoin_chainparams_main, 0, got));

    /* The sentinel is past the count and must not be reachable. */
    u_assert_true(cps[count].height == 0 && cps[count].filter_header == NULL);

    /* A chain with no table answers false rather than reading past the end. */
    u_assert_true(!dogecoin_cf_hardcoded_checkpoint_at(&dogecoin_chainparams_regtest,
                                                       1000, got));
    u_assert_true(!dogecoin_cf_hardcoded_checkpoint_at(NULL, 1000, got));
}

void test_compact_filter(void)
{
    test_cfheaders_deser_unbounded_count();
    test_cfcheckpt_deser_unbounded_count();
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
    test_cf_hardcoded_checkpoint_lookup();
    test_cfilter_indexing_with_base_height();
}
