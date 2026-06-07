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

#include <dogecoin/block.h>
#include <dogecoin/compact_block.h>
#include <dogecoin/mem.h>
#include <dogecoin/serialize.h>

/* ================================================================ */
/*  Lifecycle                                                       */
/* ================================================================ */

static void test_compact_block_new_free(void)
{
    dogecoin_compact_block *cb = dogecoin_compact_block_new();
    u_assert_not_null(cb);
    u_assert_is_null(cb->short_ids);
    u_assert_uint32_eq(cb->short_ids_count, 0);
    u_assert_is_null(cb->prefilled_txs);
    u_assert_uint32_eq(cb->prefilled_count, 0);
    u_assert_uint64_eq(cb->nonce, 0);
    dogecoin_compact_block_free(cb);
}

static void test_getblocktxn_new_free(void)
{
    dogecoin_getblocktxn *req = dogecoin_getblocktxn_new();
    u_assert_not_null(req);
    u_assert_is_null(req->indices);
    u_assert_uint32_eq(req->indices_count, 0);
    dogecoin_getblocktxn_free(req);
}

static void test_blocktxn_new_free(void)
{
    dogecoin_blocktxn *resp = dogecoin_blocktxn_new();
    u_assert_not_null(resp);
    u_assert_is_null(resp->txs);
    u_assert_uint32_eq(resp->txs_count, 0);
    dogecoin_blocktxn_free(resp);
}

static void test_compact_block_state_new_free(void)
{
    dogecoin_compact_block_state *state = dogecoin_compact_block_state_new();
    u_assert_not_null(state);
    u_assert_true(!state->compact_blocks_enabled);
    u_assert_true(!state->high_bandwidth_mode);
    u_assert_uint64_eq(state->compact_block_version, 0);
    u_assert_is_null(state->pending_cmpctblock);
    u_assert_is_null(state->available_txs);
    u_assert_is_null(state->missing_indices);
    u_assert_uint32_eq(state->missing_count, 0);
    dogecoin_compact_block_state_free(state);
}

/* ================================================================ */
/*  SipHash key derivation                                          */
/* ================================================================ */

static void test_sipkeys_deterministic(void)
{
    dogecoin_block_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.version = 1;
    hdr.bits = 0x1e0ffff0;
    hdr.timestamp = 1386325540;

    uint64_t k0a, k1a, k0b, k1b;
    dogecoin_compact_block_derive_sipkeys(&hdr, 12345ULL, &k0a, &k1a);
    dogecoin_compact_block_derive_sipkeys(&hdr, 12345ULL, &k0b, &k1b);

    /* Same inputs → same keys */
    u_assert_uint64_eq(k0a, k0b);
    u_assert_uint64_eq(k1a, k1b);

    /* Different nonce → different keys */
    uint64_t k0c, k1c;
    dogecoin_compact_block_derive_sipkeys(&hdr, 99999ULL, &k0c, &k1c);
    u_assert_true(k0a != k0c || k1a != k1c);
}

static void test_sipkeys_different_headers(void)
{
    dogecoin_block_header h1, h2;
    memset(&h1, 0, sizeof(h1));
    memset(&h2, 0, sizeof(h2));
    h1.version = 1;
    h2.version = 2; /* Only version differs */

    uint64_t k0a, k1a, k0b, k1b;
    dogecoin_compact_block_derive_sipkeys(&h1, 0, &k0a, &k1a);
    dogecoin_compact_block_derive_sipkeys(&h2, 0, &k0b, &k1b);

    /* Different headers must produce different SipHash keys */
    u_assert_true(k0a != k0b || k1a != k1b);
}

/* ================================================================ */
/*  Short ID computation                                            */
/* ================================================================ */

static void test_short_id_deterministic(void)
{
    uint64_t k0 = 0x0102030405060708ULL;
    uint64_t k1 = 0x090A0B0C0D0E0F10ULL;
    uint256_t txhash;
    memset(txhash, 0x42, 32);

    uint8_t sid1[SHORTTXID_LENGTH];
    uint8_t sid2[SHORTTXID_LENGTH];

    dogecoin_compact_block_compute_short_id(k0, k1, txhash, sid1);
    dogecoin_compact_block_compute_short_id(k0, k1, txhash, sid2);

    /* Deterministic: same inputs → same output */
    u_assert_mem_eq(sid1, sid2, SHORTTXID_LENGTH);
}

static void test_short_id_sensitivity(void)
{
    uint64_t k0 = 0xDEADBEEF00000000ULL;
    uint64_t k1 = 0xCAFEBABE00000000ULL;

    uint256_t txhash1, txhash2;
    memset(txhash1, 0x11, 32);
    memset(txhash2, 0x22, 32); /* Only txhash differs */

    uint8_t sid1[SHORTTXID_LENGTH];
    uint8_t sid2[SHORTTXID_LENGTH];

    dogecoin_compact_block_compute_short_id(k0, k1, txhash1, sid1);
    dogecoin_compact_block_compute_short_id(k0, k1, txhash2, sid2);

    /* Different txhash → different short ID (SipHash avalanche) */
    u_assert_mem_not_eq(sid1, sid2, SHORTTXID_LENGTH);

    /* Changing k0/k1 also changes the short ID */
    uint8_t sid3[SHORTTXID_LENGTH];
    dogecoin_compact_block_compute_short_id(k0 ^ 1, k1, txhash1, sid3);
    u_assert_mem_not_eq(sid1, sid3, SHORTTXID_LENGTH);
}

/* ================================================================ */
/*  getblocktxn serialization round-trip                            */
/* ================================================================ */

static void test_getblocktxn_ser_deser(void)
{
    dogecoin_getblocktxn req;
    memset(&req, 0, sizeof(req));
    memset(req.blockhash, 0xAA, 32);
    req.indices_count = 4;
    req.indices = dogecoin_calloc(4, sizeof(uint32_t));
    req.indices[0] = 0;   /* differential: 0 */
    req.indices[1] = 3;   /* differential: 3 - 0 - 1 = 2 */
    req.indices[2] = 5;   /* differential: 5 - 3 - 1 = 1 */
    req.indices[3] = 10;  /* differential: 10 - 5 - 1 = 4 */

    cstring *buf = cstr_new_sz(64);
    dogecoin_getblocktxn_serialize(buf, &req);
    u_assert_true(buf->len > 0);

    dogecoin_getblocktxn req2;
    memset(&req2, 0, sizeof(req2));
    struct const_buffer cbuf = {(const uint8_t *)buf->str, buf->len};
    u_assert_true(dogecoin_getblocktxn_deserialize(&req2, &cbuf));

    u_assert_mem_eq(req2.blockhash, req.blockhash, 32);
    u_assert_uint32_eq(req2.indices_count, 4);
    u_assert_uint32_eq(req2.indices[0], 0);
    u_assert_uint32_eq(req2.indices[1], 3);
    u_assert_uint32_eq(req2.indices[2], 5);
    u_assert_uint32_eq(req2.indices[3], 10);
    u_assert_uint32_eq(cbuf.len, 0); /* fully consumed */

    dogecoin_free(req.indices);
    dogecoin_free(req2.indices);
    cstr_free(buf, true);
}

static void test_getblocktxn_single_index(void)
{
    dogecoin_getblocktxn req;
    memset(&req, 0, sizeof(req));
    memset(req.blockhash, 0x55, 32);
    req.indices_count = 1;
    req.indices = dogecoin_calloc(1, sizeof(uint32_t));
    req.indices[0] = 7;

    cstring *buf = cstr_new_sz(64);
    dogecoin_getblocktxn_serialize(buf, &req);

    dogecoin_getblocktxn req2;
    memset(&req2, 0, sizeof(req2));
    struct const_buffer cbuf = {(const uint8_t *)buf->str, buf->len};
    u_assert_true(dogecoin_getblocktxn_deserialize(&req2, &cbuf));
    u_assert_uint32_eq(req2.indices_count, 1);
    u_assert_uint32_eq(req2.indices[0], 7);

    dogecoin_free(req.indices);
    dogecoin_free(req2.indices);
    cstr_free(buf, true);
}

static void test_getblocktxn_zero_indices(void)
{
    dogecoin_getblocktxn req;
    memset(&req, 0, sizeof(req));
    memset(req.blockhash, 0x33, 32);
    req.indices_count = 0;
    req.indices = NULL;

    cstring *buf = cstr_new_sz(64);
    dogecoin_getblocktxn_serialize(buf, &req);

    dogecoin_getblocktxn req2;
    memset(&req2, 0, sizeof(req2));
    struct const_buffer cbuf = {(const uint8_t *)buf->str, buf->len};
    u_assert_true(dogecoin_getblocktxn_deserialize(&req2, &cbuf));
    u_assert_mem_eq(req2.blockhash, req.blockhash, 32);
    u_assert_uint32_eq(req2.indices_count, 0);
    u_assert_is_null(req2.indices);

    cstr_free(buf, true);
}

/* ================================================================ */
/*  compact block reconstruction (no-missing case)                 */
/* ================================================================ */

static void test_compact_block_reconstruct_no_missing(void)
{
    /* Build a minimal compact block with 1 prefilled tx and 0 short IDs.
     * Reconstruction should succeed immediately with no missing transactions. */
    dogecoin_compact_block *cb = dogecoin_compact_block_new();
    memset(&cb->header, 0, sizeof(cb->header));
    cb->header.version = 1;
    cb->nonce = 0;
    cb->sipkey_k0 = 0;
    cb->sipkey_k1 = 0;
    cb->short_ids_count = 0;
    cb->short_ids = NULL;
    cb->prefilled_count = 1;
    cb->prefilled_txs = dogecoin_calloc(1, sizeof(dogecoin_prefilled_tx));
    cb->prefilled_txs[0].index = 0;
    cb->prefilled_txs[0].tx = dogecoin_tx_new();
    /* Leave tx fields at zero; reconstruction only places it, doesn't validate */

    dogecoin_compact_block_state *state = dogecoin_compact_block_state_new();
    dogecoin_bool ok = dogecoin_compact_block_reconstruct(cb, state, NULL, 0);
    u_assert_true(ok);
    u_assert_uint32_eq(state->available_txs_count, 1);
    u_assert_not_null(state->available_txs[0]);
    u_assert_uint32_eq(state->missing_count, 0);

    /* The prefilled tx pointer is borrowed; do not free via state.
     * compact_block_free will free the prefilled_tx. */
    state->available_txs[0] = NULL;
    dogecoin_compact_block_state_free(state);
    dogecoin_compact_block_free(cb);
}

/* ================================================================ */
/*  Public test entry point                                         */
/* ================================================================ */

void test_compact_block(void)
{
    test_compact_block_new_free();
    test_getblocktxn_new_free();
    test_blocktxn_new_free();
    test_compact_block_state_new_free();
    test_sipkeys_deterministic();
    test_sipkeys_different_headers();
    test_short_id_deterministic();
    test_short_id_sensitivity();
    test_getblocktxn_ser_deser();
    test_getblocktxn_single_index();
    test_getblocktxn_zero_indices();
    test_compact_block_reconstruct_no_missing();
}
