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
#include <dogecoin/sha2.h>
#include <dogecoin/utils.h>

#include "data/auxpow_block_371338.h"

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

/* Core puts a CBlockHeader in the cmpctblock (blockencodings.h:146), and
   CBlockHeader::SerializationOp appends a full CAuxPow whenever the version
   carries 0x100. A peer that sets the bit and then supplies no AuxPoW is
   sending a message Core cannot read: the stream throws partway through the
   parent coinbase and the message is rejected. Assert we reject it too, rather
   than reinterpreting the nonce and vectors as a bare header's worth of
   trailing data. */
static void test_compact_block_auxpow_bit_without_body_is_rejected(void)
{
    cstring *msg = cstr_new_sz(128);

    ser_s32(msg, 0x00620102);
    unsigned char prev[32], merkle[32];
    memset(prev, 0x11, sizeof(prev));
    memset(merkle, 0x22, sizeof(merkle));
    ser_bytes(msg, prev, 32);
    ser_bytes(msg, merkle, 32);
    ser_u32(msg, 0x5f5e1000);
    ser_u32(msg, 0x1e0ffff0);
    ser_u32(msg, 0xdeadbeef);
    u_assert_uint32_eq((uint32_t)msg->len, CMPCTBLOCK_HEADER_BASE_SIZE);

    /* Everything after the base header is nonce + empty vectors, not AuxPoW */
    ser_u64(msg, 0x0123456789abcdefULL);
    ser_varlen(msg, 0);
    ser_varlen(msg, 0);

    dogecoin_compact_block *cb = dogecoin_compact_block_new();
    u_assert_not_null(cb);

    struct const_buffer buf = { msg->str, msg->len };
    dogecoin_bool ok = dogecoin_compact_block_deserialize(cb, &buf,
                                                          &dogecoin_chainparams_main);
    u_assert_int_eq(ok, false);

    dogecoin_compact_block_free(cb);
    cstr_free(msg, true);
}

/* The header field of a real Dogecoin cmpctblock is 80 bytes plus AuxPoW,
   because essentially every block since 371337 is merge-mined. Build one from
   the height-371338 mainnet vector and check the three things that follow from
   that:

     - the parse consumes the whole AuxPoW header and finds the nonce behind it;
     - the retained span is exactly what arrived, so re-serializing reproduces
       the message byte for byte;
     - the SipHash keys are SHA256 over that span, AuxPoW included, matching
       Core's FillShortTxIDSelector. Deriving them from the parsed header
       instead -- 80 bytes, AuxPoW payload dropped by the parse -- gives
       different keys and therefore short IDs no Core peer would agree with. */
static void test_compact_block_real_auxpow_header_roundtrip(void)
{
    size_t hexlen = strlen(auxpow_block_371338_hex);
    size_t blen = hexlen / 2;
    uint8_t *raw = dogecoin_malloc(blen);
    u_assert_not_null(raw);
    utils_hex_to_bin(auxpow_block_371338_hex, raw, hexlen, &blen);

    /* Measure the header span the way the deserializer will: parse the block's
       header out of the full serialized block and see how far it advanced.
       Everything past that point is the block's transaction vector. */
    dogecoin_block_header *probe = dogecoin_block_header_new();
    struct const_buffer pb = { raw, blen };
    u_assert_int_eq(dogecoin_block_header_deserialize(probe, &pb,
                                                      &dogecoin_chainparams_main, NULL), 1);
    size_t hdr_span = blen - pb.len;
    u_assert_int_eq(hdr_span > CMPCTBLOCK_HEADER_BASE_SIZE, 1);
    dogecoin_block_header_free(probe);

    /* cmpctblock = <header span> || nonce || 0 short ids || 0 prefilled */
    const uint64_t nonce = 0x0123456789abcdefULL;
    cstring *msg = cstr_new_sz(hdr_span + 16);
    ser_bytes(msg, raw, hdr_span);
    ser_u64(msg, nonce);
    ser_varlen(msg, 0);
    ser_varlen(msg, 0);

    dogecoin_compact_block *cb = dogecoin_compact_block_new();
    u_assert_not_null(cb);

    struct const_buffer buf = { msg->str, msg->len };
    u_assert_int_eq(dogecoin_compact_block_deserialize(cb, &buf,
                                                       &dogecoin_chainparams_main), true);

    /* The header parsed is the height-371338 aux header */
    u_assert_uint32_eq((uint32_t)cb->header.version, 0x00620102);
    u_assert_uint32_eq(cb->header.timestamp, 1410464609);

    /* The nonce was found behind the AuxPoW, not inside it */
    u_assert_uint64_eq(cb->nonce, nonce);
    u_assert_uint32_eq(cb->short_ids_count, 0);
    u_assert_uint32_eq(cb->prefilled_count, 0);

    /* The retained span is the wire header, AuxPoW and all */
    u_assert_int_eq(cb->header_raw_len == hdr_span, 1);
    u_assert_int_eq(memcmp(cb->header_raw, raw, hdr_span), 0);

    /* Keys are SHA256(header_span || nonce_le), computed here independently */
    cstring *preimage = cstr_new_sz(hdr_span + 8);
    ser_bytes(preimage, raw, hdr_span);
    ser_u64(preimage, nonce);
    uint256_t expect;
    sha256_raw((const uint8_t *)preimage->str, preimage->len, expect);
    cstr_free(preimage, true);

    uint64_t k0 = 0, k1 = 0;
    memcpy(&k0, expect, 8);
    memcpy(&k1, expect + 8, 8);
    k0 = le64toh(k0);
    k1 = le64toh(k1);
    u_assert_int_eq(cb->sipkey_k0 == k0, 1);
    u_assert_int_eq(cb->sipkey_k1 == k1, 1);

    /* The 80-byte derivation is a different preimage and must not collide */
    uint64_t bare_k0 = 0, bare_k1 = 0;
    dogecoin_compact_block_derive_sipkeys(&cb->header, nonce, &bare_k0, &bare_k1);
    u_assert_int_eq(bare_k0 == cb->sipkey_k0, 0);

    /* Re-serializing reproduces the message exactly */
    cstring *out = cstr_new_sz(msg->len);
    u_assert_int_eq(dogecoin_compact_block_serialize(out, cb), true);
    u_assert_int_eq(out->len == msg->len, 1);
    u_assert_int_eq(memcmp(out->str, msg->str, msg->len), 0);
    cstr_free(out, true);

    dogecoin_compact_block_free(cb);
    cstr_free(msg, true);
    dogecoin_free(raw);
}

/* Without a retained span there is nothing to emit for a merge-mined header:
   dogecoin_block_header_copy carries the auxpow flags but not the payload, and
   there is no AuxPoW serializer in the tree. Serializing 80 bytes anyway would
   put a header on the wire that Core rejects, so the call fails instead. */
static void test_compact_block_serialize_refuses_headerless_auxpow(void)
{
    dogecoin_compact_block *cb = dogecoin_compact_block_new();
    u_assert_not_null(cb);
    cb->header.version = 0x00620102;
    cb->nonce = 7;

    cstring *out = cstr_new_sz(128);
    u_assert_int_eq(dogecoin_compact_block_serialize(out, cb), false);

    /* The same block without the auxpow bit serializes from the parsed header */
    cb->header.version = 0x00000002;
    u_assert_int_eq(dogecoin_compact_block_serialize(out, cb), true);
    u_assert_int_eq(out->len >= CMPCTBLOCK_HEADER_BASE_SIZE, 1);

    cstr_free(out, true);
    dogecoin_compact_block_free(cb);
}

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
    test_compact_block_auxpow_bit_without_body_is_rejected();
    test_compact_block_real_auxpow_header_roundtrip();
    test_compact_block_serialize_refuses_headerless_auxpow();
}
