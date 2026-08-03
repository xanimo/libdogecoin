/*

 The MIT License (MIT)

 Copyright (c) 2016 Matt Corallo
 Copyright (c) 2024 bluezr
 Copyright (c) 2024-2026 The Dogecoin Foundation

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

/**
 * @file compact_block.c
 * @brief BIP152 Compact Block Relay implementation.
 *
 * Implements the data structures, serialization, short transaction ID
 * computation, and P2P message construction for BIP152 compact blocks.
 */

#include <string.h>

#include <dogecoin/compact_block.h>
#include <dogecoin/mem.h>
#include <dogecoin/sha2.h>
#include <dogecoin/utils.h>
#include <dogecoin/portable_endian.h>
#include <dogecoin/protocol.h>

/* ================================================================ */
/*  Constructor / Destructor                                        */
/* ================================================================ */

dogecoin_compact_block *dogecoin_compact_block_new(void)
{
    dogecoin_compact_block *cmpctblk = dogecoin_calloc(1, sizeof(*cmpctblk));
    if (!cmpctblk) return NULL;
    return cmpctblk;
}

void dogecoin_compact_block_free(dogecoin_compact_block *cmpctblk)
{
    if (!cmpctblk) return;

    if (cmpctblk->header_raw) {
        dogecoin_free(cmpctblk->header_raw);
        cmpctblk->header_raw = NULL;
        cmpctblk->header_raw_len = 0;
    }

    if (cmpctblk->short_ids) {
        dogecoin_free(cmpctblk->short_ids);
        cmpctblk->short_ids = NULL;
    }

    if (cmpctblk->prefilled_txs) {
        uint32_t i;
        for (i = 0; i < cmpctblk->prefilled_count; i++) {
            if (cmpctblk->prefilled_txs[i].tx) {
                dogecoin_tx_free(cmpctblk->prefilled_txs[i].tx);
            }
        }
        dogecoin_free(cmpctblk->prefilled_txs);
        cmpctblk->prefilled_txs = NULL;
    }

    dogecoin_free(cmpctblk);
}

dogecoin_getblocktxn *dogecoin_getblocktxn_new(void)
{
    dogecoin_getblocktxn *req = dogecoin_calloc(1, sizeof(*req));
    if (!req) return NULL;
    return req;
}

void dogecoin_getblocktxn_free(dogecoin_getblocktxn *req)
{
    if (!req) return;
    if (req->indices) {
        dogecoin_free(req->indices);
        req->indices = NULL;
    }
    dogecoin_free(req);
}

dogecoin_blocktxn *dogecoin_blocktxn_new(void)
{
    dogecoin_blocktxn *resp = dogecoin_calloc(1, sizeof(*resp));
    if (!resp) return NULL;
    return resp;
}

void dogecoin_blocktxn_free(dogecoin_blocktxn *resp)
{
    if (!resp) return;
    if (resp->txs) {
        uint32_t i;
        for (i = 0; i < resp->txs_count; i++) {
            if (resp->txs[i]) {
                dogecoin_tx_free(resp->txs[i]);
            }
        }
        dogecoin_free(resp->txs);
        resp->txs = NULL;
    }
    dogecoin_free(resp);
}

dogecoin_compact_block_state *dogecoin_compact_block_state_new(void)
{
    dogecoin_compact_block_state *state = dogecoin_calloc(1, sizeof(*state));
    if (!state) return NULL;
    state->compact_blocks_enabled = false;
    state->high_bandwidth_mode = false;
    state->compact_block_version = 0;
    return state;
}

void dogecoin_compact_block_state_free(dogecoin_compact_block_state *state)
{
    if (!state) return;

    if (state->pending_cmpctblock) {
        dogecoin_compact_block_free(state->pending_cmpctblock);
        state->pending_cmpctblock = NULL;
    }

    if (state->available_txs) {
        /* Note: we don't free the tx objects themselves here; they are
         * borrowed references from mempool or prefilled txs. The compact
         * block (which owns prefilled txs) handles freeing those. */
        dogecoin_free(state->available_txs);
        state->available_txs = NULL;
    }

    if (state->missing_indices) {
        dogecoin_free(state->missing_indices);
        state->missing_indices = NULL;
    }

    dogecoin_free(state);
}

/* ================================================================ */
/*  Short Transaction ID Computation                                */
/* ================================================================ */

/**
 * @brief Attach the wire bytes of the header to a compact block.
 *
 * The parsed header cannot reproduce them: dogecoin_block_header_deserialize
 * parses AuxPoW into a local dogecoin_auxpow_block and frees it at cleanup,
 * and dogecoin_block_header_copy carries only the auxpow check/ctx/is flags,
 * not the payload. Retaining the span is what lets the SipHash keys and the
 * re-serialized message match what Core produced.
 */
dogecoin_bool dogecoin_compact_block_set_header_raw(
    dogecoin_compact_block *cmpctblk,
    const void *bytes,
    size_t len)
{
    if (!cmpctblk || !bytes) return false;
    if (len < CMPCTBLOCK_HEADER_BASE_SIZE) return false;
    if (len > DOGECOIN_MAX_P2P_MSG_SIZE) return false;

    uint8_t *copy = dogecoin_malloc(len);
    if (!copy) return false;
    memcpy(copy, bytes, len);

    if (cmpctblk->header_raw) dogecoin_free(cmpctblk->header_raw);
    cmpctblk->header_raw = copy;
    cmpctblk->header_raw_len = len;
    return true;
}

/**
 * Per BIP152: The SipHash keys are derived from the SHA256 of the serialized
 * block header concatenated with the compact block nonce (8 bytes LE).
 *
 * "Serialized block header" is whatever the sender streamed, which for
 * Dogecoin includes AuxPoW when the version bit is set -- Core's
 * FillShortTxIDSelector does `stream << header << nonce` through
 * CBlockHeader's serializer, not CPureBlockHeader's.
 *
 * k0 = first 8 bytes of SHA256 result (little-endian uint64)
 * k1 = next 8 bytes of SHA256 result (little-endian uint64)
 */
void dogecoin_compact_block_derive_sipkeys_raw(
    const uint8_t *header_ser,
    size_t header_ser_len,
    uint64_t nonce,
    uint64_t *k0_out,
    uint64_t *k1_out)
{
    if (!header_ser || !k0_out || !k1_out) return;

    cstring *preimage = cstr_new_sz(header_ser_len + 8);
    ser_bytes(preimage, header_ser, header_ser_len);

    /* Append the 8-byte nonce in little-endian */
    ser_u64(preimage, nonce);

    /* SHA256(header || nonce) - single SHA256 per BIP152 */
    uint256_t hash;
    sha256_raw((const uint8_t *)preimage->str, preimage->len, hash);
    cstr_free(preimage, true);

    /* Extract k0, k1 as little-endian uint64 from the hash */
    const uint8_t *p = hash;
    *k0_out = ((uint64_t)p[0])       | ((uint64_t)p[1] << 8)  |
              ((uint64_t)p[2] << 16)  | ((uint64_t)p[3] << 24) |
              ((uint64_t)p[4] << 32)  | ((uint64_t)p[5] << 40) |
              ((uint64_t)p[6] << 48)  | ((uint64_t)p[7] << 56);

    *k1_out = ((uint64_t)p[8])       | ((uint64_t)p[9] << 8)  |
              ((uint64_t)p[10] << 16) | ((uint64_t)p[11] << 24) |
              ((uint64_t)p[12] << 32) | ((uint64_t)p[13] << 40) |
              ((uint64_t)p[14] << 48) | ((uint64_t)p[15] << 56);
}

/**
 * Wrapper over the 80 base bytes. Only correct for a header with no AuxPoW;
 * see the header file.
 */
void dogecoin_compact_block_derive_sipkeys(
    const dogecoin_block_header *header,
    uint64_t nonce,
    uint64_t *k0_out,
    uint64_t *k1_out)
{
    if (!header || !k0_out || !k1_out) return;

    cstring *hdr_ser = cstr_new_sz(CMPCTBLOCK_HEADER_BASE_SIZE);
    dogecoin_block_header_serialize(hdr_ser, header);
    dogecoin_compact_block_derive_sipkeys_raw((const uint8_t *)hdr_ser->str,
                                              hdr_ser->len, nonce,
                                              k0_out, k1_out);
    cstr_free(hdr_ser, true);
}

/**
 * Per BIP152: ShortTxID = SipHash-2-4(k0, k1, txid) & 0xFFFFFFFFFFFF
 * The result is the lower 6 bytes in little-endian.
 */
void dogecoin_compact_block_compute_short_id(
    uint64_t k0,
    uint64_t k1,
    const uint256_t txhash,
    uint8_t short_id[SHORTTXID_LENGTH])
{
    uint64_t siphash_result = siphash_u256(k0, k1, (uint256_t *)txhash);

    /* Take the lower 6 bytes (little-endian) */
    short_id[0] = (uint8_t)(siphash_result & 0xFF);
    short_id[1] = (uint8_t)((siphash_result >> 8) & 0xFF);
    short_id[2] = (uint8_t)((siphash_result >> 16) & 0xFF);
    short_id[3] = (uint8_t)((siphash_result >> 24) & 0xFF);
    short_id[4] = (uint8_t)((siphash_result >> 32) & 0xFF);
    short_id[5] = (uint8_t)((siphash_result >> 40) & 0xFF);
}

/* ================================================================ */
/*  Serialization                                                   */
/* ================================================================ */

dogecoin_bool dogecoin_compact_block_serialize(cstring *s, const dogecoin_compact_block *cmpctblk)
{
    if (!s || !cmpctblk) return false;

    /* Block header: the bytes we received, if we have them. Core streams the
       CBlockHeader it holds, AuxPoW included; replaying the retained span is
       the same thing by other means, and it is the only way to reproduce a
       merge-mined header -- the tree has no AuxPoW serializer, and the parsed
       header keeps only the auxpow flags. */
    if (cmpctblk->header_raw && cmpctblk->header_raw_len >= CMPCTBLOCK_HEADER_BASE_SIZE) {
        ser_bytes(s, cmpctblk->header_raw, cmpctblk->header_raw_len);
    } else if ((cmpctblk->header.version & 0x100) == 0) {
        /* No AuxPoW to lose: the 80 base bytes are the whole header. */
        dogecoin_block_header_serialize(s, &cmpctblk->header);
    } else {
        /* Merge-mined header with no retained span. Emitting 80 bytes here
           would produce a message Core rejects, silently, so refuse instead.
           Callers assembling such a block must supply the wire header via
           dogecoin_compact_block_set_header_raw. */
        return false;
    }

    /* Nonce (8 bytes LE) */
    ser_u64(s, cmpctblk->nonce);

    /* Short IDs: varint count + raw 6-byte IDs */
    ser_varlen(s, cmpctblk->short_ids_count);
    if (cmpctblk->short_ids_count > 0 && cmpctblk->short_ids) {
        ser_bytes(s, cmpctblk->short_ids,
                  (size_t)cmpctblk->short_ids_count * SHORTTXID_LENGTH);
    }

    /* Prefilled transactions: varint count + differentially encoded entries */
    ser_varlen(s, cmpctblk->prefilled_count);
    uint32_t last_index = 0;
    uint32_t i;
    for (i = 0; i < cmpctblk->prefilled_count; i++) {
        const dogecoin_prefilled_tx *ptx = &cmpctblk->prefilled_txs[i];
        /* Differential encoding: encode (index - last_index) for first,
         * (index - last_index - 1) for subsequent */
        uint32_t diff = (i == 0) ? ptx->index : (ptx->index - last_index - 1);
        ser_varlen(s, diff);
        dogecoin_tx_serialize(s, ptx->tx);
        last_index = ptx->index;
    }

    return true;
}

dogecoin_bool dogecoin_compact_block_deserialize(
    dogecoin_compact_block *cmpctblk,
    struct const_buffer *buf,
    const dogecoin_chainparams *params)
{
    if (!cmpctblk || !buf) return false;

    /* Deserialize block header. The field is a CBlockHeader in Core
       (blockencodings.h), so it is 80 bytes plus a full CAuxPow whenever
       version bit 0x100 is set -- which is every merge-mined block. Let
       dogecoin_block_header_deserialize dispatch on that bit exactly as
       CBlockHeader::SerializationOp does, and take the span it consumed.

       A peer that sets 0x100 without supplying AuxPoW fails here, in the
       AuxPoW sub-parsers, which is what Core does too: the stream read throws
       and the message is rejected. */
    const uint8_t *hdr_start = (const uint8_t *)buf->p;
    if (buf->len < CMPCTBLOCK_HEADER_BASE_SIZE) return false;
    if (!dogecoin_block_header_deserialize(&cmpctblk->header, buf, params, NULL))
        return false;

    /* Retain the wire header. The SipHash keys are SHA256 over these bytes,
       and the parsed header cannot regenerate the AuxPoW half of them. */
    size_t hdr_len = (size_t)((const uint8_t *)buf->p - hdr_start);
    if (!dogecoin_compact_block_set_header_raw(cmpctblk, hdr_start, hdr_len))
        return false;

    /* Nonce */
    if (!deser_u64(&cmpctblk->nonce, buf))
        return false;

    /* Derive SipHash keys over the header as it arrived, AuxPoW included */
    dogecoin_compact_block_derive_sipkeys_raw(cmpctblk->header_raw,
                                              cmpctblk->header_raw_len,
                                              cmpctblk->nonce,
                                              &cmpctblk->sipkey_k0,
                                              &cmpctblk->sipkey_k1);

    /* Short IDs */
    if (!deser_varlen(&cmpctblk->short_ids_count, buf))
        return false;

    if (cmpctblk->short_ids_count > 0) {
        size_t ids_bytes = (size_t)cmpctblk->short_ids_count * SHORTTXID_LENGTH;
        if (buf->len < ids_bytes)
            return false;
        cmpctblk->short_ids = dogecoin_calloc(1, ids_bytes);
        if (!cmpctblk->short_ids)
            return false;
        if (!deser_bytes(cmpctblk->short_ids, buf, ids_bytes)) {
            dogecoin_free(cmpctblk->short_ids);
            cmpctblk->short_ids = NULL;
            return false;
        }
    }

    /* Prefilled transactions */
    if (!deser_varlen(&cmpctblk->prefilled_count, buf))
        return false;

    if (cmpctblk->prefilled_count > 0) {
        /* prefilled_count is attacker-controlled. Each prefilled entry costs at
           least a varint index plus a minimal transaction on the wire, so a count
           exceeding the remaining buffer length cannot be honest; without this the
           calloc below reserves prefilled_count * sizeof(dogecoin_prefilled_tx)
           (~68 GB at 0xFFFFFFFF) before anything is parsed. The short_ids branch
           above already bounds itself this way. */
        if (cmpctblk->prefilled_count > buf->len) return false;
        cmpctblk->prefilled_txs = dogecoin_calloc(cmpctblk->prefilled_count,
                                                    sizeof(dogecoin_prefilled_tx));
        if (!cmpctblk->prefilled_txs)
            return false;

        uint32_t last_index = 0;
        uint32_t i;
        for (i = 0; i < cmpctblk->prefilled_count; i++) {
            uint32_t diff;
            if (!deser_varlen(&diff, buf))
                return false;

            /* Undo differential encoding */
            if (i == 0) {
                cmpctblk->prefilled_txs[i].index = diff;
            } else {
                cmpctblk->prefilled_txs[i].index = last_index + diff + 1;
            }
            last_index = cmpctblk->prefilled_txs[i].index;

            /* Deserialize the full transaction */
            cmpctblk->prefilled_txs[i].tx = dogecoin_tx_new();
            size_t consumed = 0;
            if (!dogecoin_tx_deserialize(buf->p, buf->len,
                                         cmpctblk->prefilled_txs[i].tx, &consumed)) {
                return false;
            }
            if (!deser_skip(buf, consumed))
                return false;
        }
    }

    return true;
}

void dogecoin_getblocktxn_serialize(cstring *s, const dogecoin_getblocktxn *req)
{
    if (!s || !req) return;

    /* Block hash */
    ser_u256(s, req->blockhash);

    /* Indices (differentially encoded) */
    ser_varlen(s, req->indices_count);
    uint32_t last_index = 0;
    uint32_t i;
    for (i = 0; i < req->indices_count; i++) {
        uint32_t diff = (i == 0) ? req->indices[i] : (req->indices[i] - last_index - 1);
        ser_varlen(s, diff);
        last_index = req->indices[i];
    }
}

dogecoin_bool dogecoin_getblocktxn_deserialize(
    dogecoin_getblocktxn *req,
    struct const_buffer *buf)
{
    if (!req || !buf) return false;

    if (!deser_u256(req->blockhash, buf))
        return false;

    if (!deser_varlen(&req->indices_count, buf))
        return false;

    if (req->indices_count > 0) {
        /* Each index is a differentially-encoded varint, so it occupies at least one
           byte on the wire: a count larger than the remaining buffer is impossible.
           Unbounded, the calloc below reserves indices_count * 4 bytes (~17 GB at
           0xFFFFFFFF) from a request message only 33 bytes long. */
        if (req->indices_count > buf->len) return false;
        req->indices = dogecoin_calloc(req->indices_count, sizeof(uint32_t));
        if (!req->indices)
            return false;

        uint32_t last_index = 0;
        uint32_t i;
        for (i = 0; i < req->indices_count; i++) {
            uint32_t diff;
            if (!deser_varlen(&diff, buf))
                return false;
            if (i == 0) {
                req->indices[i] = diff;
            } else {
                req->indices[i] = last_index + diff + 1;
            }
            last_index = req->indices[i];
        }
    }

    return true;
}

void dogecoin_blocktxn_serialize(cstring *s, const dogecoin_blocktxn *resp)
{
    if (!s || !resp) return;

    ser_u256(s, resp->blockhash);
    ser_varlen(s, resp->txs_count);
    uint32_t i;
    for (i = 0; i < resp->txs_count; i++) {
        if (resp->txs[i]) {
            dogecoin_tx_serialize(s, resp->txs[i]);
        }
    }
}

dogecoin_bool dogecoin_blocktxn_deserialize(
    dogecoin_blocktxn *resp,
    struct const_buffer *buf)
{
    if (!resp || !buf) return false;

    if (!deser_u256(resp->blockhash, buf))
        return false;

    if (!deser_varlen(&resp->txs_count, buf))
        return false;

    if (resp->txs_count > 0) {
        /* Each transaction that follows is several bytes minimum, so a count beyond
           the remaining buffer cannot be satisfied. Unbounded, the calloc below
           reserves txs_count pointers (~34 GB at 0xFFFFFFFF) before the first
           transaction is deserialized. */
        if (resp->txs_count > buf->len) return false;
        resp->txs = dogecoin_calloc(resp->txs_count, sizeof(dogecoin_tx *));
        if (!resp->txs)
            return false;

        uint32_t i;
        for (i = 0; i < resp->txs_count; i++) {
            resp->txs[i] = dogecoin_tx_new();
            size_t consumed = 0;
            if (!dogecoin_tx_deserialize(buf->p, buf->len,
                                         resp->txs[i], &consumed)) {
                return false;
            }
            if (!deser_skip(buf, consumed))
                return false;
        }
    }

    return true;
}

/* ================================================================ */
/*  P2P Message Construction                                        */
/* ================================================================ */

#ifdef WITH_NET

dogecoin_bool dogecoin_p2p_msg_sendcmpct_deser(
    dogecoin_bool *high_bandwidth_out,
    uint64_t *version_out,
    struct const_buffer *buf)
{
    if (!buf) return false;

    uint8_t announce;
    if (!deser_bytes(&announce, buf, 1)) return false;
    /* fAnnounce is a serialized bool. Core deserializes it straight into a C++
       bool and does not reject non-canonical encodings, so treat any non-zero
       byte as true rather than rejecting the message: the field only selects a
       relay preference, so being stricter than the reference implementation
       would risk penalising peers without protecting anything. */

    uint64_t version;
    if (!deser_u64(&version, buf)) return false;

    if (high_bandwidth_out) *high_bandwidth_out = (announce == 1);
    if (version_out) *version_out = version;
    return true;
}

cstring *dogecoin_p2p_msg_sendcmpct(
    const unsigned char netmagic[4],
    dogecoin_bool high_bandwidth,
    uint64_t version)
{
    cstring *payload = cstr_new_sz(9);
    /* fAnnounce: 1 byte boolean */
    uint8_t announce = high_bandwidth ? 1 : 0;
    ser_bytes(payload, &announce, 1);
    /* nCmpctVersion: 8 bytes LE */
    ser_u64(payload, version);

    cstring *msg = dogecoin_p2p_message_new(netmagic, DOGECOIN_MSG_SENDCMPCT,
                                             payload->str, payload->len);
    cstr_free(payload, true);
    return msg;
}

cstring *dogecoin_p2p_msg_cmpctblock(
    const unsigned char netmagic[4],
    const dogecoin_compact_block *cmpctblk)
{
    if (!cmpctblk) return NULL;

    cstring *payload = cstr_new_sz(512);
    if (!dogecoin_compact_block_serialize(payload, cmpctblk)) {
        cstr_free(payload, true);
        return NULL;
    }

    cstring *msg = dogecoin_p2p_message_new(netmagic, DOGECOIN_MSG_CMPCTBLOCK,
                                             payload->str, payload->len);
    cstr_free(payload, true);
    return msg;
}

cstring *dogecoin_p2p_msg_getblocktxn(
    const unsigned char netmagic[4],
    const dogecoin_getblocktxn *req)
{
    if (!req) return NULL;

    cstring *payload = cstr_new_sz(64);
    dogecoin_getblocktxn_serialize(payload, req);

    cstring *msg = dogecoin_p2p_message_new(netmagic, DOGECOIN_MSG_GETBLOCKTXN,
                                             payload->str, payload->len);
    cstr_free(payload, true);
    return msg;
}

cstring *dogecoin_p2p_msg_blocktxn(
    const unsigned char netmagic[4],
    const dogecoin_blocktxn *resp)
{
    if (!resp) return NULL;

    cstring *payload = cstr_new_sz(256);
    dogecoin_blocktxn_serialize(payload, resp);

    cstring *msg = dogecoin_p2p_message_new(netmagic, DOGECOIN_MSG_BLOCKTXN,
                                             payload->str, payload->len);
    cstr_free(payload, true);
    return msg;
}

#endif /* WITH_NET */

/* ================================================================ */
/*  Compact Block Reconstruction                                    */
/* ================================================================ */

/**
 * Compare two 6-byte short IDs.
 * Returns 0 if equal, non-zero otherwise.
 */
static int shortid_cmp(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, SHORTTXID_LENGTH);
}

dogecoin_bool dogecoin_compact_block_reconstruct(
    const dogecoin_compact_block *cmpctblk,
    dogecoin_compact_block_state *state,
    dogecoin_tx **known_txs,
    uint32_t known_txs_count)
{
    if (!cmpctblk || !state) return false;

    /* Reset any layout left by a previous compact block on this peer's state,
       otherwise a second cmpctblock leaks the earlier arrays. */
    if (state->available_txs) {
        dogecoin_free(state->available_txs);
        state->available_txs = NULL;
    }
    state->available_txs_count = 0;
    if (state->missing_indices) {
        dogecoin_free(state->missing_indices);
        state->missing_indices = NULL;
    }
    state->missing_count = 0;

    /* Total transaction count = short_ids + prefilled.
       Both are attacker-supplied counts, already bounded against the message
       length at deserialization; guard the sum against overflow before it is
       used as an allocation size. */
    if (cmpctblk->short_ids_count > UINT32_MAX - cmpctblk->prefilled_count) return false;
    uint32_t total_txs = cmpctblk->short_ids_count + cmpctblk->prefilled_count;
    if (total_txs == 0) return false;

    /* Allocate the available_txs array (NULL means missing) */
    state->available_txs = dogecoin_calloc(total_txs, sizeof(dogecoin_tx *));
    if (!state->available_txs) return false;
    state->available_txs_count = total_txs;

    uint32_t *shortid_to_txpos = NULL;

    /* Place prefilled transactions at their correct indices */
    uint32_t i;
    for (i = 0; i < cmpctblk->prefilled_count; i++) {
        uint32_t idx = cmpctblk->prefilled_txs[i].index;
        if (idx >= total_txs) goto fail;
        /* Two prefilled entries claiming the same slot would silently overwrite
           and desynchronise the short-id mapping built below, leaving a slot
           that no short id can ever fill. Reject rather than mis-assemble. */
        if (state->available_txs[idx] != NULL) goto fail;
        state->available_txs[idx] = cmpctblk->prefilled_txs[i].tx;
    }

    /* Build a mapping from short_ids positions to available_txs positions.
     * short_ids[j] corresponds to the j-th non-prefilled slot. */
    uint32_t short_idx = 0;
    if (cmpctblk->short_ids_count > 0) {
        shortid_to_txpos = dogecoin_calloc(cmpctblk->short_ids_count, sizeof(uint32_t));
        if (!shortid_to_txpos) goto fail;
    }

    for (i = 0; i < total_txs && short_idx < cmpctblk->short_ids_count; i++) {
        if (state->available_txs[i] == NULL) {
            shortid_to_txpos[short_idx] = i;
            short_idx++;
        }
    }

    /* Try to match each short ID against known transactions */
    uint32_t missing_count = 0;
    uint32_t j;
    for (j = 0; j < cmpctblk->short_ids_count; j++) {
        const uint8_t *target_shortid = &cmpctblk->short_ids[j * SHORTTXID_LENGTH];
        dogecoin_bool found = false;

        uint32_t k;
        for (k = 0; k < known_txs_count; k++) {
            if (!known_txs[k]) continue;

            /* Compute the short ID for this known transaction */
            uint256_t txhash;
            dogecoin_tx_hash(known_txs[k], txhash);

            uint8_t computed_shortid[SHORTTXID_LENGTH];
            dogecoin_compact_block_compute_short_id(
                cmpctblk->sipkey_k0, cmpctblk->sipkey_k1,
                txhash, computed_shortid);

            if (shortid_cmp(target_shortid, computed_shortid) == 0) {
                state->available_txs[shortid_to_txpos[j]] = known_txs[k];
                found = true;
                break;
            }
        }

        if (!found) {
            missing_count++;
        }
    }

    /* Build the missing indices list */
    if (missing_count > 0) {
        state->missing_indices = dogecoin_calloc(missing_count, sizeof(uint32_t));
        if (!state->missing_indices) goto fail;
        state->missing_count = missing_count;

        uint32_t mi = 0;
        for (j = 0; j < cmpctblk->short_ids_count; j++) {
            if (state->available_txs[shortid_to_txpos[j]] == NULL) {
                state->missing_indices[mi++] = shortid_to_txpos[j];
            }
        }
    } else {
        state->missing_count = 0;
        state->missing_indices = NULL;
    }

    dogecoin_free(shortid_to_txpos);

    return (missing_count == 0);

fail:
    /* Leave the state empty rather than half-built: available_txs_count must
       never outlive the array it describes, or fill_missing() below indexes a
       NULL pointer through a still-positive count. */
    dogecoin_free(shortid_to_txpos);
    dogecoin_free(state->available_txs);
    state->available_txs = NULL;
    state->available_txs_count = 0;
    return false;
}

dogecoin_bool dogecoin_compact_block_fill_missing(
    dogecoin_compact_block_state *state,
    const dogecoin_blocktxn *resp)
{
    if (!state || !resp) return false;
    if (!state->available_txs || !state->missing_indices) return false;

    if (resp->txs_count != state->missing_count) {
        /* Mismatch between requested and received transaction count */
        return false;
    }

    uint32_t i;
    for (i = 0; i < resp->txs_count; i++) {
        uint32_t idx = state->missing_indices[i];
        if (idx >= state->available_txs_count) return false;
        state->available_txs[idx] = resp->txs[i];
    }

    /* Verify all slots are filled */
    for (i = 0; i < state->available_txs_count; i++) {
        if (state->available_txs[i] == NULL) return false;
    }

    state->missing_count = 0;
    return true;
}
