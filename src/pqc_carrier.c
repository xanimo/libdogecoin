/*

 The MIT License (MIT)

 Copyright (c) 2026 edtubbs
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

/*
 * PQC P2SH carrier transaction construction and parsing.
 *
 * Implements the P2SH carrier mode for post-quantum signature commitment
 * transactions.  TX_C creates P2SH outputs whose redeem script is simply
 * OP_DROP*5 OP_1.  TX_R spends those outputs, embedding the full PQ
 * public key and signature in the scriptSig as tagged, chunked data
 * pushes that miners accept (non-standard but consensus-valid).
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <dogecoin/mem.h>
#include <dogecoin/pqc_carrier.h>
#include <dogecoin/rmd160.h>
#include <dogecoin/script.h>
#include <dogecoin/sha2.h>
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>
#ifdef USE_LIBOQS
#include <dogecoin/pqc_falcon.h>
#include <dogecoin/pqc_dilithium.h>
#endif
#ifdef USE_RACCOON_G
#include <dogecoin/pqc_raccoon.h>
#endif

/**
 * @brief This function pushes a single opcode byte onto a
 * script buffer.
 *
 * @param s The script buffer to append to.
 * @param op The opcode byte.
 *
 * @return Nothing.
 */
static void script_push_op(cstring* s, uint8_t op)
{
    cstr_append_buf(s, &op, 1);
}

/**
 * @brief This function pushes arbitrary data onto a script
 * buffer using the smallest canonical push encoding
 * (direct / OP_PUSHDATA1 / OP_PUSHDATA2).
 *
 * @param s The script buffer to append to.
 * @param data The pointer to the data bytes.
 * @param len The length of the data.
 *
 * @return Nothing.
 */
static void script_push_data(cstring* s, const uint8_t* data, size_t len)
{
    if (len == 0) {
        script_push_op(s, 0x00); /* OP_0 */
        return;
    }
    if (len <= 75) {
        uint8_t l = (uint8_t)len;
        cstr_append_buf(s, &l, 1);
        cstr_append_buf(s, data, len);
        return;
    }
    if (len <= 255) {
        uint8_t op = 0x4c; /* OP_PUSHDATA1 */
        uint8_t l = (uint8_t)len;
        cstr_append_buf(s, &op, 1);
        cstr_append_buf(s, &l, 1);
        cstr_append_buf(s, data, len);
        return;
    }
    uint8_t op = 0x4d; /* OP_PUSHDATA2 */
    uint16_t l = (uint16_t)len;
    uint8_t le[2] = { (uint8_t)(l & 0xff), (uint8_t)((l >> 8) & 0xff) };
    cstr_append_buf(s, &op, 1);
    cstr_append_buf(s, le, 2);
    cstr_append_buf(s, data, len);
}

/**
 * @brief This function reads one push-data element from raw
 * script bytes starting at *off.  On success, *out points
 * into the original buffer and *outlen is set.
 *
 * @param s The pointer to the raw script bytes.
 * @param slen The length of the script.
 * @param off The pointer to the current offset (updated on success).
 * @param out The pointer to receive the data pointer.
 * @param outlen The pointer to receive the data length.
 *
 * @return true on success, false on truncation or unexpected opcodes.
 */
static dogecoin_bool read_push(const uint8_t* s, size_t slen, size_t* off, const uint8_t** out, size_t* outlen)
{
    if (!s || !off || !out || !outlen || *off >= slen) return false;

    uint8_t op = s[*off];
    (*off)++;
    if (op == 0x00) {
        *out = NULL;
        *outlen = 0;
        return true;
    }
    if (op <= 75) {
        size_t n = op;
        if (*off + n > slen) return false;
        *out = s + *off;
        *outlen = n;
        *off += n;
        return true;
    }
    if (op == 0x4c) { /* OP_PUSHDATA1 */
        if (*off + 1 > slen) return false;
        size_t n = s[*off];
        *off += 1;
        if (*off + n > slen) return false;
        *out = s + *off;
        *outlen = n;
        *off += n;
        return true;
    }
    if (op == 0x4d) { /* OP_PUSHDATA2 */
        if (*off + 2 > slen) return false;
        size_t n = (size_t)s[*off] | ((size_t)s[*off + 1] << 8);
        *off += 2;
        if (*off + n > slen) return false;
        *out = s + *off;
        *outlen = n;
        *off += n;
        return true;
    }
    return false;
}

/**
 * @brief This function computes HASH160 (SHA-256 then
 * RIPEMD-160) of the given data.
 *
 * @param data The pointer to the input data.
 * @param len The length of the input data.
 * @param out20 The output buffer for the 20-byte hash.
 *
 * @return Nothing.
 */
static void hash160(const uint8_t* data, size_t len, uint8_t out20[20])
{
    uint8_t h32[32];
    sha256_raw(data, len, h32);
    rmd160(h32, sizeof(h32), out20);
}

/**
 * @brief This function builds the carrier redeem script:
 * OP_DROP OP_DROP OP_DROP OP_DROP OP_DROP OP_1.  This script
 * always succeeds after consuming the five data pushes in the
 * scriptSig, allowing miners to accept the TX_R spend.
 *
 * @param out_redeem The pointer to receive the allocated redeem script.
 *
 * @return true if the script was built, false on error.
 */
dogecoin_bool dogecoin_pqc_carrier_build_redeemscript(cstring** out_redeem)
{
    if (!out_redeem) return false;
    cstring* r = cstr_new_sz(8);
    if (!r) return false;
    for (int i = 0; i < 5; i++) {
        uint8_t op_drop = OP_DROP;
        cstr_append_buf(r, &op_drop, 1);
    }
    uint8_t op_true = OP_1;
    cstr_append_buf(r, &op_true, 1);
    *out_redeem = r;
    return true;
}

/**
 * @brief This function builds the P2SH scriptPubKey
 * (OP_HASH160 <hash160(redeem)> OP_EQUAL) from the carrier
 * redeem script.  Used to create the carrier outputs in TX_C.
 *
 * @param redeem The pointer to the redeem script.
 * @param out_spk The pointer to receive the allocated scriptPubKey.
 *
 * @return true if the scriptPubKey was built, false on error.
 */
dogecoin_bool dogecoin_pqc_carrier_build_p2sh_scriptpubkey(const cstring* redeem, cstring** out_spk)
{
    if (!redeem || !out_spk) return false;
    uint8_t h160[20];
    hash160((const uint8_t*)redeem->str, redeem->len, h160);
    cstring* spk = cstr_new_sz(23);
    if (!spk) return false;

    uint8_t op_hash160 = OP_HASH160;
    uint8_t push20 = 0x14;
    uint8_t op_equal = OP_EQUAL;
    cstr_append_buf(spk, &op_hash160, 1);
    cstr_append_buf(spk, &push20, 1);
    cstr_append_buf(spk, h160, sizeof(h160));
    cstr_append_buf(spk, &op_equal, 1);
    *out_spk = spk;
    return true;
}

/**
 * @brief This function builds a single carrier-part scriptSig
 * for TX_R.  Layout: <tag8> <8-byte-hdr> <chunk0..chunk4>
 * <redeemscript>.  The header encodes version, part index/total,
 * and the public-key and full-payload lengths so the SPV parser
 * can reassemble across parts.
 *
 * @param tag8 The 8-byte algorithm tag.
 * @param part_index The zero-based index of this part.
 * @param part_total The total number of parts.
 * @param pk_len The public key length encoded in the header.
 * @param full_len The full payload length encoded in the header.
 * @param part_data The pointer to this part's data payload.
 * @param part_data_len The length of the part data.
 * @param redeem The pointer to the redeem script.
 * @param out_scriptsig The pointer to receive the allocated scriptSig.
 *
 * @return true if the scriptSig was built, false on error.
 */
dogecoin_bool dogecoin_pqc_carrier_build_part_scriptsig(
    const char tag8[DOGECOIN_PQC_CARRIER_TAG_LEN],
    uint8_t part_index,
    uint8_t part_total,
    uint16_t pk_len,
    uint16_t full_len,
    const uint8_t* part_data,
    size_t part_data_len,
    const cstring* redeem,
    cstring** out_scriptsig)
{
    if (!tag8 || !redeem || !out_scriptsig) return false;
    if (part_total == 0) return false;
    if (part_data_len > DOGECOIN_PQC_CARRIER_MAX_CHUNKS * DOGECOIN_PQC_CARRIER_CHUNK_MAX) return false;

    uint8_t hdr[DOGECOIN_PQC_CARRIER_HDR_LEN];
    hdr[0] = 0x01;
    hdr[1] = part_index;
    hdr[2] = part_total;
    hdr[3] = 0x00;
    hdr[4] = (uint8_t)((pk_len >> 8) & 0xff);
    hdr[5] = (uint8_t)(pk_len & 0xff);
    hdr[6] = (uint8_t)((full_len >> 8) & 0xff);
    hdr[7] = (uint8_t)(full_len & 0xff);

    cstring* ss = cstr_new_sz(2048);
    if (!ss) return false;

    script_push_data(ss, (const uint8_t*)tag8, DOGECOIN_PQC_CARRIER_TAG_LEN);
    script_push_data(ss, hdr, sizeof(hdr));

    size_t off = 0;
    for (size_t i = 0; i < DOGECOIN_PQC_CARRIER_MAX_CHUNKS; i++) {
        size_t n = 0;
        if (off < part_data_len) {
            n = part_data_len - off;
            if (n > DOGECOIN_PQC_CARRIER_CHUNK_MAX) n = DOGECOIN_PQC_CARRIER_CHUNK_MAX;
            script_push_data(ss, part_data + off, n);
            off += n;
        } else {
            script_push_data(ss, NULL, 0);
        }
    }

    script_push_data(ss, (const uint8_t*)redeem->str, redeem->len);
    *out_scriptsig = ss;
    return true;
}

/**
 * @brief This function parses a carrier-part scriptSig produced
 * by dogecoin_pqc_carrier_build_part_scriptsig().  Extracts the
 * 8-byte tag, part index/total, pk/full lengths, the concatenated
 * data payload, and the redeem script.  Caller must free
 * *out_part_data with dogecoin_free() and *out_redeem with
 * cstr_free().
 *
 * @param scriptsig The pointer to the scriptSig to parse.
 * @param out_tag8 The output buffer for the 8-byte tag (null-terminated).
 * @param out_part_index The pointer to receive the part index.
 * @param out_part_total The pointer to receive the part total.
 * @param out_pk_len The pointer to receive the public key length.
 * @param out_full_len The pointer to receive the full payload length.
 * @param out_part_data The pointer to receive the allocated data payload.
 * @param out_part_data_len The pointer to receive the data payload length.
 * @param out_redeem The pointer to receive the allocated redeem script.
 *
 * @return true if parsing succeeded, false on error.
 */
dogecoin_bool dogecoin_pqc_carrier_parse_part_scriptsig(
    const cstring* scriptsig,
    char out_tag8[DOGECOIN_PQC_CARRIER_TAG_LEN + 1],
    uint8_t* out_part_index,
    uint8_t* out_part_total,
    uint16_t* out_pk_len,
    uint16_t* out_full_len,
    uint8_t** out_part_data,
    size_t* out_part_data_len,
    cstring** out_redeem)
{
    if (!scriptsig || !out_tag8 || !out_part_index || !out_part_total || !out_pk_len || !out_full_len ||
        !out_part_data || !out_part_data_len || !out_redeem) {
        return false;
    }

    const uint8_t* s = (const uint8_t*)scriptsig->str;
    size_t slen = scriptsig->len;
    size_t o = 0;
    const uint8_t* p = NULL;
    size_t n = 0;

    if (!read_push(s, slen, &o, &p, &n) || n != DOGECOIN_PQC_CARRIER_TAG_LEN) return false;
    memcpy(out_tag8, p, DOGECOIN_PQC_CARRIER_TAG_LEN);
    out_tag8[DOGECOIN_PQC_CARRIER_TAG_LEN] = '\0';

    if (!read_push(s, slen, &o, &p, &n) || n != DOGECOIN_PQC_CARRIER_HDR_LEN) return false;
    if (p[0] != 0x01) return false;
    *out_part_index = p[1];
    *out_part_total = p[2];
    *out_pk_len = (uint16_t)((p[4] << 8) | p[5]);
    *out_full_len = (uint16_t)((p[6] << 8) | p[7]);

    uint8_t* buf = (uint8_t*)dogecoin_malloc(DOGECOIN_PQC_CARRIER_MAX_CHUNKS * DOGECOIN_PQC_CARRIER_CHUNK_MAX);
    if (!buf) return false;
    size_t w = 0;
    for (size_t i = 0; i < DOGECOIN_PQC_CARRIER_MAX_CHUNKS; i++) {
        if (!read_push(s, slen, &o, &p, &n)) {
            dogecoin_free(buf);
            return false;
        }
        if (n > DOGECOIN_PQC_CARRIER_CHUNK_MAX) {
            dogecoin_free(buf);
            return false;
        }
        if (n && p) {
            memcpy(buf + w, p, n);
            w += n;
        }
    }

    if (!read_push(s, slen, &o, &p, &n)) {
        dogecoin_free(buf);
        return false;
    }
    cstring* r = cstr_new_buf(p, n);
    if (!r) {
        dogecoin_free(buf);
        return false;
    }

    *out_part_data = buf;
    *out_part_data_len = w;
    *out_redeem = r;
    return true;
}

/**
 * @brief This function appends P2SH carrier outputs to a
 * transaction (TX_C).  Creates part_total outputs, each paying
 * value koinu to carrier_spk.  TX_R will later spend each
 * output with its carrier scriptSig.
 *
 * @param tx The pointer to the transaction to modify.
 * @param carrier_spk The P2SH scriptPubKey for carrier outputs.
 * @param value The value in koinu for each carrier output.
 * @param part_total The number of carrier outputs to add.
 *
 * @return true if outputs were added, false on error.
 */
dogecoin_bool dogecoin_tx_add_pqc_carrier_outputs(
    dogecoin_tx* tx,
    const cstring* carrier_spk,
    uint64_t value,
    uint8_t part_total)
{
    if (!tx || !carrier_spk || part_total == 0) return false;
    for (uint8_t i = 0; i < part_total; i++) {
        dogecoin_tx_out* out = dogecoin_tx_out_new();
        if (!out) return false;
        out->value = value;
        if (out->script_pubkey) cstr_free(out->script_pubkey, true);
        out->script_pubkey = cstr_new_buf((const uint8_t*)carrier_spk->str, carrier_spk->len);
        if (!out->script_pubkey) {
            dogecoin_tx_out_free(out);
            return false;
        }
        vector_add(tx->vout, out);
    }
    return true;
}

#if defined(USE_LIBOQS) || defined(USE_RACCOON_G)

/**
 * @brief Extract PQC pubkey+sig from carrier-format scriptSigs in a transaction.
 *
 * Handles both single-part carriers (Falcon-512) and multi-part carriers
 * (Dilithium2 with 3 parts, Raccoon-G with 24 parts).  Multi-part payloads
 * are reassembled by collecting all carrier-tagged vins, ordering by
 * part_index, and concatenating.
 *
 * @param tx The transaction to scan.
 * @param out_algo The detected PQC algorithm.
 * @param out_pk Pointer into carrier_buf for the public key.
 * @param out_pk_len Length of the public key.
 * @param out_sig Pointer into carrier_buf for the signature.
 * @param out_sig_len Length of the signature.
 * @param out_vin_index Index of the first carrier vin.
 * @param carrier_buf Reassembled payload buffer (caller frees with dogecoin_free).
 * @param carrier_buf_len Total length of reassembled payload.
 *
 * @return true if carrier data was extracted, false otherwise.
 */
dogecoin_bool dogecoin_pqc_carrier_extract_scriptsig(
    const dogecoin_tx* tx,
    dogecoin_pqc_algo_t* out_algo,
    const uint8_t** out_pk, size_t* out_pk_len,
    const uint8_t** out_sig, size_t* out_sig_len,
    size_t* out_vin_index,
    uint8_t** carrier_buf, size_t* carrier_buf_len)
{
    if (!tx || !out_algo || !out_pk || !out_pk_len || !out_sig || !out_sig_len || !out_vin_index || !carrier_buf || !carrier_buf_len)
        return false;
    *carrier_buf = NULL;
    *carrier_buf_len = 0;

    /* First pass: find any carrier-tagged vin to discover algo and part_total */
    dogecoin_pqc_algo_t algo = DOGECOIN_PQC_ALGO_FALCON;
    uint8_t discovered_total = 0;
    uint16_t discovered_pk_len = 0;
    uint16_t discovered_full_len = 0;
    size_t first_vin = 0;
    dogecoin_bool found_any = false;
    char match_tag[DOGECOIN_PQC_CARRIER_TAG_LEN + 1];

    for (size_t vin = 0; vin < tx->vin->len; vin++) {
        dogecoin_tx_in* tx_in = vector_idx(tx->vin, vin);
        if (!tx_in || !tx_in->script_sig || tx_in->script_sig->len < 20)
            continue;
        char tag8[DOGECOIN_PQC_CARRIER_TAG_LEN + 1];
        uint8_t pi = 0, pt = 0;
        uint16_t pk_l = 0, fl = 0;
        uint8_t* pd = NULL;
        size_t pdl = 0;
        cstring* rd = NULL;
        if (!dogecoin_pqc_carrier_parse_part_scriptsig(tx_in->script_sig, tag8, &pi, &pt,
                                                        &pk_l, &fl, &pd, &pdl, &rd)) {
            continue;
        }
        if (pd) dogecoin_free(pd);
        if (rd) cstr_free(rd, true);

        if (memcmp(tag8, "FLC1FULL", 8) == 0)
            algo = DOGECOIN_PQC_ALGO_FALCON;
        else if (memcmp(tag8, "DIL2FULL", 8) == 0)
            algo = DOGECOIN_PQC_ALGO_DILITHIUM;
#ifdef USE_RACCOON_G
        else if (memcmp(tag8, "RCG4FULL", 8) == 0)
            algo = DOGECOIN_PQC_ALGO_RACCOONG;
#endif
        else
            continue;

        memcpy(match_tag, tag8, DOGECOIN_PQC_CARRIER_TAG_LEN + 1);
        discovered_total = pt;
        discovered_pk_len = pk_l;
        discovered_full_len = fl;
        first_vin = vin;
        found_any = true;
        break;
    }

    if (!found_any || discovered_total == 0 || discovered_full_len == 0 || discovered_pk_len == 0)
        return false;

    /* Allocate part collection arrays */
    uint8_t** parts_data = (uint8_t**)dogecoin_calloc(discovered_total, sizeof(uint8_t*));
    size_t*  parts_len  = (size_t*)dogecoin_calloc(discovered_total, sizeof(size_t));
    if (!parts_data || !parts_len) {
        if (parts_data) dogecoin_free(parts_data);
        if (parts_len) dogecoin_free(parts_len);
        return false;
    }

    uint8_t parts_found = 0;

    /* Second pass: collect all parts with matching tag */
    for (size_t vin = 0; vin < tx->vin->len && parts_found < discovered_total; vin++) {
        dogecoin_tx_in* tx_in = vector_idx(tx->vin, vin);
        if (!tx_in || !tx_in->script_sig || tx_in->script_sig->len < 20)
            continue;
        char tag8[DOGECOIN_PQC_CARRIER_TAG_LEN + 1];
        uint8_t pi = 0, pt = 0;
        uint16_t pk_l = 0, fl = 0;
        uint8_t* pd = NULL;
        size_t pdl = 0;
        cstring* rd = NULL;
        if (!dogecoin_pqc_carrier_parse_part_scriptsig(tx_in->script_sig, tag8, &pi, &pt,
                                                        &pk_l, &fl, &pd, &pdl, &rd)) {
            continue;
        }
        if (rd) cstr_free(rd, true);

        if (memcmp(tag8, match_tag, DOGECOIN_PQC_CARRIER_TAG_LEN) != 0 ||
            pt != discovered_total || pi >= discovered_total) {
            if (pd) dogecoin_free(pd);
            continue;
        }

        if (parts_data[pi]) {
            /* Duplicate part_index -- skip */
            if (pd) dogecoin_free(pd);
            continue;
        }
        parts_data[pi] = pd;
        parts_len[pi] = pdl;
        parts_found++;
    }

    /* Verify all parts were collected */
    if (parts_found != discovered_total) {
        for (uint8_t i = 0; i < discovered_total; i++) {
            if (parts_data[i]) dogecoin_free(parts_data[i]);
        }
        dogecoin_free(parts_data);
        dogecoin_free(parts_len);
        return false;
    }

    /* Reassemble full payload: concatenate parts in order */
    size_t total_len = 0;
    for (uint8_t i = 0; i < discovered_total; i++)
        total_len += parts_len[i];

    /* Truncate to full_len if parts carry padding beyond payload */
    if (total_len > (size_t)discovered_full_len)
        total_len = (size_t)discovered_full_len;

    uint8_t* full_buf = (uint8_t*)dogecoin_malloc(total_len);
    if (!full_buf) {
        for (uint8_t i = 0; i < discovered_total; i++) {
            if (parts_data[i]) dogecoin_free(parts_data[i]);
        }
        dogecoin_free(parts_data);
        dogecoin_free(parts_len);
        return false;
    }

    size_t offset = 0;
    for (uint8_t i = 0; i < discovered_total; i++) {
        size_t copy_len = parts_len[i];
        if (offset + copy_len > total_len)
            copy_len = total_len - offset;
        if (copy_len > 0)
            memcpy(full_buf + offset, parts_data[i], copy_len);
        offset += copy_len;
        dogecoin_free(parts_data[i]);
    }
    dogecoin_free(parts_data);
    dogecoin_free(parts_len);

    /* Split into pk and sig */
    if (total_len < (size_t)(discovered_pk_len + 1) || discovered_pk_len == 0) {
        dogecoin_free(full_buf);
        return false;
    }

    size_t sig_len = total_len - discovered_pk_len;
    *out_algo = algo;
    *out_pk = full_buf;
    *out_pk_len = discovered_pk_len;
    *out_sig = full_buf + discovered_pk_len;
    *out_sig_len = sig_len;
    *out_vin_index = first_vin;
    *carrier_buf = full_buf;
    *carrier_buf_len = total_len;
    return true;
}

/**
 * @brief Verify a PQC carrier reveal by reconstructing TX_BASE from raw TX_C
 * bytes, deriving the sighash32, and verifying the PQC signature over it.
 *
 * TX_BASE is reconstructed from TX_C by stripping the OP_RETURN commitment
 * output and all canonical P2SH carrier outputs, then restoring the total
 * carrier value to the first output.  This is the same transaction template
 * that was signed when the PQC signature was originally produced.
 *
 * @param algo The PQC algorithm.
 * @param txc_raw The serialized TX_C bytes.
 * @param txc_raw_len The length of the serialized TX_C.
 * @param pk The PQC public key bytes.
 * @param pk_len The length of the public key.
 * @param sig The PQC signature bytes.
 * @param sig_len The length of the signature.
 * @param out_sighash Output buffer for the computed 32-byte sighash (zeroed on failure).
 *
 * @return true iff the PQC signature verified successfully over the sighash.
 */
dogecoin_bool dogecoin_pqc_carrier_verify_reveal(
    dogecoin_pqc_algo_t algo,
    const uint8_t* txc_raw,
    size_t txc_raw_len,
    const uint8_t* pk,
    size_t pk_len,
    const uint8_t* sig,
    size_t sig_len,
    uint8_t out_sighash[32])
{
    if (out_sighash) memset(out_sighash, 0, 32);
    if (!txc_raw || txc_raw_len == 0 || !pk || pk_len == 0 || !sig || sig_len == 0)
        return false;

    dogecoin_tx* txc = dogecoin_tx_new();
    if (!txc) return false;
    size_t consumed = 0;
    if (!dogecoin_tx_deserialize(txc_raw, txc_raw_len, txc, &consumed)) {
        dogecoin_tx_free(txc);
        return false;
    }

    /* Build TX_BASE by removing the OP_RETURN and P2SH carrier outputs.
       Precompute the canonical carrier P2SH scriptPubKey for exact matching. */
    uint8_t carrier_redeem[6] = {0x75, 0x75, 0x75, 0x75, 0x75, 0x51};
    uint8_t carrier_sha[32];
    sha256_raw(carrier_redeem, sizeof(carrier_redeem), carrier_sha);
    uint8_t carrier_h160[20];
    rmd160(carrier_sha, sizeof(carrier_sha), carrier_h160);
    uint8_t carrier_spk[23];
    carrier_spk[0]  = 0xa9; /* OP_HASH160 */
    carrier_spk[1]  = 0x14; /* PUSH 20 bytes */
    memcpy(carrier_spk + 2, carrier_h160, 20);
    carrier_spk[22] = 0x87; /* OP_EQUAL */

    dogecoin_tx* tx_base = dogecoin_tx_new();
    if (!tx_base) {
        dogecoin_tx_free(txc);
        return false;
    }
    tx_base->version = txc->version;
    tx_base->locktime = txc->locktime;

    for (size_t vi = 0; vi < txc->vin->len; vi++) {
        dogecoin_tx_in* orig = vector_idx(txc->vin, vi);
        dogecoin_tx_in* copy = dogecoin_tx_in_new();
        if (!copy) {
            dogecoin_tx_free(tx_base);
            dogecoin_tx_free(txc);
            return false;
        }
        memcpy(copy->prevout.hash, orig->prevout.hash, sizeof(copy->prevout.hash));
        copy->prevout.n = orig->prevout.n;
        copy->sequence = orig->sequence;
        if (orig->script_sig && orig->script_sig->len > 0) {
            /* Free the default empty cstring that dogecoin_tx_in_new()
               allocates before overwriting, then propagate OOM on failure. */
            if (copy->script_sig) cstr_free(copy->script_sig, true);
            copy->script_sig = cstr_new_buf(orig->script_sig->str, orig->script_sig->len);
            if (!copy->script_sig) {
                dogecoin_tx_in_free(copy);
                dogecoin_tx_free(tx_base);
                dogecoin_tx_free(txc);
                return false;
            }
        }
        vector_add(tx_base->vin, copy);
    }

    uint64_t carrier_total = 0;
    for (size_t vo = 0; vo < txc->vout->len; vo++) {
        dogecoin_tx_out* orig = vector_idx(txc->vout, vo);
        /* Skip OP_RETURN (nulldata) outputs */
        if (orig->script_pubkey && orig->script_pubkey->len > 0 &&
            (uint8_t)orig->script_pubkey->str[0] == 0x6a) {
            continue;
        }
        /* Skip canonical P2SH carrier outputs — exact match only */
        if (orig->script_pubkey && orig->script_pubkey->len == 23 &&
            memcmp(orig->script_pubkey->str, carrier_spk, 23) == 0) {
            carrier_total += orig->value;
            continue;
        }
        dogecoin_tx_out* copy = dogecoin_tx_out_new();
        if (!copy) {
            dogecoin_tx_free(tx_base);
            dogecoin_tx_free(txc);
            return false;
        }
        copy->value = orig->value;
        if (orig->script_pubkey && orig->script_pubkey->len > 0) {
            if (copy->script_pubkey) cstr_free(copy->script_pubkey, true);
            copy->script_pubkey = cstr_new_buf(orig->script_pubkey->str, orig->script_pubkey->len);
            if (!copy->script_pubkey) {
                dogecoin_tx_out_free(copy);
                dogecoin_tx_free(tx_base);
                dogecoin_tx_free(txc);
                return false;
            }
        }
        vector_add(tx_base->vout, copy);
    }

    /* Restore carrier cost to first output (was deducted during TX_C construction) */
    if (carrier_total > 0 && tx_base->vout->len > 0) {
        dogecoin_tx_out* first_out = vector_idx(tx_base->vout, 0);
        first_out->value += carrier_total;
    }

    dogecoin_bool verified = false;
    if (txc->vin->len > 0) {
        dogecoin_tx_in* first_in = vector_idx(txc->vin, 0);
        /* Validate P2PKH scriptSig bounds */
        if (first_in->script_sig &&
            first_in->script_sig->len >= DOGECOIN_PQC_MIN_P2PKH_SCRIPTSIG_LEN &&
            first_in->script_sig->len <= DOGECOIN_PQC_MAX_P2PKH_SCRIPTSIG_LEN) {
            const uint8_t* ss = (const uint8_t*)first_in->script_sig->str;
            size_t sslen = first_in->script_sig->len;
            size_t pos = 0;
            uint8_t sig_push_len = ss[pos++];
            /* Reject OP_PUSHDATA1/2/4 — DER sigs are always < 76 bytes */
            if (sig_push_len >= DOGECOIN_PQC_MIN_DER_SIG_PUSH_LEN &&
                sig_push_len <= DOGECOIN_PQC_MAX_DER_SIG_PUSH_LEN &&
                pos + sig_push_len <= sslen &&
                ss[pos] == 0x30 /* DER SEQUENCE */) {
                pos += sig_push_len;
                if (pos < sslen) {
                    uint8_t pk_push_len = ss[pos++];
                    if (pk_push_len == 33 && pos + 33 <= sslen) {
                        const uint8_t* ecdsa_pk = ss + pos;
                        /* Compute HASH160 of the pubkey */
                        uint8_t sha_out[32];
                        sha256_raw(ecdsa_pk, 33, sha_out);
                        uint8_t h160[20];
                        rmd160(sha_out, 32, h160);
                        /* Build P2PKH scriptPubKey */
                        cstring* spk = cstr_new_sz(25);
                        if (spk) {
                            uint8_t p2pkh_prefix[] = {0x76, 0xa9, 0x14};
                            uint8_t p2pkh_suffix[] = {0x88, 0xac};
                            cstr_append_buf(spk, p2pkh_prefix, 3);
                            cstr_append_buf(spk, h160, 20);
                            cstr_append_buf(spk, p2pkh_suffix, 2);

                            uint8_t sighash[32];
                            if (dogecoin_tx_sighash32(tx_base, spk, 0, SIGHASH_ALL, sighash)) {
                                if (out_sighash) memcpy(out_sighash, sighash, 32);
#ifdef USE_LIBOQS
                                if (algo == DOGECOIN_PQC_ALGO_FALCON)
                                    verified = dogecoin_falcon512_verify(pk, pk_len, sighash, 32, sig, sig_len);
                                else if (algo == DOGECOIN_PQC_ALGO_DILITHIUM)
                                    verified = dogecoin_dilithium2_verify(pk, pk_len, sighash, 32, sig, sig_len);
#endif
#ifdef USE_RACCOON_G
                                if (algo == DOGECOIN_PQC_ALGO_RACCOONG)
                                    verified = dogecoin_raccoong44_verify(pk, pk_len, sighash, 32, sig, sig_len);
#endif
                            }
                            cstr_free(spk, true);
                        }
                        /* If spk allocation failed, verified remains false — safer
                           than dereferencing a NULL cstring in cstr_append_buf. */
                    }
                }
            }
        }
    }

    dogecoin_tx_free(tx_base);
    dogecoin_tx_free(txc);
    return verified;
}

#endif /* USE_LIBOQS */
