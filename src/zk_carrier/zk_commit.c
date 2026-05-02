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
 * ZK carrier — TX_C / TX_R construction.
 *
 * This is the integration glue requested by the reserved-opcode proposal:
 * we deliberately reuse the PQ carrier pattern (src/pqc_carrier.c) — same
 * P2SH redeem script, same chunked scriptSig layout, same 8-byte tag slot —
 * so a single SPV path can recognise both PQ-signature and ZK-proof carrier
 * transactions.  Only the ASCII tag changes (PQC uses "FLC1FULL", "DIL2FULL",
 * "RCG4FULL"; ZK uses "ZKP1FULL").
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <dogecoin/cstr.h>
#include <dogecoin/mem.h>
#include <dogecoin/pqc_carrier.h>
#include <dogecoin/pqc_falcon.h>
#include <dogecoin/rmd160.h>
#include <dogecoin/script.h>
#include <dogecoin/sha2.h>
#include <dogecoin/tx.h>
#include <dogecoin/zk_carrier.h>

/* Per-part chunked payload capacity (mirrors PQC carrier). */
#define ZK_PART_PAYLOAD_MAX (DOGECOIN_PQC_CARRIER_MAX_CHUNKS * DOGECOIN_PQC_CARRIER_CHUNK_MAX)

/**
 * @brief Internal helper: derive the number of PQC-shaped carrier outputs
 * needed to ferry a payload of `payload_len` bytes through TX_R.
 *
 * Mirrors the PQC carrier's chunking math (DOGECOIN_PQC_CARRIER_MAX_CHUNKS *
 * DOGECOIN_PQC_CARRIER_CHUNK_MAX bytes per part).  Always returns at least
 * one part so SPV has something to walk even for an empty payload.
 *
 * @param payload_len     length of the ZKP1 payload to chunk
 * @param out_part_total  receives the part count (1..255)
 *
 * @return true on success; false if the payload would need >255 parts
 */
static dogecoin_bool zk_compute_part_total(size_t payload_len, uint8_t* out_part_total)
{
    if (payload_len == 0) {
        /* Always at least one carrier output so SPV has something to walk. */
        *out_part_total = 1;
        return true;
    }
    size_t parts = (payload_len + ZK_PART_PAYLOAD_MAX - 1) / ZK_PART_PAYLOAD_MAX;
    if (parts == 0 || parts > 0xFF) return false;
    *out_part_total = (uint8_t)parts;
    return true;
}

/**
 * @brief Append the OP_RETURN commit output and the P2SH carrier outputs
 * (one per required reveal-part) to an in-progress TX_C transaction.
 *
 * Combines dogecoin_zk_build_opreturn_scriptpubkey + dogecoin_tx_add_pqc_*
 * outputs into a single call so the TX_C build path mirrors how PQC
 * commitments are added.  `payload` is the payload that will later be
 * revealed in TX_R; the number of carrier outputs is derived from its length
 * via zk_compute_part_total.
 *
 * @param tx               in-progress transaction to append outputs to
 * @param payload          ZKP1 payload that will be revealed by TX_R
 * @param payload_len      byte length of `payload`
 * @param mode             ZK mode written into the OP_RETURN commitment
 * @param carrier_value    per-output value in koinu (must be >= dust)
 * @param out_carrier_spk  receives the P2SH scriptPubKey of the carrier
 *                         outputs (caller frees with cstr_free(..., true))
 * @param out_part_total   receives the number of carrier outputs created
 *
 * @return DOGECOIN_ZK_OK on success, or one of DOGECOIN_ZK_ERR_INVALID_ARG /
 *         DOGECOIN_ZK_ERR_BAD_MODE / DOGECOIN_ZK_ERR_OOM /
 *         DOGECOIN_ZK_ERR_TRUNCATED on failure
 */
dogecoin_zk_err_t dogecoin_zk_build_carrier_tx_c(
    dogecoin_tx* tx,
    const uint8_t* payload,
    size_t payload_len,
    dogecoin_zk_mode_t mode,
    uint64_t carrier_value,
    cstring** out_carrier_spk,
    uint8_t* out_part_total)
{
    if (!tx || !payload || payload_len == 0 || !out_carrier_spk || !out_part_total) {
        return DOGECOIN_ZK_ERR_INVALID_ARG;
    }
    *out_carrier_spk = NULL;
    *out_part_total = 0;

    uint8_t commit[32];
    dogecoin_zk_err_t e = dogecoin_zk_get_commitment_hash(payload, payload_len, commit);
    if (e != DOGECOIN_ZK_OK) return e;

    /* 1. OP_RETURN commit output (vout 0 by convention). */
    cstring* opret = NULL;
    e = dogecoin_zk_build_opreturn_scriptpubkey(mode, commit, &opret);
    if (e != DOGECOIN_ZK_OK) return e;
    {
        dogecoin_tx_out* out = dogecoin_tx_out_new();
        if (!out) { cstr_free(opret, true); return DOGECOIN_ZK_ERR_OOM; }
        out->value = 0;
        if (out->script_pubkey) cstr_free(out->script_pubkey, true);
        out->script_pubkey = cstr_new_buf((const uint8_t*)opret->str, opret->len);
        if (!out->script_pubkey) {
            dogecoin_tx_out_free(out);
            cstr_free(opret, true);
            return DOGECOIN_ZK_ERR_OOM;
        }
        vector_add(tx->vout, out);
        cstr_free(opret, true);
    }

    /* 2. Carrier P2SH outputs.  Reuse the PQC redeem + scriptPubKey helpers
     *    verbatim — same `OP_DROP*5 OP_1` redeem script, same hash160 P2SH. */
    cstring* redeem = NULL;
    if (!dogecoin_pqc_carrier_build_redeemscript(&redeem) || !redeem) {
        return DOGECOIN_ZK_ERR_OOM;
    }
    cstring* carrier_spk = NULL;
    if (!dogecoin_pqc_carrier_build_p2sh_scriptpubkey(redeem, &carrier_spk) || !carrier_spk) {
        cstr_free(redeem, true);
        return DOGECOIN_ZK_ERR_OOM;
    }
    cstr_free(redeem, true);

    uint8_t part_total = 0;
    if (!zk_compute_part_total(payload_len, &part_total)) {
        cstr_free(carrier_spk, true);
        return DOGECOIN_ZK_ERR_INVALID_ARG;
    }
    if (!dogecoin_tx_add_pqc_carrier_outputs(tx, carrier_spk, carrier_value, part_total)) {
        cstr_free(carrier_spk, true);
        return DOGECOIN_ZK_ERR_OOM;
    }

    *out_carrier_spk = carrier_spk;
    *out_part_total = part_total;
    return DOGECOIN_ZK_OK;
}

/**
 * @brief Build the per-part scriptSigs that TX_R will use to spend the TX_C
 * carrier outputs and reveal the previously-committed ZKP1 payload.
 *
 * One scriptSig is produced per chunk of the payload, each tagged with the
 * canonical "ZKP1FULL" 8-byte tag and the (i, part_total) coordinates the
 * reassembly path expects.  The advisory pk_len/full_len header fields are
 * set from the embedded ZKP1 lengths; SPV consumers must rely on the 32-bit
 * length fields inside the payload itself when reassembling.
 *
 * @param payload          ZKP1 payload to chunk into TX_R inputs
 * @param payload_len      length of `payload`
 * @param out_scriptsigs   receives a freshly-allocated cstring* array with
 *                         `*out_part_total` entries; caller frees each
 *                         element with cstr_free(..., true) and the array
 *                         itself with dogecoin_free()
 * @param out_part_total   receives the part count produced
 *
 * @return DOGECOIN_ZK_OK on success, DOGECOIN_ZK_ERR_INVALID_ARG /
 *         DOGECOIN_ZK_ERR_OOM on failure
 */
dogecoin_zk_err_t dogecoin_zk_build_carrier_tx_r_scriptsigs(
    const uint8_t* payload,
    size_t payload_len,
    cstring*** out_scriptsigs,
    uint8_t* out_part_total)
{
    if (!payload || payload_len == 0 || !out_scriptsigs || !out_part_total) {
        return DOGECOIN_ZK_ERR_INVALID_ARG;
    }
    *out_scriptsigs = NULL;
    *out_part_total = 0;

    uint8_t part_total = 0;
    if (!zk_compute_part_total(payload_len, &part_total)) {
        return DOGECOIN_ZK_ERR_INVALID_ARG;
    }

    cstring* redeem = NULL;
    if (!dogecoin_pqc_carrier_build_redeemscript(&redeem) || !redeem) {
        return DOGECOIN_ZK_ERR_OOM;
    }

    cstring** sigs = (cstring**)dogecoin_calloc(part_total, sizeof(cstring*));
    if (!sigs) {
        cstr_free(redeem, true);
        return DOGECOIN_ZK_ERR_OOM;
    }

    /* For ZK carriers we don't carry a separate "public key" the way PQC
     * does; we reuse the pk_len/full_len fields of the PQC header to mean
     * (public_inputs_len, payload_len) so an SPV parser can find the public
     * inputs slice without re-decoding the embedded ZKP1 magic.  Decoding
     * the payload is the canonical way; the header values are advisory. */
    dogecoin_zk_mode_t hdr_mode;
    uint32_t hdr_circ;
    const uint8_t* hdr_pi = NULL;
    size_t hdr_pi_len = 0;
    const uint8_t* hdr_proof = NULL;
    size_t hdr_proof_len = 0;
    uint16_t advisory_pl = 0;
    if (dogecoin_zk_decode_payload(payload, payload_len, &hdr_mode, &hdr_circ,
                                   &hdr_pi, &hdr_pi_len, &hdr_proof, &hdr_proof_len,
                                   NULL, NULL) == DOGECOIN_ZK_OK) {
        advisory_pl = (uint16_t)(hdr_pi_len > 0xFFFFu ? 0xFFFFu : hdr_pi_len);
    }
    /* If full payload exceeds 16-bit "full_len" advisory field, fall back to
     * the truncated value 0xFFFF — SPV consumers must rely on the embedded
     * ZKP1 length fields, which are 32-bit. */
    uint16_t advisory_full = (uint16_t)(payload_len > 0xFFFFu ? 0xFFFFu : payload_len);

    for (uint8_t i = 0; i < part_total; i++) {
        size_t off = (size_t)i * ZK_PART_PAYLOAD_MAX;
        size_t len = payload_len - off;
        if (len > ZK_PART_PAYLOAD_MAX) len = ZK_PART_PAYLOAD_MAX;
        cstring* ss = NULL;
        if (!dogecoin_pqc_carrier_build_part_scriptsig(
                DOGECOIN_ZK_CARRIER_TAG8, i, part_total,
                advisory_pl, advisory_full,
                payload + off, len, redeem, &ss) || !ss) {
            for (uint8_t k = 0; k < i; k++) {
                if (sigs[k]) cstr_free(sigs[k], true);
            }
            dogecoin_free(sigs);
            cstr_free(redeem, true);
            return DOGECOIN_ZK_ERR_OOM;
        }
        sigs[i] = ss;
    }

    cstr_free(redeem, true);
    *out_scriptsigs = sigs;
    *out_part_total = part_total;
    return DOGECOIN_ZK_OK;
}

/**
 * @brief Reassemble the ZKP1 payload from the carrier inputs of TX_R.
 *
 * Walks every input of `tx_r`, matches the canonical PQC-style carrier
 * scriptSig tagged with "ZKP1FULL", validates per-part headers (matching
 * part_total / full_len / no duplicate indices), concatenates the parts
 * in order, and returns the reassembled payload buffer.
 *
 * @param tx_r             reveal transaction whose inputs spend TX_C carriers
 * @param out_payload      receives a freshly-allocated payload buffer
 *                         (caller frees with dogecoin_free())
 * @param out_payload_len  receives the byte length of *out_payload
 *
 * @return DOGECOIN_ZK_OK on success, or one of DOGECOIN_ZK_ERR_INVALID_ARG /
 *         DOGECOIN_ZK_ERR_OOM / DOGECOIN_ZK_ERR_TRUNCATED on failure
 */
dogecoin_zk_err_t dogecoin_zk_extract_carrier_payload(
    const dogecoin_tx* tx_r,
    uint8_t** out_payload,
    size_t* out_payload_len)
{
    if (!tx_r || !out_payload || !out_payload_len) return DOGECOIN_ZK_ERR_INVALID_ARG;
    *out_payload = NULL;
    *out_payload_len = 0;

    /* Walk every input, find the ZK-tagged carrier parts, reassemble. */
    if (!tx_r->vin) return DOGECOIN_ZK_ERR_INVALID_ARG;

    uint8_t expected_total = 0;
    uint16_t advisory_full = 0;
    uint8_t** part_bufs = NULL;
    size_t* part_lens = NULL;
    int seen_any = 0;

    for (size_t vin = 0; vin < tx_r->vin->len; vin++) {
        dogecoin_tx_in* in = (dogecoin_tx_in*)vector_idx(tx_r->vin, vin);
        if (!in || !in->script_sig || in->script_sig->len < 20) continue;

        char tag8[DOGECOIN_PQC_CARRIER_TAG_LEN + 1];
        uint8_t pi = 0, pt = 0;
        uint16_t pk_len = 0, full_len = 0;
        uint8_t* part_data = NULL;
        size_t part_data_len = 0;
        cstring* redeem = NULL;
        if (!dogecoin_pqc_carrier_parse_part_scriptsig(in->script_sig, tag8, &pi, &pt,
                                                       &pk_len, &full_len,
                                                       &part_data, &part_data_len, &redeem)) {
            continue;
        }
        if (memcmp(tag8, DOGECOIN_ZK_CARRIER_TAG8, DOGECOIN_PQC_CARRIER_TAG_LEN) != 0 ||
            pt == 0 || pi >= pt) {
            if (part_data) dogecoin_free(part_data);
            if (redeem) cstr_free(redeem, true);
            continue;
        }

        if (!seen_any) {
            expected_total = pt;
            advisory_full = full_len;
            part_bufs = (uint8_t**)dogecoin_calloc(expected_total, sizeof(uint8_t*));
            part_lens = (size_t*)dogecoin_calloc(expected_total, sizeof(size_t));
            if (!part_bufs || !part_lens) {
                if (part_bufs) dogecoin_free(part_bufs);
                if (part_lens) dogecoin_free(part_lens);
                if (redeem) cstr_free(redeem, true);
                dogecoin_free(part_data);
                return DOGECOIN_ZK_ERR_OOM;
            }
            seen_any = 1;
        }

        if (pt != expected_total) {
            if (redeem) cstr_free(redeem, true);
            dogecoin_free(part_data);
            continue;
        }
        if (part_bufs[pi]) {
            /* Duplicate part — keep the first. */
            if (redeem) cstr_free(redeem, true);
            dogecoin_free(part_data);
            continue;
        }
        part_bufs[pi] = part_data;
        part_lens[pi] = part_data_len;
        if (redeem) cstr_free(redeem, true);
    }

    if (!seen_any) return DOGECOIN_ZK_ERR_TRUNCATED;

    /* Verify all parts present, sum lengths. */
    size_t total = 0;
    for (uint8_t i = 0; i < expected_total; i++) {
        if (!part_bufs[i]) {
            for (uint8_t k = 0; k < expected_total; k++) {
                if (part_bufs[k]) dogecoin_free(part_bufs[k]);
            }
            dogecoin_free(part_bufs);
            dogecoin_free(part_lens);
            return DOGECOIN_ZK_ERR_TRUNCATED;
        }
        total += part_lens[i];
    }

    /* Cross-check advisory_full when it isn't the saturated sentinel. */
    if (advisory_full != 0xFFFFu && advisory_full != (uint16_t)total) {
        for (uint8_t k = 0; k < expected_total; k++) {
            if (part_bufs[k]) dogecoin_free(part_bufs[k]);
        }
        dogecoin_free(part_bufs);
        dogecoin_free(part_lens);
        return DOGECOIN_ZK_ERR_TRUNCATED;
    }

    uint8_t* out = (uint8_t*)dogecoin_malloc(total);
    if (!out) {
        for (uint8_t k = 0; k < expected_total; k++) {
            if (part_bufs[k]) dogecoin_free(part_bufs[k]);
        }
        dogecoin_free(part_bufs);
        dogecoin_free(part_lens);
        return DOGECOIN_ZK_ERR_OOM;
    }
    size_t off = 0;
    for (uint8_t i = 0; i < expected_total; i++) {
        memcpy(out + off, part_bufs[i], part_lens[i]);
        off += part_lens[i];
        dogecoin_free(part_bufs[i]);
    }
    dogecoin_free(part_bufs);
    dogecoin_free(part_lens);

    /* Sanity-check magic so an obvious non-ZK carrier doesn't pass through. */
    if (off < DOGECOIN_ZK_CARRIER_MAGIC_LEN ||
        memcmp(out, DOGECOIN_ZK_CARRIER_MAGIC, DOGECOIN_ZK_CARRIER_MAGIC_LEN) != 0) {
        dogecoin_free(out);
        return DOGECOIN_ZK_ERR_BAD_MAGIC;
    }

    *out_payload = out;
    *out_payload_len = off;
    return DOGECOIN_ZK_OK;
}

/**
 * @brief Walk a tx's vouts looking for the canonical TX_C OP_RETURN
 * commitment (`0x6a 0x25 "DZKC" <mode-byte> <commitment32>`).
 *
 * Returns true on the first match and writes the mode + 32-byte commit;
 * returns false otherwise.  Mirrors dogecoin_tx_extract_falcon512_commit
 * (src/pqc_falcon.c) so the SPV layer can detect ZK commitments alongside
 * Falcon/Dilithium/Raccoon ones.  No allocation.
 *
 * @param tx            transaction to scan
 * @param out_mode      receives the decoded mode byte on success
 * @param out_commit32  receives the 32-byte SHA256d commitment on success
 *
 * @return true if a DZKC commitment is found, false otherwise
 */
dogecoin_bool dogecoin_tx_extract_zk_commit(
    const dogecoin_tx* tx,
    dogecoin_zk_mode_t* out_mode,
    uint8_t out_commit32[32])
{
    if (!tx || !out_mode || !out_commit32 || !tx->vout) {
        return false;
    }

    /* Total scriptPubKey length is 1 (OP_RETURN) + 1 (push len) + 4 (tag) +
       1 (mode) + 32 (commit) = 39 bytes.  The push length byte equals
       DOGECOIN_ZK_OPRETURN_DATA_LEN (37). */
    const size_t expected_len = 1 + 1 + (size_t)DOGECOIN_ZK_OPRETURN_DATA_LEN;

    for (unsigned i = 0; i < tx->vout->len; ++i) {
        const dogecoin_tx_out* o = (const dogecoin_tx_out*)vector_idx(tx->vout, i);
        if (!o || !o->script_pubkey || o->script_pubkey->len != expected_len) {
            continue;
        }

        const unsigned char* p = (const unsigned char*)o->script_pubkey->str;
        if (p[0] != 0x6a /* OP_RETURN */ ||
            p[1] != (uint8_t)DOGECOIN_ZK_OPRETURN_DATA_LEN ||
            memcmp(p + 2, DOGECOIN_ZK_OPRETURN_TAG, DOGECOIN_ZK_OPRETURN_TAG_LEN) != 0) {
            continue;
        }

        /* Reject unknown modes so a tampered/garbage byte cannot pose as a
         * valid ZK commitment.  Match the same allow-list used by the
         * encoder/decoder (zk_mode_is_known in zk_carrier.c). */
        uint8_t mode_byte = p[2 + DOGECOIN_ZK_OPRETURN_TAG_LEN];
        switch (mode_byte) {
        case DOGECOIN_ZK_MODE_GROTH16:
        case DOGECOIN_ZK_MODE_PLONK:
        case DOGECOIN_ZK_MODE_STARK_S2:
            break;
        default:
            continue;
        }
        *out_mode = (dogecoin_zk_mode_t)mode_byte;
        memcpy(out_commit32, p + 2 + DOGECOIN_ZK_OPRETURN_TAG_LEN + 1, 32);
        return true;
    }
    return false;
}

/**
 * @brief Compute the tx_base sighash for a candidate TX_C — the value the
 * ZK prover MUST commit to as the `tx_binding` public input.
 *
 * Mirrors the PQC carrier's tx_base reconstruction in src/pqc_carrier.c so
 * a ZK proof is bound to the same on-chain transaction the equivalent PQC
 * signature would be: starting from `tx_c`, all OP_RETURN (nulldata)
 * outputs are stripped, all outputs whose scriptPubKey equals `carrier_spk`
 * are stripped with their values summed back into the first remaining
 * output, and the sighash is computed via dogecoin_tx_sighash32(tx_base,
 * signer_p2pkh_spk, vin_index=0, SIGHASH_ALL).  The top byte of the result
 * is zeroed so the value is an unambiguous BN254 field element when fed
 * into a circom circuit.
 *
 * @param tx_c              candidate TX_C transaction
 * @param signer_p2pkh_spk  canonical P2PKH spk of the funding-input signer
 *                          (use dogecoin_zk_extract_signer_p2pkh_spk)
 * @param carrier_spk       P2SH spk of the ZK carrier outputs (returned by
 *                          dogecoin_zk_build_carrier_tx_c)
 * @param out_sighash       receives the 32-byte (top-byte-zeroed) digest
 *
 * @return DOGECOIN_ZK_OK on success, DOGECOIN_ZK_ERR_INVALID_ARG /
 *         DOGECOIN_ZK_ERR_OOM / DOGECOIN_ZK_ERR_VERIFY_FAIL on failure
 */
dogecoin_zk_err_t dogecoin_zk_compute_tx_base_sighash(
    const dogecoin_tx* tx_c,
    const cstring* signer_p2pkh_spk,
    const cstring* carrier_spk,
    uint8_t out_sighash[32])
{
    if (!tx_c || !signer_p2pkh_spk || !carrier_spk || !out_sighash) {
        return DOGECOIN_ZK_ERR_INVALID_ARG;
    }
    /* tx_c is a public-API parameter; defend against partially-initialised
     * tx structs the same way dogecoin_tx_extract_zk_commit does. */
    if (!tx_c->vin || !tx_c->vout) {
        return DOGECOIN_ZK_ERR_INVALID_ARG;
    }

    dogecoin_tx* tx_base = dogecoin_tx_new();
    if (!tx_base) return DOGECOIN_ZK_ERR_OOM;
    tx_base->version = tx_c->version;
    tx_base->locktime = tx_c->locktime;

    for (size_t vi = 0; vi < tx_c->vin->len; vi++) {
        dogecoin_tx_in* orig = vector_idx(tx_c->vin, vi);
        dogecoin_tx_in* copy = dogecoin_tx_in_new();
        if (!copy) { dogecoin_tx_free(tx_base); return DOGECOIN_ZK_ERR_OOM; }
        memcpy(copy->prevout.hash, orig->prevout.hash, sizeof(copy->prevout.hash));
        copy->prevout.n = orig->prevout.n;
        copy->sequence  = orig->sequence;
        if (orig->script_sig && orig->script_sig->len > 0) {
            cstr_free(copy->script_sig, true);
            copy->script_sig = cstr_new_buf(orig->script_sig->str, orig->script_sig->len);
        } else if (!copy->script_sig) {
            /* dogecoin_tx_sighash invokes cstr_resize on tx_in->script_sig
             * unconditionally, so make sure we hand it a non-NULL cstring
             * even when the source input has no scriptSig yet (TX_C is
             * usually unsigned at this point). */
            copy->script_sig = cstr_new_sz(0);
        }
        vector_add(tx_base->vin, copy);
    }

    uint64_t carrier_total = 0;
    for (size_t vo = 0; vo < tx_c->vout->len; vo++) {
        dogecoin_tx_out* orig = vector_idx(tx_c->vout, vo);
        if (!orig || !orig->script_pubkey || orig->script_pubkey->len == 0) continue;
        /* Skip OP_RETURN nulldata outputs (DZKC commitment lives there). */
        if ((uint8_t)orig->script_pubkey->str[0] == 0x6a /* OP_RETURN */) continue;
        /* Skip canonical P2SH carrier outputs (exact 23-byte match). */
        if (orig->script_pubkey->len == carrier_spk->len &&
            memcmp(orig->script_pubkey->str, carrier_spk->str, carrier_spk->len) == 0) {
            carrier_total += orig->value;
            continue;
        }
        dogecoin_tx_out* copy = dogecoin_tx_out_new();
        if (!copy) { dogecoin_tx_free(tx_base); return DOGECOIN_ZK_ERR_OOM; }
        copy->value = orig->value;
        cstr_free(copy->script_pubkey, true);
        copy->script_pubkey = cstr_new_buf(orig->script_pubkey->str, orig->script_pubkey->len);
        vector_add(tx_base->vout, copy);
    }

    /* Restore carrier cost to the first remaining output, matching how the
     * PQC carrier reverses the carrier-fee deduction performed during TX_C
     * construction. */
    if (carrier_total > 0 && tx_base->vout->len > 0) {
        dogecoin_tx_out* first_out = vector_idx(tx_base->vout, 0);
        first_out->value += carrier_total;
    }

    uint8_t sh[32];
    dogecoin_bool ok = dogecoin_tx_sighash32(tx_base, signer_p2pkh_spk, 0, SIGHASH_ALL, sh);
    dogecoin_tx_free(tx_base);
    if (!ok) return DOGECOIN_ZK_ERR_VERIFY_FAIL;

    /* Zero top byte → 248-bit unambiguous BN254 field element.  Cuts at most
     * 8 bits from a 256-bit collision-resistant digest, leaving 2^248 work
     * for any preimage attack — comfortably beyond what's relevant for a
     * tx-binding tag. */
    sh[0] = 0x00;
    memcpy(out_sighash, sh, 32);
    return DOGECOIN_ZK_OK;
}

/**
 * @brief Extract the canonical 25-byte P2PKH scriptPubKey of the signer for
 * input 0 of `tx`, parsing a standard `<sig> <pubkey>` P2PKH scriptSig.
 *
 * Reproduces the P2PKH parser used by
 * dogecoin_pqc_carrier_verify_signature_with_tx so the ZK carrier extracts
 * the *same* signer scriptPubKey as the PQC carrier when computing the
 * tx_base sighash a ZK proof is bound to.
 *
 * @param tx  transaction whose input 0 carries a P2PKH unlock
 *
 * @return a freshly-allocated cstring P2PKH scriptPubKey
 *         (caller frees with cstr_free(..., true)), or NULL when the
 *         scriptSig isn't a recognisable P2PKH input
 */
cstring* dogecoin_zk_extract_signer_p2pkh_spk(const dogecoin_tx* tx)
{
    if (!tx || !tx->vin || tx->vin->len == 0) return NULL;
    dogecoin_tx_in* first_in = vector_idx(tx->vin, 0);
    if (!first_in || !first_in->script_sig ||
        first_in->script_sig->len < DOGECOIN_PQC_MIN_P2PKH_SCRIPTSIG_LEN ||
        first_in->script_sig->len > DOGECOIN_PQC_MAX_P2PKH_SCRIPTSIG_LEN) return NULL;
    const uint8_t* ss = (const uint8_t*)first_in->script_sig->str;
    size_t sslen = first_in->script_sig->len;
    if (sslen == 0) return NULL;
    size_t pos = 0;
    uint8_t sig_push_len = ss[pos++];
    if (sig_push_len < DOGECOIN_PQC_MIN_DER_SIG_PUSH_LEN ||
        sig_push_len > DOGECOIN_PQC_MAX_DER_SIG_PUSH_LEN ||
        pos + sig_push_len > sslen ||
        ss[pos] != 0x30 /* DER SEQUENCE */) return NULL;
    pos += sig_push_len;
    if (pos >= sslen) return NULL;
    uint8_t pk_push_len = ss[pos++];
    if (pk_push_len != 33 || pos + 33 > sslen) return NULL;
    const uint8_t* ecdsa_pk = ss + pos;
    uint8_t sha_out[32];
    sha256_raw(ecdsa_pk, 33, sha_out);
    uint8_t h160[20];
    rmd160(sha_out, 32, h160);
    cstring* spk = cstr_new_sz(25);
    if (!spk) return NULL;
    static const uint8_t p2pkh_prefix[] = {0x76, 0xa9, 0x14};
    static const uint8_t p2pkh_suffix[] = {0x88, 0xac};
    cstr_append_buf(spk, p2pkh_prefix, 3);
    cstr_append_buf(spk, h160, 20);
    cstr_append_buf(spk, p2pkh_suffix, 2);
    return spk;
}
