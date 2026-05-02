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
 * ZK P2SH carrier payload extraction and reassembly.
 *
 * Extends the PQ carrier pattern (src/pqc_carrier.c) for ZK proofs. Reads
 * multi-part scriptSigs from TX_R, reassembles the canonical ZKP1 payload,
 * and extracts public inputs, proof, and (for v1) verification key.
 */

/*
 * ZK carrier — payload codec, error strings, and OP_RETURN scriptPubKey
 * helper.  TX_C/TX_R construction lives in zk_commit.c, which thinly wraps
 * the existing PQ carrier helpers (src/pqc_carrier.c) so both carriers
 * share one on-chain shape.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <dogecoin/cstr.h>
#include <dogecoin/mem.h>
#include <dogecoin/script.h>
#include <dogecoin/sha2.h>
#include <dogecoin/zk_carrier.h>

/**
 * @brief Convert a dogecoin_zk_err_t code to a short human-readable string.
 *
 * Mirrors the strerror-style helpers used elsewhere in libdogecoin (e.g.
 * dogecoin_pqc_strerror) so callers can log a single line on failure.
 *
 * @param err the error code returned by any dogecoin_zk_* entry point
 *
 * @return a NUL-terminated string literal — never NULL, never freed
 */
const char* dogecoin_zk_strerror(dogecoin_zk_err_t err)
{
    switch (err) {
    case DOGECOIN_ZK_OK:                  return "ok";
    case DOGECOIN_ZK_ERR_INVALID_ARG:     return "invalid argument";
    case DOGECOIN_ZK_ERR_BAD_MAGIC:       return "bad payload magic (expected ZKP1)";
    case DOGECOIN_ZK_ERR_BAD_MODE:        return "unknown ZK mode";
    case DOGECOIN_ZK_ERR_TRUNCATED:       return "payload truncated";
    case DOGECOIN_ZK_ERR_OOM:             return "out of memory";
    case DOGECOIN_ZK_ERR_NOT_IMPLEMENTED: return "not implemented in this build";
    case DOGECOIN_ZK_ERR_DELEGATED:       return "operation delegated to host (use snarkjs/rapidsnark)";
    case DOGECOIN_ZK_ERR_VERIFY_FAIL:     return "proof verification failed";
    case DOGECOIN_ZK_ERR_BAD_VERSION:     return "unknown ZK payload version";
    default:                              break;
    }
    return "unknown ZK carrier error";
}

/**
 * @brief Internal helper: is `mode` one of the known dogecoin_zk_mode_t values?
 *
 * Used by both the encoder and decoder to gate the mode byte before any
 * downstream logic so untrusted on-chain bytes can't reach mode-specific
 * code paths.
 *
 * @param mode the candidate mode byte cast to dogecoin_zk_mode_t
 *
 * @return true if `mode` is one of GROTH16/PLONK/STARK_S2, false otherwise
 */
static dogecoin_bool zk_mode_is_known(dogecoin_zk_mode_t mode)
{
    switch (mode) {
    case DOGECOIN_ZK_MODE_GROTH16:
    case DOGECOIN_ZK_MODE_PLONK:
    case DOGECOIN_ZK_MODE_STARK_S2:
        return true;
    }
    return false;
}

/**
 * @brief Encode a proof + public inputs (and optional verification key)
 * into the canonical ZKP1 carrier payload.
 *
 * When `vk_bytes` is NULL or `vk_len` is zero the encoder emits a v0 (no-vk)
 * payload; otherwise it emits a v1 payload with the vk bytes appended after
 * the proof so the reveal is fully self-contained for on-chain validation.
 * All length fields are written big-endian to match the on-wire ZKP1
 * specification.
 *
 * @param mode              one of DOGECOIN_ZK_MODE_GROTH16/PLONK/STARK_S2
 * @param circuit_id        application-level circuit identifier (BE32)
 * @param public_inputs     pointer to the snarkjs-style public-inputs blob
 * @param public_inputs_len length of `public_inputs` (must fit in 16 bits)
 * @param proof             pointer to the proof bytes
 * @param proof_len         length of `proof` (capped at 32 MiB)
 * @param vk_bytes          optional verification-key bytes (NULL → v0)
 * @param vk_len            length of `vk_bytes`
 * @param out_payload       receives a freshly-allocated ZKP1 buffer
 *                          (caller frees with dogecoin_free())
 * @param out_payload_len   receives the byte length of *out_payload
 *
 * @return DOGECOIN_ZK_OK on success, or one of DOGECOIN_ZK_ERR_INVALID_ARG /
 *         DOGECOIN_ZK_ERR_BAD_MODE / DOGECOIN_ZK_ERR_OOM on failure
 */
dogecoin_zk_err_t dogecoin_zk_encode_payload(
    dogecoin_zk_mode_t mode,
    uint32_t circuit_id,
    const uint8_t* public_inputs,
    size_t public_inputs_len,
    const uint8_t* proof,
    size_t proof_len,
    const uint8_t* vk_bytes,
    size_t vk_len,
    uint8_t** out_payload,
    size_t* out_payload_len)
{
    if (!out_payload || !out_payload_len) return DOGECOIN_ZK_ERR_INVALID_ARG;
    if (public_inputs_len > 0 && !public_inputs) return DOGECOIN_ZK_ERR_INVALID_ARG;
    if (proof_len > 0 && !proof) return DOGECOIN_ZK_ERR_INVALID_ARG;
    if (vk_len > 0 && !vk_bytes) return DOGECOIN_ZK_ERR_INVALID_ARG;
    if (!zk_mode_is_known(mode)) return DOGECOIN_ZK_ERR_BAD_MODE;
    if (public_inputs_len > 0xFFFFu) return DOGECOIN_ZK_ERR_INVALID_ARG;
    /* Cap proof and vk bytes at 32 MiB each to keep size fields sane and
     * chunking bounded.  vk JSON for Groth16/PLONK is typically a few KB. */
    if (proof_len > 0x02000000u) return DOGECOIN_ZK_ERR_INVALID_ARG;
    if (vk_len    > 0x02000000u) return DOGECOIN_ZK_ERR_INVALID_ARG;

    /* v1 (vk-included) when caller supplied a vk; v0 otherwise.  v0 is
     * retained so legacy callers and existing on-chain pairs decode cleanly,
     * but new payloads SHOULD always include the vk for self-contained
     * on-chain validation. */
    uint8_t version = (vk_bytes && vk_len > 0)
                        ? (uint8_t)DOGECOIN_ZK_PAYLOAD_VERSION_V1
                        : (uint8_t)DOGECOIN_ZK_PAYLOAD_VERSION_V0;

    size_t total = (size_t)DOGECOIN_ZK_CARRIER_HDR_FIXED + public_inputs_len + 4 + proof_len;
    if (version == DOGECOIN_ZK_PAYLOAD_VERSION_V1) {
        total += 4 + vk_len;
    }
    uint8_t* buf = (uint8_t*)dogecoin_malloc(total);
    if (!buf) return DOGECOIN_ZK_ERR_OOM;

    size_t off = 0;
    memcpy(buf + off, DOGECOIN_ZK_CARRIER_MAGIC, DOGECOIN_ZK_CARRIER_MAGIC_LEN);
    off += DOGECOIN_ZK_CARRIER_MAGIC_LEN;
    buf[off++] = (uint8_t)mode;
    buf[off++] = version;
    buf[off++] = (uint8_t)((circuit_id >> 24) & 0xff);
    buf[off++] = (uint8_t)((circuit_id >> 16) & 0xff);
    buf[off++] = (uint8_t)((circuit_id >> 8) & 0xff);
    buf[off++] = (uint8_t)((circuit_id) & 0xff);
    buf[off++] = (uint8_t)((public_inputs_len >> 8) & 0xff);
    buf[off++] = (uint8_t)((public_inputs_len) & 0xff);
    if (public_inputs_len > 0) {
        memcpy(buf + off, public_inputs, public_inputs_len);
        off += public_inputs_len;
    }
    buf[off++] = (uint8_t)((proof_len >> 24) & 0xff);
    buf[off++] = (uint8_t)((proof_len >> 16) & 0xff);
    buf[off++] = (uint8_t)((proof_len >> 8) & 0xff);
    buf[off++] = (uint8_t)((proof_len) & 0xff);
    if (proof_len > 0) {
        memcpy(buf + off, proof, proof_len);
        off += proof_len;
    }
    if (version == DOGECOIN_ZK_PAYLOAD_VERSION_V1) {
        buf[off++] = (uint8_t)((vk_len >> 24) & 0xff);
        buf[off++] = (uint8_t)((vk_len >> 16) & 0xff);
        buf[off++] = (uint8_t)((vk_len >> 8) & 0xff);
        buf[off++] = (uint8_t)((vk_len) & 0xff);
        if (vk_len > 0) {
            memcpy(buf + off, vk_bytes, vk_len);
            off += vk_len;
        }
    }

    *out_payload = buf;
    *out_payload_len = off;
    return DOGECOIN_ZK_OK;
}

/**
 * @brief Decode a ZKP1 carrier payload back into its constituent fields.
 *
 * All `out_*` pointers alias into the input buffer (no allocation).  The
 * caller must keep `payload` alive while using the decoded fields.  When the
 * payload is v0 (no embedded vk) `*out_vk` is set to NULL and `*out_vk_len`
 * to 0.  When the payload is v1, `*out_vk` aliases the embedded vk bytes.
 * Pass NULL for `out_vk` / `out_vk_len` if the caller does not care about
 * the vk slot (legacy callers).
 *
 * @param payload                pointer to the ZKP1 buffer
 * @param payload_len            byte length of `payload`
 * @param out_mode               receives the decoded mode
 * @param out_circuit_id         receives the decoded BE32 circuit id
 * @param out_public_inputs      receives a pointer aliasing the public bytes
 * @param out_public_inputs_len  receives the public-inputs length
 * @param out_proof              receives a pointer aliasing the proof bytes
 * @param out_proof_len          receives the proof length
 * @param out_vk                 (optional) receives a pointer aliasing the vk
 * @param out_vk_len             (optional) receives the vk length
 *
 * @return DOGECOIN_ZK_OK on success, or one of DOGECOIN_ZK_ERR_INVALID_ARG /
 *         DOGECOIN_ZK_ERR_BAD_MAGIC / DOGECOIN_ZK_ERR_BAD_MODE /
 *         DOGECOIN_ZK_ERR_TRUNCATED on failure
 */
dogecoin_zk_err_t dogecoin_zk_decode_payload(
    const uint8_t* payload,
    size_t payload_len,
    dogecoin_zk_mode_t* out_mode,
    uint32_t* out_circuit_id,
    const uint8_t** out_public_inputs,
    size_t* out_public_inputs_len,
    const uint8_t** out_proof,
    size_t* out_proof_len,
    const uint8_t** out_vk,
    size_t* out_vk_len)
{
    if (!payload || !out_mode || !out_circuit_id ||
        !out_public_inputs || !out_public_inputs_len ||
        !out_proof || !out_proof_len) {
        return DOGECOIN_ZK_ERR_INVALID_ARG;
    }
    if (payload_len < DOGECOIN_ZK_CARRIER_HDR_FIXED) return DOGECOIN_ZK_ERR_TRUNCATED;
    if (memcmp(payload, DOGECOIN_ZK_CARRIER_MAGIC, DOGECOIN_ZK_CARRIER_MAGIC_LEN) != 0) {
        return DOGECOIN_ZK_ERR_BAD_MAGIC;
    }

    size_t off = DOGECOIN_ZK_CARRIER_MAGIC_LEN;
    uint8_t mode_byte = payload[off++];
    uint8_t version = payload[off++];
    /* Reject payloads whose version byte is not in the documented set.
       The mask is intentionally permissive (the version field is a single
       byte today and v0/v1 are the only assignments), but applying it
       up-front isolates "unknown version" from "truncated buffer" so the
       error code returned to callers actually describes the failure. */
    if ((version & ~DOGECOIN_ZK_PAYLOAD_VERSION_MASK) != 0 ||
        (version != DOGECOIN_ZK_PAYLOAD_VERSION_V0 &&
         version != DOGECOIN_ZK_PAYLOAD_VERSION_V1)) {
        /* Unknown version — refuse rather than silently accept. */
        return DOGECOIN_ZK_ERR_BAD_VERSION;
    }
    dogecoin_zk_mode_t mode = (dogecoin_zk_mode_t)mode_byte;
    if (!zk_mode_is_known(mode)) return DOGECOIN_ZK_ERR_BAD_MODE;

    uint32_t circuit_id = ((uint32_t)payload[off] << 24) |
                          ((uint32_t)payload[off + 1] << 16) |
                          ((uint32_t)payload[off + 2] << 8) |
                          ((uint32_t)payload[off + 3]);
    off += 4;
    uint16_t pl = (uint16_t)(((uint16_t)payload[off] << 8) | payload[off + 1]);
    off += 2;

    if (pl > payload_len - off) return DOGECOIN_ZK_ERR_TRUNCATED;
    const uint8_t* public_ptr = payload + off;
    off += pl;

    if (4 > payload_len - off) return DOGECOIN_ZK_ERR_TRUNCATED;
    uint32_t xl = ((uint32_t)payload[off] << 24) |
                  ((uint32_t)payload[off + 1] << 16) |
                  ((uint32_t)payload[off + 2] << 8) |
                  ((uint32_t)payload[off + 3]);
    off += 4;
    if (xl > payload_len - off) return DOGECOIN_ZK_ERR_TRUNCATED;
    const uint8_t* proof_ptr = payload + off;
    off += xl;

    const uint8_t* vk_ptr = NULL;
    uint32_t kl = 0;
    if (version == DOGECOIN_ZK_PAYLOAD_VERSION_V1) {
        if (4 > payload_len - off) return DOGECOIN_ZK_ERR_TRUNCATED;
        kl = ((uint32_t)payload[off] << 24) |
             ((uint32_t)payload[off + 1] << 16) |
             ((uint32_t)payload[off + 2] << 8) |
             ((uint32_t)payload[off + 3]);
        off += 4;
        if (kl > payload_len - off) return DOGECOIN_ZK_ERR_TRUNCATED;
        vk_ptr = (kl > 0) ? (payload + off) : NULL;
        off += kl;
    }

    if (off != payload_len) return DOGECOIN_ZK_ERR_TRUNCATED; /* trailing bytes */

    *out_mode = mode;
    *out_circuit_id = circuit_id;
    *out_public_inputs = pl > 0 ? public_ptr : NULL;
    *out_public_inputs_len = pl;
    *out_proof = xl > 0 ? proof_ptr : NULL;
    *out_proof_len = xl;
    if (out_vk)     *out_vk     = vk_ptr;
    if (out_vk_len) *out_vk_len = kl;
    return DOGECOIN_ZK_OK;
}

/**
 * @brief Compute the TX_C commitment value: SHA256d(payload).
 *
 * This is the 32-byte digest the ZK carrier embeds in the OP_RETURN of TX_C.
 * Reveal-side validators recompute this from the reassembled payload bytes
 * and compare against the on-chain commit32 to prove the reveal binds to the
 * commit.
 *
 * @param payload         pointer to the ZKP1 carrier payload
 * @param payload_len     byte length of `payload` (must be > 0)
 * @param out_commitment  receives the 32-byte SHA256d digest
 *
 * @return DOGECOIN_ZK_OK on success, DOGECOIN_ZK_ERR_INVALID_ARG on bad args
 */
dogecoin_zk_err_t dogecoin_zk_get_commitment_hash(
    const uint8_t* payload,
    size_t payload_len,
    uint8_t out_commitment[32])
{
    if (!payload || payload_len == 0 || !out_commitment) return DOGECOIN_ZK_ERR_INVALID_ARG;
    /* SHA256d (double-SHA256), the standard Bitcoin/Dogecoin commitment hash. */
    sha256_raw(payload, payload_len, out_commitment);
    sha256_raw(out_commitment, 32, out_commitment);
    return DOGECOIN_ZK_OK;
}

/**
 * @brief Build the OP_RETURN scriptPubKey carrying the ZK commitment.
 *
 * Layout: `OP_RETURN <push 37> "DZKC" <mode-byte> <commitment32>`.  The
 * resulting scriptPubKey is exactly 39 bytes and is unspendable, so it does
 * not consume a UTXO.  Caller frees `*out_spk` with cstr_free(..., true).
 *
 * @param mode        the ZK mode byte (matches what the encoder wrote)
 * @param commitment  the 32-byte SHA256d(payload) digest
 * @param out_spk     receives a freshly-allocated cstring scriptPubKey
 *
 * @return DOGECOIN_ZK_OK on success, DOGECOIN_ZK_ERR_INVALID_ARG /
 *         DOGECOIN_ZK_ERR_BAD_MODE / DOGECOIN_ZK_ERR_OOM on failure
 */
dogecoin_zk_err_t dogecoin_zk_build_opreturn_scriptpubkey(
    dogecoin_zk_mode_t mode,
    const uint8_t commitment[32],
    cstring** out_spk)
{
    if (!out_spk || !commitment) return DOGECOIN_ZK_ERR_INVALID_ARG;
    if (!zk_mode_is_known(mode)) return DOGECOIN_ZK_ERR_BAD_MODE;

    /* Layout: OP_RETURN <push 37> "DZKC" <mode> <commitment32>
       Total scriptPubKey length: 1 (OP_RETURN) + 1 (push len) + 37 = 39 bytes. */
    cstring* s = cstr_new_sz(39);
    if (!s) return DOGECOIN_ZK_ERR_OOM;

    uint8_t op_return = OP_RETURN;
    cstr_append_buf(s, &op_return, 1);

    uint8_t data[DOGECOIN_ZK_OPRETURN_DATA_LEN];
    memcpy(data, DOGECOIN_ZK_OPRETURN_TAG, DOGECOIN_ZK_OPRETURN_TAG_LEN);
    data[DOGECOIN_ZK_OPRETURN_TAG_LEN] = (uint8_t)mode;
    memcpy(data + DOGECOIN_ZK_OPRETURN_TAG_LEN + 1, commitment, 32);

    /* DOGECOIN_ZK_OPRETURN_DATA_LEN is 37 — fits in a direct push (<= 75). */
    uint8_t push_len = (uint8_t)DOGECOIN_ZK_OPRETURN_DATA_LEN;
    cstr_append_buf(s, &push_len, 1);
    cstr_append_buf(s, data, DOGECOIN_ZK_OPRETURN_DATA_LEN);

    *out_spk = s;
    return DOGECOIN_ZK_OK;
}

/**
 * @brief Parse one decimal token of a snarkjs public-inputs JSON array into
 * a 32-byte big-endian field element.
 *
 * The SPV reveal validator uses this to recover the canonical `tx_binding`
 * value embedded in the third public input (Phase-1 reveal layout) and
 * compare it against the tx_base sighash recomputed locally — see the BIP,
 * §"Phase 1: Base Transaction Binding".  No nested objects are expected;
 * snarkjs `public.json` is a flat array of decimal strings.
 *
 * @param public_inputs      the JSON-array bytes (e.g. `["0","1","1234..."]`)
 * @param public_inputs_len  length of `public_inputs`
 * @param idx                0-based index of the token to extract
 * @param out_be32           receives the 32-byte big-endian value
 * @param out_token_count    (optional) receives the total token count seen
 *
 * @return DOGECOIN_ZK_OK on success; DOGECOIN_ZK_ERR_INVALID_ARG when the
 *         array contains fewer than `idx+1` tokens, when a non-decimal
 *         digit is encountered, or when the value would overflow 32 bytes
 */
dogecoin_zk_err_t dogecoin_zk_parse_public_input_be32(
    const uint8_t* public_inputs,
    size_t public_inputs_len,
    size_t idx,
    uint8_t out_be32[32],
    size_t* out_token_count)
{
    if (!public_inputs || !out_be32) return DOGECOIN_ZK_ERR_INVALID_ARG;
    memset(out_be32, 0, 32);
    if (out_token_count) *out_token_count = 0;

    /* Walk the JSON array as a stream of double-quoted tokens; capture the
     * one at `idx`.  No nested objects are expected — snarkjs public.json
     * is a flat array of decimal strings. */
    char selected[80] = {0};
    size_t selected_len = 0;
    int    have_selected = 0;
    size_t token_count = 0;
    size_t j = 0;
    while (j < public_inputs_len) {
        if (public_inputs[j] != '"') { j++; continue; }
        j++;
        size_t start = j;
        while (j < public_inputs_len && public_inputs[j] != '"') j++;
        if (j >= public_inputs_len) break;
        size_t tok_len = j - start;
        if (token_count == idx && tok_len < sizeof(selected)) {
            memcpy(selected, public_inputs + start, tok_len);
            selected[tok_len] = '\0';
            selected_len = tok_len;
            have_selected = 1;
        }
        token_count++;
        j++;
    }
    if (out_token_count) *out_token_count = token_count;
    if (!have_selected || selected_len == 0) return DOGECOIN_ZK_ERR_INVALID_ARG;

    /* Schoolbook decimal-to-base-256 with a 32-byte big-endian accumulator. */
    for (size_t k = 0; k < selected_len; k++) {
        char c = selected[k];
        if (c < '0' || c > '9') return DOGECOIN_ZK_ERR_INVALID_ARG;
        unsigned carry = (unsigned)(c - '0');
        for (int bi = 31; bi >= 0; bi--) {
            unsigned v = (unsigned)out_be32[bi] * 10u + carry;
            out_be32[bi] = (uint8_t)(v & 0xff);
            carry = v >> 8;
        }
        if (carry) return DOGECOIN_ZK_ERR_INVALID_ARG;
    }
    return DOGECOIN_ZK_OK;
}
