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

#include <string.h>
#include <stdint.h>

#include <dogecoin/sha2.h>
#include <dogecoin/mem.h>
#include <dogecoin/pqc_raccoon.h>
#include <dogecoin/pqc_falcon.h>
#include <dogecoin/tx.h>
#include <dogecoin/random.h>

#ifndef USE_LIBOQS
/* When liboqs is disabled, pqc_falcon.c is not compiled, so provide the
 * shared sighash helper here for the Raccoon-G backend. */
dogecoin_bool dogecoin_tx_sighash32(const dogecoin_tx* tx_to,
                                    const cstring* fromPubKey,
                                    size_t in_num, int hashtype,
                                    uint8_t out32[32])
{
    if (!tx_to || !fromPubKey || !out32) {
        return false;
    }
    uint256_t hash;
    if (!dogecoin_tx_sighash(tx_to, fromPubKey, in_num, hashtype, hash)) {
        return false;
    }
    memcpy(out32, hash, 32);
    return true;
}
#endif

/**
 * @brief This function computes SHA256(pk || msg) and writes
 * a 32-byte digest to out32.
 *
 * @param out32 The output buffer for the 32-byte hash.
 * @param pk The pointer to the public key bytes.
 * @param pk_len The length of the public key.
 * @param msg The pointer to the message bytes.
 * @param msg_len The length of the message.
 *
 * @return Nothing.
 */
static inline void sha256_pk_msg(uint8_t out32[32],
                                 const uint8_t* pk, size_t pk_len,
                                 const uint8_t* msg, size_t msg_len)
{
    sha256_context ctx;
    sha256_init(&ctx);
    if (pk && pk_len) {
        sha256_write(&ctx, pk, pk_len);
    }
    if (msg && msg_len) {
        sha256_write(&ctx, msg, msg_len);
    }
    sha256_finalize(&ctx, out32);
}

/**
 * @brief This function computes a 32-byte Raccoon-G-44
 * commitment as SHA256(pk || sig).
 *
 * @param pk The pointer to the public key bytes.
 * @param pk_len The length of the public key.
 * @param signature The pointer to the signature bytes.
 * @param signature_len The length of the signature.
 * @param out32 The output buffer for the 32-byte commitment.
 *
 * @return true if the commitment was computed, false on invalid input.
 */
dogecoin_bool dogecoin_raccoong44_commit_bytes(const uint8_t* pk, size_t pk_len,
                                               const uint8_t* signature, size_t signature_len,
                                               uint8_t out32[32])
{
    if (!pk || !signature || !out32) {
        return false;
    }
    sha256_pk_msg(out32, pk, pk_len, signature, signature_len);
    return true;
}

/**
 * @brief This function appends an OP_RETURN output carrying
 * the "RCG4" tag and a 32-byte Raccoon-G-44 commitment to a
 * transaction.
 *
 * @param tx The pointer to the transaction to modify.
 * @param commit32 The 32-byte commitment hash.
 *
 * @return true if the output was added, false on invalid input.
 */
dogecoin_bool dogecoin_tx_add_raccoong44_commit(dogecoin_tx* tx, const uint8_t commit32[DOGECOIN_PQC_RACCOON_COMMIT_LEN])
{
    if (!tx || !commit32) {
        return false;
    }

    cstring* spk = cstr_new_sz(1 + 1 + DOGECOIN_PQC_RACCOON_PUSH_TOTAL);
    uint8_t opret = 0x6a;
    uint8_t push  = DOGECOIN_PQC_RACCOON_PUSH_TOTAL;

    cstr_append_buf(spk, &opret, 1);
    cstr_append_buf(spk, &push, 1);
    cstr_append_buf(spk, (const uint8_t*)DOGECOIN_PQC_RACCOON_TAG, DOGECOIN_PQC_RACCOON_TAG_LEN);
    cstr_append_buf(spk, commit32, 32);

    dogecoin_tx_out* out = dogecoin_tx_out_new();
    if (!out) {
        cstr_free(spk, true);
        return false;
    }
    out->value = 0;
    if (out->script_pubkey) {
        cstr_free(out->script_pubkey, true);
    }
    out->script_pubkey = spk;
    vector_add(tx->vout, out);
    return true;
}

/**
 * @brief This function extracts the first "RCG4" tagged
 * Raccoon-G-44 commitment from a transaction's outputs.
 *
 * @param tx The pointer to the transaction to search.
 * @param out32 The output buffer for the 32-byte commitment.
 *
 * @return true if a commitment was found, false otherwise.
 */
dogecoin_bool dogecoin_tx_extract_raccoong44_commit(const dogecoin_tx* tx, uint8_t out32[DOGECOIN_PQC_RACCOON_COMMIT_LEN])
{
    if (!tx || !out32) {
        return false;
    }

    for (unsigned i = 0; i < tx->vout->len; ++i) {
        const dogecoin_tx_out* o = vector_idx(tx->vout, i);
        if (!o || !o->script_pubkey || o->script_pubkey->len < (1 + 1 + DOGECOIN_PQC_RACCOON_PUSH_TOTAL))
            continue;

        const unsigned char* p = (const unsigned char*)o->script_pubkey->str;
        size_t n = o->script_pubkey->len;

        if (n == (1 + 1 + DOGECOIN_PQC_RACCOON_PUSH_TOTAL) &&
            p[0] == 0x6a &&
            p[1] == DOGECOIN_PQC_RACCOON_PUSH_TOTAL &&
            memcmp(p + 2, DOGECOIN_PQC_RACCOON_TAG, DOGECOIN_PQC_RACCOON_TAG_LEN) == 0) {
            memcpy(out32, p + 2 + DOGECOIN_PQC_RACCOON_TAG_LEN, 32);
            return true;
        }
    }
    return false;
}


#ifdef USE_RACCOON_G

/*
 * In-tree Raccoon-G-44 backend. Built when --enable-raccoon-g is configured.
 *
 * Every entry point routes through `src/raccoon_g/` and is byte-exact
 * against the upstream `p-11/lattice-hd-wallets` Python reference; see
 * `src/raccoon_g/README.md` and `test/raccoong_*` KAT drivers.
 */

#include "raccoon_g/raccoong.h"

dogecoin_bool dogecoin_raccoong44_is_available(void)
{
    return raccoong_is_ready();
}

dogecoin_bool dogecoin_raccoong44_keypair(uint8_t** pk, size_t* pk_len,
                                          uint8_t** sk, size_t* sk_len)
{
    if (!pk || !pk_len || !sk || !sk_len) {
        return false;
    }
    if (!raccoong_is_ready()) {
        return false;
    }

    size_t pkl = raccoong_pk_len();
    size_t skl = raccoong_sk_len();
    if (!pkl || !skl) {
        return false;
    }

    uint8_t* pk_buf = (uint8_t*)dogecoin_malloc(pkl);
    uint8_t* sk_buf = (uint8_t*)dogecoin_malloc(skl);
    if (!pk_buf || !sk_buf) {
        if (pk_buf) dogecoin_free(pk_buf);
        if (sk_buf) dogecoin_free(sk_buf);
        return false;
    }

    /* Seed-deterministic keygen requires a 32-byte seed; the public API does
     * not take one, so we draw it from the libdogecoin RNG.  Callers that
     * need byte-deterministic keypairs should use `raccoong_keygen_from_seed`
     * directly with a caller-supplied seed. */
    uint8_t seed[32];
    if (!dogecoin_random_bytes(seed, sizeof(seed), 0)) {
        dogecoin_free(pk_buf);
        dogecoin_free(sk_buf);
        return false;
    }
    if (!raccoong_keygen_from_seed(seed, pk_buf, pkl, sk_buf, skl)) {
        dogecoin_mem_zero(seed, sizeof(seed));
        dogecoin_free(pk_buf);
        dogecoin_free(sk_buf);
        return false;
    }
    dogecoin_mem_zero(seed, sizeof(seed));
    *pk = pk_buf;
    *pk_len = pkl;
    *sk = sk_buf;
    *sk_len = skl;
    return true;
}

dogecoin_bool dogecoin_raccoong44_sign(const uint8_t* sk, size_t sk_len,
                                       const uint8_t* msg, size_t msg_len,
                                       uint8_t** sig_out, size_t* sig_len)
{
    if (!sk || !msg || !sig_out || !sig_len) {
        return false;
    }
    if (!raccoong_is_ready()) {
        return false;
    }
    size_t cap = raccoong_sig_max_len();
    if (!cap) {
        return false;
    }
    uint8_t* buf = (uint8_t*)dogecoin_malloc(cap);
    if (!buf) {
        return false;
    }
    size_t outlen = cap;
    if (!raccoong_sign(sk, sk_len, msg, msg_len, buf, &outlen)) {
        dogecoin_free(buf);
        return false;
    }
    *sig_out = buf;
    *sig_len = outlen;
    return true;
}

dogecoin_bool dogecoin_raccoong44_verify(const uint8_t* pk, size_t pk_len,
                                         const uint8_t* msg, size_t msg_len,
                                         const uint8_t* sig, size_t sig_len)
{
    if (!pk || !msg || !sig) {
        return false;
    }
    if (!raccoong_is_ready()) {
        return false;
    }
    return raccoong_verify(pk, pk_len, msg, msg_len, sig, sig_len);
}

dogecoin_bool dogecoin_raccoong44_hd_derive_priv(const uint8_t* parent_sk, size_t parent_sk_len,
                                                 const uint8_t* parent_pk, size_t parent_pk_len,
                                                 const uint8_t chaincode[DOGECOIN_PQC_RACCOON_CHAINCODE_LEN],
                                                 uint32_t index, dogecoin_bool hardened,
                                                 uint8_t** child_sk, size_t* child_sk_len,
                                                 uint8_t** child_pk, size_t* child_pk_len)
{
    if (!parent_sk || !parent_pk || !chaincode ||
        !child_sk || !child_sk_len || !child_pk || !child_pk_len) {
        return false;
    }
    if (!raccoong_is_ready()) {
        return false;
    }
    size_t skl = raccoong_sk_len();
    size_t pkl = raccoong_pk_len();
    if (!skl || !pkl) {
        return false;
    }
    uint8_t* sk_buf = (uint8_t*)dogecoin_malloc(skl);
    uint8_t* pk_buf = (uint8_t*)dogecoin_malloc(pkl);
    if (!sk_buf || !pk_buf) {
        if (sk_buf) dogecoin_free(sk_buf);
        if (pk_buf) dogecoin_free(pk_buf);
        return false;
    }
    if (!raccoong_hd_derive_priv(parent_sk, parent_sk_len, parent_pk, parent_pk_len,
                                 chaincode, index, hardened,
                                 sk_buf, skl, pk_buf, pkl)) {
        dogecoin_free(sk_buf);
        dogecoin_free(pk_buf);
        return false;
    }
    *child_sk = sk_buf;
    *child_sk_len = skl;
    *child_pk = pk_buf;
    *child_pk_len = pkl;
    return true;
}

dogecoin_bool dogecoin_raccoong44_hd_derive_pub(const uint8_t* parent_pk, size_t parent_pk_len,
                                                const uint8_t chaincode[DOGECOIN_PQC_RACCOON_CHAINCODE_LEN],
                                                uint32_t index,
                                                uint8_t** child_pk, size_t* child_pk_len)
{
    if (!parent_pk || !chaincode || !child_pk || !child_pk_len) {
        return false;
    }
    if (index & 0x80000000U) {
        return false; /* hardened derivation requires the secret key */
    }
    if (!raccoong_is_ready()) {
        return false;
    }
    size_t pkl = raccoong_pk_len();
    if (!pkl) {
        return false;
    }
    uint8_t* pk_buf = (uint8_t*)dogecoin_malloc(pkl);
    if (!pk_buf) {
        return false;
    }
    if (!raccoong_hd_derive_pub(parent_pk, parent_pk_len, chaincode, index,
                                pk_buf, pkl)) {
        dogecoin_free(pk_buf);
        return false;
    }
    *child_pk = pk_buf;
    *child_pk_len = pkl;
    return true;
}

#endif
