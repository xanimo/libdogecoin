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
#include <dogecoin/utils.h>
#include <dogecoin/pqc_falcon.h>

#ifdef USE_LIBOQS
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include <oqs/sig.h>
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
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
 * @brief This function computes a 32-byte Falcon-512 commitment
 * as SHA256(pk || sig).
 *
 * @param pk The pointer to the public key bytes.
 * @param pk_len The length of the public key.
 * @param msg The pointer to the signature bytes.
 * @param msg_len The length of the signature.
 * @param out32 The output buffer for the 32-byte commitment.
 *
 * @return true if the commitment was computed, false on invalid input.
 */
dogecoin_bool dogecoin_falcon512_commit_bytes(const uint8_t* pk, size_t pk_len,
                                               const uint8_t* msg, size_t msg_len,
                                               uint8_t out32[32])
{
    if (!pk || !msg || !out32) {
        return false;
    }
    sha256_pk_msg(out32, pk, pk_len, msg, msg_len);
    return true;
}

/**
 * @brief This function appends an OP_RETURN output carrying
 * the "FLC1" tag and a 32-byte Falcon-512 commitment to a
 * transaction.
 *
 * @param tx The pointer to the transaction to modify.
 * @param commit32 The 32-byte commitment hash.
 *
 * @return true if the output was added, false on invalid input.
 */
dogecoin_bool dogecoin_tx_add_falcon512_commit(dogecoin_tx* tx, const uint8_t commit32[DOGECOIN_PQC_FALCON_COMMIT_LEN]) {
    if (!tx || !commit32) {
        return false;
    }

    // script: OP_RETURN (0x6a) PUSHDATA(36) "FLC1" <32 bytes>
    cstring* spk = cstr_new_sz(1 + 1 + DOGECOIN_PQC_FALCON_PUSH_TOTAL);
    uint8_t opret = 0x6a;
    uint8_t push  = DOGECOIN_PQC_FALCON_PUSH_TOTAL;

    cstr_append_buf(spk, &opret, 1);
    cstr_append_buf(spk, &push, 1);
    cstr_append_buf(spk, (const uint8_t*)DOGECOIN_PQC_FALCON_TAG, DOGECOIN_PQC_FALCON_TAG_LEN);
    cstr_append_buf(spk, commit32, 32);

    dogecoin_tx_out* out = dogecoin_tx_out_new();
    if (!out) {
        cstr_free(spk, true);
        return false;
    }

    /* OP_RETURN outputs are zero-value by policy. */
    out->value = 0;
    if (out->script_pubkey) {
        cstr_free(out->script_pubkey, true);
    }
    out->script_pubkey = spk;

    vector_add(tx->vout, out);
    return true;
}

/**
 * @brief This function extracts the first "FLC1" tagged
 * Falcon-512 commitment from a transaction's outputs.
 *
 * @param tx The pointer to the transaction to search.
 * @param out_commit32 The output buffer for the 32-byte commitment.
 *
 * @return true if a commitment was found, false otherwise.
 */
dogecoin_bool dogecoin_tx_extract_falcon512_commit(const dogecoin_tx* tx, uint8_t out_commit32[DOGECOIN_PQC_FALCON_COMMIT_LEN]) {
    if (!tx || !out_commit32) {
        return false;
    }

    // Look for the first vout whose script matches: 6a 24 "FLC1" <32 bytes>
    for (unsigned i = 0; i < tx->vout->len; ++i) {
        const dogecoin_tx_out* o = vector_idx(tx->vout, i);
        if (!o || !o->script_pubkey || o->script_pubkey->len < (1 + 1 + DOGECOIN_PQC_FALCON_PUSH_TOTAL))
            continue;

        const unsigned char* p = (const unsigned char*)o->script_pubkey->str;
        size_t n = o->script_pubkey->len;

        if (n == (1 + 1 + DOGECOIN_PQC_FALCON_PUSH_TOTAL) &&
            p[0] == 0x6a &&
            p[1] == DOGECOIN_PQC_FALCON_PUSH_TOTAL &&
            memcmp(p + 2, DOGECOIN_PQC_FALCON_TAG, DOGECOIN_PQC_FALCON_TAG_LEN) == 0) {
            memcpy(out_commit32, p + 2 + DOGECOIN_PQC_FALCON_TAG_LEN, 32);
            return true;
        }
    }
    return false;
}

/**
 * @brief This function computes a transaction sighash and
 * writes the raw 32-byte digest to out32.
 *
 * @param tx_to The pointer to the transaction.
 * @param fromPubKey The scriptPubKey of the input being signed.
 * @param in_num The index of the input being signed.
 * @param hashtype The sighash type (e.g. SIGHASH_ALL).
 * @param out32 The output buffer for the 32-byte hash.
 *
 * @return true if the sighash was computed, false on error.
 */
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

#ifdef USE_LIBOQS

/**
 * @brief This function generates a Falcon-512 keypair via
 * liboqs and allocates the public and secret key buffers.
 *
 * @param pk The pointer to receive the allocated public key.
 * @param pk_len The pointer to receive the public key length.
 * @param sk The pointer to receive the allocated secret key.
 * @param sk_len The pointer to receive the secret key length.
 *
 * @return true if the keypair was generated, false on error.
 */
dogecoin_bool dogecoin_falcon512_keypair(uint8_t** pk, size_t* pk_len,
                                         uint8_t** sk, size_t* sk_len)
{
    if (!pk || !pk_len || !sk || !sk_len) {
        return false;
    }

    OQS_SIG* alg = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (!alg) {
        return false;
    }

    uint8_t* pk_buf = (uint8_t*)dogecoin_malloc(alg->length_public_key);
    uint8_t* sk_buf = (uint8_t*)dogecoin_malloc(alg->length_secret_key);
    if (!pk_buf || !sk_buf) {
        if (pk_buf) dogecoin_free(pk_buf);
        if (sk_buf) dogecoin_free(sk_buf);
        OQS_SIG_free(alg);
        return false;
    }

    OQS_STATUS st = OQS_SIG_keypair(alg, pk_buf, sk_buf);
    if (st != OQS_SUCCESS) {
        dogecoin_free(pk_buf);
        dogecoin_free(sk_buf);
        OQS_SIG_free(alg);
        return false;
    }

    *pk = pk_buf;
    *pk_len = alg->length_public_key;
    *sk = sk_buf;
    *sk_len = alg->length_secret_key;

    OQS_SIG_free(alg);
    return true;
}

/**
 * @brief This function signs a message with a Falcon-512
 * secret key and allocates the signature buffer.
 *
 * @param sk The pointer to the secret key.
 * @param sk_len The length of the secret key.
 * @param msg The pointer to the message to sign.
 * @param msg_len The length of the message.
 * @param sig_out The pointer to receive the allocated signature.
 * @param sig_len The pointer to receive the signature length.
 *
 * @return true if signing succeeded, false on error.
 */
dogecoin_bool dogecoin_falcon512_sign(const uint8_t* sk, size_t sk_len,
                                      const uint8_t* msg, size_t msg_len,
                                      uint8_t** sig_out, size_t* sig_len)
{
    if (!sk || !msg || !sig_out || !sig_len) {
        return false;
    }

    OQS_SIG* alg = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (!alg) {
        return false;
    }

    /* Optional length check */
    if (sk_len && sk_len != alg->length_secret_key) {
        OQS_SIG_free(alg);
        return false;
    }

    uint8_t* sig_buf = (uint8_t*)dogecoin_malloc(alg->length_signature);
    if (!sig_buf) {
        OQS_SIG_free(alg);
        return false;
    }

    size_t outlen = 0;
    OQS_STATUS st = OQS_SIG_sign(alg, sig_buf, &outlen, msg, msg_len, sk);
    if (st != OQS_SUCCESS) {
        dogecoin_free(sig_buf);
        OQS_SIG_free(alg);
        return false;
    }

    *sig_out = sig_buf;
    *sig_len = outlen;
    OQS_SIG_free(alg);
    return true;
}

/**
 * @brief This function verifies a Falcon-512 signature
 * against a public key and message.
 *
 * @param pk The pointer to the public key.
 * @param pk_len The length of the public key.
 * @param msg The pointer to the message.
 * @param msg_len The length of the message.
 * @param sig The pointer to the signature.
 * @param sig_len The length of the signature.
 *
 * @return true if the signature is valid, false otherwise.
 */
dogecoin_bool dogecoin_falcon512_verify(const uint8_t* pk, size_t pk_len,
                                        const uint8_t* msg, size_t msg_len,
                                        const uint8_t* sig, size_t sig_len)
{
    if (!pk || !msg || !sig) {
        return false;
    }

    OQS_SIG* alg = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (!alg) {
        return false;
    }

    /* Optional length check */
    if (pk_len && pk_len != alg->length_public_key) {
        OQS_SIG_free(alg);
        return false;
    }

    OQS_STATUS st = OQS_SIG_verify(alg, msg, msg_len, sig, sig_len, pk);
    OQS_SIG_free(alg);
    return st == OQS_SUCCESS;
}

#endif /* USE_LIBOQS */
