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
#include <dogecoin/pqc_dilithium.h>

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

/*
 * Helper hash primitive used by commitment builders.
 * Computes SHA256(pk || msg) and writes a 32-byte digest to out32.
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

/* Selects the preferred liboqs algorithm name for Dilithium2-level security. */
static const char* get_dilithium2_alg_name(void) {
#ifdef USE_LIBOQS
    OQS_SIG* alg = OQS_SIG_new("ML-DSA-44");
    if (alg) {
        OQS_SIG_free(alg);
        return "ML-DSA-44";
    }
    alg = OQS_SIG_new("Dilithium2");
    if (alg) {
        OQS_SIG_free(alg);
        return "Dilithium2";
    }
#endif
    return NULL;
}

dogecoin_bool dogecoin_dilithium2_commit_bytes(const uint8_t* pk, size_t pk_len,
                                               const uint8_t* signature, size_t signature_len,
                                               uint8_t out32[32])
{
    if (!pk || !signature || !out32) {
        return false;
    }
    sha256_pk_msg(out32, pk, pk_len, signature, signature_len);
    return true;
}

/* Append tagged Dilithium2 commitment output (OP_RETURN "DIL2" || commit32). */
dogecoin_bool dogecoin_tx_add_dilithium2_commit(dogecoin_tx* tx, const uint8_t* commit32) {
    if (!tx || !commit32) {
        return false;
    }

    cstring* spk = cstr_new_sz(1 + 1 + DOGECOIN_PQC_DILITHIUM_PUSH_TOTAL);
    uint8_t opret = 0x6a;
    uint8_t push  = DOGECOIN_PQC_DILITHIUM_PUSH_TOTAL;

    cstr_append_buf(spk, &opret, 1);
    cstr_append_buf(spk, &push, 1);
    cstr_append_buf(spk, (const uint8_t*)DOGECOIN_PQC_DILITHIUM_TAG, DOGECOIN_PQC_DILITHIUM_TAG_LEN);
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

/* Extract first canonical Dilithium2 commitment from tx outputs, if present. */
dogecoin_bool dogecoin_tx_extract_dilithium2_commit(const dogecoin_tx* tx, uint8_t* out32) {
    if (!tx || !out32) {
        return false;
    }

    for (unsigned i = 0; i < tx->vout->len; ++i) {
        const dogecoin_tx_out* o = vector_idx(tx->vout, i);
        if (!o || !o->script_pubkey || o->script_pubkey->len < (1 + 1 + DOGECOIN_PQC_DILITHIUM_PUSH_TOTAL))
            continue;

        const unsigned char* p = (const unsigned char*)o->script_pubkey->str;
        size_t n = o->script_pubkey->len;

        if (n == (1 + 1 + DOGECOIN_PQC_DILITHIUM_PUSH_TOTAL) &&
            p[0] == 0x6a &&
            p[1] == DOGECOIN_PQC_DILITHIUM_PUSH_TOTAL &&
            memcmp(p + 2, DOGECOIN_PQC_DILITHIUM_TAG, DOGECOIN_PQC_DILITHIUM_TAG_LEN) == 0) {
            memcpy(out32, p + 2 + DOGECOIN_PQC_DILITHIUM_TAG_LEN, 32);
            return true;
        }
    }
    return false;
}

#ifdef USE_LIBOQS

/* Generate Dilithium2 (ML-DSA-44 compatible) key material. */
dogecoin_bool dogecoin_dilithium2_keypair(uint8_t** pk, size_t* pk_len,
                                          uint8_t** sk, size_t* sk_len)
{
    if (!pk || !pk_len || !sk || !sk_len) {
        return false;
    }
    const char* alg_name = get_dilithium2_alg_name();
    if (!alg_name) {
        return false;
    }
    OQS_SIG* alg = OQS_SIG_new(alg_name);
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

/* Sign arbitrary message bytes with a Dilithium2 secret key. */
dogecoin_bool dogecoin_dilithium2_sign(const uint8_t* sk, size_t sk_len,
                                       const uint8_t* msg, size_t msg_len,
                                       uint8_t** sig_out, size_t* sig_len)
{
    if (!sk || !msg || !sig_out || !sig_len) {
        return false;
    }
    const char* alg_name = get_dilithium2_alg_name();
    if (!alg_name) {
        return false;
    }
    OQS_SIG* alg = OQS_SIG_new(alg_name);
    if (!alg) {
        return false;
    }

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

/* Verify a Dilithium2 signature for given message/public-key bytes. */
dogecoin_bool dogecoin_dilithium2_verify(const uint8_t* pk, size_t pk_len,
                                         const uint8_t* msg, size_t msg_len,
                                         const uint8_t* sig, size_t sig_len)
{
    if (!pk || !msg || !sig) {
        return false;
    }
    const char* alg_name = get_dilithium2_alg_name();
    if (!alg_name) {
        return false;
    }
    OQS_SIG* alg = OQS_SIG_new(alg_name);
    if (!alg) {
        return false;
    }

    if (pk_len && pk_len != alg->length_public_key) {
        OQS_SIG_free(alg);
        return false;
    }
    OQS_STATUS st = OQS_SIG_verify(alg, msg, msg_len, sig, sig_len, pk);
    OQS_SIG_free(alg);
    return st == OQS_SUCCESS;
}

#endif
