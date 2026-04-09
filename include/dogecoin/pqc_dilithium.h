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

#ifndef __LIBDOGECOIN_PQC_DILITHIUM_H__
#define __LIBDOGECOIN_PQC_DILITHIUM_H__

#include <stddef.h>
#include <stdint.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/cstr.h>
#include <dogecoin/tx.h>

LIBDOGECOIN_BEGIN_DECL

#define DOGECOIN_PQC_DILITHIUM_TAG        "DIL2"
#define DOGECOIN_PQC_DILITHIUM_TAG_LEN    4
#define DOGECOIN_PQC_DILITHIUM_COMMIT_LEN 32
#define DOGECOIN_PQC_DILITHIUM_PUSH_TOTAL (DOGECOIN_PQC_DILITHIUM_TAG_LEN + DOGECOIN_PQC_DILITHIUM_COMMIT_LEN)

/*
 * Generate a Dilithium2 keypair.
 */
#ifdef USE_LIBOQS
LIBDOGECOIN_API dogecoin_bool dogecoin_dilithium2_keypair(uint8_t** pk, size_t* pk_len,
                                                           uint8_t** sk, size_t* sk_len);

/*
 * Sign a message with Dilithium2.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_dilithium2_sign(const uint8_t* sk, size_t sk_len,
                                                        const uint8_t* msg, size_t msg_len,
                                                        uint8_t** sig, size_t* sig_len);

/*
 * Verify a Dilithium2 signature.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_dilithium2_verify(const uint8_t* pk, size_t pk_len,
                                                          const uint8_t* msg, size_t msg_len,
                                                          const uint8_t* sig, size_t sig_len);

/*
 * Compute commit = SHA256(pk || sig).
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_dilithium2_commit_bytes(const uint8_t* pk, size_t pk_len,
                                                                const uint8_t* signature, size_t signature_len,
                                                                uint8_t commit32[DOGECOIN_PQC_DILITHIUM_COMMIT_LEN]);

/*
 * Append OP_RETURN output carrying "DIL2" || commit32 (0 DOGE).
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_tx_add_dilithium2_commit(dogecoin_tx* tx,
                                                                 const uint8_t commit32[DOGECOIN_PQC_DILITHIUM_COMMIT_LEN]);

/*
 * Extract first "DIL2" commit32 from a transaction.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_tx_extract_dilithium2_commit(const dogecoin_tx* tx,
                                                                     uint8_t out_commit32[DOGECOIN_PQC_DILITHIUM_COMMIT_LEN]);
#endif

LIBDOGECOIN_END_DECL

#endif /* __LIBDOGECOIN_PQC_DILITHIUM_H__ */
