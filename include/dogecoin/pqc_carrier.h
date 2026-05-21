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

#ifndef __LIBDOGECOIN_PQC_CARRIER_H__
#define __LIBDOGECOIN_PQC_CARRIER_H__

#include <stddef.h>
#include <stdint.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/cstr.h>
#include <dogecoin/tx.h>

LIBDOGECOIN_BEGIN_DECL

#define DOGECOIN_PQC_CARRIER_MAX_CHUNKS 3
#define DOGECOIN_PQC_CARRIER_CHUNK_MAX 520
#define DOGECOIN_PQC_CARRIER_HDR_LEN 8
#define DOGECOIN_PQC_CARRIER_TAG_LEN 8

/* P2PKH scriptSig length bounds for PQC sighash derivation.
   A valid P2PKH scriptSig is: <push DER_sig+hashtype> <push compressed_pubkey>
   Min: 1 (push opcode) + 71 (min DER sig + hashtype) + 1 (push opcode) + 33 (pubkey) = 106
   Max: 1 + 73 + 1 + 33 = 108, but allow up to 180 for safety margin. */
#define DOGECOIN_PQC_MIN_P2PKH_SCRIPTSIG_LEN 106
#define DOGECOIN_PQC_MAX_P2PKH_SCRIPTSIG_LEN 180

/* DER signature push length bounds (includes 1-byte sighash type).
   Min: 8 (shortest valid DER) + 1 (hashtype) = 9.
   Max: 72 (longest valid DER) + 1 (hashtype) = 73. */
#define DOGECOIN_PQC_MIN_DER_SIG_PUSH_LEN 9
#define DOGECOIN_PQC_MAX_DER_SIG_PUSH_LEN 73

/* PQC algorithm discriminant used by carrier extraction and SPV validation. */
typedef enum {
    DOGECOIN_PQC_ALGO_FALCON,
    DOGECOIN_PQC_ALGO_DILITHIUM,
#ifdef USE_RACCOON_G
    DOGECOIN_PQC_ALGO_RACCOONG
#endif
} dogecoin_pqc_algo_t;

/*
 * Build the OP_DROP-based redeem script for PQC carrier P2SH outputs.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_pqc_carrier_build_redeemscript(cstring** out_redeem);

/*
 * Build a P2SH scriptPubKey from a redeem script.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_pqc_carrier_build_p2sh_scriptpubkey(const cstring* redeem, cstring** out_spk);

/*
 * Build a carrier scriptSig for one part of a multi-part PQC payload.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_pqc_carrier_build_part_scriptsig(
    const char tag8[DOGECOIN_PQC_CARRIER_TAG_LEN],
    uint8_t part_index,
    uint8_t part_total,
    uint16_t pk_len,
    uint16_t full_len,
    const uint8_t* part_data,
    size_t part_data_len,
    const cstring* redeem,
    cstring** out_scriptsig);

/*
 * Parse a carrier scriptSig to extract tag, part metadata, and payload.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_pqc_carrier_parse_part_scriptsig(
    const cstring* scriptsig,
    char out_tag8[DOGECOIN_PQC_CARRIER_TAG_LEN + 1],
    uint8_t* out_part_index,
    uint8_t* out_part_total,
    uint16_t* out_pk_len,
    uint16_t* out_full_len,
    uint8_t** out_part_data,
    size_t* out_part_data_len,
    cstring** out_redeem);

/*
 * Add carrier P2SH outputs to a transaction.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_tx_add_pqc_carrier_outputs(
    dogecoin_tx* tx,
    const cstring* carrier_spk,
    uint64_t value,
    uint8_t part_total);

/*
 * Extract PQC pubkey+sig from carrier-format scriptSigs (multi-part reassembly).
 * Caller must free *carrier_buf with dogecoin_free().
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_pqc_carrier_extract_scriptsig(
    const dogecoin_tx* tx,
    dogecoin_pqc_algo_t* out_algo,
    const uint8_t** out_pk,
    size_t* out_pk_len,
    const uint8_t** out_sig,
    size_t* out_sig_len,
    size_t* out_vin_index,
    uint8_t** carrier_buf,
    size_t* carrier_buf_len);

/*
 * Phase 2: verify a PQC carrier reveal by reconstructing TX_BASE from raw TX_C
 * bytes, deriving the sighash32, and verifying the PQC signature over it.
 * out_sighash receives the computed sighash (zeroed on failure).
 * Returns true iff the signature is valid.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_pqc_carrier_verify_reveal(
    dogecoin_pqc_algo_t algo,
    const uint8_t* txc_raw,
    size_t txc_raw_len,
    const uint8_t* pk,
    size_t pk_len,
    const uint8_t* sig,
    size_t sig_len,
    uint8_t out_sighash[32]);

LIBDOGECOIN_END_DECL

#endif /* __LIBDOGECOIN_PQC_CARRIER_H__ */
