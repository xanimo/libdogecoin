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
 * PLONK proof system.
 *
 * Proving and in-process verification are delegated.  The mode byte
 * (DOGECOIN_ZK_MODE_PLONK = 1) is reserved here so on-chain artifacts can
 * be encoded today; verification is performed off-box by the canonical
 * snarkjs verifier (see contrib/zk_carrier/scripts/) which accepts the same
 * JSON public_inputs/proof/vk libdogecoin packages into the ZKP1 payload.
 */

#include <stddef.h>
#include <stdint.h>

#include <dogecoin/zk_carrier.h>

/**
 * @brief Stub PLONK prover entry point — always returns DOGECOIN_ZK_ERR_DELEGATED.
 *
 * Mirrors dogecoin_zk_generate_groth16_proof: libdogecoin reserves the
 * symbol so the public API can declare both proof systems symmetrically,
 * but proving lives in the wallet/UI (snarkjs) — see
 * contrib/zk_carrier/witness_helper.py and the demo scripts under
 * contrib/zk_carrier/scripts/.
 *
 * @param witness_json      ignored
 * @param witness_json_len  ignored
 * @param circuit_path      ignored
 * @param out_proof         set to NULL on return (when non-NULL)
 * @param out_proof_len     set to 0 on return (when non-NULL)
 * @param out_public        set to NULL on return (when non-NULL)
 * @param out_public_len    set to 0 on return (when non-NULL)
 *
 * @return DOGECOIN_ZK_ERR_DELEGATED, always
 */
dogecoin_zk_err_t dogecoin_zk_generate_plonk_proof(
    const uint8_t* witness_json,
    size_t witness_json_len,
    const char* circuit_path,
    uint8_t** out_proof,
    size_t* out_proof_len,
    uint8_t** out_public,
    size_t* out_public_len)
{
    (void)witness_json;
    (void)witness_json_len;
    (void)circuit_path;
    if (out_proof) *out_proof = NULL;
    if (out_proof_len) *out_proof_len = 0;
    if (out_public) *out_public = NULL;
    if (out_public_len) *out_public_len = 0;
    /* Per libdogecoin policy, proving lives outside the library. */
    return DOGECOIN_ZK_ERR_DELEGATED;
}
