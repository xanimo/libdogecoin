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
 * Groth16 entry points.
 *
 * Policy:
 *
 *   * Proving NEVER runs inside libdogecoin.  The prover lives in a higher
 *     layer (snarkjs in a wallet/UI, or the rapidsnark CLI on a host).
 *     `dogecoin_zk_generate_groth16_proof` therefore always returns
 *     DOGECOIN_ZK_ERR_DELEGATED — see contrib/zk_carrier/witness_helper.py
 *     for the supported way to drive snarkjs end-to-end.
 *
 *   * Verification CAN run inside libdogecoin when built with rapidsnark
 *     (HAVE_RAPIDSNARK).  Otherwise verification is also DELEGATED, which
 *     lets the demo script fall back to `snarkjs groth16 verify`.
 *
 * The "delegated" status is not a stub: it's the documented behaviour of the
 * mobile-friendly build, and callers (the demo script, the wallet/UI) handle it.
 *
 * Tying into the reserved-opcode proposal: when a future reserved-opcode validator
 * lands, an interpreter implementation will pull the verification key from a
 * consensus-anchored registry, reuse `dogecoin_zk_extract_carrier_payload`
 * to get the public inputs and proof, and call `dogecoin_zk_verify_groth16`
 * (or PLONK / STARK equivalents) for the matching mode byte.
 */

#if defined(HAVE_CONFIG_H)
#include "libdogecoin-config.h"
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <dogecoin/mem.h>
#include <dogecoin/zk_carrier.h>

#ifdef HAVE_RAPIDSNARK
/* Forward declaration of the rapidsnark v0.0.8 verifier C ABI.  Header lives
 * at <rapidsnark/verifier.h> in the depends-staged install but we re-declare
 * it here so HAVE_RAPIDSNARK builds don't require pulling the upstream header
 * into libdogecoin's include path.  Argument order MUST match upstream:
 *
 *     int groth16_verify(const char *proof,
 *                        const char *inputs,
 *                        const char *verification_key,
 *                        char *error_msg, unsigned long error_msg_maxsize);
 *
 * Returns 0 (VERIFIER_VALID_PROOF) on success, 1 (VERIFIER_INVALID_PROOF) for
 * a well-formed-but-invalid proof, 2 (VERIFIER_ERROR) for any parse or
 * arithmetic error (with a short diagnostic in error_msg).  See
 * depends/packages/rapidsnark.mk. */
extern int groth16_verify(const char* proof_json,
                          const char* public_json,
                          const char* vk_json,
                          char* error_msg,
                          unsigned long error_msg_maxsize);
#endif

#ifdef HAVE_MCL
/* Forward declaration of the herumi/mcl-backed verifier implemented in
 * src/zk_carrier/zk_groth16_mcl.cpp.  Returns 0 on successful verification,
 * non-zero on any error (with a short non-sensitive diagnostic in err_buf).
 * Linked in via depends/packages/mcl.mk + ./configure --with-mcl. */
extern int groth16_verify_mcl(const char* vk_json,
                              const char* public_json,
                              const char* proof_json,
                              char* err_buf,
                              unsigned long err_buf_max);
#endif

/**
 * @brief Stub Groth16 prover entry point — always returns DOGECOIN_ZK_ERR_DELEGATED.
 *
 * libdogecoin's policy is that proving lives in the wallet/UI (snarkjs) or
 * in a host-side rapidsnark CLI.  This entry point exists for surface-area
 * completeness so the public header can declare the prover symmetrically
 * with the verifier; the supported way to produce a Groth16 proof is the
 * helper at `contrib/zk_carrier/witness_helper.py`.
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
dogecoin_zk_err_t dogecoin_zk_generate_groth16_proof(
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
    /* Intentional: see file header.  Use contrib/zk_carrier/witness_helper.py. */
    return DOGECOIN_ZK_ERR_DELEGATED;
}

/**
 * @brief Verify a Groth16 proof against a verification key and public inputs.
 *
 * When libdogecoin was built with `--with-rapidsnark` (HAVE_RAPIDSNARK is
 * defined) this calls into the upstream rapidsnark v0.0.8 verifier.  When
 * built with `--with-mcl` it calls the herumi/mcl-backed verifier in
 * src/zk_carrier/zk_groth16_mcl.cpp.  Otherwise it returns
 * DOGECOIN_ZK_ERR_DELEGATED so callers can fall back to off-box verification
 * (e.g. `snarkjs groth16 verify`).
 *
 * All three blobs are snarkjs-style JSON and are not assumed to be
 * NUL-terminated; this function makes NUL-terminated copies before passing
 * them to the underlying C ABI.
 *
 * @param vk_json          verification-key JSON bytes
 * @param vk_json_len      length of `vk_json`
 * @param public_json      `public.json` bytes (snarkjs flat decimal array)
 * @param public_json_len  length of `public_json`
 * @param proof_json       `proof.json` bytes
 * @param proof_json_len   length of `proof_json`
 *
 * @return DOGECOIN_ZK_OK on a valid proof; DOGECOIN_ZK_ERR_VERIFY_FAIL on a
 *         well-formed-but-invalid proof or a parse error; DOGECOIN_ZK_ERR_*
 *         for invalid arguments / OOM; DOGECOIN_ZK_ERR_DELEGATED when no
 *         in-process verifier was linked
 */
dogecoin_zk_err_t dogecoin_zk_verify_groth16(
    const uint8_t* vk_json,
    size_t vk_json_len,
    const uint8_t* public_json,
    size_t public_json_len,
    const uint8_t* proof_json,
    size_t proof_json_len)
{
    /* No verification key was supplied or embedded in the reveal, so the caller
     * cannot do an in-process check.  Return DELEGATED so the SPV reveal can
     * still rely on the on-chain commitment/binding checks. */
    if (!vk_json || vk_json_len == 0) {
        return DOGECOIN_ZK_ERR_DELEGATED;
    }
    if (!public_json || public_json_len == 0 ||
        !proof_json  || proof_json_len  == 0) {
        return DOGECOIN_ZK_ERR_INVALID_ARG;
    }
#ifdef HAVE_RAPIDSNARK
    /* rapidsnark wants NUL-terminated JSON strings.  Copy into NUL-terminated
     * buffers; the caller's blobs are bytes that may not be terminated. */
    char* vk = (char*)dogecoin_malloc(vk_json_len + 1);
    char* pubj = (char*)dogecoin_malloc(public_json_len + 1);
    char* prf = (char*)dogecoin_malloc(proof_json_len + 1);
    if (!vk || !pubj || !prf) {
        if (vk) dogecoin_free(vk);
        if (pubj) dogecoin_free(pubj);
        if (prf) dogecoin_free(prf);
        return DOGECOIN_ZK_ERR_OOM;
    }
    memcpy(vk, vk_json, vk_json_len);
    vk[vk_json_len] = '\0';
    memcpy(pubj, public_json, public_json_len);
    pubj[public_json_len] = '\0';
    memcpy(prf, proof_json, proof_json_len);
    prf[proof_json_len] = '\0';

    char err[256];
    err[0] = '\0';
    /* Upstream rapidsnark v0.0.8 ABI: groth16_verify(proof, inputs, vk, ...). */
    int rc = groth16_verify(prf, pubj, vk, err, sizeof(err));
    dogecoin_free(vk);
    dogecoin_free(pubj);
    dogecoin_free(prf);
    if (rc != 0) {
        return DOGECOIN_ZK_ERR_VERIFY_FAIL;
    }
    return DOGECOIN_ZK_OK;
#elif defined(HAVE_MCL)
    /* mcl-backed verifier (depends/packages/mcl.mk + --with-mcl).  Like the
     * rapidsnark path it expects NUL-terminated JSON, so copy into freshly
     * allocated NUL-terminated buffers. */
    char* vk = (char*)dogecoin_malloc(vk_json_len + 1);
    char* pubj = (char*)dogecoin_malloc(public_json_len + 1);
    char* prf = (char*)dogecoin_malloc(proof_json_len + 1);
    if (!vk || !pubj || !prf) {
        if (vk) dogecoin_free(vk);
        if (pubj) dogecoin_free(pubj);
        if (prf) dogecoin_free(prf);
        return DOGECOIN_ZK_ERR_OOM;
    }
    memcpy(vk, vk_json, vk_json_len);     vk[vk_json_len] = '\0';
    memcpy(pubj, public_json, public_json_len); pubj[public_json_len] = '\0';
    memcpy(prf, proof_json, proof_json_len);    prf[proof_json_len] = '\0';

    char err[256];
    err[0] = '\0';
    int rc = groth16_verify_mcl(vk, pubj, prf, err, sizeof(err));
    dogecoin_free(vk);
    dogecoin_free(pubj);
    dogecoin_free(prf);
    if (rc != 0) {
        return DOGECOIN_ZK_ERR_VERIFY_FAIL;
    }
    return DOGECOIN_ZK_OK;
#else
    /* No rapidsnark linked: caller falls back to off-box verification.
     * The demo script handles this with `snarkjs groth16 verify`. */
    return DOGECOIN_ZK_ERR_DELEGATED;
#endif
}

/**
 * @brief Verify any ZK reveal payload by mode, dispatching to the per-system
 * verifier above.
 *
 * Decodes the payload's mode / public-inputs / proof / (optional) embedded
 * vk slices, then forwards to dogecoin_zk_verify_groth16 (mode 0) or
 * returns DOGECOIN_ZK_ERR_DELEGATED for mode 1 (PLONK — verified via
 * snarkjs by the demo helpers) and DOGECOIN_ZK_ERR_NOT_IMPLEMENTED for mode
 * 2 (STARK).  When the payload itself carries an embedded verification key
 * (v1 layout) it is preferred over the caller-supplied `vk_blob`; the
 * external vk is only used as a fallback for legacy v0 payloads.
 *
 * @param payload       ZKP1 reveal payload bytes
 * @param payload_len   byte length of `payload`
 * @param vk_blob       (optional) externally-supplied verification key for v0
 * @param vk_blob_len   byte length of `vk_blob` (0 if `vk_blob` is NULL)
 *
 * @return DOGECOIN_ZK_OK on a valid proof; one of DOGECOIN_ZK_ERR_* on
 *         decode / argument / verifier failure; DOGECOIN_ZK_ERR_DELEGATED
 *         when verification is left to an off-box helper
 */
dogecoin_zk_err_t dogecoin_zk_verify_proof(
    const uint8_t* payload,
    size_t payload_len,
    const uint8_t* vk_blob,
    size_t vk_blob_len)
{
    dogecoin_zk_mode_t mode;
    uint32_t circuit_id;
    const uint8_t* public_inputs;
    size_t public_inputs_len;
    const uint8_t* proof;
    size_t proof_len;
    const uint8_t* embedded_vk = NULL;
    size_t embedded_vk_len = 0;

    dogecoin_zk_err_t e = dogecoin_zk_decode_payload(
        payload, payload_len, &mode, &circuit_id,
        &public_inputs, &public_inputs_len, &proof, &proof_len,
        &embedded_vk, &embedded_vk_len);
    if (e != DOGECOIN_ZK_OK) return e;
    (void)circuit_id;

    /* Prefer the vk embedded in the reveal payload — that's the whole point
     * of the v1 self-contained-reveal layout: every byte needed to validate
     * the proof on chain is in the reveal itself.  Fall back to the caller-
     * supplied vk only when the payload didn't carry one (legacy v0).      */
    const uint8_t* eff_vk    = (embedded_vk && embedded_vk_len > 0) ? embedded_vk    : vk_blob;
    size_t         eff_vk_len = (embedded_vk && embedded_vk_len > 0) ? embedded_vk_len : vk_blob_len;

    switch (mode) {
    case DOGECOIN_ZK_MODE_GROTH16:
        return dogecoin_zk_verify_groth16(eff_vk, eff_vk_len,
                                          public_inputs, public_inputs_len,
                                          proof, proof_len);
    case DOGECOIN_ZK_MODE_PLONK:
        /* No native PLONK verifier is linked into libdogecoin; the canonical
         * verifier is snarkjs (see contrib/zk_carrier/scripts/).  The reveal
         * and embedded vk are exposed to the caller for off-box verification. */
        return DOGECOIN_ZK_ERR_DELEGATED;
    case DOGECOIN_ZK_MODE_STARK_S2:
        return DOGECOIN_ZK_ERR_NOT_IMPLEMENTED;
    }
    return DOGECOIN_ZK_ERR_BAD_MODE;
}
