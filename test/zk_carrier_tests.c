/**********************************************************************
 * Copyright (c) 2026 edtubbs                                         *
 * Copyright (c) 2026 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <test/utest.h>

#include <dogecoin/cstr.h>
#include <dogecoin/mem.h>
#include <dogecoin/pqc_falcon.h>
#include <dogecoin/script.h>
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>
#include <dogecoin/zk_carrier.h>

static void test_zk_codec_roundtrip_with_vk(void)
{
    /* v1 self-contained reveal: the encoder embeds the verification key inline
     * so the decoder (and the on-chain verifier) can validate the proof using
     * only data extracted from the on-chain reveal — no out-of-band channel. */
    const uint8_t pub[]   = {0x10, 0x20, 0x30};
    const uint8_t proof[] = "{\"pi_a\":[],\"pi_b\":[],\"pi_c\":[]}";
    const uint8_t vk[]    = "{\"protocol\":\"groth16\",\"curve\":\"bn128\","
                            "\"nPublic\":1,\"vk_alpha_1\":[\"1\",\"2\",\"1\"]}";

    uint8_t* payload = NULL;
    size_t payload_len = 0;
    dogecoin_zk_err_t e = dogecoin_zk_encode_payload(
        DOGECOIN_ZK_MODE_GROTH16, 0x12345678,
        pub, sizeof(pub),
        proof, sizeof(proof),
        vk, sizeof(vk),
        &payload, &payload_len);
    u_assert_int_eq(e, DOGECOIN_ZK_OK);
    /* Version byte (offset 5 = "reserved"/version slot) MUST be v1 = 0x01 to
     * signal that the trailing vk is part of the canonical payload. */
    u_assert_int_eq(payload[5], 0x01);

    dogecoin_zk_mode_t mode_out;
    uint32_t cid_out;
    const uint8_t* pub_out;  size_t pub_out_len;
    const uint8_t* proof_out; size_t proof_out_len;
    const uint8_t* vk_out = NULL; size_t vk_out_len = 0;
    e = dogecoin_zk_decode_payload(payload, payload_len,
                                   &mode_out, &cid_out,
                                   &pub_out, &pub_out_len,
                                   &proof_out, &proof_out_len,
                                   &vk_out, &vk_out_len);
    u_assert_int_eq(e, DOGECOIN_ZK_OK);
    u_assert_int_eq(pub_out_len, sizeof(pub));
    u_assert_int_eq(memcmp(pub_out, pub, sizeof(pub)), 0);
    u_assert_int_eq(proof_out_len, sizeof(proof));
    u_assert_int_eq(memcmp(proof_out, proof, sizeof(proof)), 0);
    u_assert_int_eq(vk_out_len, sizeof(vk));
    u_assert_int_eq(memcmp(vk_out, vk, sizeof(vk)), 0);

    /* Tamper-detection on the embedded vk must invalidate the commitment, so
     * a malicious carrier cannot swap the vk without changing the on-chain
     * commit32 hash — this is the consensus-relevant property of v1. */
    uint8_t commit_a[32], commit_b[32];
    e = dogecoin_zk_get_commitment_hash(payload, payload_len, commit_a);
    u_assert_int_eq(e, DOGECOIN_ZK_OK);
    /* The vk bytes are at the very end of the payload; flip one. */
    payload[payload_len - 1] ^= 0x80;
    e = dogecoin_zk_get_commitment_hash(payload, payload_len, commit_b);
    u_assert_int_eq(e, DOGECOIN_ZK_OK);
    u_assert_int_eq(memcmp(commit_a, commit_b, 32) == 0 ? 1 : 0, 0);
    payload[payload_len - 1] ^= 0x80; /* restore */

    dogecoin_free(payload);
}

static void test_zk_codec_roundtrip(void)
{
    const uint8_t pub[]   = {0x01, 0x02, 0x03, 0x04, 0x05};
    /* Synthetic proof bytes — in practice these are JSON from snarkjs. */
    const uint8_t proof[] = "{\"pi_a\":[\"1\",\"2\"],\"pi_b\":[],\"pi_c\":[]}";
    uint8_t* payload = NULL;
    size_t payload_len = 0;

    dogecoin_zk_err_t e = dogecoin_zk_encode_payload(
        DOGECOIN_ZK_MODE_GROTH16, 0xDEADBEEF,
        pub, sizeof(pub),
        proof, sizeof(proof),
        NULL, 0,
        &payload, &payload_len);
    u_assert_int_eq(e, DOGECOIN_ZK_OK);
    u_assert_uint32_not_eq(payload != NULL, 0);
    u_assert_uint32_not_eq(payload_len, 0);

    /* Header: ZKP1 magic + 1 mode + 1 reserved + 4 circuit_id + 2 pl + ... */
    u_assert_int_eq(memcmp(payload, "ZKP1", 4), 0);
    u_assert_int_eq(payload[4], (uint8_t)DOGECOIN_ZK_MODE_GROTH16);
    u_assert_int_eq(payload[5], 0x00);
    u_assert_int_eq(payload[6], 0xDE);
    u_assert_int_eq(payload[7], 0xAD);
    u_assert_int_eq(payload[8], 0xBE);
    u_assert_int_eq(payload[9], 0xEF);

    dogecoin_zk_mode_t mode_out;
    uint32_t cid_out;
    const uint8_t* pub_out;
    size_t pub_out_len;
    const uint8_t* proof_out;
    size_t proof_out_len;
    const uint8_t* vk_out = (const uint8_t*)0xdead;
    size_t vk_out_len = 99;
    e = dogecoin_zk_decode_payload(payload, payload_len,
                                   &mode_out, &cid_out,
                                   &pub_out, &pub_out_len,
                                   &proof_out, &proof_out_len,
                                   &vk_out, &vk_out_len);
    u_assert_int_eq(e, DOGECOIN_ZK_OK);
    u_assert_int_eq(mode_out, DOGECOIN_ZK_MODE_GROTH16);
    u_assert_int_eq((int)cid_out, (int)0xDEADBEEF);
    u_assert_int_eq(pub_out_len, sizeof(pub));
    u_assert_int_eq(memcmp(pub_out, pub, sizeof(pub)), 0);
    u_assert_int_eq(proof_out_len, sizeof(proof));
    u_assert_int_eq(memcmp(proof_out, proof, sizeof(proof)), 0);
    /* v0 payload (no vk supplied to encoder): decoder must report vk slot as
     * empty so callers can detect "vk distributed out-of-band". */
    u_assert_int_eq(vk_out == NULL ? 1 : 0, 1);
    u_assert_int_eq((int)vk_out_len, 0);
    /* Version byte = v0 since no vk was supplied. */
    u_assert_int_eq(payload[5], 0x00);

    /* Tamper-detection: flip a byte in the payload, commitment must change. */
    uint8_t commit_a[32], commit_b[32];
    e = dogecoin_zk_get_commitment_hash(payload, payload_len, commit_a);
    u_assert_int_eq(e, DOGECOIN_ZK_OK);
    payload[payload_len - 1] ^= 0x01;
    e = dogecoin_zk_get_commitment_hash(payload, payload_len, commit_b);
    u_assert_int_eq(e, DOGECOIN_ZK_OK);
    u_assert_int_eq(memcmp(commit_a, commit_b, 32) == 0 ? 1 : 0, 0);
    payload[payload_len - 1] ^= 0x01; /* restore */

    /* Determinism: same input -> same digest. */
    uint8_t commit_c[32];
    e = dogecoin_zk_get_commitment_hash(payload, payload_len, commit_c);
    u_assert_int_eq(e, DOGECOIN_ZK_OK);
    u_assert_int_eq(memcmp(commit_a, commit_c, 32), 0);

    dogecoin_free(payload);
}

static void test_zk_decode_rejects_bad_magic(void)
{
    uint8_t buf[DOGECOIN_ZK_CARRIER_HDR_FIXED + 4];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, "ZKPx", 4); /* wrong magic */
    /* fill remaining header so length checks don't trip first */
    buf[12] = 0; buf[13] = 0; buf[14] = 0; buf[15] = 0; /* xl=0 */

    dogecoin_zk_mode_t mode_out;
    uint32_t cid_out;
    const uint8_t* pub_out;
    size_t pub_out_len;
    const uint8_t* proof_out;
    size_t proof_out_len;
    dogecoin_zk_err_t e = dogecoin_zk_decode_payload(buf, sizeof(buf),
                                                     &mode_out, &cid_out,
                                                     &pub_out, &pub_out_len,
                                                     &proof_out, &proof_out_len, NULL, NULL);
    u_assert_int_eq(e, DOGECOIN_ZK_ERR_BAD_MAGIC);
}

static void test_zk_decode_rejects_bad_mode(void)
{
    uint8_t buf[DOGECOIN_ZK_CARRIER_HDR_FIXED + 4];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, "ZKP1", 4);
    buf[4] = 99; /* unknown mode */
    /* circuit_id zero, pl=0, xl=0 */
    dogecoin_zk_mode_t mode_out;
    uint32_t cid_out;
    const uint8_t* pub_out;
    size_t pub_out_len;
    const uint8_t* proof_out;
    size_t proof_out_len;
    dogecoin_zk_err_t e = dogecoin_zk_decode_payload(buf, sizeof(buf),
                                                     &mode_out, &cid_out,
                                                     &pub_out, &pub_out_len,
                                                     &proof_out, &proof_out_len, NULL, NULL);
    u_assert_int_eq(e, DOGECOIN_ZK_ERR_BAD_MODE);
}

static void test_zk_decode_rejects_truncated(void)
{
    uint8_t buf[5];
    memcpy(buf, "ZKP1", 4);
    buf[4] = 0;
    dogecoin_zk_mode_t mode_out;
    uint32_t cid_out;
    const uint8_t* pub_out;
    size_t pub_out_len;
    const uint8_t* proof_out;
    size_t proof_out_len;
    dogecoin_zk_err_t e = dogecoin_zk_decode_payload(buf, sizeof(buf),
                                                     &mode_out, &cid_out,
                                                     &pub_out, &pub_out_len,
                                                     &proof_out, &proof_out_len, NULL, NULL);
    u_assert_int_eq(e, DOGECOIN_ZK_ERR_TRUNCATED);
}

static void test_zk_opreturn_layout(void)
{
    uint8_t commit[32];
    for (int i = 0; i < 32; i++) commit[i] = (uint8_t)(i * 7 + 1);

    cstring* spk = NULL;
    dogecoin_zk_err_t e = dogecoin_zk_build_opreturn_scriptpubkey(
        DOGECOIN_ZK_MODE_GROTH16, commit, &spk);
    u_assert_int_eq(e, DOGECOIN_ZK_OK);
    u_assert_int_eq(spk != NULL, 1);
    /* Total length: 1 (OP_RETURN) + 1 (push len) + 37 (data) = 39. */
    u_assert_int_eq((int)spk->len, 39);
    u_assert_int_eq((unsigned char)spk->str[0], OP_RETURN);
    u_assert_int_eq((unsigned char)spk->str[1], DOGECOIN_ZK_OPRETURN_DATA_LEN);
    u_assert_int_eq(memcmp(spk->str + 2, "DZKC", 4), 0);
    u_assert_int_eq((unsigned char)spk->str[6], (unsigned char)DOGECOIN_ZK_MODE_GROTH16);
    u_assert_int_eq(memcmp(spk->str + 7, commit, 32), 0);
    cstr_free(spk, true);
}

static void test_zk_carrier_tx_roundtrip(void)
{
    /* A modest-sized payload (covers >1 chunk but <1 part). */
    uint8_t pub[8];
    for (int i = 0; i < 8; i++) pub[i] = (uint8_t)(0xA0 + i);
    uint8_t proof[600];
    for (size_t i = 0; i < sizeof(proof); i++) proof[i] = (uint8_t)(i & 0xff);

    uint8_t* payload = NULL;
    size_t payload_len = 0;
    dogecoin_zk_err_t e = dogecoin_zk_encode_payload(
        DOGECOIN_ZK_MODE_GROTH16, 0x42,
        pub, sizeof(pub),
        proof, sizeof(proof),
        NULL, 0,
        &payload, &payload_len);
    u_assert_int_eq(e, DOGECOIN_ZK_OK);

    /* Build TX_C. */
    dogecoin_tx* tx_c = dogecoin_tx_new();
    cstring* carrier_spk = NULL;
    uint8_t part_total = 0;
    e = dogecoin_zk_build_carrier_tx_c(tx_c, payload, payload_len,
                                       DOGECOIN_ZK_MODE_GROTH16,
                                       100000000ull,
                                       &carrier_spk, &part_total);
    u_assert_int_eq(e, DOGECOIN_ZK_OK);
    u_assert_int_eq(part_total >= 1 ? 1 : 0, 1);
    u_assert_int_eq(carrier_spk != NULL, 1);
    /* TX_C should have 1 OP_RETURN + N carrier outputs. */
    u_assert_int_eq((int)tx_c->vout->len, 1 + part_total);

    dogecoin_tx_out* opret = (dogecoin_tx_out*)vector_idx(tx_c->vout, 0);
    u_assert_int_eq((int)opret->value, 0);
    u_assert_int_eq((unsigned char)opret->script_pubkey->str[0], OP_RETURN);

    /* Build TX_R scriptSigs and reconstruct a tx with those inputs. */
    cstring** scriptsigs = NULL;
    uint8_t part_total_r = 0;
    e = dogecoin_zk_build_carrier_tx_r_scriptsigs(payload, payload_len,
                                                  &scriptsigs, &part_total_r);
    u_assert_int_eq(e, DOGECOIN_ZK_OK);
    u_assert_int_eq(part_total_r, part_total);

    dogecoin_tx* tx_r = dogecoin_tx_new();
    for (uint8_t i = 0; i < part_total_r; i++) {
        dogecoin_tx_in* in = dogecoin_tx_in_new();
        in->prevout.n = i;
        memset(&in->prevout.hash, 0xAB, sizeof(in->prevout.hash));
        cstr_free(in->script_sig, true);
        in->script_sig = cstr_new_buf((const uint8_t*)scriptsigs[i]->str, scriptsigs[i]->len);
        in->sequence = 0xffffffff;
        vector_add(tx_r->vin, in);
        cstr_free(scriptsigs[i], true);
    }
    dogecoin_free(scriptsigs);

    /* Extract and compare. */
    uint8_t* extracted = NULL;
    size_t extracted_len = 0;
    e = dogecoin_zk_extract_carrier_payload(tx_r, &extracted, &extracted_len);
    u_assert_int_eq(e, DOGECOIN_ZK_OK);
    u_assert_int_eq((int)extracted_len, (int)payload_len);
    u_assert_int_eq(memcmp(extracted, payload, payload_len), 0);
    dogecoin_free(extracted);

    /* Commitment of extracted payload must equal the embedded OP_RETURN commit. */
    uint8_t commit_expected[32];
    e = dogecoin_zk_get_commitment_hash(payload, payload_len, commit_expected);
    u_assert_int_eq(e, DOGECOIN_ZK_OK);
    u_assert_int_eq(memcmp(opret->script_pubkey->str + 7, commit_expected, 32), 0);

    cstr_free(carrier_spk, true);
    dogecoin_tx_free(tx_c);
    dogecoin_tx_free(tx_r);
    dogecoin_free(payload);
}

static void test_zk_modes_dispatch(void)
{
    /* Build a minimal valid PLONK-tagged payload, verify dispatch returns
     * DELEGATED for PLONK (libdogecoin policy: PLONK proving + verification
     * runs in the host wallet/UI via snarkjs; we don't ship a native PLONK
     * verifier).  Same for STARK. */
    uint8_t* payload = NULL;
    size_t payload_len = 0;
    uint8_t one = 0x01;
    dogecoin_zk_err_t e = dogecoin_zk_encode_payload(
        DOGECOIN_ZK_MODE_PLONK, 0, &one, 1, &one, 1, NULL, 0, &payload, &payload_len);
    u_assert_int_eq(e, DOGECOIN_ZK_OK);
    e = dogecoin_zk_verify_proof(payload, payload_len, &one, 1);
    u_assert_int_eq(e, DOGECOIN_ZK_ERR_DELEGATED);
    dogecoin_free(payload);

    /* Same for STARK (reserved; native verifier not implemented). */
    e = dogecoin_zk_encode_payload(
        DOGECOIN_ZK_MODE_STARK_S2, 0, &one, 1, &one, 1, NULL, 0, &payload, &payload_len);
    u_assert_int_eq(e, DOGECOIN_ZK_OK);
    e = dogecoin_zk_verify_proof(payload, payload_len, &one, 1);
    u_assert_int_eq(e, DOGECOIN_ZK_ERR_NOT_IMPLEMENTED);
    dogecoin_free(payload);
}

static void test_zk_prover_is_delegated(void)
{
    /* libdogecoin's policy: proving never runs in-process. */
    uint8_t* p = NULL; size_t pl = 0;
    uint8_t* q = NULL; size_t ql = 0;
    dogecoin_zk_err_t e = dogecoin_zk_generate_groth16_proof(
        (const uint8_t*)"{}", 2, "/tmp/none.zkey",
        &p, &pl, &q, &ql);
    u_assert_int_eq(e, DOGECOIN_ZK_ERR_DELEGATED);
    e = dogecoin_zk_generate_plonk_proof(
        (const uint8_t*)"{}", 2, "/tmp/none.zkey",
        &p, &pl, &q, &ql);
    u_assert_int_eq(e, DOGECOIN_ZK_ERR_DELEGATED);
}

/* tx_base sighash binding: the ZK proof's `tx_binding` public input MUST
 * equal the sighash of the TX_C with OP_RETURN + carrier outputs stripped,
 * exactly mirroring the PQC carrier signing model.  This test asserts:
 *  1. `dogecoin_zk_compute_tx_base_sighash` strips OP_RETURN + carriers and
 *     re-adds the carrier value to the first remaining output, and
 *  2. The resulting sighash matches the sighash of the carrier-free base
 *     tx — so the SPV decoder's `[zk-commit] tx_binding match` check on a
 *     replayed proof under a different funding tx will mismatch by design.
 */
static void test_zk_tx_base_sighash_binding(void)
{
    /* Build a synthetic carrier_spk and a "base" TX_C (single P2PKH vout). */
    uint8_t carrier_h160[20];
    memset(carrier_h160, 0xa5, sizeof carrier_h160);
    cstring* carrier_spk = cstr_new_sz(23);
    static const uint8_t hdr[] = {0xa9, 0x14};
    static const uint8_t tail[] = {0x87};
    cstr_append_buf(carrier_spk, hdr, 2);
    cstr_append_buf(carrier_spk, carrier_h160, 20);
    cstr_append_buf(carrier_spk, tail, 1);

    cstring* signer_spk = cstr_new_sz(25);
    static const uint8_t p2pkh_pre[] = {0x76, 0xa9, 0x14};
    static const uint8_t p2pkh_post[] = {0x88, 0xac};
    uint8_t signer_h160[20];
    memset(signer_h160, 0x77, sizeof signer_h160);
    cstr_append_buf(signer_spk, p2pkh_pre, 3);
    cstr_append_buf(signer_spk, signer_h160, 20);
    cstr_append_buf(signer_spk, p2pkh_post, 2);

    /* tx_base: 1 vin, 1 P2PKH vout @ 100000000 koinu */
    dogecoin_tx* tx_base = dogecoin_tx_new();
    {
        dogecoin_tx_in* in = dogecoin_tx_in_new();
        memset(in->prevout.hash, 0, 32);
        in->prevout.n = 0;
        in->sequence = 0xffffffff;
        in->script_sig = cstr_new_sz(0); /* dogecoin_tx_sighash requires non-NULL script_sig */
        vector_add(tx_base->vin, in);
        dogecoin_tx_out* out = dogecoin_tx_out_new();
        out->value = 100000000;
        cstr_free(out->script_pubkey, true);
        out->script_pubkey = cstr_new_buf(signer_spk->str, signer_spk->len);
        vector_add(tx_base->vout, out);
    }
    uint8_t base_sighash[32];
    u_assert_int_eq(dogecoin_tx_sighash32(tx_base, signer_spk, 0, SIGHASH_ALL, base_sighash), true);

    /* tx_c: same vin, P2PKH vout reduced by 100000 (carrier value), then
     * an OP_RETURN nulldata output, then a P2SH carrier output of value
     * 100000.  This is the canonical TX_C layout zk_add_commit_and_carrier_tx
     * produces. */
    dogecoin_tx* tx_c = dogecoin_tx_new();
    {
        dogecoin_tx_in* in = dogecoin_tx_in_new();
        memset(in->prevout.hash, 0, 32);
        in->prevout.n = 0;
        in->sequence = 0xffffffff;
        in->script_sig = cstr_new_sz(0);
        vector_add(tx_c->vin, in);

        dogecoin_tx_out* out = dogecoin_tx_out_new();
        out->value = 100000000 - 100000; /* carrier deducted */
        cstr_free(out->script_pubkey, true);
        out->script_pubkey = cstr_new_buf(signer_spk->str, signer_spk->len);
        vector_add(tx_c->vout, out);

        dogecoin_tx_out* opret = dogecoin_tx_out_new();
        opret->value = 0;
        cstr_free(opret->script_pubkey, true);
        opret->script_pubkey = cstr_new_sz(8);
        static const uint8_t op_return_dummy[] = {0x6a, 0x06, 'D','Z','K','C', 0x00, 0x01};
        cstr_append_buf(opret->script_pubkey, op_return_dummy, sizeof op_return_dummy);
        vector_add(tx_c->vout, opret);

        dogecoin_tx_out* carr = dogecoin_tx_out_new();
        carr->value = 100000;
        cstr_free(carr->script_pubkey, true);
        carr->script_pubkey = cstr_new_buf(carrier_spk->str, carrier_spk->len);
        vector_add(tx_c->vout, carr);
    }

    uint8_t recomputed[32];
    u_assert_int_eq(dogecoin_zk_compute_tx_base_sighash(tx_c, signer_spk, carrier_spk, recomputed),
                    DOGECOIN_ZK_OK);

    /* Recomputed sighash matches the base sighash with the top byte zeroed. */
    uint8_t expected[32];
    memcpy(expected, base_sighash, 32);
    expected[0] = 0x00;
    u_assert_mem_eq(recomputed, expected, 32);

    /* A different funding tx (alt_value) must produce a different sighash. */
    dogecoin_tx_out* alt_out = vector_idx(tx_base->vout, 0);
    alt_out->value = 99500000;
    uint8_t alt_sighash[32];
    u_assert_int_eq(dogecoin_tx_sighash32(tx_base, signer_spk, 0, SIGHASH_ALL, alt_sighash), true);
    u_assert_int_eq(memcmp(alt_sighash, base_sighash, 32) != 0, 1);

    dogecoin_tx_free(tx_c);
    dogecoin_tx_free(tx_base);
    cstr_free(carrier_spk, true);
    cstr_free(signer_spk, true);
}

void test_zk_carrier(void)
{
    test_zk_codec_roundtrip();
    test_zk_codec_roundtrip_with_vk();
    test_zk_decode_rejects_bad_magic();
    test_zk_decode_rejects_bad_mode();
    test_zk_decode_rejects_truncated();
    test_zk_opreturn_layout();
    test_zk_carrier_tx_roundtrip();
    test_zk_tx_base_sighash_binding();
    test_zk_modes_dispatch();
    test_zk_prover_is_delegated();
}
