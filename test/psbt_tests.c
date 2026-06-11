/*
 The MIT License (MIT)

 Copyright (c) 2025 bluezr
 Copyright (c) 2025 The Dogecoin Foundation

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

#include <assert.h>
#include <string.h>
#include <stdio.h>

#include <test/utest.h>

#include <dogecoin/cstr.h>
#include <dogecoin/key.h>
#include <dogecoin/psbt.h>
#include <dogecoin/script.h>
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>

/* ── Helpers ────────────────────────────────────────────────── */

/* Build a minimal unsigned dogecoin_tx with one input and two outputs. */
static dogecoin_tx *make_unsigned_tx(void)
{
    dogecoin_tx *tx = dogecoin_tx_new();
    tx->version  = 1;
    tx->locktime = 0;

    /* Input: spend a known outpoint with empty scriptSig */
    dogecoin_tx_in *txin = dogecoin_tx_in_new();
    /* prevout: all-zeros txid, vout 0 */
    memset(txin->prevout.hash, 0, sizeof(txin->prevout.hash));
    txin->prevout.n = 0;
    txin->sequence  = 0xFFFFFFFF;
    /* scriptSig must be empty for PSBT */
    if (txin->script_sig) { cstr_free(txin->script_sig, true); txin->script_sig = NULL; }
    txin->script_sig = cstr_new_sz(0);
    vector_add(tx->vin, txin);

    /* Output: 100 DOGE to a P2PKH (arbitrary hash160) */
    dogecoin_tx_out *txout = dogecoin_tx_out_new();
    txout->value = 10000000000LL; /* 100 DOGE in koinu */
    uint8_t dummy_hash160[20];
    memset(dummy_hash160, 0xAB, sizeof(dummy_hash160));
    txout->script_pubkey = cstr_new_sz(25);
    dogecoin_script_build_p2pkh(txout->script_pubkey, dummy_hash160);
    vector_add(tx->vout, txout);

    return tx;
}

/* Build a minimal "previous transaction" (the UTXO being spent). */
static dogecoin_tx *make_prev_tx(const uint8_t hash160[20])
{
    dogecoin_tx *tx = dogecoin_tx_new();
    tx->version = 1;

    /* Coinbase-style input */
    dogecoin_tx_in *txin = dogecoin_tx_in_new();
    memset(txin->prevout.hash, 0, sizeof(txin->prevout.hash));
    txin->prevout.n = 0xFFFFFFFF;
    txin->sequence  = 0xFFFFFFFF;
    if (txin->script_sig) { cstr_free(txin->script_sig, true); }
    txin->script_sig = cstr_new_buf("\x01\x00", 2); /* minimal coinbase script */
    vector_add(tx->vin, txin);

    /* Output 0: the UTXO we'll be spending */
    dogecoin_tx_out *txout = dogecoin_tx_out_new();
    txout->value = 10000000000LL;
    txout->script_pubkey = cstr_new_sz(25);
    dogecoin_script_build_p2pkh(txout->script_pubkey, hash160);
    vector_add(tx->vout, txout);

    return tx;
}

/* ── Test: lifecycle / create / free ────────────────────────── */
static void test_psbt_lifecycle(void)
{
    dogecoin_psbt *psbt = dogecoin_psbt_new();
    u_assert_int_eq(psbt->version, PSBT_VERSION_0);
    u_assert_int_eq(psbt->num_inputs, 0);
    u_assert_int_eq(psbt->num_outputs, 0);
    dogecoin_psbt_free(psbt);

    /* NULL safety */
    dogecoin_psbt_free(NULL);
}

/* ── Test: creator role ─────────────────────────────────────── */
static void test_psbt_creator(void)
{
    dogecoin_tx *tx = make_unsigned_tx();
    dogecoin_psbt *psbt = dogecoin_psbt_create(tx);
    u_assert_not_null(psbt);
    u_assert_int_eq((int)psbt->num_inputs, 1);
    u_assert_int_eq((int)psbt->num_outputs, 1);
    u_assert_int_eq(psbt->version, PSBT_VERSION_0);
    u_assert_not_null(psbt->tx);

    /* Creator must reject a tx with non-empty scriptSig */
    dogecoin_tx_in *txin = vector_idx(tx->vin, 0);
    cstr_free(txin->script_sig, true);
    txin->script_sig = cstr_new_buf("\x01\x51", 2); /* OP_1 */
    dogecoin_psbt *bad = dogecoin_psbt_create(tx);
    u_assert_is_null(bad);

    dogecoin_psbt_free(psbt);
    dogecoin_tx_free(tx);
}

/* ── Test: serialization round-trip ────────────────────────── */
static void test_psbt_serialization(void)
{
    dogecoin_tx *tx = make_unsigned_tx();
    dogecoin_psbt *orig = dogecoin_psbt_create(tx);
    dogecoin_tx_free(tx);
    u_assert_not_null(orig);

    /* Serialize */
    cstring *raw = dogecoin_psbt_serialize(orig);
    u_assert_not_null(raw);
    u_assert_int_eq((int)raw->len > PSBT_MAGIC_LEN, 1);

    /* Verify magic */
    u_assert_int_eq(memcmp(raw->str, PSBT_MAGIC_BYTES, PSBT_MAGIC_LEN), 0);

    /* Deserialize */
    dogecoin_psbt *decoded = NULL;
    dogecoin_bool ok = dogecoin_psbt_deserialize(
        (const uint8_t *)raw->str, raw->len, &decoded);
    u_assert_int_eq(ok, true);
    u_assert_not_null(decoded);
    u_assert_int_eq((int)decoded->num_inputs, 1);
    u_assert_int_eq((int)decoded->num_outputs, 1);

    /* Re-serialize and compare bytes */
    cstring *raw2 = dogecoin_psbt_serialize(decoded);
    u_assert_int_eq(raw->len, raw2->len);
    u_assert_int_eq(memcmp(raw->str, raw2->str, raw->len), 0);

    cstr_free(raw,  true);
    cstr_free(raw2, true);
    dogecoin_psbt_free(orig);
    dogecoin_psbt_free(decoded);
}

/* ── Test: base64 round-trip ────────────────────────────────── */
static void test_psbt_base64(void)
{
    dogecoin_tx *tx = make_unsigned_tx();
    dogecoin_psbt *orig = dogecoin_psbt_create(tx);
    dogecoin_tx_free(tx);

    char *b64 = dogecoin_psbt_to_base64(orig);
    u_assert_not_null(b64);
    u_assert_int_eq(((int)strlen(b64)) > 0, 1);

    dogecoin_psbt *decoded = NULL;
    u_assert_int_eq(dogecoin_psbt_from_base64(b64, &decoded), true);
    u_assert_not_null(decoded);
    u_assert_int_eq((int)decoded->num_inputs, 1);
    u_assert_int_eq((int)decoded->num_outputs, 1);

    dogecoin_free(b64);
    dogecoin_psbt_free(orig);
    dogecoin_psbt_free(decoded);
}

/* ── Test: hex round-trip ───────────────────────────────────── */
static void test_psbt_hex(void)
{
    dogecoin_tx *tx = make_unsigned_tx();
    dogecoin_psbt *orig = dogecoin_psbt_create(tx);
    dogecoin_tx_free(tx);

    char *hex = dogecoin_psbt_to_hex(orig);
    u_assert_not_null(hex);

    dogecoin_psbt *decoded = NULL;
    u_assert_int_eq(dogecoin_psbt_from_hex(hex, &decoded), true);
    u_assert_not_null(decoded);

    /* Re-hex and compare */
    char *hex2 = dogecoin_psbt_to_hex(decoded);
    u_assert_int_eq(strcmp(hex, hex2), 0);

    dogecoin_free(hex);
    dogecoin_free(hex2);
    dogecoin_psbt_free(orig);
    dogecoin_psbt_free(decoded);
}

/* ── Test: updater role ─────────────────────────────────────── */
static void test_psbt_updater(void)
{
    dogecoin_tx *tx = make_unsigned_tx();
    dogecoin_psbt *psbt = dogecoin_psbt_create(tx);
    dogecoin_tx_free(tx);

    /* Set non-witness UTXO */
    uint8_t dummy_hash160[20];
    memset(dummy_hash160, 0xAB, sizeof(dummy_hash160));
    dogecoin_tx *utxo = make_prev_tx(dummy_hash160);
    u_assert_int_eq(dogecoin_psbt_input_set_utxo(psbt, 0, utxo), true);
    u_assert_not_null(psbt->inputs[0].non_witness_utxo);
    dogecoin_tx_free(utxo);

    /* Set sighash type */
    u_assert_int_eq(dogecoin_psbt_input_set_sighash(psbt, 0, SIGHASH_ALL), true);
    u_assert_int_eq(psbt->inputs[0].has_sighash_type, true);
    u_assert_int_eq((int)psbt->inputs[0].sighash_type, SIGHASH_ALL);

    /* Add keypath */
    uint8_t fake_pubkey[33];
    memset(fake_pubkey, 0x02, sizeof(fake_pubkey));
    uint32_t path[3] = { 0x8000002C, 0x80000003, 0x80000000 };
    u_assert_int_eq(dogecoin_psbt_input_add_keypath(psbt, 0, fake_pubkey, 33,
                                                     0xDEADBEEF, path, 3), true);
    u_assert_int_eq((int)psbt->inputs[0].num_keypaths, 1);
    u_assert_int_eq((int)psbt->inputs[0].keypaths[0].fingerprint, (int)0xDEADBEEF);

    /* Out of range */
    u_assert_int_eq(dogecoin_psbt_input_set_utxo(psbt, 99, NULL), false);
    u_assert_int_eq(dogecoin_psbt_output_set_redeemscript(psbt, 99, NULL, 0), false);

    dogecoin_psbt_free(psbt);
}

/* ── Test: signer + finalizer + extractor ─────────────────── */
static void test_psbt_sign_finalize_extract(void)
{
    /* Generate a key pair */
    dogecoin_key privkey;
    dogecoin_privkey_init(&privkey);
    dogecoin_privkey_gen(&privkey);

    dogecoin_pubkey pubkey;
    dogecoin_pubkey_init(&pubkey);
    dogecoin_pubkey_from_key(&privkey, &pubkey);
    u_assert_int_eq(dogecoin_pubkey_is_valid(&pubkey), true);

    /* Get hash160 of that pubkey */
    uint8_t hash160[20];
    dogecoin_pubkey_get_hash160(&pubkey, hash160);

    /* Build unsigned tx spending a P2PKH output to that pubkey */
    dogecoin_tx *tx = dogecoin_tx_new();
    tx->version = 1; tx->locktime = 0;

    dogecoin_tx_in *txin = dogecoin_tx_in_new();
    memset(txin->prevout.hash, 0x11, sizeof(txin->prevout.hash));
    txin->prevout.n = 0;
    txin->sequence  = 0xFFFFFFFF;
    if (txin->script_sig) { cstr_free(txin->script_sig, true); }
    txin->script_sig = cstr_new_sz(0);
    vector_add(tx->vin, txin);

    dogecoin_tx_out *txout = dogecoin_tx_out_new();
    txout->value = 5000000000LL; /* 50 DOGE */
    uint8_t dest_hash[20]; memset(dest_hash, 0xCC, 20);
    txout->script_pubkey = cstr_new_sz(25);
    dogecoin_script_build_p2pkh(txout->script_pubkey, dest_hash);
    vector_add(tx->vout, txout);

    /* Create PSBT */
    dogecoin_psbt *psbt = dogecoin_psbt_create(tx);
    u_assert_not_null(psbt);
    dogecoin_tx_free(tx);

    /* Build the UTXO (previous tx at the outpoint) */
    dogecoin_tx *utxo = make_prev_tx(hash160);
    u_assert_int_eq(dogecoin_psbt_input_set_utxo(psbt, 0, utxo), true);
    dogecoin_tx_free(utxo);

    /* Validation before signing */
    u_assert_int_eq(dogecoin_psbt_is_valid(psbt),     true);
    u_assert_int_eq(dogecoin_psbt_is_finalized(psbt), false);

    /* Sign */
    u_assert_int_eq(dogecoin_psbt_sign(psbt, &privkey), true);
    u_assert_int_eq((int)psbt->inputs[0].num_partial_sigs, 1);

    /* Partial sig pubkey must match our key */
    dogecoin_psbt_partialsig *ps = &psbt->inputs[0].partial_sigs[0];
    u_assert_int_eq((int)ps->pubkey_len, DOGECOIN_ECKEY_COMPRESSED_LENGTH);
    u_assert_int_eq(memcmp(ps->pubkey, pubkey.pubkey, DOGECOIN_ECKEY_COMPRESSED_LENGTH), 0);
    u_assert_int_eq(((int)ps->sig_len) > 0, 1);

    /* Signing again with same key should not duplicate the entry */
    u_assert_int_eq(dogecoin_psbt_sign(psbt, &privkey), true);
    u_assert_int_eq((int)psbt->inputs[0].num_partial_sigs, 1);

    /* Finalize */
    u_assert_int_eq(dogecoin_psbt_finalize(psbt), true);
    u_assert_not_null(psbt->inputs[0].final_script_sig);
    u_assert_int_eq(dogecoin_psbt_is_finalized(psbt), true);

    /* Extract */
    dogecoin_tx *signed_tx = dogecoin_psbt_extract(psbt);
    u_assert_not_null(signed_tx);
    dogecoin_tx_in *signed_in = vector_idx(signed_tx->vin, 0);
    u_assert_not_null(signed_in->script_sig);
    u_assert_int_eq(((int)signed_in->script_sig->len) > 0, 1);

    dogecoin_tx_free(signed_tx);
    dogecoin_psbt_free(psbt);
    dogecoin_privkey_cleanse(&privkey);
}

/* ── Test: combiner role ────────────────────────────────────── */
static void test_psbt_combiner(void)
{
    /* Two different signers sign the same PSBT */
    dogecoin_key key1, key2;
    dogecoin_privkey_init(&key1); dogecoin_privkey_gen(&key1);
    dogecoin_privkey_init(&key2); dogecoin_privkey_gen(&key2);

    dogecoin_pubkey pub1, pub2;
    dogecoin_pubkey_init(&pub1); dogecoin_pubkey_from_key(&key1, &pub1);
    dogecoin_pubkey_init(&pub2); dogecoin_pubkey_from_key(&key2, &pub2);

    /* Build a 1-of-1 PSBT (both keys will sign independently) */
    dogecoin_tx *tx = dogecoin_tx_new();
    tx->version = 1; tx->locktime = 0;
    dogecoin_tx_in *txin = dogecoin_tx_in_new();
    memset(txin->prevout.hash, 0x22, sizeof(txin->prevout.hash));
    txin->prevout.n = 0; txin->sequence = 0xFFFFFFFF;
    if (txin->script_sig) { cstr_free(txin->script_sig, true); }
    txin->script_sig = cstr_new_sz(0);
    vector_add(tx->vin, txin);
    dogecoin_tx_out *txout = dogecoin_tx_out_new();
    txout->value = 1000000000LL;
    uint8_t dh[20]; memset(dh, 0xDD, 20);
    txout->script_pubkey = cstr_new_sz(25);
    dogecoin_script_build_p2pkh(txout->script_pubkey, dh);
    vector_add(tx->vout, txout);

    dogecoin_psbt *psbt1 = dogecoin_psbt_create(tx);
    dogecoin_psbt *psbt2 = dogecoin_psbt_create(tx);
    dogecoin_tx_free(tx);

    /* Each signer sets the UTXO (using key1's hash160, though not strictly
     * verified here — we're testing combine, not signing correctness) */
    uint8_t h1[20]; dogecoin_pubkey_get_hash160(&pub1, h1);
    dogecoin_tx *utxo = make_prev_tx(h1);
    dogecoin_psbt_input_set_utxo(psbt1, 0, utxo);
    dogecoin_psbt_input_set_utxo(psbt2, 0, utxo);
    dogecoin_tx_free(utxo);

    dogecoin_psbt_sign(psbt1, &key1);
    dogecoin_psbt_sign(psbt2, &key2);

    u_assert_int_eq((int)psbt1->inputs[0].num_partial_sigs, 1);
    u_assert_int_eq((int)psbt2->inputs[0].num_partial_sigs, 1);

    /* Combine: psbt1 absorbs psbt2's signature */
    u_assert_int_eq(dogecoin_psbt_combine(psbt1, psbt2), true);
    u_assert_int_eq((int)psbt1->inputs[0].num_partial_sigs, 2);

    /* Combining again should not add duplicates */
    u_assert_int_eq(dogecoin_psbt_combine(psbt1, psbt2), true);
    u_assert_int_eq((int)psbt1->inputs[0].num_partial_sigs, 2);

    dogecoin_psbt_free(psbt1);
    dogecoin_psbt_free(psbt2);
    dogecoin_privkey_cleanse(&key1);
    dogecoin_privkey_cleanse(&key2);
}

/* ── Test: serialize → deserialize with all fields set ──────── */
static void test_psbt_roundtrip_full(void)
{
    dogecoin_key privkey;
    dogecoin_privkey_init(&privkey); dogecoin_privkey_gen(&privkey);
    dogecoin_pubkey pubkey;
    dogecoin_pubkey_init(&pubkey); dogecoin_pubkey_from_key(&privkey, &pubkey);

    uint8_t hash160[20];
    dogecoin_pubkey_get_hash160(&pubkey, hash160);

    dogecoin_tx *tx = dogecoin_tx_new();
    tx->version = 1; tx->locktime = 0;
    dogecoin_tx_in *txin = dogecoin_tx_in_new();
    memset(txin->prevout.hash, 0x33, sizeof(txin->prevout.hash));
    txin->prevout.n = 0; txin->sequence = 0xFFFFFFFF;
    if (txin->script_sig) { cstr_free(txin->script_sig, true); }
    txin->script_sig = cstr_new_sz(0);
    vector_add(tx->vin, txin);
    dogecoin_tx_out *txout = dogecoin_tx_out_new();
    txout->value = 2000000000LL;
    uint8_t dh[20]; memset(dh, 0xEE, 20);
    txout->script_pubkey = cstr_new_sz(25);
    dogecoin_script_build_p2pkh(txout->script_pubkey, dh);
    vector_add(tx->vout, txout);

    dogecoin_psbt *psbt = dogecoin_psbt_create(tx);
    dogecoin_tx_free(tx);

    /* Set UTXO */
    dogecoin_tx *utxo = make_prev_tx(hash160);
    dogecoin_psbt_input_set_utxo(psbt, 0, utxo);
    dogecoin_tx_free(utxo);

    /* Set sighash */
    dogecoin_psbt_input_set_sighash(psbt, 0, SIGHASH_ALL);

    /* Add keypath */
    uint32_t path[2] = { 0x80000000, 0x00000000 };
    dogecoin_psbt_input_add_keypath(psbt, 0, pubkey.pubkey, 33, 0x12345678, path, 2);

    /* Sign */
    dogecoin_psbt_sign(psbt, &privkey);
    u_assert_int_eq((int)psbt->inputs[0].num_partial_sigs, 1);

    /* Serialize, deserialize, re-serialize — byte equality */
    cstring *raw1 = dogecoin_psbt_serialize(psbt);
    dogecoin_psbt *decoded = NULL;
    u_assert_int_eq(dogecoin_psbt_deserialize(
        (const uint8_t *)raw1->str, raw1->len, &decoded), true);
    u_assert_not_null(decoded);

    /* Verify fields survived round-trip */
    u_assert_not_null(decoded->inputs[0].non_witness_utxo);
    u_assert_int_eq(decoded->inputs[0].has_sighash_type, true);
    u_assert_int_eq((int)decoded->inputs[0].sighash_type, SIGHASH_ALL);
    u_assert_int_eq((int)decoded->inputs[0].num_keypaths, 1);
    u_assert_int_eq((int)decoded->inputs[0].keypaths[0].fingerprint, 0x12345678);
    u_assert_int_eq((int)decoded->inputs[0].num_partial_sigs, 1);

    cstring *raw2 = dogecoin_psbt_serialize(decoded);
    u_assert_int_eq(raw1->len, raw2->len);
    u_assert_int_eq(memcmp(raw1->str, raw2->str, raw1->len), 0);

    /* Finalize and extract on the decoded copy */
    u_assert_int_eq(dogecoin_psbt_finalize(decoded), true);
    dogecoin_tx *signed_tx = dogecoin_psbt_extract(decoded);
    u_assert_not_null(signed_tx);
    dogecoin_tx_in *sin = vector_idx(signed_tx->vin, 0);
    u_assert_int_eq(((int)sin->script_sig->len) > 0, 1);

    dogecoin_tx_free(signed_tx);
    cstr_free(raw1, true);
    cstr_free(raw2, true);
    dogecoin_psbt_free(psbt);
    dogecoin_psbt_free(decoded);
    dogecoin_privkey_cleanse(&privkey);
}

/* ── Test: invalid inputs rejected ─────────────────────────── */
static void test_psbt_invalid(void)
{
    /* NULL / garbage data */
    dogecoin_psbt *out = NULL;
    u_assert_int_eq(dogecoin_psbt_deserialize(NULL, 0, &out), false);
    u_assert_int_eq(dogecoin_psbt_deserialize((const uint8_t *)"garbage", 7, &out), false);
    u_assert_is_null(out);

    /* Wrong magic */
    uint8_t bad[6] = { 'b', 'a', 'd', '!', 0xff, 0x00 };
    u_assert_int_eq(dogecoin_psbt_deserialize(bad, sizeof(bad), &out), false);

    /* Extractor requires finalized PSBT */
    dogecoin_tx *tx = make_unsigned_tx();
    dogecoin_psbt *psbt = dogecoin_psbt_create(tx);
    dogecoin_tx_free(tx);
    u_assert_is_null(dogecoin_psbt_extract(psbt)); /* not finalized */
    dogecoin_psbt_free(psbt);
}

/* ── Test: BIP174 invalid vectors ────────────────────────────── */
/*
 * Each of these hex blobs is listed as INVALID in the BIP174 spec.
 * https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#test-vector-1
 * dogecoin_psbt_deserialize must reject all of them.
 */
static void test_psbt_bip174_invalid_vectors(void)
{
    static const struct { const char *desc; const char *hex; } cases[] = {
        /* Raw network tx — wrong magic, not a PSBT at all */
        { "raw network tx",
          "0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6"
          "000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a"
          "9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd"
          "95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce3"
          "1feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652"
          "088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1"
          "300" },
        /* PSBT with 2-output tx but no per-output maps (truncated) */
        { "missing per-output maps",
          "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64"
          "641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2"
          "868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24"
          "d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371b"
          "bba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012"
          "039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bb"
          "b2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34"
          "bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38"
          "978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587"
          "0247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a"
          "240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c0121"
          "03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045"
          "022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d0220"
          "67338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b7"
          "2beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000" },
        /* Non-empty scriptSig in the unsigned tx — BIP174 creator rule violation */
        { "non-empty scriptSig in unsigned tx",
          "70736274ff0100fd0a010200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf15"
          "3821a8139f877a5b7be4000000006a47304402204759661797c01b036b25928948686218347"
          "d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866"
          "d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca"
          "682dc86e2d73fa88292feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821"
          "a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cb"
          "e81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b"
          "9ee0efe9fa039cca459788ac00000000000001012000e1f5050000000017a9143545e6e33b"
          "832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01"
          "fb82308000000" },
        /* Global map missing the unsigned tx key entirely */
        { "missing unsigned tx",
          "70736274ff000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c946"
          "3afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349"
          "eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a48"
          "90b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2"
          "eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c"
          "00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22"
          "e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314"
          "e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a99"
          "6372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd9"
          "61d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb"
          "1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778ef"
          "ecd61fcac6f79a4ea169393380734464f84f2ab30000000000" },
        /* Duplicate non-witness UTXO key (type 0x00) in input map */
        { "duplicate non-witness UTXO key",
          "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64"
          "641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2"
          "868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24"
          "d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371b"
          "bba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012"
          "039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bb"
          "b2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34"
          "bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38"
          "978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587"
          "0247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a"
          "240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c0121"
          "03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045"
          "022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d0220"
          "67338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b7"
          "2beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000001003f"
          "0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
          "0000000000ffffffff010000000000000000036a010000000000000000" },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        dogecoin_psbt *psbt = NULL;
        dogecoin_bool ok = dogecoin_psbt_from_hex(cases[i].hex, &psbt);
        u_assert_int_eq(ok, false);
        u_assert_is_null(psbt);
    }
}

/* ── Test: BIP174 valid vectors ──────────────────────────────── */
/*
 * Real hex blobs from the BIP174 spec.
 * https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#test-vector-1
 */
static void test_psbt_bip174_valid_vectors(void)
{
    dogecoin_psbt *psbt;

    /* Creator: 2-in 2-out unsigned PSBT, all per-input/output maps empty.
     * Round-trips to byte-identical hex since there is no witness data. */
    {
        static const char hex[] =
            "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c875792"
            "4f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c0"
            "71b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2"
            "b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876"
            "a588df5546e8742d1d87008f000000000000000000";
        psbt = NULL;
        u_assert_int_eq(dogecoin_psbt_from_hex(hex, &psbt), true);
        u_assert_not_null(psbt);
        u_assert_int_eq((int)psbt->num_inputs,  2);
        u_assert_int_eq((int)psbt->num_outputs, 2);
        u_assert_int_eq(psbt->version, PSBT_VERSION_0);
        u_assert_is_null(psbt->inputs[0].non_witness_utxo);
        u_assert_is_null(psbt->inputs[1].non_witness_utxo);
        /* Re-serialised bytes must be identical to the spec hex */
        char *reshex = dogecoin_psbt_to_hex(psbt);
        u_assert_str_eq(reshex, hex);
        dogecoin_free(reshex);
        dogecoin_psbt_free(psbt);
    }

    /* Valid v1: 1 P2PKH input with non_witness_utxo, 2 empty outputs */
    {
        static const char hex[] =
            "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad6"
            "4641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5ba"
            "c2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050"
            "f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0"
            "371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a"
            "9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b"
            "4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c435594"
            "3abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c"
            "62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a"
            "6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229"
            "f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02"
            "db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f"
            "210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309f"
            "fb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2"
            "592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab"
            "300000000000000";
        psbt = NULL;
        u_assert_int_eq(dogecoin_psbt_from_hex(hex, &psbt), true);
        u_assert_not_null(psbt);
        u_assert_int_eq((int)psbt->num_inputs,  1);
        u_assert_int_eq((int)psbt->num_outputs, 2);
        u_assert_not_null(psbt->inputs[0].non_witness_utxo);
        /* previous tx has 2 outputs */
        u_assert_int_eq((int)psbt->inputs[0].non_witness_utxo->vout->len, 2);
        u_assert_int_eq(psbt->inputs[0].has_sighash_type, false);
        u_assert_int_eq((int)psbt->inputs[0].num_partial_sigs, 0);
        dogecoin_psbt_free(psbt);
    }

    /* Valid v3: same layout as v1 but the input map carries SIGHASH_ALL */
    {
        static const char hex[] =
            "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad6"
            "4641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5ba"
            "c2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050"
            "f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0"
            "371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a"
            "9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b"
            "4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c435594"
            "3abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c"
            "62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a"
            "6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229"
            "f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02"
            "db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f"
            "210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309f"
            "fb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2"
            "592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab"
            "30000000001030401000000000000";
        psbt = NULL;
        u_assert_int_eq(dogecoin_psbt_from_hex(hex, &psbt), true);
        u_assert_not_null(psbt);
        u_assert_int_eq((int)psbt->num_inputs,  1);
        u_assert_int_eq((int)psbt->num_outputs, 2);
        u_assert_not_null(psbt->inputs[0].non_witness_utxo);
        u_assert_int_eq(psbt->inputs[0].has_sighash_type, true);
        u_assert_int_eq((int)psbt->inputs[0].sighash_type, SIGHASH_ALL);
        dogecoin_psbt_free(psbt);
    }

    /* Valid v7: unknown input fields are preserved across round-trip */
    {
        static const char hex[] =
            "70736274ff01003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffff"
            "ffffffffffffffff0000000000ffffffff010000000000000000036a010000000000000a"
            "f00102030405060708090f0102030405060708090a0b0c0d0e0f0000";
        psbt = NULL;
        u_assert_int_eq(dogecoin_psbt_from_hex(hex, &psbt), true);
        u_assert_not_null(psbt);
        u_assert_int_eq((int)psbt->num_inputs,  1);
        u_assert_int_eq((int)psbt->num_outputs, 1);
        u_assert_int_eq((int)psbt->inputs[0].num_unknowns, 1);
        u_assert_int_eq((int)psbt->inputs[0].unknowns[0].key_len,   10);
        u_assert_int_eq((int)psbt->inputs[0].unknowns[0].value_len, 15);
        /* Re-serialised bytes must be identical — unknown fields round-trip */
        char *reshex = dogecoin_psbt_to_hex(psbt);
        u_assert_str_eq(reshex, hex);
        dogecoin_free(reshex);
        dogecoin_psbt_free(psbt);
    }

}

/* ── Entry point ────────────────────────────────────────────── */
void test_psbt(void)
{
    test_psbt_lifecycle();
    test_psbt_creator();
    test_psbt_serialization();
    test_psbt_base64();
    test_psbt_hex();
    test_psbt_updater();
    test_psbt_sign_finalize_extract();
    test_psbt_combiner();
    test_psbt_roundtrip_full();
    test_psbt_invalid();
    test_psbt_bip174_invalid_vectors();
    test_psbt_bip174_valid_vectors();
}
