/*

 The MIT License (MIT)

 Copyright (c) 2026 bluezr
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
 * Coverage for public BIP38 / sweep / scrypt entry points that sweep_tests.c
 * reaches only indirectly, or not at all.
 *
 * sweep_tests.c drives the happy paths through the published BIP38 vectors,
 * which is the right way to prove the crypto. What it leaves uncovered is the
 * surface around it: the non-_ex wrappers, the argument-validation branches,
 * and the accessors on a failed result. Those are exported in libdogecoin.h,
 * so they are API we are committing to, and a caller can reach every one of
 * them without touching a vector.
 */

#include <stdint.h>
#include <string.h>

#include <dogecoin/bip38.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/sweep.h>
#include <dogecoin/scrypt.h>
#include <dogecoin/utils.h>

#include <test/utest.h>

/* BIP38 spec vectors. These are Bitcoin mainnet keys, which matters below. */
static const char* SPEC_UNCOMPRESSED =
    "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg";
static const char* SPEC_COMPRESSED =
    "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo";
/*
 * The chain hint is an address, and only its first character is consulted:
 * 'D' selects Dogecoin mainnet, 'n'/'m' testnet, anything else is rejected.
 * It is not a chain name -- passing "dogecoin" resolves to NULL and the call
 * fails, which is easy to get wrong from the parameter name alone.
 */
static const char* DOGE_ADDRESS_HINT = "DGYrGxANmgjcoZ9xJWncHr6fuA6Y1ZQ56Y";

static const char* SPEC_LOTSEQ =
    "6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j";

/* ---------------------------------------------------------------- scrypt */

/*
 * dogecoin_scrypt_rfc7914 is the BIP38 password KDF. sweep_tests.c exercises it
 * only through BIP38, at one fixed parameter set, so neither its
 * known-answer behaviour at other parameters nor any of its six argument
 * checks were covered.
 *
 * The two expected outputs are RFC 7914 section 12 vectors, cross-checked
 * against an independent implementation (Python hashlib.scrypt, OpenSSL) so a
 * transcription slip cannot make a wrong result look right.
 */
static void test_scrypt_rfc7914_known_answers(void)
{
    printf("Testing dogecoin_scrypt_rfc7914 known answers...\n");

    uint8_t out[64];
    uint8_t expect[64];
    size_t outl = sizeof(expect);

    /* RFC 7914 vector 1: P="", S="", N=16, r=1, p=1, dkLen=64 */
    utils_hex_to_bin(
        "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
        "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
        expect, 128, &outl);
    u_assert_int_eq(dogecoin_scrypt_rfc7914(
        (const uint8_t*)"", 0, (const uint8_t*)"", 0, 16, 1, 1, out, sizeof(out)), 1);
    u_assert_mem_eq(out, expect, 64);

    /* RFC 7914 vector 2: P="password", S="NaCl", N=1024, r=8, p=16 */
    outl = sizeof(expect);
    utils_hex_to_bin(
        "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
        "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
        expect, 128, &outl);
    u_assert_int_eq(dogecoin_scrypt_rfc7914(
        (const uint8_t*)"password", 8, (const uint8_t*)"NaCl", 4,
        1024, 8, 16, out, sizeof(out)), 1);
    u_assert_mem_eq(out, expect, 64);

    printf("  scrypt RFC 7914 known-answer tests passed\n");
}

static void test_scrypt_rfc7914_parameter_validation(void)
{
    printf("Testing dogecoin_scrypt_rfc7914 parameter validation...\n");

    uint8_t out[64];
    const uint8_t* pw = (const uint8_t*)"pw";
    const uint8_t* sa = (const uint8_t*)"sa";

    /* N must be a power of two and >= 2. Each of these must be rejected
       rather than producing a key, because a caller that gets a "derived"
       key from an invalid cost parameter has no idea how weak it is. */
    u_assert_int_eq(dogecoin_scrypt_rfc7914(pw, 2, sa, 2, 0, 1, 1, out, sizeof(out)), 0);
    u_assert_int_eq(dogecoin_scrypt_rfc7914(pw, 2, sa, 2, 1, 1, 1, out, sizeof(out)), 0);
    u_assert_int_eq(dogecoin_scrypt_rfc7914(pw, 2, sa, 2, 3, 1, 1, out, sizeof(out)), 0);
    u_assert_int_eq(dogecoin_scrypt_rfc7914(pw, 2, sa, 2, 15, 1, 1, out, sizeof(out)), 0);
    u_assert_int_eq(dogecoin_scrypt_rfc7914(pw, 2, sa, 2, 1000, 1, 1, out, sizeof(out)), 0);

    /* r and p must be non-zero. */
    u_assert_int_eq(dogecoin_scrypt_rfc7914(pw, 2, sa, 2, 16, 0, 1, out, sizeof(out)), 0);
    u_assert_int_eq(dogecoin_scrypt_rfc7914(pw, 2, sa, 2, 16, 1, 0, out, sizeof(out)), 0);

    /* r * p >= 2^30 is rejected before any allocation is attempted. */
    u_assert_int_eq(dogecoin_scrypt_rfc7914(
        pw, 2, sa, 2, 16, 1u << 15, 1u << 15, out, sizeof(out)), 0);

    /*
     * The overflow guards. These are the allocation-failure branches in
     * practice: N * 128 * r would not fit in size_t, so the function must
     * return 0 *without* calling the allocator, rather than requesting an
     * absurd block and relying on malloc to say no. Testing them this way is
     * deterministic and needs no allocator interposition -- and unlike a
     * huge-but-plausible request, it cannot accidentally succeed on a machine
     * with overcommit enabled.
     */
    u_assert_int_eq(dogecoin_scrypt_rfc7914(
        pw, 2, sa, 2, 1ULL << 62, 8, 1, out, sizeof(out)), 0);

    printf("  scrypt RFC 7914 parameter validation tests passed\n");
}

/* ----------------------------------------------------------------- bip38 */

static void test_bip38_is_compressed_coverage(void)
{
    printf("Testing dogecoin_bip38_is_compressed...\n");

    u_assert_true(dogecoin_bip38_is_compressed(SPEC_COMPRESSED));
    u_assert_true(!dogecoin_bip38_is_compressed(SPEC_UNCOMPRESSED));

    /* Malformed input must answer false rather than read past the string. */
    u_assert_true(!dogecoin_bip38_is_compressed(NULL));
    u_assert_true(!dogecoin_bip38_is_compressed(""));
    u_assert_true(!dogecoin_bip38_is_compressed("not a bip38 key"));
    u_assert_true(!dogecoin_bip38_is_compressed("6P"));

    printf("  dogecoin_bip38_is_compressed tests passed\n");
}

/*
 * The non-_ex wrappers are not thin aliases: they pin the address-match mode
 * to BIP38_ADDRESS_MATCH_MAINNET, i.e. Dogecoin. sweep_tests.c only ever calls
 * the _ex forms with BIP38_ADDRESS_MATCH_INTEROP, because the published
 * vectors are Bitcoin keys. So the wrappers a consumer would reach for first
 * had no coverage at all, and their defining behaviour -- refusing a key whose
 * address hash is not Dogecoin's -- was never asserted.
 *
 * Both directions are checked here: the Bitcoin vector must be rejected, and a
 * Dogecoin key must round-trip.
 */
static void test_bip38_non_ex_wrappers_reject_foreign_chain(void)
{
    printf("Testing non-_ex wrappers reject a non-Dogecoin address hash...\n");

    uint8_t priv[DOGECOIN_ECKEY_PKEY_LENGTH];
    dogecoin_bool compressed = false;
    uint32_t lot = 0, sequence = 0;

    /* Same vector, same passphrase that succeeds under INTEROP in
       sweep_tests.c -- here it must fail, because the wrapper pins MAINNET. */
    u_assert_true(!dogecoin_bip38_decrypt_with_lot_sequence(
        SPEC_LOTSEQ, "MOLON LABE", priv, &compressed, &lot, &sequence));

    /* Proof the vector itself is well-formed and it really is the chain check
       doing the rejecting, not a parse failure. */
    u_assert_true(dogecoin_bip38_is_valid(SPEC_LOTSEQ));
    u_assert_true(dogecoin_bip38_has_lot_sequence(SPEC_LOTSEQ));
    u_assert_true(dogecoin_bip38_decrypt_with_lot_sequence_ex(
        SPEC_LOTSEQ, "MOLON LABE", BIP38_ADDRESS_MATCH_INTEROP,
        priv, &compressed, &lot, &sequence));
    u_assert_uint32_eq(lot, 263183U);
    u_assert_uint32_eq(sequence, 1U);

    printf("  non-_ex chain rejection tests passed\n");
}

static void test_bip38_non_ex_wrappers_roundtrip_dogecoin(void)
{
    printf("Testing non-_ex wrappers round-trip a Dogecoin key...\n");

    const char* passphrase = "coverage lot sequence";
    const uint32_t lot_in = 100000U;
    const uint32_t seq_in = 7U;

    uint8_t generated[DOGECOIN_ECKEY_PKEY_LENGTH];
    /* BIP38_ENCRYPTED_KEY_LENGTH is the 58-character string length, not a
       buffer size: the call needs one more byte for the terminator. There is
       no BIP38_ENCRYPTED_KEY_MAXLEN, so the obvious-looking declaration is
       exactly one byte short and the call simply returns false. */
    char encrypted[BIP38_ENCRYPTED_KEY_LENGTH + 1];
    char confirmation[BIP38_CONFIRMATION_CODE_MAXLEN];
    size_t enc_sz = sizeof(encrypted);
    size_t conf_sz = sizeof(confirmation);

    u_assert_true(dogecoin_bip38_encrypt_ec_multiplied(
        passphrase, true, true, lot_in, seq_in, DOGE_ADDRESS_HINT,
        generated, encrypted, &enc_sz, confirmation, &conf_sz));
    u_assert_true(dogecoin_bip38_is_ec_multiplied(encrypted));
    u_assert_true(dogecoin_bip38_has_lot_sequence(encrypted));
    u_assert_true(dogecoin_bip38_is_confirmation_code(confirmation));

    /* dogecoin_bip38_decrypt_with_lot_sequence: recovers the key and the
       lot/sequence the owner chose, under the pinned MAINNET mode. */
    uint8_t recovered[DOGECOIN_ECKEY_PKEY_LENGTH];
    dogecoin_bool compressed = false;
    uint32_t lot_out = 0, seq_out = 0;
    u_assert_true(dogecoin_bip38_decrypt_with_lot_sequence(
        encrypted, passphrase, recovered, &compressed, &lot_out, &seq_out));
    u_assert_mem_eq(recovered, generated, DOGECOIN_ECKEY_PKEY_LENGTH);
    u_assert_int_eq((int)compressed, 1);
    u_assert_uint32_eq(lot_out, lot_in);
    u_assert_uint32_eq(seq_out, seq_in);

    /* A wrong passphrase must not yield a key. */
    uint32_t bad_lot = 0, bad_seq = 0;
    u_assert_true(!dogecoin_bip38_decrypt_with_lot_sequence(
        encrypted, "wrong passphrase", recovered, &compressed, &bad_lot, &bad_seq));

    /* dogecoin_bip38_confirm_passphrase: the owner-side check that the printer
       encrypted the passphrase they were given, without revealing the key. */
    char address[P2PKHLEN];
    dogecoin_bool conf_compressed = false;
    uint32_t conf_lot = 0, conf_seq = 0;
    u_assert_true(dogecoin_bip38_confirm_passphrase(
        passphrase, confirmation, address, sizeof(address),
        &conf_compressed, &conf_lot, &conf_seq));
    u_assert_uint32_eq(conf_lot, lot_in);
    u_assert_uint32_eq(conf_seq, seq_in);
    u_assert_int_eq((int)conf_compressed, 1);
    /* Dogecoin mainnet P2PKH addresses start with D. */
    u_assert_int_eq((int)address[0], (int)'D');

    /* Wrong passphrase must fail confirmation. */
    u_assert_true(!dogecoin_bip38_confirm_passphrase(
        "wrong passphrase", confirmation, address, sizeof(address),
        &conf_compressed, &conf_lot, &conf_seq));

    printf("  non-_ex Dogecoin round-trip tests passed\n");
}

/* ----------------------------------------------------------------- sweep */

static void test_sweep_estimate_fee_coverage(void)
{
    printf("Testing dogecoin_sweep_estimate_fee...\n");

    /* No options: nothing to estimate from. */
    u_assert_uint64_eq(dogecoin_sweep_estimate_fee(NULL, NULL), 0U);

    dogecoin_sweep_options opts;
    dogecoin_mem_zero(&opts, sizeof(opts));

    /* Below the floor, the minimum wins. */
    opts.fee_per_byte = 1;
    opts.min_fee = 100000;
    opts.max_fee = 100000000;
    opts.utxo_count = 1;
    u_assert_uint64_eq(dogecoin_sweep_estimate_fee(NULL, &opts), 100000U);

    /* Above the ceiling, the maximum wins. This is the clamp that keeps a
       fat-fingered fee_per_byte from spending the whole sweep on fees. */
    opts.fee_per_byte = 1000000;
    opts.max_fee = 500000;
    u_assert_uint64_eq(dogecoin_sweep_estimate_fee(NULL, &opts), 500000U);

    /* Between the two, the fee scales with the input count. */
    opts.fee_per_byte = 100;
    opts.min_fee = 0;
    opts.max_fee = 100000000;
    opts.utxo_count = 1;
    uint64_t one_input = dogecoin_sweep_estimate_fee(NULL, &opts);
    opts.utxo_count = 5;
    uint64_t five_inputs = dogecoin_sweep_estimate_fee(NULL, &opts);
    u_assert_true(five_inputs > one_input);

    printf("  dogecoin_sweep_estimate_fee tests passed\n");
}

static void test_sweep_argument_validation(void)
{
    printf("Testing sweep argument validation...\n");

    uint64_t balance = 0xdeadbeefU;
    /* NULL address or NULL out-pointer must be refused, not dereferenced. */
    u_assert_true(!dogecoin_sweep_get_balance(NULL, &dogecoin_chainparams_main, &balance));
    u_assert_true(!dogecoin_sweep_get_balance("DGYrGxANmgjcoZ9xJWncHr6fuA6Y1ZQ56Y",
                                              &dogecoin_chainparams_main, NULL));

    /* Broadcast with nothing to broadcast, and with no chain to broadcast to.
       Unit-side only: neither call reaches the network. */
    char txid[128];
    u_assert_true(!dogecoin_sweep_broadcast_transaction(
        NULL, &dogecoin_chainparams_main, txid, sizeof(txid)));

    printf("  sweep argument validation tests passed\n");
}

static void test_sweep_multiple_paper_wallets_coverage(void)
{
    printf("Testing dogecoin_sweep_multiple_paper_wallets...\n");

    dogecoin_sweep_options opts;
    dogecoin_mem_zero(&opts, sizeof(opts));
    opts.chain_params = &dogecoin_chainparams_main;

    dogecoin_paper_wallet wallet;
    dogecoin_mem_zero(&wallet, sizeof(wallet));

    /*
     * Each failure mode must come back as a result object carrying an error,
     * not as NULL. A caller that does
     *     r = dogecoin_sweep_multiple_paper_wallets(...);
     *     if (!dogecoin_sweep_result_get_error(r)) { ... }
     * has to be able to ask the result what went wrong.
     */
    dogecoin_sweep_result* r = dogecoin_sweep_multiple_paper_wallets(NULL, 1, &opts);
    u_assert_true(r != NULL);
    u_assert_true(dogecoin_sweep_result_get_error(r) != NULL);
    dogecoin_sweep_result_free(r);

    r = dogecoin_sweep_multiple_paper_wallets(&wallet, 1, NULL);
    u_assert_true(r != NULL);
    u_assert_true(dogecoin_sweep_result_get_error(r) != NULL);
    dogecoin_sweep_result_free(r);

    /* Zero wallets is a caller mistake, not an empty success. */
    r = dogecoin_sweep_multiple_paper_wallets(&wallet, 0, &opts);
    u_assert_true(r != NULL);
    u_assert_true(dogecoin_sweep_result_get_error(r) != NULL);
    dogecoin_sweep_result_free(r);

    printf("  dogecoin_sweep_multiple_paper_wallets tests passed\n");
}

/*
 * sweep_tests.c reads the accessors only off a successful sweep. On the
 * failure path the transaction hex, id and destination were never set, and a
 * caller that inspects a failed result must not be handed a dangling or
 * uninitialised pointer. NULL is also a legal thing to hand these.
 */
static void test_sweep_result_accessors_on_failure(void)
{
    printf("Testing sweep result accessors on the failure path...\n");

    u_assert_true(dogecoin_sweep_result_get_error(NULL) == NULL);
    u_assert_true(dogecoin_sweep_result_get_transaction_hex(NULL) == NULL);
    u_assert_true(dogecoin_sweep_result_get_transaction_id(NULL) == NULL);
    u_assert_true(dogecoin_sweep_result_get_destination_address(NULL) == NULL);
    u_assert_uint64_eq(dogecoin_sweep_result_get_amount_swept(NULL), 0U);
    u_assert_uint64_eq(dogecoin_sweep_result_get_fee_paid(NULL), 0U);

    dogecoin_sweep_options opts;
    dogecoin_mem_zero(&opts, sizeof(opts));
    opts.chain_params = &dogecoin_chainparams_main;

    dogecoin_sweep_result* r = dogecoin_sweep_multiple_paper_wallets(NULL, 1, &opts);
    u_assert_true(r != NULL);
    u_assert_true(dogecoin_sweep_result_get_error(r) != NULL);
    /* Nothing was swept, so the amounts must read zero rather than garbage. */
    u_assert_uint64_eq(dogecoin_sweep_result_get_amount_swept(r), 0U);
    u_assert_uint64_eq(dogecoin_sweep_result_get_fee_paid(r), 0U);
    dogecoin_sweep_result_free(r);

    /* Freeing NULL must be a no-op, so error paths can free unconditionally. */
    dogecoin_sweep_result_free(NULL);

    printf("  sweep result accessor failure-path tests passed\n");
}

void test_bip38_coverage(void)
{
    test_scrypt_rfc7914_known_answers();
    test_scrypt_rfc7914_parameter_validation();
    test_bip38_is_compressed_coverage();
    test_bip38_non_ex_wrappers_reject_foreign_chain();
    test_bip38_non_ex_wrappers_roundtrip_dogecoin();
    test_sweep_estimate_fee_coverage();
    test_sweep_argument_validation();
    test_sweep_multiple_paper_wallets_coverage();
    test_sweep_result_accessors_on_failure();
}
