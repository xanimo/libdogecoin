/*
 * Copyright (c) 2024 The Dogecoin Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>

#include <dogecoin/sweep.h>
#include <dogecoin/bip38.h>
#include <dogecoin/base58.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/key.h>
#include <dogecoin/address.h>
#include <dogecoin/utils.h>
#include <dogecoin/mem.h>
#include <dogecoin/constants.h>
#include <dogecoin/ecc.h>
#include <dogecoin/transaction.h>

#include <test/utest.h>

static void sweep_test_cleanup_transactions(void)
{
    remove_all();
}

typedef struct bip38_test_vector_ {
    const char* passphrase;
    const char* encrypted;
    const char* wif;
    const char* hex;
    dogecoin_bool compressed;
} bip38_test_vector;

/* BIP-0038 non-EC vectors (algorithm check; private key bytes are valid on Dogecoin). */
static const bip38_test_vector BIP38_NON_EC_VECTORS[] = {
    {
        "TestingOneTwoThree",
        "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
        "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR",
        "CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
        false
    },
    {
        "Satoshi",
        "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
        "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5",
        "09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
        false
    },
    {
        "TestingOneTwoThree",
        "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
        "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP",
        "CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
        true
    },
    {
        "Satoshi",
        "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
        "KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7",
        "09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
        true
    }
};

/* BIP-0038 EC-multiplied vectors (algorithm check; privkey bytes are chain-agnostic). */
static const bip38_test_vector BIP38_EC_VECTORS[] = {
    {
        "TestingOneTwoThree",
        "6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
        NULL,
        "A43A940577F4E97F5C4D39EB14FF083A98187C64EA7C99EF7CE460833959A519",
        false
    },
    {
        "Satoshi",
        "6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
        NULL,
        "C2C8036DF268F498099350718C4A3EF3984D2BE84618C2650F5171DCC5EB660A",
        false
    }
};

/* Test official BIP38 vectors (non-EC multiplied). */
static void test_bip38_reference_vectors(void)
{
    printf("Testing BIP38 reference vectors (non-EC multiplied)...\n");

    size_t i;
    for (i = 0; i < sizeof(BIP38_NON_EC_VECTORS) / sizeof(BIP38_NON_EC_VECTORS[0]); i++) {
        const bip38_test_vector* v = &BIP38_NON_EC_VECTORS[i];
        uint8_t expected_priv[DOGECOIN_ECKEY_PKEY_LENGTH];
        size_t hexlen = strlen(v->hex);
        size_t outl = sizeof(expected_priv);
        utils_hex_to_bin(v->hex, expected_priv, hexlen, &outl);
        u_assert_uint64_eq((uint64_t)outl, (uint64_t)DOGECOIN_ECKEY_PKEY_LENGTH);

        u_assert_true(dogecoin_bip38_is_valid(v->encrypted));

        uint8_t decrypted_key[DOGECOIN_ECKEY_PKEY_LENGTH];
        dogecoin_bool compressed = false;
        dogecoin_bool ok = dogecoin_bip38_decrypt_ex(
            v->encrypted, v->passphrase, BIP38_ADDRESS_MATCH_INTEROP, decrypted_key, &compressed);
        u_assert_true(ok);
        u_assert_int_eq((int)compressed, (int)v->compressed);
        u_assert_mem_eq(decrypted_key, expected_priv, DOGECOIN_ECKEY_PKEY_LENGTH);
    }

    printf("  BIP38 reference vector tests passed\n");
}

static void test_bip38_ec_reference_vectors(void)
{
    printf("Testing BIP38 reference vectors (EC multiplied)...\n");

    size_t i;
    for (i = 0; i < sizeof(BIP38_EC_VECTORS) / sizeof(BIP38_EC_VECTORS[0]); i++) {
        const bip38_test_vector* v = &BIP38_EC_VECTORS[i];
        uint8_t expected_priv[DOGECOIN_ECKEY_PKEY_LENGTH];
        size_t hexlen = strlen(v->hex);
        size_t outl = sizeof(expected_priv);
        utils_hex_to_bin(v->hex, expected_priv, hexlen, &outl);
        u_assert_uint64_eq((uint64_t)outl, (uint64_t)DOGECOIN_ECKEY_PKEY_LENGTH);

        u_assert_true(dogecoin_bip38_is_valid(v->encrypted));
        u_assert_true(dogecoin_bip38_is_ec_multiplied(v->encrypted));

        uint8_t decrypted_key[DOGECOIN_ECKEY_PKEY_LENGTH];
        dogecoin_bool compressed = false;
        u_assert_true(dogecoin_bip38_decrypt_ex(
            v->encrypted, v->passphrase, BIP38_ADDRESS_MATCH_INTEROP, decrypted_key, &compressed));
        u_assert_int_eq((int)compressed, (int)v->compressed);
        u_assert_mem_eq(decrypted_key, expected_priv, DOGECOIN_ECKEY_PKEY_LENGTH);
    }

    printf("  BIP38 EC reference vector tests passed\n");
}

static void test_bip38_ec_intermediate_encrypt_roundtrip(void)
{
    printf("Testing BIP38 EC intermediate + encrypt roundtrip...\n");

    const char* passphrase = "TestingOneTwoThree";
    const char* expected_intermediate =
        "passphrasepxFy57B9v8HtUsszJYKReoNDV6VHjUSGt8EVJmux9n1J3Ltf1gRxyDGXqnf9qm";
    uint8_t decoded[128];
    uint8_t ownerentropy[8];
    char intermediate[BIP38_INTERMEDIATE_CODE_MAXLEN];
    char encrypted[BIP38_ENCRYPTED_KEY_LENGTH + 1];
    size_t intermediate_sz;
    size_t encrypted_sz;
    size_t declen;

    declen = dogecoin_base58_decode_check(expected_intermediate, decoded, sizeof(decoded));
    u_assert_uint64_eq((uint64_t)declen, (uint64_t)(BIP38_INTERMEDIATE_PAYLOAD_LEN + 4));
    memcpy(ownerentropy, decoded + 8, 8);

    intermediate_sz = sizeof(intermediate);
    u_assert_true(dogecoin_bip38_generate_intermediate_code(
        passphrase, false, 0, 0, ownerentropy, intermediate, &intermediate_sz));
    u_assert_str_eq(expected_intermediate, intermediate);
    u_assert_true(dogecoin_bip38_is_intermediate_code(intermediate));

    encrypted_sz = sizeof(encrypted);
    u_assert_true(dogecoin_bip38_encrypt_from_intermediate(
        intermediate, false, NULL, NULL, NULL, encrypted, &encrypted_sz, NULL, NULL));
    u_assert_true(dogecoin_bip38_is_ec_multiplied(encrypted));

    uint8_t priv[DOGECOIN_ECKEY_PKEY_LENGTH];
    dogecoin_bool compressed = true;
    u_assert_true(dogecoin_bip38_decrypt_ex(encrypted, passphrase, BIP38_ADDRESS_MATCH_INTEROP, priv, &compressed));
    u_assert_int_eq((int)compressed, 0);
    u_assert_true(dogecoin_ecc_verify_privatekey(priv));
    dogecoin_mem_zero(priv, sizeof(priv));

    printf("  BIP38 EC intermediate + encrypt roundtrip tests passed\n");
}

static void test_bip38_ec_lot_sequence_vectors(void)
{
    printf("Testing BIP38 EC lot/sequence vectors...\n");

    const char* passphrase = "MOLON LABE";
    const char* encrypted =
        "6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j";
    const char* confirmation =
        "cfrm38V8aXBn7JWA1ESmFMUn6erxeBGZGAxJPY4e36S9QWkzZKtaVqLNMgnifETYw7BPwWC9aPD";
    const char* expected_hex =
        "44EA95AFBF138356A05EA32110DFD627232D0F2991AD221187BE356F19FA8190";
    const char* expected_address = "1Jscj8ALrYu2y9TD8NrpvDBugPedmbj4Yh";

    uint8_t expected_priv[DOGECOIN_ECKEY_PKEY_LENGTH];
    size_t hexlen = strlen(expected_hex);
    size_t outl = sizeof(expected_priv);
    utils_hex_to_bin(expected_hex, expected_priv, hexlen, &outl);

    u_assert_true(dogecoin_bip38_is_valid(encrypted));
    u_assert_true(dogecoin_bip38_is_ec_multiplied(encrypted));
    u_assert_true(dogecoin_bip38_has_lot_sequence(encrypted));

    uint8_t decrypted_key[DOGECOIN_ECKEY_PKEY_LENGTH];
    dogecoin_bool compressed = true;
    uint32_t lot = 0;
    uint32_t sequence = 0;
    u_assert_true(dogecoin_bip38_decrypt_with_lot_sequence_ex(
        encrypted, passphrase, BIP38_ADDRESS_MATCH_INTEROP,
        decrypted_key, &compressed, &lot, &sequence));
    u_assert_int_eq((int)compressed, 0);
    u_assert_uint32_eq(lot, 263183U);
    u_assert_uint32_eq(sequence, 1U);
    u_assert_mem_eq(decrypted_key, expected_priv, DOGECOIN_ECKEY_PKEY_LENGTH);

    char confirmed_address[P2PKHLEN];
    dogecoin_bool confirm_compressed = true;
    uint32_t confirm_lot = 0;
    uint32_t confirm_seq = 0;
    u_assert_true(dogecoin_bip38_confirm_passphrase_ex(
        passphrase,
        confirmation,
        BIP38_ADDRESS_MATCH_INTEROP,
        confirmed_address,
        sizeof(confirmed_address),
        &confirm_compressed,
        &confirm_lot,
        &confirm_seq));
    u_assert_str_eq(expected_address, confirmed_address);
    u_assert_int_eq((int)confirm_compressed, 0);
    u_assert_uint32_eq(confirm_lot, 263183U);
    u_assert_uint32_eq(confirm_seq, 1U);

    char enc2[BIP38_ENCRYPTED_KEY_LENGTH + 1];
    size_t enc2_sz = sizeof(enc2);
    uint8_t gen_priv[DOGECOIN_ECKEY_PKEY_LENGTH];
    u_assert_true(dogecoin_bip38_encrypt_ec_multiplied(
        passphrase,
        false,
        true,
        263183U,
        1U,
        expected_address,
        gen_priv,
        enc2,
        &enc2_sz,
        NULL,
        NULL));
    u_assert_true(dogecoin_bip38_decrypt_with_lot_sequence_ex(
        enc2, passphrase, BIP38_ADDRESS_MATCH_INTEROP,
        decrypted_key, &compressed, &lot, &sequence));

    dogecoin_mem_zero(decrypted_key, sizeof(decrypted_key));
    printf("  BIP38 EC lot/sequence vector tests passed\n");
}

static void test_bip38_ec_lot_sequence_greek_vector(void)
{
    printf("Testing BIP38 EC lot/sequence (Greek passphrase vector)...\n");

    /* BIP-0038 test vector: Greek uppercase ΜΟΛΩΝ ΛΑΒΕ (UTF-8). */
    const char* passphrase = "\xCE\x9C\xCE\x9F\xCE\x9B\xCE\xA9\xCE\x9D \xCE\x9B\xCE\x91\xCE\x92\xCE\x95";
    const char* encrypted =
        "6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH";
    const char* confirmation =
        "cfrm38V8G4qq2ywYEFfWLD5Cc6msj9UwsG2Mj4Z6QdGJAFQpdatZLavkgRd1i4iBMdRngDqDs51";
    const char* expected_hex =
        "CA2759AA4ADB0F96C414F36ABEB8DB59342985BE9FA50FAAC228C8E7D90E3006";

    uint8_t expected_priv[DOGECOIN_ECKEY_PKEY_LENGTH];
    size_t hexlen = strlen(expected_hex);
    size_t outl = sizeof(expected_priv);
    utils_hex_to_bin(expected_hex, expected_priv, hexlen, &outl);

    uint8_t decrypted_key[DOGECOIN_ECKEY_PKEY_LENGTH];
    dogecoin_bool compressed = true;
    uint32_t lot = 0;
    uint32_t sequence = 0;
    u_assert_true(dogecoin_bip38_decrypt_with_lot_sequence_ex(
        encrypted, passphrase, BIP38_ADDRESS_MATCH_INTEROP,
        decrypted_key, &compressed, &lot, &sequence));
    u_assert_int_eq((int)compressed, 0);
    u_assert_uint32_eq(lot, 806938U);
    u_assert_uint32_eq(sequence, 1U);
    u_assert_mem_eq(decrypted_key, expected_priv, DOGECOIN_ECKEY_PKEY_LENGTH);

    char confirmed_address[P2PKHLEN];
    u_assert_true(dogecoin_bip38_confirm_passphrase_ex(
        passphrase, confirmation, BIP38_ADDRESS_MATCH_INTEROP,
        confirmed_address, sizeof(confirmed_address), NULL, &lot, &sequence));
    u_assert_uint32_eq(lot, 806938U);
    u_assert_uint32_eq(sequence, 1U);
    u_assert_true(dogecoin_bip38_is_confirmation_code(confirmation));

    dogecoin_mem_zero(decrypted_key, sizeof(decrypted_key));
    printf("  BIP38 EC Greek lot/sequence vector tests passed\n");
}

static void test_bip38_nfc_passphrase_vector(void)
{
    printf("Testing BIP38 NFC passphrase vector...\n");

    /* Decomposed UTF-8 input (includes embedded NUL); scrypt uses NFC per BIP-0038. */
    static const uint8_t decomposed_passphrase[] = {
        0xCF, 0x92, 0xCC, 0x81, 0x00, 0xF0, 0x90, 0x90, 0x80, 0xF0, 0x9F, 0x92, 0xA9
    };
    const char* encrypted = "6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn";
    const char* expected_address = "16ktGzmfrurhbhi6JGqsMWf7TyqK9HNAeF";

    uint8_t decrypted_key[DOGECOIN_ECKEY_PKEY_LENGTH];
    dogecoin_bool compressed = true;
    u_assert_true(dogecoin_bip38_decrypt_passphrase_ex(
        encrypted,
        decomposed_passphrase,
        sizeof(decomposed_passphrase),
        BIP38_ADDRESS_MATCH_INTEROP,
        decrypted_key,
        &compressed));
    u_assert_int_eq((int)compressed, 0);
    u_assert_true(dogecoin_bip38_verify_address_hash(encrypted, expected_address));

    /* Roundtrip: encrypt_passphrase + decrypt_passphrase with same byte sequence. */
    dogecoin_key nfc_key;
    dogecoin_privkey_init(&nfc_key);
    u_assert_true(dogecoin_privkey_gen(&nfc_key));
    char nfc_addr[P2PKHLEN];
    dogecoin_pubkey nfc_pub;
    dogecoin_pubkey_init(&nfc_pub);
    dogecoin_pubkey_from_key(&nfc_key, &nfc_pub);
    u_assert_true(dogecoin_pubkey_getaddr_p2pkh(&nfc_pub, &dogecoin_chainparams_main, nfc_addr));

    char enc_rt[BIP38_ENCRYPTED_KEY_LENGTH + 1];
    size_t enc_rt_sz = sizeof(enc_rt);
    u_assert_true(dogecoin_bip38_encrypt_passphrase(
        nfc_key.privkey,
        decomposed_passphrase,
        sizeof(decomposed_passphrase),
        nfc_addr,
        true,
        enc_rt,
        &enc_rt_sz));
    u_assert_true(dogecoin_bip38_decrypt_passphrase(
        enc_rt, decomposed_passphrase, sizeof(decomposed_passphrase), decrypted_key, &compressed));
    u_assert_true(compressed);
    u_assert_mem_eq(nfc_key.privkey, decrypted_key, DOGECOIN_ECKEY_PKEY_LENGTH);

    dogecoin_privkey_cleanse(&nfc_key);
    dogecoin_pubkey_cleanse(&nfc_pub);
    dogecoin_mem_zero(decrypted_key, sizeof(decrypted_key));
    printf("  BIP38 NFC passphrase vector tests passed\n");
}

/* Test paper wallet creation and validation */
static void test_paper_wallet_creation(void)
{
    printf("Testing paper wallet creation...\n");

    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    dogecoin_paper_wallet* wallet1 = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet1);

    dogecoin_key gen_wif_key;
    dogecoin_privkey_init(&gen_wif_key);
    u_assert_true(dogecoin_privkey_gen(&gen_wif_key));
    char test_wif[PRIVKEYWIFLEN];
    size_t wif_sz = sizeof(test_wif);
    dogecoin_privkey_encode_wif(&gen_wif_key, chain, test_wif, &wif_sz);
    dogecoin_privkey_cleanse(&gen_wif_key);

    dogecoin_bool result = dogecoin_paper_wallet_set_wif(wallet1, test_wif, chain);
    u_assert_true(result);

    char address[P2PKHLEN];
    result = dogecoin_paper_wallet_get_address(wallet1, address, sizeof(address));
    u_assert_true(result);
    printf("  WIF Address: %s\n", address);

    u_assert_true(dogecoin_paper_wallet_is_valid(wallet1));

    dogecoin_paper_wallet_free(wallet1);

    dogecoin_paper_wallet* wallet2 = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet2);

    const char* test_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    result = dogecoin_paper_wallet_set_hex(wallet2, test_hex, chain);
    u_assert_true(result);

    result = dogecoin_paper_wallet_get_address(wallet2, address, sizeof(address));
    u_assert_true(result);
    printf("  Hex Address: %s\n", address);

    u_assert_true(dogecoin_paper_wallet_is_valid(wallet2));

    dogecoin_paper_wallet_free(wallet2);

    sweep_test_cleanup_transactions();
    printf("  Paper wallet creation tests passed\n");
}

/* Test BIP38 encryption/decryption */
static void test_bip38_encryption(void)
{
    printf("Testing BIP38 encryption/decryption...\n");

    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    dogecoin_key key;
    dogecoin_privkey_gen(&key);

    dogecoin_pubkey pubkey;
    dogecoin_pubkey_from_key(&key, &pubkey);

    char address[P2PKHLEN];
    dogecoin_pubkey_getaddr_p2pkh(&pubkey, chain, address);
    printf("  Test address: %s\n", address);

    char encrypted_key[BIP38_ENCRYPTED_KEY_LENGTH + 1];
    size_t encrypted_size = sizeof(encrypted_key);
    const char* passphrase = "test_passphrase_123";

    dogecoin_bool result = dogecoin_bip38_encrypt(
        key.privkey,
        passphrase,
        address,
        true,
        encrypted_key,
        &encrypted_size
    );
    u_assert_true(result);
    printf("  Encrypted key: %s\n", encrypted_key);

    result = dogecoin_bip38_is_valid(encrypted_key);
    u_assert_true(result);

    uint8_t decrypted_key[DOGECOIN_ECKEY_PKEY_LENGTH];
    dogecoin_bool compressed;
    result = dogecoin_bip38_decrypt(encrypted_key, passphrase, decrypted_key, &compressed);
    u_assert_true(result);
    u_assert_true(compressed);

    u_assert_mem_eq(key.privkey, decrypted_key, DOGECOIN_ECKEY_PKEY_LENGTH);

    dogecoin_paper_wallet* wallet = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet);

    result = dogecoin_paper_wallet_set_encrypted(wallet, encrypted_key, passphrase, chain);
    u_assert_true(result);

    char wallet_address[P2PKHLEN];
    result = dogecoin_paper_wallet_get_address(wallet, wallet_address, sizeof(wallet_address));
    u_assert_true(result);
    u_assert_str_eq(address, wallet_address);

    u_assert_true(dogecoin_paper_wallet_is_valid(wallet));

    dogecoin_paper_wallet_free(wallet);

    printf("  BIP38 encryption/decryption tests passed\n");
}

/* Test sweep options */
static void test_sweep_options(void)
{
    printf("Testing sweep options...\n");

    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    dogecoin_sweep_options* options = dogecoin_sweep_options_new(chain);
    u_assert_not_null(options);

    const char* dest_address = "D7Y55vD8nNtW7VnT9Xr6Qc4vB8hN3jK2mP";
    dogecoin_bool result = dogecoin_sweep_options_set_destination(options, dest_address);
    u_assert_true(result);
    u_assert_str_eq(options->destination_address, dest_address);

    result = dogecoin_sweep_options_set_fee(options, 2000, 1000, 5000);
    u_assert_true(result);
    u_assert_uint64_eq(options->fee_per_byte, 2000ULL);
    u_assert_uint64_eq(options->min_fee, 1000ULL);
    u_assert_uint64_eq(options->max_fee, 5000ULL);

    dogecoin_sweep_options_set_rbf(options, true);
    u_assert_true(options->use_rbf);

    dogecoin_sweep_options_set_locktime(options, 1234567890);
    u_assert_uint32_eq(options->locktime, 1234567890U);

    dogecoin_sweep_options_free(options);

    printf("  Sweep options tests passed\n");
}

/* Test sweep result */
static void test_sweep_result(void)
{
    printf("Testing sweep result...\n");

    dogecoin_sweep_result* result = dogecoin_sweep_result_new();
    u_assert_not_null(result);

    u_assert_int_eq((int)result->success, 0);
    u_assert_is_null(result->error_message);
    u_assert_is_null(result->transaction_hex);
    u_assert_is_null(result->transaction_id);
    u_assert_uint64_eq(result->amount_swept, 0ULL);
    u_assert_uint64_eq(result->fee_paid, 0ULL);
    u_assert_is_null(result->destination_address);

    u_assert_is_null(dogecoin_sweep_result_get_error(result));
    u_assert_is_null(dogecoin_sweep_result_get_transaction_hex(result));
    u_assert_is_null(dogecoin_sweep_result_get_transaction_id(result));
    u_assert_uint64_eq(dogecoin_sweep_result_get_amount_swept(result), 0ULL);
    u_assert_uint64_eq(dogecoin_sweep_result_get_fee_paid(result), 0ULL);
    u_assert_is_null(dogecoin_sweep_result_get_destination_address(result));

    dogecoin_sweep_result_free(result);

    printf("  Sweep result tests passed\n");
}

/* Test paper wallet private key extraction */
static void test_paper_wallet_private_key_extraction(void)
{
    printf("Testing paper wallet private key extraction...\n");

    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    dogecoin_paper_wallet* wallet1 = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet1);

    dogecoin_key wkey;
    dogecoin_privkey_init(&wkey);
    u_assert_true(dogecoin_privkey_gen(&wkey));
    char test_wif[PRIVKEYWIFLEN];
    size_t wif_sz = sizeof(test_wif);
    dogecoin_privkey_encode_wif(&wkey, chain, test_wif, &wif_sz);
    dogecoin_privkey_cleanse(&wkey);

    dogecoin_bool result = dogecoin_paper_wallet_set_wif(wallet1, test_wif, chain);
    u_assert_true(result);

    char extracted_wif[PRIVKEYWIFLEN];
    result = dogecoin_paper_wallet_get_wif(wallet1, extracted_wif, sizeof(extracted_wif));
    u_assert_true(result);
    u_assert_str_eq(test_wif, extracted_wif);

    uint8_t private_key[DOGECOIN_ECKEY_PKEY_LENGTH];
    result = dogecoin_paper_wallet_get_private_key(wallet1, private_key);
    u_assert_true(result);

    dogecoin_paper_wallet_free(wallet1);

    dogecoin_paper_wallet* wallet2 = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet2);

    const char* test_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    result = dogecoin_paper_wallet_set_hex(wallet2, test_hex, chain);
    u_assert_true(result);

    result = dogecoin_paper_wallet_get_private_key(wallet2, private_key);
    u_assert_true(result);

    char hex_out[65];
    utils_bin_to_hex(private_key, DOGECOIN_ECKEY_PKEY_LENGTH, hex_out);
    u_assert_str_eq(test_hex, hex_out);

    dogecoin_paper_wallet_free(wallet2);

    printf("  Paper wallet private key extraction tests passed\n");
}

/* Re-set on one wallet object must not leak the prior address buffer. */
static void test_paper_wallet_reuse(void)
{
    printf("Testing paper wallet set_* reuse...\n");
    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    dogecoin_paper_wallet* wallet = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet);

    dogecoin_key wkey;
    dogecoin_privkey_init(&wkey);
    u_assert_true(dogecoin_privkey_gen(&wkey));
    char test_wif[PRIVKEYWIFLEN];
    size_t wif_sz = sizeof(test_wif);
    dogecoin_privkey_encode_wif(&wkey, chain, test_wif, &wif_sz);
    dogecoin_privkey_cleanse(&wkey);

    u_assert_true(dogecoin_paper_wallet_set_wif(wallet, test_wif, chain));
    char addr1[P2PKHLEN];
    u_assert_true(dogecoin_paper_wallet_get_address(wallet, addr1, sizeof(addr1)));

    const char* test_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    u_assert_true(dogecoin_paper_wallet_set_hex(wallet, test_hex, chain));
    char addr2[P2PKHLEN];
    u_assert_true(dogecoin_paper_wallet_get_address(wallet, addr2, sizeof(addr2)));
    u_assert_true(strcmp(addr1, addr2) != 0);

    uint8_t priv[DOGECOIN_ECKEY_PKEY_LENGTH];
    u_assert_true(dogecoin_paper_wallet_get_private_key(wallet, priv));
    char hex_out[65];
    utils_bin_to_hex(priv, DOGECOIN_ECKEY_PKEY_LENGTH, hex_out);
    u_assert_str_eq(test_hex, hex_out);
    dogecoin_mem_zero(priv, sizeof(priv));

    dogecoin_paper_wallet_free(wallet);
    printf("  Paper wallet reuse tests passed\n");
}

static void test_bip38_confirm_interop_testnet(void)
{
    printf("Testing BIP38 INTEROP confirm (testnet address hash)...\n");

    const char* passphrase = "interop_testnet_confirm";
    char encrypted[BIP38_ENCRYPTED_KEY_LENGTH + 1];
    size_t enc_sz = sizeof(encrypted);
    char confirmation[BIP38_CONFIRMATION_CODE_MAXLEN];
    size_t confirm_sz = sizeof(confirmation);
    uint8_t gen_priv[DOGECOIN_ECKEY_PKEY_LENGTH];

    u_assert_true(dogecoin_bip38_encrypt_ec_multiplied(
        passphrase,
        true,
        false,
        0,
        0,
        "nConfirmInteropHint",
        gen_priv,
        encrypted,
        &enc_sz,
        confirmation,
        &confirm_sz));

    char confirmed_address[P2PKHLEN];
    u_assert_true(dogecoin_bip38_confirm_passphrase_ex(
        passphrase,
        confirmation,
        BIP38_ADDRESS_MATCH_INTEROP,
        confirmed_address,
        sizeof(confirmed_address),
        NULL,
        NULL,
        NULL));
    u_assert_true(confirmed_address[0] == 'n' || confirmed_address[0] == 'm');

    dogecoin_mem_zero(gen_priv, sizeof(gen_priv));
    printf("  BIP38 INTEROP confirm testnet tests passed\n");
}

/* Test BIP38 validation */
static void test_bip38_validation(void)
{
    printf("Testing BIP38 validation...\n");

    u_assert_int_eq((int)dogecoin_bip38_is_valid(NULL), 0);
    u_assert_int_eq((int)dogecoin_bip38_is_valid(""), 0);
    u_assert_int_eq((int)dogecoin_bip38_is_valid("invalid"), 0);
    u_assert_int_eq((int)dogecoin_bip38_is_valid("1234567890123456789012345678901234567890123456789012345678901234567890"), 0);

    u_assert_true(dogecoin_bip38_is_valid(
        "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg"));

    {
        const char* valid = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg";
        /* decode_check requires data[] length >= strlen(base58); payload is 39 bytes + 4 checksum. */
        uint8_t payload[128];
        char bad[BIP38_ENCRYPTED_KEY_LENGTH + 1];
        size_t declen = dogecoin_base58_decode_check(valid, payload, sizeof(payload));
        u_assert_uint64_eq((uint64_t)declen, 39u + 4u);
        payload[2] = 0xFF;
        u_assert_true(dogecoin_base58_encode_check(payload, 39, bad, sizeof(bad)) != 0);
        u_assert_int_eq((int)dogecoin_bip38_is_valid(bad), 0);
        {
            uint8_t hash_out[4];
            uint8_t flag_out = 0;
            u_assert_int_eq((int)dogecoin_bip38_get_address_hash(bad, hash_out), 0);
            u_assert_int_eq((int)dogecoin_bip38_get_flag_byte(bad, &flag_out), 0);
        }
    }

    printf("  BIP38 validation tests passed\n");
}

static void test_bip38_negative_cases(void)
{
    printf("Testing BIP38 negative cases...\n");

    /* Non-EC and EC keys reject a wrong passphrase via address-hash check. */
    const char* non_ec_encrypted = BIP38_NON_EC_VECTORS[0].encrypted;
    const char* ec_encrypted = BIP38_EC_VECTORS[0].encrypted;
    uint8_t priv[DOGECOIN_ECKEY_PKEY_LENGTH];
    dogecoin_bool compressed = false;

    u_assert_int_eq(
        (int)dogecoin_bip38_decrypt_ex(
            non_ec_encrypted, "wrong passphrase", BIP38_ADDRESS_MATCH_INTEROP, priv, &compressed),
        0);
    u_assert_int_eq(
        (int)dogecoin_bip38_decrypt_ex(
            ec_encrypted, "wrong passphrase", BIP38_ADDRESS_MATCH_INTEROP, priv, &compressed),
        0);

    {
        char addr[P2PKHLEN];
        memset(addr, 0, sizeof(addr));
        u_assert_int_eq(
            (int)dogecoin_bip38_confirm_passphrase_ex(
                "wrong passphrase",
                "cfrm38V8aXBn7JWA1ESmFMUn6erxeBGZGAxJPY4e36S9QWkzZKtaVqLNMgnifETYw7BPwWC9aPD",
                BIP38_ADDRESS_MATCH_INTEROP,
                addr,
                sizeof(addr),
                NULL,
                NULL,
                NULL),
            0);
    }

    {
        uint32_t lot = 0;
        uint32_t sequence = 0;
        dogecoin_bip38_generate_lot_sequence(&lot, &sequence);
        u_assert_true(lot >= 1 && lot <= 1048575U);
        u_assert_true(sequence <= 4095U);
    }

    printf("  BIP38 negative tests passed\n");
}

/* Test sweep functionality (basic WIF + UTXO setup; signing is covered by transaction tests). */
static void test_sweep_functionality(void)
{
    printf("Testing sweep functionality...\n");
    sweep_test_cleanup_transactions();

    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    dogecoin_paper_wallet* wallet = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet);

    dogecoin_key sw_key;
    dogecoin_privkey_init(&sw_key);
    u_assert_true(dogecoin_privkey_gen(&sw_key));
    char test_wif[PRIVKEYWIFLEN];
    size_t wif_sz = sizeof(test_wif);
    dogecoin_privkey_encode_wif(&sw_key, chain, test_wif, &wif_sz);
    dogecoin_privkey_cleanse(&sw_key);

    dogecoin_bool result = dogecoin_paper_wallet_set_wif(wallet, test_wif, chain);
    u_assert_true(result);

    dogecoin_sweep_options* options = dogecoin_sweep_options_new(chain);
    u_assert_not_null(options);

    const char* dest_address = "DHprgyNMcy3Ct9zVbJCrezYywxTBDWPL3v";
    result = dogecoin_sweep_options_set_destination(options, dest_address);
    u_assert_true(result);

    result = dogecoin_sweep_options_set_utxo(
        options,
        "b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074",
        1,
        "12.0");
    u_assert_true(result);

    /* Exercise the actual sweep pipeline: build -> sign -> validate. */
    dogecoin_transaction* tx = dogecoin_sweep_create_transaction(wallet, options);
    u_assert_not_null(tx);

    u_assert_true(dogecoin_sweep_sign_transaction(tx, wallet));
    u_assert_true(dogecoin_sweep_validate_transaction(tx, wallet, options));

    uint64_t in_count = 0;
    uint64_t out_count = 0;
    uint64_t in_value = 0;
    uint64_t out_value = 0;
    uint64_t fee_value = 0;
    u_assert_true(dogecoin_sweep_get_stats(
        tx, options, &in_count, &out_count, &in_value, &out_value, &fee_value));
    u_assert_uint64_eq(in_count, 1ULL);
    u_assert_uint64_eq(out_count, 1ULL);
    u_assert_uint64_eq(in_value, 1200000000ULL);
    u_assert_true(fee_value > 0);
    u_assert_uint64_eq(in_value, out_value + fee_value);
    dogecoin_tx_free(tx);

    sweep_test_cleanup_transactions();

    dogecoin_sweep_result* sweep = dogecoin_sweep_paper_wallet(wallet, options);
    u_assert_not_null(sweep);
    u_assert_true(sweep->success);
    u_assert_not_null(sweep->transaction_hex);
    u_assert_not_null(sweep->transaction_id);
    u_assert_true(strlen(sweep->transaction_hex) > 0);
    u_assert_true(strlen(sweep->transaction_id) == 64);
    dogecoin_sweep_result_free(sweep);

    dogecoin_sweep_options_free(options);
    dogecoin_paper_wallet_free(wallet);

    sweep_test_cleanup_transactions();
    printf("  Sweep functionality tests passed\n");
}

static void test_bip38_generate_and_sweep(void)
{
    printf("Testing BIP38 generate + sweep transaction build...\n");
    sweep_test_cleanup_transactions();

    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    dogecoin_key key;
    dogecoin_privkey_init(&key);
    dogecoin_privkey_gen(&key);

    dogecoin_pubkey pubkey;
    dogecoin_pubkey_init(&pubkey);
    dogecoin_pubkey_from_key(&key, &pubkey);

    char source_address[P2PKHLEN];
    u_assert_true(dogecoin_pubkey_getaddr_p2pkh(&pubkey, chain, source_address));

    const char* passphrase = "libdogecoin_bip38_sweep_gen_test";
    char encrypted[BIP38_ENCRYPTED_KEY_LENGTH + 1];
    size_t enc_sz = sizeof(encrypted);
    u_assert_true(dogecoin_bip38_encrypt(key.privkey, passphrase, source_address, true,
                                         encrypted, &enc_sz));
    u_assert_true(dogecoin_bip38_is_valid(encrypted));

    uint8_t roundtrip[DOGECOIN_ECKEY_PKEY_LENGTH];
    dogecoin_bool compressed = false;
    u_assert_true(dogecoin_bip38_decrypt(encrypted, passphrase, roundtrip, &compressed));
    u_assert_true(compressed);
    u_assert_mem_eq(key.privkey, roundtrip, DOGECOIN_ECKEY_PKEY_LENGTH);

    dogecoin_paper_wallet* wallet = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet);
    u_assert_true(dogecoin_paper_wallet_set_encrypted(wallet, encrypted, passphrase, chain));
    u_assert_true(dogecoin_paper_wallet_is_valid(wallet));

    dogecoin_sweep_options* options = dogecoin_sweep_options_new(chain);
    u_assert_not_null(options);
    u_assert_true(dogecoin_sweep_options_set_destination(options, "DHprgyNMcy3Ct9zVbJCrezYywxTBDWPL3v"));
    u_assert_true(dogecoin_sweep_options_set_utxo(
        options,
        "b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074",
        1,
        "12.0"));

    char wif_check[PRIVKEYWIFLEN];
    u_assert_true(dogecoin_paper_wallet_get_wif(wallet, wif_check, sizeof(wif_check)));

    dogecoin_transaction* tx = dogecoin_sweep_create_transaction(wallet, options);
    u_assert_not_null(tx);
    u_assert_true(dogecoin_sweep_sign_transaction(tx, wallet));
    u_assert_true(dogecoin_sweep_validate_transaction(tx, wallet, options));
    dogecoin_tx_free(tx);
    sweep_test_cleanup_transactions();

    dogecoin_sweep_result* sweep = dogecoin_sweep_paper_wallet(wallet, options);
    u_assert_not_null(sweep);
    u_assert_true(sweep->success);
    u_assert_not_null(sweep->transaction_hex);
    u_assert_not_null(sweep->transaction_id);
    u_assert_true(strlen(sweep->transaction_hex) > 0);
    dogecoin_sweep_result_free(sweep);

    dogecoin_sweep_options_free(options);
    dogecoin_paper_wallet_free(wallet);
    dogecoin_privkey_cleanse(&key);
    dogecoin_pubkey_cleanse(&pubkey);

    sweep_test_cleanup_transactions();
    printf("  BIP38 generate + sweep tests passed (BIP38 + wallet + options)\n");
}

static void test_multi_utxo_sweep(void)
{
    printf("Testing multi-UTXO sweep (same key)...\n");
    sweep_test_cleanup_transactions();

    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    dogecoin_paper_wallet* wallet = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet);

    dogecoin_key key;
    dogecoin_privkey_init(&key);
    u_assert_true(dogecoin_privkey_gen(&key));
    char test_wif[PRIVKEYWIFLEN];
    size_t wif_sz = sizeof(test_wif);
    dogecoin_privkey_encode_wif(&key, chain, test_wif, &wif_sz);
    dogecoin_privkey_cleanse(&key);

    u_assert_true(dogecoin_paper_wallet_set_wif(wallet, test_wif, chain));

    dogecoin_sweep_options* options = dogecoin_sweep_options_new(chain);
    u_assert_not_null(options);
    u_assert_true(dogecoin_sweep_options_set_destination(options, "DHprgyNMcy3Ct9zVbJCrezYywxTBDWPL3v"));
    u_assert_uint64_eq(dogecoin_sweep_fee_per_kb_to_per_byte(1000000ULL), 1000ULL);
    u_assert_true(dogecoin_sweep_options_set_fee(
        options, dogecoin_sweep_fee_per_kb_to_per_byte(1000000ULL), 1000, 5000000));
    u_assert_true(dogecoin_sweep_options_add_utxo(
        options,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        0,
        "50.0"));
    u_assert_true(dogecoin_sweep_options_add_utxo(
        options,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        1,
        "50.0"));
    u_assert_uint64_eq(dogecoin_sweep_options_utxo_count(options), 2ULL);

    dogecoin_sweep_result* sweep = dogecoin_sweep_paper_wallet(wallet, options);
    u_assert_not_null(sweep);
    u_assert_true(sweep->success);
    u_assert_not_null(sweep->transaction_hex);
    u_assert_true(strlen(sweep->transaction_hex) > 0);
    dogecoin_sweep_result_free(sweep);

    dogecoin_sweep_options_free(options);
    dogecoin_paper_wallet_free(wallet);

    sweep_test_cleanup_transactions();
    printf("  Multi-UTXO sweep tests passed\n");
}

/* Test error handling */
static void test_rbf_locktime_sweep(void)
{
    printf("Testing RBF + locktime sweep...\n");
    sweep_test_cleanup_transactions();

    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    dogecoin_paper_wallet* wallet = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet);

    dogecoin_key key;
    dogecoin_privkey_init(&key);
    u_assert_true(dogecoin_privkey_gen(&key));
    char test_wif[PRIVKEYWIFLEN];
    size_t wif_sz = sizeof(test_wif);
    dogecoin_privkey_encode_wif(&key, chain, test_wif, &wif_sz);
    dogecoin_privkey_cleanse(&key);

    u_assert_true(dogecoin_paper_wallet_set_wif(wallet, test_wif, chain));

    dogecoin_sweep_options* options = dogecoin_sweep_options_new(chain);
    u_assert_not_null(options);
    u_assert_true(dogecoin_sweep_options_set_destination(options, "DHprgyNMcy3Ct9zVbJCrezYywxTBDWPL3v"));
    u_assert_true(dogecoin_sweep_options_set_fee(options, 1000, 1000, 5000000));
    u_assert_true(dogecoin_sweep_options_set_utxo(
        options,
        "b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074",
        1,
        "12.0"));
    dogecoin_sweep_options_set_rbf(options, true);
    dogecoin_sweep_options_set_locktime(options, 500000U);

    dogecoin_transaction* tx = dogecoin_sweep_create_transaction(wallet, options);
    u_assert_not_null(tx);
    u_assert_uint32_eq(tx->locktime, 500000U);
    u_assert_true(dogecoin_sweep_sign_transaction(tx, wallet));
    u_assert_true(dogecoin_sweep_validate_transaction(tx, wallet, options));
    dogecoin_tx_free(tx);

    dogecoin_sweep_options_free(options);
    dogecoin_paper_wallet_free(wallet);
    sweep_test_cleanup_transactions();
    printf("  RBF + locktime sweep tests passed\n");
}

static void test_sweep_error_handling(void)
{
    printf("Testing error handling...\n");

    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    u_assert_int_eq((int)dogecoin_paper_wallet_set_wif(NULL, "test", chain), 0);
    u_assert_int_eq((int)dogecoin_paper_wallet_set_wif(dogecoin_paper_wallet_new(), NULL, chain), 0);
    u_assert_int_eq((int)dogecoin_paper_wallet_set_wif(dogecoin_paper_wallet_new(), "test", NULL), 0);

    dogecoin_paper_wallet* wallet = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet);

    u_assert_int_eq((int)dogecoin_paper_wallet_set_wif(wallet, "invalid_wif", chain), 0);
    u_assert_int_eq((int)dogecoin_paper_wallet_is_valid(wallet), 0);

    dogecoin_paper_wallet_free(wallet);

    printf("  Error handling tests passed\n");
}

void test_sweep(void)
{
    sweep_test_cleanup_transactions();
    test_paper_wallet_creation();
    test_bip38_encryption();
    test_sweep_options();
    test_sweep_result();
    test_paper_wallet_private_key_extraction();
    test_paper_wallet_reuse();
    test_bip38_validation();
    test_bip38_negative_cases();
    test_bip38_reference_vectors();
    test_bip38_ec_reference_vectors();
    test_bip38_ec_intermediate_encrypt_roundtrip();
    test_bip38_ec_lot_sequence_vectors();
    test_bip38_ec_lot_sequence_greek_vector();
    test_bip38_confirm_interop_testnet();
    test_bip38_nfc_passphrase_vector();
    test_sweep_functionality();
    test_bip38_generate_and_sweep();
    test_multi_utxo_sweep();
    test_rbf_locktime_sweep();
    test_sweep_error_handling();
}
