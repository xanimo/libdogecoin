/**********************************************************************
 * Copyright (c) 2022 bluezr                                          *
 * Copyright (c) 2022-2023 The Dogecoin Foundation                     *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. *
 **********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include <test/utest.h>

#include <dogecoin/address.h>
#include <dogecoin/buffer.h>
#include <dogecoin/key.h>
#include <dogecoin/koinu.h>
#include <dogecoin/transaction.h>
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>
#include <dogecoin/pqc_dilithium.h>
#include <dogecoin/pqc_falcon.h>
#include <dogecoin/pqc_carrier.h>
#ifdef USE_RACCOON_G
#include <dogecoin/pqc_raccoon.h>
#endif

/*
 * Transaction API tests (UTXO build/sign) plus optional Falcon-512 commit test.
 */
void test_transaction()
{
    // internal keys
    char* private_key_wif = "ci5prbqz7jXyFPVWKkHhPq4a9N8Dag3TpeRfuqqC2Nfr7gSqx1fy";
    char* public_key_hex = "031dc1e49cfa6ae15edd6fa871a91b1f768e6f6cab06bf7a87ac0d8beb9229075b";
    char* internal_p2pkh_address = "noxKJyGPugPRN4wqvrwsrtYXuQCk7yQEsy";
    char* utxo_scriptpubkey = "76a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac";

    // external keys
    char* external_p2pkh_address = "nbGfXLskPh7eM1iG5zz5EfDkkNTo9TRmde";

    // our raw hexadecimal transaction step by step
    const char* unsigned_single_utxo_hexadecimal_transaction = "0100000001746007aed61e8531faba1af6610f10a5422c70a2a7eb6ffb51cb7a7b7b5e45b40100000000ffffffff0000000000";
    const char* unsigned_double_utxo_hexadecimal_transaction = "0100000002746007aed61e8531faba1af6610f10a5422c70a2a7eb6ffb51cb7a7b7b5e45b40100000000ffffffffe216461c60c629333ac6b40d29b5b0b6d0ce241aea5903cf4329fc65dc3b11420100000000ffffffff0000000000";
    const char* unsigned_double_utxo_single_output_hexadecimal_transaction = "0100000002746007aed61e8531faba1af6610f10a5422c70a2a7eb6ffb51cb7a7b7b5e45b40100000000ffffffffe216461c60c629333ac6b40d29b5b0b6d0ce241aea5903cf4329fc65dc3b11420100000000ffffffff010065cd1d000000001976a9144da2f8202789567d402f7f717c01d98837e4325488ac00000000";
    const char* unsigned_hexadecimal_transaction = "0100000002746007aed61e8531faba1af6610f10a5422c70a2a7eb6ffb51cb7a7b7b5e45b40100000000ffffffffe216461c60c629333ac6b40d29b5b0b6d0ce241aea5903cf4329fc65dc3b11420100000000ffffffff020065cd1d000000001976a9144da2f8202789567d402f7f717c01d98837e4325488ac30b4b529000000001976a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac00000000";
    const char* expected_single_input_signed_transaction = "0100000002746007aed61e8531faba1af6610f10a5422c70a2a7eb6ffb51cb7a7b7b5e45b4010000006b48304502210090bddac300243d16dca5e38ab6c80d5848e0d710d77702223bacd6682654f6fe02201b5c2e8b1143d8a807d604dc18068b4278facce561c302b0c66a4f2a5a4aa66f0121031dc1e49cfa6ae15edd6fa871a91b1f768e6f6cab06bf7a87ac0d8beb9229075bffffffffe216461c60c629333ac6b40d29b5b0b6d0ce241aea5903cf4329fc65dc3b11420100000000ffffffff020065cd1d000000001976a9144da2f8202789567d402f7f717c01d98837e4325488ac30b4b529000000001976a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac00000000";
    const char* expected_signed_raw_hexadecimal_transaction = "0100000002746007aed61e8531faba1af6610f10a5422c70a2a7eb6ffb51cb7a7b7b5e45b4010000006b48304502210090bddac300243d16dca5e38ab6c80d5848e0d710d77702223bacd6682654f6fe02201b5c2e8b1143d8a807d604dc18068b4278facce561c302b0c66a4f2a5a4aa66f0121031dc1e49cfa6ae15edd6fa871a91b1f768e6f6cab06bf7a87ac0d8beb9229075bffffffffe216461c60c629333ac6b40d29b5b0b6d0ce241aea5903cf4329fc65dc3b1142010000006a47304402200e19c2a66846109aaae4d29376040fc4f7af1a519156fe8da543dc6f03bb50a102203a27495aba9eead2f154e44c25b52ccbbedef084f0caf1deedaca87efd77e4e70121031dc1e49cfa6ae15edd6fa871a91b1f768e6f6cab06bf7a87ac0d8beb9229075bffffffff020065cd1d000000001976a9144da2f8202789567d402f7f717c01d98837e4325488ac30b4b529000000001976a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac00000000";
    const char* expected_single_utxo_signed_transaction = "0100000001e216461c60c629333ac6b40d29b5b0b6d0ce241aea5903cf4329fc65dc3b1142010000006b483045022100e22ad3aba33c15a6f24f68c059369c9d6d4e8bc9a76af5ef589e483fa0c14ce202206cfacacf81f97766a3451df6bd073482fbeba379d441120ce3d13ee4cf154ec10121031dc1e49cfa6ae15edd6fa871a91b1f768e6f6cab06bf7a87ac0d8beb9229075bffffffff019810993b000000001976a9144da2f8202789567d402f7f717c01d98837e4325488ac00000000";

    // we will begin by deserializing the 2 raw hexadecimal transactions from dogecoin core as assigned below (raw_hexadecimal_transaction_from_tx_worth_2_dogecoin, raw_hexadecimal_transaction_from_tx_worth_10_dogecoin) which contain the utxos we intended to spend. the assertions are interspersed within each corresponding JSON response from dogecoin core to make cross referencing the validity of our assertions containing the deserialized data easier. this is intended to provide proof that the data we used to create our first valid and accepted dogecoin testnet transaction with the variables in this test is legitimate:

    char* utxo_txid_from_tx_worth_2_dogecoin = "b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074";
    const char* raw_hexadecimal_transaction_from_tx_worth_2_dogecoin = "0100000001e298a076ea26489c4ea60b34cb79a386a16aeef17cd646e9bdc3e4486b4abadf0100000068453042021e623cf9ebc2e2736343827c2dda22a85c41347d5fe17e4a1dfa57ebb3eb0e022075baa343944021a24a8a99c5a90b3af2fd47b92bd1e1fe0f7dc1a5cb95086df0012102ac1447c59fd7b96cee31e4a22ec051cf393d76bc3f275bcd5aa7580377d32e14feffffff02208d360b890000001976a914a4a942c99c94522a025b2b8cfd2edd149fb4995488ac00c2eb0b000000001976a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac96fe3700";
    int utxo_previous_output_index_from_tx_worth_2_dogecoin = 1;

    dogecoin_tx* tx_worth_2 = dogecoin_tx_new();

    uint8_t* data_bin_2 = dogecoin_malloc(strlen(raw_hexadecimal_transaction_from_tx_worth_2_dogecoin) / 2 + 1);
    size_t outlength_2 = 0;
    // convert raw_hexadecimal_transaction_from_tx_worth_2_dogecoin to byte array to dogecoin_tx and if it fails free from memory
    utils_hex_to_bin(raw_hexadecimal_transaction_from_tx_worth_2_dogecoin, data_bin_2, strlen(raw_hexadecimal_transaction_from_tx_worth_2_dogecoin), &outlength_2);

    if (!dogecoin_tx_deserialize(data_bin_2, outlength_2, tx_worth_2, NULL)) {
        // free dogecoin_tx
        printf("deserializing tx_worth_2 failed\n");
        dogecoin_tx_free(tx_worth_2);
    }
    // free byte array
    dogecoin_free(data_bin_2);

    // below is the JSON response from dogecoin cores RPC method `getrawtransaction` but by appending true to the end we receive the data in JSON format as oppose to raw hexadecimal format:

    // > dogecoin-cli getrawtransaction b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074 true
    // {
    //   "hex": "0100000001e298a076ea26489c4ea60b34cb79a386a16aeef17cd646e9bdc3e4486b4abadf0100000068453042021e623cf9ebc2e2736343827c2dda22a85c41347d5fe17e4a1dfa57ebb3eb0e022075baa343944021a24a8a99c5a90b3af2fd47b92bd1e1fe0f7dc1a5cb95086df0012102ac1447c59fd7b96cee31e4a22ec051cf393d76bc3f275bcd5aa7580377d32e14feffffff02208d360b890000001976a914a4a942c99c94522a025b2b8cfd2edd149fb4995488ac00c2eb0b000000001976a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac96fe3700",
    u_assert_str_eq("0100000001e298a076ea26489c4ea60b34cb79a386a16aeef17cd646e9bdc3e4486b4abadf0100000068453042021e623cf9ebc2e2736343827c2dda22a85c41347d5fe17e4a1dfa57ebb3eb0e022075baa343944021a24a8a99c5a90b3af2fd47b92bd1e1fe0f7dc1a5cb95086df0012102ac1447c59fd7b96cee31e4a22ec051cf393d76bc3f275bcd5aa7580377d32e14feffffff02208d360b890000001976a914a4a942c99c94522a025b2b8cfd2edd149fb4995488ac00c2eb0b000000001976a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac96fe3700", raw_hexadecimal_transaction_from_tx_worth_2_dogecoin);
    //   "txid": "b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074",
        u_assert_str_eq("b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074", utxo_txid_from_tx_worth_2_dogecoin);
    //   "hash": "b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074",
    //   "size": 223,
    //   "vsize": 223,
    //   "version": 1,
        u_assert_int_eq(1, tx_worth_2->version);
    //   "locktime": 3669654,
        u_assert_int_eq(3669654, tx_worth_2->locktime);
        dogecoin_tx_in* tx_in_2 = vector_idx(tx_worth_2->vin, 0);
    //   "vin": [
    //     {
            char* reversed_txid = utils_uint8_to_hex(tx_in_2->prevout.hash, sizeof(tx_in_2->prevout.hash));
            utils_reverse_hex(reversed_txid, 64);
    //       "txid": "dfba4a6b48e4c3bde946d67cf1ee6aa186a379cb340ba64e9c4826ea76a098e2",
            u_assert_str_eq("dfba4a6b48e4c3bde946d67cf1ee6aa186a379cb340ba64e9c4826ea76a098e2", reversed_txid);
    //       "vout": 1,
            u_assert_int_eq(1, tx_in_2->prevout.n);
    //       "scriptSig": {
    //         "asm": "3042021e623cf9ebc2e2736343827c2dda22a85c41347d5fe17e4a1dfa57ebb3eb0e022075baa343944021a24a8a99c5a90b3af2fd47b92bd1e1fe0f7dc1a5cb95086df0[ALL] 02ac1447c59fd7b96cee31e4a22ec051cf393d76bc3f275bcd5aa7580377d32e14",
    //         "hex": "453042021e623cf9ebc2e2736343827c2dda22a85c41347d5fe17e4a1dfa57ebb3eb0e022075baa343944021a24a8a99c5a90b3af2fd47b92bd1e1fe0f7dc1a5cb95086df0012102ac1447c59fd7b96cee31e4a22ec051cf393d76bc3f275bcd5aa7580377d32e14"
                u_assert_str_eq("453042021e623cf9ebc2e2736343827c2dda22a85c41347d5fe17e4a1dfa57ebb3eb0e022075baa343944021a24a8a99c5a90b3af2fd47b92bd1e1fe0f7dc1a5cb95086df0012102ac1447c59fd7b96cee31e4a22ec051cf393d76bc3f275bcd5aa7580377d32e14", utils_uint8_to_hex((const uint8_t *)tx_in_2->script_sig->str, tx_in_2->script_sig->len));
    //       },
    //       "sequence": 4294967294
            uint8_t* sequence = (uint8_t *)4294967294;
            u_assert_str_eq(utils_uint8_to_hex((const uint8_t *)&sequence, strlen((const char *)(const uint8_t *)&sequence)), utils_uint8_to_hex((const uint8_t *)&tx_in_2->sequence, strlen((const char *)(const uint8_t *)&tx_in_2->sequence)));
    //     }
    //   ],
    //   "vout": [
    //     {
    //       "value": 5885.98644000,
            dogecoin_tx_out* tx_out = vector_idx(tx_worth_2->vout, 0);
            char dogecoin[21];
            dogecoin_mem_zero(dogecoin, sizeof(dogecoin));
            koinu_to_coins_str(tx_out->value, dogecoin);
            u_assert_str_eq(dogecoin, "5885.98644000");
    //       "n": 0,
    //       "scriptPubKey": {
    //         "asm": "OP_DUP OP_HASH160 a4a942c99c94522a025b2b8cfd2edd149fb49954 OP_EQUALVERIFY OP_CHECKSIG",
    //         "hex": "76a914a4a942c99c94522a025b2b8cfd2edd149fb4995488ac",
                u_assert_str_eq("76a914a4a942c99c94522a025b2b8cfd2edd149fb4995488ac", utils_uint8_to_hex((const uint8_t *)tx_out->script_pubkey->str, tx_out->script_pubkey->len));
    //         "reqSigs": 1,
    //         "type": "pubkeyhash",
    //         "addresses": [
    //           "njCorBdd1TZxHzDGQgnRqA8UTLforArtQn"
    //         ]
    //       }
    //     },
    //     {
    //       "value": 2.00000000,
    //       "n": 1,
            tx_out = vector_idx(tx_worth_2->vout, 1);
            koinu_to_coins_str(tx_out->value, (char*)dogecoin);
            u_assert_str_eq((char*)dogecoin, "2.00000000");
    //       "scriptPubKey": {
    //         "asm": "OP_DUP OP_HASH160 d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c OP_EQUALVERIFY OP_CHECKSIG",
    //         "hex": "76a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac",
                u_assert_str_eq("76a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac", utxo_scriptpubkey);
                u_assert_str_eq("76a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac", utils_uint8_to_hex((const uint8_t *)tx_out->script_pubkey->str, tx_out->script_pubkey->len));
    //         "reqSigs": 1,
    //         "type": "pubkeyhash",
    //         "addresses": [
    //           "noxKJyGPugPRN4wqvrwsrtYXuQCk7yQEsy"
    //         ]
    //       }
    //     }
    //   ],
        dogecoin_tx_free(tx_worth_2);
    //   "blockhash": "69960ffcd0194ee7578c9ad49d89aef1eb2074bbbceb201344c386462d53344f",
    //   "confirmations": 25192,
    //   "time": 1647548015,
    //   "blocktime": 1647548015
    // }
    // ---------------------------------------------------------------- end 1st transaction data validation----------------------------------------------------------------


    char* utxo_txid_from_tx_worth_10_dogecoin = "42113bdc65fc2943cf0359ea1a24ced0b6b0b5290db4c63a3329c6601c4616e2";
    const char* raw_hexadecimal_transaction_from_tx_worth_10_dogecoin = "01000000011b557be8ca232244085641b91d6a587ebaf227d7dd1db4c578b3a3878ac2c676010000006a4730440220739ee157e98f60eda768fb473168fb6b25878572e9aaa9d2593ef1217291558e02206d0da7f862571f6826d5cacea408445b934c1191cde77c46e146ad8b867250d70121024b67a792594a459d525d50dd4d4fb21a792c0241596d522ed627cabf0ed3d4abfeffffff02600c39fab91400001976a9141476c35e582eb198e1a28c455005a70c6869586888ac00ca9a3b000000001976a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac95fe3700";
    int utxo_previous_output_index_from_tx_worth_10_dogecoin = 1;

    dogecoin_tx* tx_worth_10 = dogecoin_tx_new();
    uint8_t* data_bin_10 = dogecoin_malloc(strlen(raw_hexadecimal_transaction_from_tx_worth_10_dogecoin));
    size_t outlength_10 = 0;

    // convert incomingrawtx to byte array to dogecoin_tx and if it fails free from memory
    utils_hex_to_bin(raw_hexadecimal_transaction_from_tx_worth_10_dogecoin, data_bin_10, strlen(raw_hexadecimal_transaction_from_tx_worth_10_dogecoin), &outlength_10);
    if (!dogecoin_tx_deserialize(data_bin_10, outlength_10, tx_worth_10, NULL)) {
        // free dogecoin_tx
        dogecoin_tx_free(tx_worth_10);
    }
    // free byte array
    dogecoin_free(data_bin_10);

    // dogecoin-cli getrawtransaction 42113bdc65fc2943cf0359ea1a24ced0b6b0b5290db4c63a3329c6601c4616e2 true
    // {
    //   "hex": "01000000011b557be8ca232244085641b91d6a587ebaf227d7dd1db4c578b3a3878ac2c676010000006a4730440220739ee157e98f60eda768fb473168fb6b25878572e9aaa9d2593ef1217291558e02206d0da7f862571f6826d5cacea408445b934c1191cde77c46e146ad8b867250d70121024b67a792594a459d525d50dd4d4fb21a792c0241596d522ed627cabf0ed3d4abfeffffff02600c39fab91400001976a9141476c35e582eb198e1a28c455005a70c6869586888ac00ca9a3b000000001976a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac95fe3700",
    u_assert_str_eq("01000000011b557be8ca232244085641b91d6a587ebaf227d7dd1db4c578b3a3878ac2c676010000006a4730440220739ee157e98f60eda768fb473168fb6b25878572e9aaa9d2593ef1217291558e02206d0da7f862571f6826d5cacea408445b934c1191cde77c46e146ad8b867250d70121024b67a792594a459d525d50dd4d4fb21a792c0241596d522ed627cabf0ed3d4abfeffffff02600c39fab91400001976a9141476c35e582eb198e1a28c455005a70c6869586888ac00ca9a3b000000001976a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac95fe3700", raw_hexadecimal_transaction_from_tx_worth_10_dogecoin);
    //   "txid": "42113bdc65fc2943cf0359ea1a24ced0b6b0b5290db4c63a3329c6601c4616e2",
        u_assert_str_eq("42113bdc65fc2943cf0359ea1a24ced0b6b0b5290db4c63a3329c6601c4616e2", utxo_txid_from_tx_worth_10_dogecoin);
    //   "hash": "42113bdc65fc2943cf0359ea1a24ced0b6b0b5290db4c63a3329c6601c4616e2",
    //   "size": 225,
    //   "vsize": 225,
    //   "version": 1,
        u_assert_int_eq(1, tx_worth_10->version);
    //   "locktime": 3669653,
        u_assert_int_eq(3669653, tx_worth_10->locktime);
    //   "vin": [
        dogecoin_tx_in* tx_in_10 = vector_idx(tx_worth_10->vin, 0);
    //     {
            reversed_txid = utils_uint8_to_hex(tx_in_10->prevout.hash, sizeof(tx_in_10->prevout.hash));
            utils_reverse_hex(reversed_txid, 64);
    //       "txid": "76c6c28a87a3b378c5b41dddd727f2ba7e586a1db9415608442223cae87b551b",
            u_assert_str_eq("76c6c28a87a3b378c5b41dddd727f2ba7e586a1db9415608442223cae87b551b", reversed_txid);
    //       "vout": 1,
            u_assert_int_eq(1, tx_in_10->prevout.n);
    //       "scriptSig": {
    //         "asm": "30440220739ee157e98f60eda768fb473168fb6b25878572e9aaa9d2593ef1217291558e02206d0da7f862571f6826d5cacea408445b934c1191cde77c46e146ad8b867250d7[ALL] 024b67a792594a459d525d50dd4d4fb21a792c0241596d522ed627cabf0ed3d4ab",
    //         "hex": "4730440220739ee157e98f60eda768fb473168fb6b25878572e9aaa9d2593ef1217291558e02206d0da7f862571f6826d5cacea408445b934c1191cde77c46e146ad8b867250d70121024b67a792594a459d525d50dd4d4fb21a792c0241596d522ed627cabf0ed3d4ab"
                u_assert_str_eq("4730440220739ee157e98f60eda768fb473168fb6b25878572e9aaa9d2593ef1217291558e02206d0da7f862571f6826d5cacea408445b934c1191cde77c46e146ad8b867250d70121024b67a792594a459d525d50dd4d4fb21a792c0241596d522ed627cabf0ed3d4ab", utils_uint8_to_hex((const uint8_t *)tx_in_10->script_sig->str, tx_in_10->script_sig->len));
    //       },
    //       "sequence": 4294967294
            sequence = (uint8_t *)4294967294;
            u_assert_str_eq(utils_uint8_to_hex((const uint8_t *)&sequence, strlen((const char *)(const uint8_t *)&sequence)), utils_uint8_to_hex((const uint8_t *)&tx_in_10->sequence, strlen((const char *)(const uint8_t *)&tx_in_10->sequence)));
    //     }
    //   ],
    //   "vout": [
    //     {
    //       "value": 227889.99548000,
    //       "n": 0,
            dogecoin_tx_out* tx_out_10 = vector_idx(tx_worth_10->vout, 0);
            koinu_to_coins_str(tx_out_10->value, (char*)dogecoin);
            u_assert_str_eq((char*)dogecoin, "227889.99548000");
    //       "scriptPubKey": {
    //         "asm": "OP_DUP OP_HASH160 1476c35e582eb198e1a28c455005a70c68695868 OP_EQUALVERIFY OP_CHECKSIG",
    //         "hex": "76a9141476c35e582eb198e1a28c455005a70c6869586888ac",
                u_assert_str_eq("76a9141476c35e582eb198e1a28c455005a70c6869586888ac", utils_uint8_to_hex((const uint8_t *)tx_out_10->script_pubkey->str, tx_out_10->script_pubkey->len));
    //         "reqSigs": 1,
    //         "type": "pubkeyhash",
    //         "addresses": [
    //           "nW4N3v84cSn1eeH5mVTDeqzqrNGvTXNUb7"
    //         ]
    //       }
    //     },
    //     {
    //       "value": 10.00000000,
    //       "n": 1,
            tx_out_10 = vector_idx(tx_worth_10->vout, 1);
            koinu_to_coins_str(tx_out_10->value, (char*)dogecoin);
            u_assert_str_eq((char*)dogecoin, "10.00000000");
    //       "scriptPubKey": {
    //         "asm": "OP_DUP OP_HASH160 d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c OP_EQUALVERIFY OP_CHECKSIG",
    //         "hex": "76a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac",
                u_assert_str_eq("76a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac", utils_uint8_to_hex((const uint8_t *)tx_out_10->script_pubkey->str, tx_out_10->script_pubkey->len));
    //         "reqSigs": 1,
    //         "type": "pubkeyhash",
    //         "addresses": [
    //           "noxKJyGPugPRN4wqvrwsrtYXuQCk7yQEsy"
    //         ]
    //       }
    //     }
    //   ],
        dogecoin_tx_free(tx_worth_10);
    //   "blockhash": "69960ffcd0194ee7578c9ad49d89aef1eb2074bbbceb201344c386462d53344f",
    //   "confirmations": 25358,
    //   "time": 1647548015,
    //   "blocktime": 1647548015
    // }
    // ---------------------------------------------------------------- end 2nd transaction data validation----------------------------------------------------------------


    // -------------------------------- address validation --------------------------------

    // prove internal p2pkh was derived from private key in wif format which
    // validates libdogecoins addressing functionality as both were generated by dogecoin core:
    u_assert_int_eq(verifyPrivPubKeypair(private_key_wif, internal_p2pkh_address, true), 1);

    // prove internal p2pkh address was derived from public key hex:

    char p2pkh_pubkey_internal[P2PKHLEN];
    dogecoin_pubkey pubkeytx;
    dogecoin_pubkey_init(&pubkeytx);
    pubkeytx.compressed = true;

    // convert our public key hex to byte array:
    uint8_t* pubkeydat = utils_hex_to_uint8(public_key_hex);

    // copy byte array pubkeydat to dogecoin_pubkey.pubkey:
    memcpy(pubkeytx.pubkey, pubkeydat, strlen(public_key_hex) / 2);

    // derive p2pkh address from new injected dogecoin_pubkey with known hexadecimal public key:
    dogecoin_pubkey_getaddr_p2pkh(&pubkeytx, &dogecoin_chainparams_test, (char*)p2pkh_pubkey_internal);

    // assert the p2pkh address we just generated matches the one from dogecoin core:
    u_assert_str_eq(internal_p2pkh_address, (char*)p2pkh_pubkey_internal);

    // validate p2pkh we will send 5 dogecoin to:
    u_assert_int_eq(verifyP2pkhAddress(external_p2pkh_address, strlen(external_p2pkh_address)), 1);

    dogecoin_pubkey_cleanse(&pubkeytx);
    // -------------------------------- transaction generation & validation --------------------------------

    // ----------------------------------------------------------------
    // test building transaction with multiple inputs and signing with sign_transaction:

    // instantiate a new working_transaction object by calling start_transaction()
    // which passes back index and stores in index variable
    int working_transaction_index = start_transaction();

    // add 1st input worth 2 dogecoin:
    u_assert_int_eq(add_utxo(working_transaction_index, utxo_txid_from_tx_worth_2_dogecoin, utxo_previous_output_index_from_tx_worth_2_dogecoin), 1);

    // add 2nd input worth 10 dogecoin:
    u_assert_int_eq(add_utxo(working_transaction_index, utxo_txid_from_tx_worth_10_dogecoin, utxo_previous_output_index_from_tx_worth_10_dogecoin), 1);

    // add output to transaction which is amount and address we are sending to:
    u_assert_int_eq(add_output(working_transaction_index, external_p2pkh_address, "5"), 1);

    // confirm total output value equals total utxo input value minus transaction fee
    // validate external p2pkh address by converting script hash to p2pkh and asserting equal:
    char* raw_hexadecimal_transaction  = finalize_transaction(working_transaction_index, external_p2pkh_address, ".00226", "12.0", internal_p2pkh_address);

    u_assert_int_eq(sign_transaction(working_transaction_index, utxo_scriptpubkey, private_key_wif), 1);
    u_assert_str_eq(get_raw_transaction(working_transaction_index), expected_signed_raw_hexadecimal_transaction);

    // ----------------------------------------------------------------
    // test building transaction with single input and signing with sign_transaction:

    // instantiate a new working_transaction object by calling start_transaction()
    // which passes back index and stores in index variable
    working_transaction_index = start_transaction();

    // add 2nd input worth 10 dogecoin:
    u_assert_int_eq(add_utxo(working_transaction_index, utxo_txid_from_tx_worth_10_dogecoin, utxo_previous_output_index_from_tx_worth_10_dogecoin), 1);

    // add output to transaction which is amount and address we are sending to:
    u_assert_int_eq(add_output(working_transaction_index, external_p2pkh_address, "9.99887"), 1);

    // confirm total output value equals total utxo input value minus transaction fee
    // validate external p2pkh address by converting script hash to p2pkh and asserting equal:
    raw_hexadecimal_transaction  = finalize_transaction(working_transaction_index, external_p2pkh_address, ".00113", "10.0", internal_p2pkh_address);

    u_assert_int_eq(sign_transaction(working_transaction_index, utxo_scriptpubkey, private_key_wif), 1);
    u_assert_str_eq(get_raw_transaction(working_transaction_index), expected_single_utxo_signed_transaction);

    // ----------------------------------------------------------------
    // test store_raw_transaction:

    int working_transaction_index2 = store_raw_transaction(get_raw_transaction(working_transaction_index));
    u_assert_int_eq(working_transaction_index, working_transaction_index2 - 1);
    u_assert_str_eq(get_raw_transaction(working_transaction_index), get_raw_transaction(working_transaction_index2));

    // ----------------------------------------------------------------
    // test clear_transaction:

    clear_transaction(working_transaction_index2);
    u_assert_is_null(get_raw_transaction(working_transaction_index2));

    // ----------------------------------------------------------------
    // test building transaction and signing with sign_raw_transaction:

    // instantiate a new working_transaction object by calling start_transaction()
    // which passes back index and stores in index variable
    working_transaction_index = start_transaction();

    // add 1st input worth 2 dogecoin:
    u_assert_int_eq(add_utxo(working_transaction_index, utxo_txid_from_tx_worth_2_dogecoin, utxo_previous_output_index_from_tx_worth_2_dogecoin), 1);

    // get raw hexadecimal transaction to sign in the next steps
    raw_hexadecimal_transaction = get_raw_transaction(working_transaction_index);

    u_assert_str_eq(unsigned_single_utxo_hexadecimal_transaction, raw_hexadecimal_transaction);

    // add 2nd input worth 10 dogecoin:
    u_assert_int_eq(add_utxo(working_transaction_index, utxo_txid_from_tx_worth_10_dogecoin, utxo_previous_output_index_from_tx_worth_10_dogecoin), 1);

    raw_hexadecimal_transaction = get_raw_transaction(working_transaction_index);
    u_assert_str_eq(raw_hexadecimal_transaction, unsigned_double_utxo_hexadecimal_transaction);

    // add output to transaction which is amount and address we are sending to:
    u_assert_int_eq(add_output(working_transaction_index, external_p2pkh_address, "5"), 1);

    raw_hexadecimal_transaction = get_raw_transaction(working_transaction_index);
    u_assert_str_eq(raw_hexadecimal_transaction, unsigned_double_utxo_single_output_hexadecimal_transaction);

    // confirm total output value equals total utxo input value minus transaction fee
    // validate external p2pkh address by converting script hash to p2pkh and asserting equal:
    raw_hexadecimal_transaction = finalize_transaction(working_transaction_index, external_p2pkh_address, ".00226", "12.0", internal_p2pkh_address);

    // assert complete raw hexadecimal transaction is equal to expected unsigned_hexadecimal_transaction
    u_assert_str_eq(raw_hexadecimal_transaction, unsigned_hexadecimal_transaction);

    // sign current working transaction input index 0 of raw tx hex with script pubkey from utxo with sighash type of 1 (SIGHASH_ALL),
    // amount of 2 dogecoin represented as koinu (multiplied by 100 million) and with private key in wif format
    u_assert_int_eq(sign_raw_transaction(0, raw_hexadecimal_transaction, utxo_scriptpubkey, 1, private_key_wif), 1);

    // assert that our hexadecimal buffer (raw_hexadecimal_transaction) is equal to the expected transaction
    // with the first input signed:
    u_assert_str_eq(raw_hexadecimal_transaction, expected_single_input_signed_transaction);
    save_raw_transaction(working_transaction_index, raw_hexadecimal_transaction);
    raw_hexadecimal_transaction = get_raw_transaction(working_transaction_index);

    // sign current working transaction input index 1 of raw tx hex with script pubkey from utxo with sighash type of 1 (SIGHASH_ALL),
    // amount of 10 dogecoin represented as koinu (multiplied by 100 million) and with private key in wif format
    u_assert_int_eq(sign_raw_transaction(1, raw_hexadecimal_transaction, utxo_scriptpubkey, 1, private_key_wif), 1);
    // assert that our hexadecimal bufer (raw_hexadecimal_transaction) is equal to the expected finalized
    // transaction with both inputs signed:
    u_assert_str_eq(raw_hexadecimal_transaction, expected_signed_raw_hexadecimal_transaction);


    // ----------------------------------------------------------------
    // test building transaction and signing with sign_transaction_w_privkey:

    // instantiate a new working_transaction object by calling start_transaction()
    // which passes back index and stores in index variable
    working_transaction_index = start_transaction();

    // add 1st input worth 2 dogecoin:
    u_assert_int_eq(add_utxo(working_transaction_index, utxo_txid_from_tx_worth_2_dogecoin, utxo_previous_output_index_from_tx_worth_2_dogecoin), 1);

    // get raw hexadecimal transaction to sign in the next steps
    raw_hexadecimal_transaction = get_raw_transaction(working_transaction_index);

    u_assert_str_eq(unsigned_single_utxo_hexadecimal_transaction, raw_hexadecimal_transaction);

    // add 2nd input worth 10 dogecoin:
    u_assert_int_eq(add_utxo(working_transaction_index, utxo_txid_from_tx_worth_10_dogecoin, utxo_previous_output_index_from_tx_worth_10_dogecoin), 1);

    raw_hexadecimal_transaction = get_raw_transaction(working_transaction_index);
    u_assert_str_eq(raw_hexadecimal_transaction, unsigned_double_utxo_hexadecimal_transaction);

    // add output to transaction which is amount and address we are sending to:
    u_assert_int_eq(add_output(working_transaction_index, external_p2pkh_address, "5"), 1);

    raw_hexadecimal_transaction = get_raw_transaction(working_transaction_index);
    u_assert_str_eq(raw_hexadecimal_transaction, unsigned_double_utxo_single_output_hexadecimal_transaction);

    // confirm total output value equals total utxo input value minus transaction fee
    // validate external p2pkh address by converting script hash to p2pkh and asserting equal:
    raw_hexadecimal_transaction = finalize_transaction(working_transaction_index, external_p2pkh_address, ".00226", "12.0", internal_p2pkh_address);

    // assert complete raw hexadecimal transaction is equal to expected unsigned_hexadecimal_transaction
    u_assert_str_eq(raw_hexadecimal_transaction, unsigned_hexadecimal_transaction);

    // sign current working transaction input index 0 of raw tx hex with script pubkey from utxo with sighash type of 1 (SIGHASH_ALL),
    // amount of 2 dogecoin represented as koinu (multiplied by 100 million) and with private key in wif format
    u_assert_int_eq(sign_transaction_w_privkey(working_transaction_index, 0, private_key_wif), 1);
    raw_hexadecimal_transaction = get_raw_transaction(working_transaction_index);

    // assert that our hexadecimal buffer (raw_hexadecimal_transaction) is equal to the expected transaction
    // with the first input signed:
    u_assert_str_eq(raw_hexadecimal_transaction, expected_single_input_signed_transaction);

    // sign current working transaction input index 1 of raw tx hex with script pubkey from utxo with sighash type of 1 (SIGHASH_ALL),
    // amount of 10 dogecoin represented as koinu (multiplied by 100 million) and with private key in wif format
    u_assert_int_eq(sign_transaction_w_privkey(working_transaction_index, 1, private_key_wif), 1);
    raw_hexadecimal_transaction = get_raw_transaction(working_transaction_index);
    // assert that our hexadecimal bufer (raw_hexadecimal_transaction) is equal to the expected finalized
    // transaction with both inputs signed:
    u_assert_str_eq(raw_hexadecimal_transaction, expected_signed_raw_hexadecimal_transaction);

    // test get_raw_transaction_ex with the working transaction index
    char* buf = malloc(TXHEXMAXLEN + 1);
    u_assert_not_null(buf);
    int len = get_raw_transaction_ex(working_transaction_index, buf, TXHEXMAXLEN + 1);
    u_assert_true(len > 0);
    u_assert_str_eq(buf, get_raw_transaction(working_transaction_index));
    dogecoin_free(buf);

    // test sign_raw_transaction_ex (two-step) on the unsigned two-input TX
    size_t needed = 0;

    // query required size
    u_assert_int_eq(sign_raw_transaction_ex(0, unsigned_hexadecimal_transaction, NULL, &needed, utxo_scriptpubkey, 1, private_key_wif), 1);

    // allocate and sign
    char* out = malloc(needed);
    u_assert_not_null(out);
    u_assert_int_eq(sign_raw_transaction_ex(0, unsigned_hexadecimal_transaction, out, &needed, utxo_scriptpubkey, 1, private_key_wif), 1);

    // must match the expected single-input signed TX
    u_assert_str_eq(out, expected_single_input_signed_transaction);
    dogecoin_free(out);

    // ----------------------------------------------------------------
    // test conversion from p2pkh to script hash and back

    char* res = dogecoin_malloc(40 + 6 + 4 + 1);
    char p2pkh_address[P2PKHLEN];
    u_assert_int_eq(dogecoin_p2pkh_address_to_pubkey_hash(internal_p2pkh_address, res), 1);
    u_assert_str_eq(res, utxo_scriptpubkey);

    u_assert_true(getAddrFromPubkeyHash(res, isTestnetFromB58Prefix(internal_p2pkh_address), p2pkh_address));
    u_assert_str_eq(p2pkh_address, internal_p2pkh_address);

    u_assert_int_eq(dogecoin_p2pkh_address_to_pubkey_hash(external_p2pkh_address, res), 1);
    u_assert_str_not_eq(res, utxo_scriptpubkey);

    u_assert_true(getAddrFromPubkeyHash(res, isTestnetFromB58Prefix(external_p2pkh_address), p2pkh_address));
    u_assert_str_eq(p2pkh_address, external_p2pkh_address);
    dogecoin_free(res);

    // ----------------------------------------------------------------
    // test conversion from private key (wif) to script hash
    res = dogecoin_private_key_wif_to_pubkey_hash(private_key_wif);

    u_assert_str_eq(res, utxo_scriptpubkey);
    dogecoin_free(res);

    // ----------------------------------------------------------------
    // test remove_all - *not noticeable unless running valgrind ./tests*
    // remove working transaction object from hashmap
    remove_all();

    // ----------------------------------------------------------------
    // test chainparams wrapper functions

    // Call isTestnetFromB58Prefix
    u_assert_true(isTestnetFromB58Prefix("nhUDhr7bUum2LE2JsuZqY4iy411CQoweuD"));

    // Call isMainnetFromB58Prefix
    u_assert_true(isMainnetFromB58Prefix("D6vSSr6ftnicfpSNARqezdehAL5Abe2LQw"));

    // ----------------------------------------------------------------
    // optional Falcon-512 OP_RETURN commit test (only when built with liboqs)
#ifdef USE_LIBOQS
    uint8_t *pk = NULL, *sk = NULL, *sig = NULL;
    size_t pk_len = 0, sk_len = 0, sig_len = 0;

    // generate keypair
    u_assert_true(dogecoin_falcon512_keypair(&pk, &pk_len, &sk, &sk_len));

    // sign a simple 32-byte message (for demo; a tx sighash could also be used)
    uint8_t msg[32];
    for (int i = 0; i < 32; ++i) msg[i] = (uint8_t)i;
    u_assert_true(dogecoin_falcon512_sign(sk, sk_len, msg, sizeof msg, &sig, &sig_len));

    // verify signature
    u_assert_true(dogecoin_falcon512_verify(pk, pk_len, msg, sizeof msg, sig, sig_len));

    // compute commit = SHA256(pk||sig)
    uint8_t commit32[32];
    u_assert_true(dogecoin_falcon512_commit_bytes(pk, pk_len, sig, sig_len, commit32));

    // build a tx and add OP_RETURN commit
    dogecoin_tx* txc = dogecoin_tx_new();
    u_assert_true(dogecoin_tx_add_falcon512_commit(txc, commit32));

    uint8_t extracted[32];
    u_assert_true(dogecoin_tx_extract_falcon512_commit(txc, extracted));
    u_assert_true(memcmp(extracted, commit32, 32) == 0);

    // cleanup
    dogecoin_tx_free(txc);
    dogecoin_free(pk);
    dogecoin_free(sk);
    dogecoin_free(sig);

    // optional Dilithium2 OP_RETURN commit test
    uint8_t *dpk = NULL, *dsk = NULL, *dsig = NULL;
    size_t dpk_len = 0, dsk_len = 0, dsig_len = 0;

    u_assert_true(dogecoin_dilithium2_keypair(&dpk, &dpk_len, &dsk, &dsk_len));
    u_assert_true(dogecoin_dilithium2_sign(dsk, dsk_len, msg, sizeof msg, &dsig, &dsig_len));
    u_assert_true(dogecoin_dilithium2_verify(dpk, dpk_len, msg, sizeof msg, dsig, dsig_len));

    uint8_t dcommit32[32];
    u_assert_true(dogecoin_dilithium2_commit_bytes(dpk, dpk_len, dsig, dsig_len, dcommit32));

    dogecoin_tx* dtxc = dogecoin_tx_new();
    u_assert_true(dogecoin_tx_add_dilithium2_commit(dtxc, dcommit32));

    uint8_t dextracted[32];
    u_assert_true(dogecoin_tx_extract_dilithium2_commit(dtxc, dextracted));
    u_assert_true(memcmp(dextracted, dcommit32, 32) == 0);

    dogecoin_tx_free(dtxc);
    dogecoin_free(dpk);
    dogecoin_free(dsk);
    dogecoin_free(dsig);

#ifdef USE_RACCOON_G
    // optional Raccoon-G-44 OP_RETURN commit + HD derivation test
    uint8_t *rpk = NULL, *rsk = NULL, *rsig = NULL;
    size_t rpk_len = 0, rsk_len = 0, rsig_len = 0;

    u_assert_true(dogecoin_raccoong44_keypair(&rpk, &rpk_len, &rsk, &rsk_len));
    u_assert_true(dogecoin_raccoong44_sign(rsk, rsk_len, msg, sizeof msg, &rsig, &rsig_len));
    u_assert_true(dogecoin_raccoong44_verify(rpk, rpk_len, msg, sizeof msg, rsig, rsig_len));

    uint8_t rcommit32[32];
    u_assert_true(dogecoin_raccoong44_commit_bytes(rpk, rpk_len, rsig, rsig_len, rcommit32));

    dogecoin_tx* rtxc = dogecoin_tx_new();
    u_assert_true(dogecoin_tx_add_raccoong44_commit(rtxc, rcommit32));

    uint8_t rextracted[32];
    u_assert_true(dogecoin_tx_extract_raccoong44_commit(rtxc, rextracted));
    u_assert_true(memcmp(rextracted, rcommit32, 32) == 0);

    uint8_t hd_chaincode[DOGECOIN_PQC_RACCOON_CHAINCODE_LEN];
    memset(hd_chaincode, 0x42, sizeof(hd_chaincode));
    uint8_t *child_sk = NULL, *child_pk = NULL, *child_pubonly = NULL;
    size_t child_sk_len = 0, child_pk_len = 0, child_pubonly_len = 0;
    u_assert_true(dogecoin_raccoong44_hd_derive_priv(rsk, rsk_len, rpk, rpk_len, hd_chaincode, 7, false, &child_sk, &child_sk_len, &child_pk, &child_pk_len));
    u_assert_true(dogecoin_raccoong44_hd_derive_pub(rpk, rpk_len, hd_chaincode, 7, &child_pubonly, &child_pubonly_len));
    u_assert_true(child_pk_len == child_pubonly_len);
    u_assert_true(memcmp(child_pk, child_pubonly, child_pk_len) == 0);

    /* Sign with the derived child secret key and verify against the derived
       child public key. This is a critical regression test for the additive
       lattice HD scheme: derive_priv and derive_pub agreeing on pk_bytes is
       NOT sufficient — the matching (sk, pk) pair must also produce a sig
       that verifies. The previous (now-removed) implementation passed the
       pk-equality check while silently producing non-matching keys. */
    uint8_t *child_sig = NULL;
    size_t child_sig_len = 0;
    u_assert_true(dogecoin_raccoong44_sign(child_sk, child_sk_len, msg, sizeof msg, &child_sig, &child_sig_len));
    u_assert_true(dogecoin_raccoong44_verify(child_pk, child_pk_len, msg, sizeof msg, child_sig, child_sig_len));

    /* Key-isolation: signing with the PARENT secret must NOT verify against
       the CHILD public key, otherwise the derivation collapses domains. */
    uint8_t *parent_sig = NULL;
    size_t parent_sig_len = 0;
    u_assert_true(dogecoin_raccoong44_sign(rsk, rsk_len, msg, sizeof msg, &parent_sig, &parent_sig_len));
    u_assert_true(dogecoin_raccoong44_verify(child_pk, child_pk_len, msg, sizeof msg, parent_sig, parent_sig_len) == false);

    dogecoin_tx_free(rtxc);
    dogecoin_free(rpk);
    dogecoin_free(rsk);
    dogecoin_free(rsig);
    dogecoin_free(child_sk);
    dogecoin_free(child_pk);
    dogecoin_free(child_pubonly);
    dogecoin_free(child_sig);
    dogecoin_free(parent_sig);
#endif /* USE_RACCOON_G */

    cstring* carrier_redeem = NULL;
    cstring* carrier_spk = NULL;
    u_assert_true(dogecoin_pqc_carrier_build_redeemscript(&carrier_redeem));
    u_assert_true(dogecoin_pqc_carrier_build_p2sh_scriptpubkey(carrier_redeem, &carrier_spk));

    const uint16_t test_pk_len = 48;
    const uint16_t test_sig_len = 96;
    size_t full_len = (size_t)test_pk_len + (size_t)test_sig_len;
    uint8_t* full = dogecoin_malloc(full_len);
    for (size_t i = 0; i < full_len; i++) full[i] = (uint8_t)(i & 0xff);
    cstring* carrier_ss = NULL;
    char tag8[DOGECOIN_PQC_CARRIER_TAG_LEN] = { 'F','L','C','1','F','U','L','L' };
    u_assert_true(dogecoin_pqc_carrier_build_part_scriptsig(
        tag8, 0, 1, test_pk_len, (uint16_t)full_len, full, full_len, carrier_redeem, &carrier_ss));

    char out_tag8[9];
    uint8_t part_index = 0, part_total = 0;
    uint16_t out_pk_len = 0, out_full_len = 0;
    uint8_t* out_part = NULL;
    size_t out_part_len = 0;
    cstring* out_redeem = NULL;
    u_assert_true(dogecoin_pqc_carrier_parse_part_scriptsig(
        carrier_ss, out_tag8, &part_index, &part_total, &out_pk_len, &out_full_len, &out_part, &out_part_len, &out_redeem));
    u_assert_true(part_index == 0 && part_total == 1);
    u_assert_true(out_pk_len == test_pk_len);
    u_assert_true(out_full_len == full_len);
    u_assert_true(out_part_len == full_len);
    u_assert_true(memcmp(out_part, full, full_len) == 0);
    u_assert_true(out_redeem->len == carrier_redeem->len);
    u_assert_true(memcmp(out_redeem->str, carrier_redeem->str, carrier_redeem->len) == 0);

    dogecoin_free(out_part);
    cstr_free(out_redeem, true);
    cstr_free(carrier_ss, true);
    dogecoin_free(full);
    cstr_free(carrier_spk, true);
    cstr_free(carrier_redeem, true);
#endif
}

/*
 * Large multi-input transaction (regression for finalize/sign on ~50 vin).
 * Run as its own test so armhf/QEMU does not retain test_transaction() stack.
 */
void test_transaction_large(void)
{
    const char* private_key_wif = "ci5prbqz7jXyFPVWKkHhPq4a9N8Dag3TpeRfuqqC2Nfr7gSqx1fy";
    const char* utxo_scriptpubkey = "76a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac";
    const char* raw_hexadecimal_transaction;
    int working_transaction_index;

    working_transaction_index = start_transaction();

    // add inputs
    u_assert_int_eq(add_utxo(working_transaction_index, "00df9507524acbf5ccc1c00d152216c984192f1fc6edad81406b4371a7d91038", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "5d08f2928cefd155e377fe40a521cf66317bcde0a24c0d9094090306196dbbf8", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "9b9f872cbebff7d2242cbbde8d0fe7ca108be55bdde4a7e6905001f51bce2fc6", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "c9ef9105f0af21bef3df7affb68a8ccbf140b57bb3d880feafa98ff4a5ce7681", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "9e31e81fcb20f493affd2e3d4ec6cc7438021253b6e8869407479ed1b999ead3", 2), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "78314092f843b6b78347c87c7d43c1591586d56bfe6de800a10ed6ac600d330d", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "78cf3fc573cdd7b2226717ec697d5f9e813479194ba18aaf5ae715aa8a8d4427", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "a1cba23b31985476f25514b6593efd0fd0c625ceab071e90c3815521af385d4d", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "62fea417be4c37db98c220fe96f4753518d0422e6c6727d66162648c9c169bbd", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "d395def4e5590af657be7abc71549492e5d4f3679a60c758c20bf44c7daa5a51", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "55ea0e1b6612ae80e1b3f197dcf109e17d04bd9cd9853d4e826eac5cdd71b43a", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "9c58ce226db9e0595d49e1c1673d93a01f40afe92f6d588bc74b4a17decfe253", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "53a0bd6ea2d02d40323b6e1ea11357367a0d4632b2f8404632330e8c89c3ded6", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "d25dfc12e402124e7fe69488c9b330c6034ec7913d540b70c0539282d5000732", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "649b00be10ab02d6e884bb32946b682b03d2ed24d8c73a21a902d2c9f6731176", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "698f5b6e17a0c98266142276cfaf26776681275c9f7496a551ecfdb5dfad1960", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "15ffbba4111326cd0648c93c1b611d96a629e712e1ad849c9336bf3d99ec2767", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "27c6bd41f6146f5bfb690598e3c845603d9ada3b8ff468e8a4b4a9664b29c569", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "9ebd232f9e707ed0022a5367a519570f6df22b8e50eebc0a6874a5e4ab0ef3f2", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "d0af485f0930a91806916ee1ff815e0edf97aa4f9fda8bc6704e83dcfe00a0b4", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "da3b58e9113265ce41206181ccd7f76d1c333f702138c242e1255f6f04c4bd30", 4), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "7e026ee12f2f738242676d039222c887f6866818828567ec4a9a39ebf0e6e9a0", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "8d9c6d9be6bac379cbb05fa2fcaa37a364e3e2bd3186d5ca45f699656a0f3fbe", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "fbc24b8568e222e732e8a3573848b56a508880f4c27c67135ce9a5b814732e58", 8), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "66421a7d021930ac6ca4aa0b237736a7367a0ac5a86b62a7d1edc7a624786d2f", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "bbd247c762ecf4da6d010278afe1416efbc966af7a0d84a398d18fdd81defeb4", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "c648456de8b63927111afec155757962ee13dc569b1b441e2cd49766f27a0a11", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "f5cc0ffc8f39e6f654bf0de0c9e9d163fc49b0b57f3fc654d989bbfd99b34e09", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "d63e2e43e12fbb7d9478670e31ee66b3a4952d20e970b93cc1e3a534b7146b5d", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "a8cabbf23f3262679728c4de3774be1ee81b730fd4736b4b9c652841729b0fce", 4), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "7952236e62d381ea8f929e002d3195c202832be7017d9de69de262b03f5a97c5", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "8413920ef9835a24d2bb12c0e2d4354b432c863ad9a9a08ff5dd2762524e8f88", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "cd3dfdbd6eb1ea4dcaa1523ac50511ed8ed085595669fa9bfebe5706c95b9560", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "717010ccb3c7e2ca8114609c5a580901a1bfcaf63d56932f0f4417eacf6d6cdc", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "662368f336ecbb37758b886f431720219c3134ab00a9a4a3a3e400d8375923ba", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "5ab35e2e591de678b10df0d5ea5b64fde69351a35e0acc3597579c1966b091cc", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "7c3e156ac8abd2ba40a6123c5ca0cd06619a7bfcd19b58623a71dfde204c2eab", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "cd30ca40690d047446538a9da5336ac59b210739f99d0b3cd197f0a06cc709ea", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "ea05d48e2166cebc99b07769ee593396554f6e7fa8e82edef653d35b8e1c63c8", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "a4ac7e4a0320aae3545e73edc40871c8a103f27e93090553fd81b3d836c0f7d1", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "34e0f4b1762e258abaefe6a56d7060d6070e7ac8d229256e3890772b988c318d", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "872a896cae8669f0578f48ae5a8876923c957f35df3a5a96a4e3372498670105", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "e53023539c1be3112baba7a5ae55d5feebdd93f7131170d09346c09a46f45fc4", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "91e640201d2762b8ddd6dac653a87267c52ef2341809fa4f7b5340323a115aee", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "9a390760c8f4ed07eaf8ac75ccededd6d17784951c41579bec1a13492b300a6d", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "b2218023c6c9e6c41e017dfe63975acf95dd739a3a3ead13e58e6e9ab6bad28e", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "f9fb2f91935120241c59efb8c1d0d0f2994753520defbbde3e4c623c1d8f75d3", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "183c428655c9988cdf54613265ccbf8e0e082ae4534ce5f352e5fa9500974993", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "53484bf1dba5cd4d14512129af2c8088a2700e2d2c73431f121cb5971170b5db", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "b7674978eda56ee91f5003ae6ffbcda169cb016913c99562b32bc6ef91753998", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "21db9e7e6e2b72a972ad4a7e511ca7d3bce5f6bc043dbb05b8c03f8b4a97df37", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "c338e6dd38b40fe144c25a5c6d14c44f40611d3569e874beda608dc01ae658dd", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "b9638873605d5f4a8a1e5eea4a87ece8e6525c51816ca70d8dd8f650f359c19b", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "20875c96439f6248ed393da0b67cc62ef4bd463a0c42ced465e3c51caceee060", 0), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "5be3badc9048ffc367fc8ca485a5523b0741f8748229ad560f31f6a1f1f9705e", 1), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "ed14fd5e700619b7a64413a61cbccba4861dfe30688a7cdedb322f7e562a37ef", 1), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "4ddfffea5375a08774981c0e5fec8ffab4cc4912c0d1dc5470efb35b1f0c1be6", 1), 1);
    u_assert_int_eq(add_utxo(working_transaction_index, "ab2a5bad51b793715304ffa208ca9127d20a1f1fe7892c58cdbb6c8f2b6fc5e2", 0), 1);

    // add outputs
    u_assert_int_eq(add_output(working_transaction_index, "DGKhMhaagCrpQuzuKQoZsGYnCsw8f2DuBq", "97687.14577424"), 1);

    // finalize the transaction and verify its not null or empty
    raw_hexadecimal_transaction = finalize_transaction(working_transaction_index, "DGKhMhaagCrpQuzuKQoZsGYnCsw8f2DuBq", "0.08679272", "97687.23256696", "DMVMYSajAj7qQ7L6D81KiGxTMx8mrB9cgc");
    u_assert_not_null(raw_hexadecimal_transaction);
    u_assert_str_not_eq(raw_hexadecimal_transaction, "");

    /* Large-tx signing buffers must be heap-allocated (armhf/QEMU stack is ~8 MiB). */
    char* txhex_large = (char*)calloc(1, TXHEXMAXLEN + 1);
    char* tx_work_buf = (char*)calloc(1, TXHEXMAXLEN + 1);
    u_assert_not_null(txhex_large);
    u_assert_not_null(tx_work_buf);

    // test finalize_transaction_ex on the large transaction
    u_assert_true(finalize_transaction_ex(working_transaction_index, "DGKhMhaagCrpQuzuKQoZsGYnCsw8f2DuBq", "0.08679272", "97687.23256696", "DMVMYSajAj7qQ7L6D81KiGxTMx8mrB9cgc", txhex_large, TXHEXMAXLEN + 1) > 0);
    u_assert_str_not_eq(txhex_large, "");

    // get_raw_transaction_ex must produce identical hex
    int len2 = get_raw_transaction_ex(working_transaction_index, tx_work_buf, TXHEXMAXLEN + 1);
    u_assert_true(len2 > 0);
    u_assert_str_eq(tx_work_buf, txhex_large);

    // test sign_raw_transaction_ex on input 0 of the large transaction
    size_t need2 = 0;
    u_assert_int_eq(sign_raw_transaction_ex(0, txhex_large, NULL, &need2, utxo_scriptpubkey, 1, private_key_wif), 1);

    char* out2 = malloc(need2);
    u_assert_not_null(out2);
    u_assert_int_eq(sign_raw_transaction_ex(0, txhex_large, out2, &need2, utxo_scriptpubkey, 1, private_key_wif), 1);
    u_assert_true(strlen(out2) > 0);
    free(out2);

    // sign just vin-0 and store it
    u_assert_true(sign_indexed_raw_transaction_ex(working_transaction_index, 0, utxo_scriptpubkey, 1, private_key_wif, tx_work_buf, TXHEXMAXLEN + 1));
    u_assert_str_eq(tx_work_buf, get_raw_transaction(working_transaction_index));

    // sign all remaining inputs in one shot
    u_assert_true(sign_transaction_ex(working_transaction_index, utxo_scriptpubkey, private_key_wif, tx_work_buf, TXHEXMAXLEN + 1));
    u_assert_str_eq(tx_work_buf, get_raw_transaction(working_transaction_index));

    // convenience wrapper that does the same with just the priv-key
    u_assert_true(sign_transaction_w_privkey_ex(working_transaction_index, private_key_wif, tx_work_buf, TXHEXMAXLEN + 1));
    u_assert_str_eq(tx_work_buf, get_raw_transaction(working_transaction_index));

    free(txhex_large);
    free(tx_work_buf);
}
