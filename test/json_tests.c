/**********************************************************************
 * Copyright (c) 2022 raffecat                                        *
 * Copyright (c) 2022 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "utest.h"

#include <dogecoin/dogecoin.h>
#include <dogecoin/json_out.h>
#include <dogecoin/tx.h>
#include <dogecoin/cstr.h>
#include <dogecoin/utils.h>

void test_json_out() {

    // test fixtures.
    const char* raw_txn_hex = "0100000001e298a076ea26489c4ea60b34cb79a386a16aeef17cd646e9bdc3e4486b4abadf0100000068453042021e623cf9ebc2e2736343827c2dda22a85c41347d5fe17e4a1dfa57ebb3eb0e022075baa343944021a24a8a99c5a90b3af2fd47b92bd1e1fe0f7dc1a5cb95086df0012102ac1447c59fd7b96cee31e4a22ec051cf393d76bc3f275bcd5aa7580377d32e14feffffff02208d360b890000001976a914a4a942c99c94522a025b2b8cfd2edd149fb4995488ac00c2eb0b000000001976a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac96fe3700";
    const char* expect_json = "{\"txid\":\"746007aed61e8531faba1af6610f10a5422c70a2a7eb6ffb51cb7a7b7b5e45b4\",\"hash\":\"746007aed61e8531faba1af6610f10a5422c70a2a7eb6ffb51cb7a7b7b5e45b4\",\"size\":223,\"vsize\":223,\"version\":1,\"locktime\":3669654,\"vin\":[{\"txid\":\"e298a076ea26489c4ea60b34cb79a386a16aeef17cd646e9bdc3e4486b4abadf\",\"vout\":1,\"scriptSig\":{\"asm\":\"3042021e623cf9ebc2e2736343827c2dda22a85c41347d5fe17e4a1dfa57ebb33042021e623cf9ebc2e2736343827c2dda22a85c41347d5fe17e4a1dfa57ebb33042021e62 02ac1447c59fd7b96cee31e4a22ec051cf393d76bc3f275bcd5aa7580377d32e02\",\"hex\":\"453042021e623cf9ebc2e2736343827c2dda22a85c41347d5fe17e4a1dfa57eb453042021e623cf9ebc2e2736343827c2dda22a85c41347d5fe17e4a1dfa57eb453042021e623cf9ebc2e2736343827c2dda22a85c41347d5fe17e4a1dfa57eb453042021e623cf9\"},\"sequence\":4294967294}],\"vout\":[{\"value\":5885.98644000,\"koinu\":588598644000,\"n\":0,\"scriptPubKey\":{\"asm\":\"OP_DUP OP_HASH160 a4a942c99c94522a025b2b8cfd2edd149fb49954 OP_EQUALVERIFY OP_CHECKSIG\",\"hex\":\"76a914a4a942c99c94522a025b2b8cfd2edd149fb4995488ac\"}},{\"value\":2.00000000,\"koinu\":200000000,\"n\":1,\"scriptPubKey\":{\"asm\":\"OP_DUP OP_HASH160 d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c OP_EQUALVERIFY OP_CHECKSIG\",\"hex\":\"76a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac\"}}]}";

    // convert hex to byte array.
    uint8_t* raw_txn = dogecoin_malloc(strlen(raw_txn_hex) / 2 + 1);
    size_t txn_len = 0;
    utils_hex_to_bin(raw_txn_hex, raw_txn, strlen(raw_txn_hex), &txn_len);

    // deserialize the transaction bytes.
    dogecoin_tx* tx = dogecoin_tx_new();
    if (!dogecoin_tx_deserialize(raw_txn, txn_len, tx, NULL)) {
        u_failed("invalid tx hex");
        return;
    }

    // output the transaction as JSON.
    doge_stream s = doge_stream_new_membuf(0); // doge_stream_indent
    doge_txn_to_json(&s, tx);
    cstring* tx_json = doge_stream_to_cstring(&s);

    // printf("JSON: %s", tx_json->str);
    u_assert_str_eq(tx_json->str, expect_json);

    // free data
    cstr_free(tx_json, true);
    doge_stream_free(&s);
    dogecoin_free(raw_txn);
    dogecoin_tx_free(tx);
}
