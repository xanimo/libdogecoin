/*

 The MIT License (MIT)

 Copyright (c) 2016 Jonas Schnelli
 Copyright (c) 2023 bluezr
 Copyright (c) 2023 edtubbs
 Copyright (c) 2023-2024 The Dogecoin Foundation

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
#include <ctype.h>
#ifndef _MSC_VER
#include <getopt.h>
#include <unistd.h>
#else
#include <win/wingetopt.h>
#include <win/winunistd.h>
#endif

#ifdef HAVE_CONFIG_H
#  include "libdogecoin-config.h"
#endif
#include <stdbool.h>
#include <locale.h>
#include <stdio.h>   /* printf */
#include <stdlib.h>  /* atoi, malloc */
#include <string.h>  /* strcpy */
#include <wchar.h>   /* wprintf */

#include <dogecoin/uthash.h>

#include <dogecoin/address.h>
#include <dogecoin/base58.h>
#include <dogecoin/bip32.h>
#include <dogecoin/bip39.h>
#include <dogecoin/bip44.h>
#include <dogecoin/cstr.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/ecc.h>
#include <dogecoin/eckey.h>
#include <dogecoin/koinu.h>
#include <dogecoin/seal.h>
#include <dogecoin/serialize.h>
#include <dogecoin/sign.h>
#include <dogecoin/slip0039.h>
#include <dogecoin/script.h>
#include <dogecoin/tool.h>
#include <dogecoin/transaction.h>
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>
#include <dogecoin/wow.h>
#include <dogecoin/pqc_dilithium.h>
#include <dogecoin/pqc_falcon.h>
#include <dogecoin/pqc_carrier.h>
#ifdef USE_RACCOON_G
#include <dogecoin/pqc_raccoon.h>
#endif
#ifdef USE_ZK_CARRIER
#include <dogecoin/zk_carrier.h>
#endif

#define SUCH_ADDRESS_MAX_LEN 128
static const char* SUCH_MULTISIG_REDEEM_SCRIPT_LABEL = "multisig redeem script: %s\n";
static const char* SUCH_MULTISIG_P2SH_ADDRESS_LABEL = "multisig p2sh address: %s\n";

// ******************************** SUCH -C TRANSACTION MENU ********************************
#include <dogecoin/threadsafe.h>
#ifdef WITH_NET
#include <dogecoin/net.h>
void broadcasting_menu(int txindex, int is_testnet) {
    int running = 1;
    int selected = -1;
    const dogecoin_chainparams* chain = is_testnet ? &dogecoin_chainparams_test : &dogecoin_chainparams_main;
    working_transaction* tx = cli_find_transaction(txindex);
    char* raw_hexadecimal_tx = cli_get_raw_transaction(txindex);
    while (running) {
        int length = cli_get_transaction_count();
        printf("length: %d\n", length);
        for (int i = 0; i < length; i++) {
            printf("\n--------------------------------\n");
            printf("transaction to broadcast: %s\n", raw_hexadecimal_tx);
            selected == i ? printf("confirm:         [X]\n") : 0;

            if (selected == i) {
                printf("\n\n");
                printf("please confirm this is the transaction you want to send:\n");
                printf("1. yes\n");
                printf("2. no\n");
                switch (atoi(getl("\ncommand"))) {
                        case 1: {
                            size_t rht_hex_len = raw_hexadecimal_tx ? strspn(raw_hexadecimal_tx, VALID_HEX_CHARS) : 0;
                            if (raw_hexadecimal_tx == NULL || rht_hex_len == 0 || (rht_hex_len % 2) != 0 || raw_hexadecimal_tx[rht_hex_len] != '\0' || rht_hex_len > DOGECOIN_MAX_TX_HEX_LEN - 1) {
                                printf("Transaction is invalid or too large.\n");
                                break;
                                }
                            uint8_t* data_bin = dogecoin_malloc(rht_hex_len / 2 + 1);
                            size_t outlen = 0;
                            utils_hex_to_bin(raw_hexadecimal_tx, data_bin, rht_hex_len, &outlen);

                            /* Deserializing the transaction and broadcasting it to the network. */
                            if (dogecoin_tx_deserialize(data_bin, outlen, tx->transaction, NULL)) {
                                broadcast_tx(chain, tx->transaction, 0, 10, 15, 0);
                                }
                            else {
                                printf("Transaction is invalid\n");
                                }
                            dogecoin_free(data_bin);
                            selected = -1; // set selected to number out of bounds for i
                            i = length; // reset loop to start
                            break;
                        }
                        case 2: {
                            selected = -1; // set selected to number out of bounds for i
                            i = length; // reset loop to start
                            break;
                        }
                    }
                }
            // if on last iteration, jump into switch case pausing loop
            // execution so user has ability to reset loop index in order
            // to target desired input to edit. otherwise set loop index to
            // length thus finishing final iteration and set running to 0 to
            // escape encompassing while loop so we return to previous menu
            if (i == length) {
                printf("\n\n");
                printf("1. broadcast transaction\n");
                printf("2. main menu\n");
                switch (atoi(getl("\ncommand"))) {
                        case 1:
                            // tx_input submenu

                            selected = i;
                            i = i - i - 1;
                            break;
                        case 2:
                            i = length;
                            running = 0;
                            break;
                    }
                }
            }
        }
    }
#endif

// keeping is_testnet for integration with validation functions
// can remove #pragma once that's completed
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
void signing_menu(int txindex, int is_testnet) {
#pragma GCC diagnostic pop
    int running = 1;
    int input_to_sign;
    char* raw_hexadecimal_tx;
    char* private_key_wif;
    char redeem_script_hex[1200]; /* large enough for up to 15-of-15 multisig */
    while (running) {
        printf("\n 1. sign input (from current working transaction)\n");
        printf(" 2. sign input (raw hexadecimal transaction)\n");
        printf(" 3. print signed transaction\n");
        printf(" 4. go back\n\n");
        int choice = atoi(getl("command"));
        switch (choice) {
                case 1:
                case 2: {
                    input_to_sign = atoi(getl("input to sign")); // 0
                    private_key_wif = (char*)get_private_key("private_key"); // ci5prbqz7jXyFPVWKkHhPq4a9N8Dag3TpeRfuqqC2Nfr7gSqx1fy

                    /* Optionally prompt for a P2SH multisig redeem script hex.
                     * Leave blank to fall back to single-key P2PKH (the
                     * traditional behavior). */
                    snprintf(redeem_script_hex, sizeof(redeem_script_hex), "%s",
                             getl("redeem script hex (blank for single-key P2PKH)"));

                    if (choice == 1) {
                        raw_hexadecimal_tx = cli_get_raw_transaction(txindex);
                    } else {
                        raw_hexadecimal_tx = (char*)get_raw_tx("raw transaction");
                    }

                    int ok = 0;
                    if (redeem_script_hex[0] != '\0') {
                        /* P2SH multisig: sign_indexed_raw_transaction_ex updates
                         * the in-memory tx_in's scriptSig (OP_0 <sig...> <redeem>).
                         * Pass a buffer big enough to hold a fully-signed tx hex
                         * back. */
                        char signed_buf[TXHEXMAXLEN + 1];
                        snprintf(signed_buf, sizeof(signed_buf), "%s", raw_hexadecimal_tx);
                        ok = sign_indexed_raw_transaction_ex(txindex, input_to_sign,
                                                             redeem_script_hex,
                                                             1 /* SIGHASH_ALL */,
                                                             private_key_wif,
                                                             signed_buf, sizeof(signed_buf));
                        if (ok) {
                            printf("signed tx hex: %s\n", signed_buf);
                        }
                    } else {
                        char* script_pubkey = dogecoin_private_key_wif_to_pubkey_hash(private_key_wif);
                        // 76a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac
                        ok = sign_indexed_raw_transaction(txindex, input_to_sign,
                                                          raw_hexadecimal_tx, script_pubkey,
                                                          1, private_key_wif);
                    }

                    if (!ok) {
                        printf("signing indexed raw transaction failed!\n");
                    } else {
                        printf("transaction input successfully signed!\n");
                    }
                    break;
                }
                case 3:
                    printf("raw_tx: %s\n", cli_get_raw_transaction(txindex));
                    break;
                case 4:
                    running = 0;
                    break;
        }
    }
}

static void print_multisig_info(const dogecoin_chainparams* chain, const char* pubkey_list, unsigned int required_signatures)
{
    if (!pubkey_list || strlen(pubkey_list) == 0) {
        printf("Error: Missing public keys (comma-separated compressed pubkeys)\n");
        return;
    }
    if (required_signatures == 0) {
        printf("Error: Missing required signatures\n");
        return;
    }

    char* pubkeys_input_copy = dogecoin_char_vla(strlen(pubkey_list) + 1);
    memcpy_safe(pubkeys_input_copy, pubkey_list, strlen(pubkey_list) + 1);

    /* 16 is the consensus/script limit enforced by dogecoin_script_build_multisig */
    vector_t* pubkeys = vector_new(16, dogecoin_free);
    char* token = strtok(pubkeys_input_copy, ",");
    while (token) {
        while (*token == ' ')
            token++;
        if (strlen(token) != 66) {
            printf("Error: Public keys must be compressed hex (66 chars each)\n");
            vector_free(pubkeys, true);
            free(pubkeys_input_copy);
            return;
        }

        dogecoin_pubkey* pk = dogecoin_malloc(sizeof(*pk));
        dogecoin_pubkey_init(pk);
        pk->compressed = 1;

        size_t outlen = 0;
        utils_hex_to_bin(token, pk->pubkey, strlen(token), &outlen);
        if (outlen != 33 || !dogecoin_pubkey_is_valid(pk)) {
            printf("Error: Invalid compressed public key in list\n");
            dogecoin_free(pk);
            vector_free(pubkeys, true);
            free(pubkeys_input_copy);
            return;
        }
        vector_add(pubkeys, pk);
        token = strtok(NULL, ",");
    }

    cstring* redeem_script = cstr_new_sz(550); /* max ~547 bytes for 16 compressed pubkeys */
    if (!dogecoin_script_build_multisig(redeem_script, required_signatures, pubkeys)) {
        printf("Error: Failed to build multisig redeem script\n");
        cstr_free(redeem_script, true);
        vector_free(pubkeys, true);
        free(pubkeys_input_copy);
        return;
    }

    /* utils_uint8_to_hex() returns an internal static buffer */
    const char* redeem_script_hex = utils_uint8_to_hex((const uint8_t*)redeem_script->str, redeem_script->len);
    uint160_t script_hash;
    dogecoin_script_get_scripthash(redeem_script, script_hash);

    /* keep ample room for all base58 address variants plus terminator */
    char p2sh_address[SUCH_ADDRESS_MAX_LEN];
    if (!dogecoin_p2sh_addr_from_hash160(script_hash, chain, p2sh_address, sizeof(p2sh_address))) {
        printf("Error: Failed to derive p2sh address from redeem script\n");
        cstr_free(redeem_script, true);
        vector_free(pubkeys, true);
        free(pubkeys_input_copy);
        return;
    }

    printf(SUCH_MULTISIG_REDEEM_SCRIPT_LABEL, redeem_script_hex);
    printf(SUCH_MULTISIG_P2SH_ADDRESS_LABEL, p2sh_address);

    cstr_free(redeem_script, true);
    vector_free(pubkeys, true);
    free(pubkeys_input_copy);
}

void sub_menu(int txindex, int is_testnet) {
    int running = 1;
    int temp_vout_index;
    char* temp_hex_utxo_txid;
    const char* temp_ext_p2pkh;
    char* multisig_pubkeys = NULL;
    unsigned int multisig_required_signatures = 0;
    char* raw_hexadecimal_transaction;
    const dogecoin_chainparams* chain = is_testnet ? &dogecoin_chainparams_test : &dogecoin_chainparams_main;
    while (running) {
        printf("\n 1. add input\n");
        printf(" 2. add output\n");
        printf(" 3. finalize transaction\n");
        printf(" 4. sign transaction\n");
        printf(" 5. multisig script/address\n");
#ifdef WITH_NET
        printf(" 6. broadcast transaction\n");
#endif
        printf(" 8. print transaction\n");
        printf(" 9. main menu\n\n");
        switch (atoi(getl("command"))) {
                case 1:
                    printf("raw_tx: %s\n", cli_get_raw_transaction(txindex));
                    temp_vout_index = atoi(getl("vout index")); // 1
                    temp_hex_utxo_txid = (char*)getl("txid"); // b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074 & 42113bdc65fc2943cf0359ea1a24ced0b6b0b5290db4c63a3329c6601c4616e2
                    cli_add_utxo(txindex, temp_hex_utxo_txid, temp_vout_index);
                    printf("raw_tx: %s\n", cli_get_raw_transaction(txindex));
                    break;
                case 2:
                    /* getl() returns a pointer into a single static buffer,
                     * so the second getl() below would overwrite the amount
                     * before cli_add_output() reads it. Snapshot it first. */
                    {
                        char temp_amt_buf[64];
                        const char* _amt = getl("amount to send to destination address"); // 5
                        snprintf(temp_amt_buf, sizeof(temp_amt_buf), "%s", _amt);
                        temp_ext_p2pkh = getl("destination address"); // nbGfXLskPh7eM1iG5zz5EfDkkNTo9TRmde
                        printf("destination: %s\n", temp_ext_p2pkh);
                        printf("addout success: %d\n", cli_add_output(txindex, (char*)temp_ext_p2pkh, temp_amt_buf));
                    }
                    char* str = cli_get_raw_transaction(txindex);
                    printf("raw_tx: %s\n", str);
                    break;
                case 3:
                    /* getl() returns a pointer into a single static buffer,
                     * so each subsequent call overwrites the previous return
                     * value. Snapshot every prompt into its own buffer before
                     * passing them to cli_finalize_transaction(). */
                    {
                        char out_addr_buf[128], fee_buf[64], total_buf[64], change_buf[128];
                        snprintf(out_addr_buf, sizeof(out_addr_buf), "%s",
                                 getl("re-enter destination address for verification"));
                        snprintf(fee_buf, sizeof(fee_buf), "%s",
                                 getl("desired fee"));
                        snprintf(total_buf, sizeof(total_buf), "%s",
                                 getl("total amount for verification"));
                        snprintf(change_buf, sizeof(change_buf), "%s",
                                 getl("senders address"));
                        raw_hexadecimal_transaction = cli_finalize_transaction(
                            txindex, out_addr_buf, fee_buf, total_buf, change_buf);
                    }
                    printf("raw_tx: %s\n", raw_hexadecimal_transaction);
                    break;
                case 4:
                    signing_menu(txindex, is_testnet);
                    break;
                case 5:
                    /* get_raw_tx allows inputs larger than getl's 100-byte buffer */
                    multisig_pubkeys = (char*)get_raw_tx("comma-separated compressed pubkeys");
                    multisig_required_signatures = (unsigned int)strtoul(getl("required signatures"), (char**)NULL, 10);
                    print_multisig_info(chain, multisig_pubkeys, multisig_required_signatures);
                    break;
#ifdef WITH_NET
                case 6:
                    broadcasting_menu(txindex, is_testnet);
                    break;
#endif
                case 8:
                    printf("raw_tx: %s\n", cli_get_raw_transaction(txindex));
                    break;
                case 9:
                    running = 0;
                    break;
            }
        }
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
void transaction_input_menu(int txindex, int is_testnet) {
#pragma GCC diagnostic pop
    int running_transaction_input_menu = 1;
    working_transaction* tx = cli_find_transaction(txindex);
    while (running_transaction_input_menu) {
        int length = tx->transaction->vin->len;
        int selected = -1;
        char* hex_utxo_txid;
        int vout;
        char* raw_hexadecimal_tx;
        char* script_pubkey;
        int input_to_sign;
        char* private_key_wif;
        for (int i = 0; i < length; i++) {
            printf("\n--------------------------------\n");
            printf("input index:      %d\n", i);
            dogecoin_tx_in* tx_in = vector_idx(tx->transaction->vin, i);
            vout = tx_in->prevout.n;
            printf("prevout.n:        %d\n", vout);
            hex_utxo_txid = utils_uint8_to_hex(tx_in->prevout.hash, sizeof tx_in->prevout.hash);
            printf("txid:             %s\n", hex_utxo_txid);
            printf("script signature: %s\n", utils_uint8_to_hex((const uint8_t*)tx_in->script_sig->str, tx_in->script_sig->len));
            printf("tx_in->sequence:  %x\n", tx_in->sequence);
            selected == i ? printf("selected:         [X]\n") : 0;

            if (selected == i) {
                printf("\n\n");
                printf("1. select field to edit\n");
                printf("2. finish editing\n");
                switch (atoi(getl("\ncommand"))) {
                        case 1:
                            // tx_input submenu
                            printf("1. prevout.n\n");
                            printf("2. txid\n");
                            printf("3. script signature\n");
                            switch (atoi(getl("field to edit"))) {
                                    case 1:
                                        printf("prevout.n\n");
                                        vout = atoi(getl("new input index"));
                                        tx_in->prevout.n = vout;
                                        break;
                                    case 2:
                                        hex_utxo_txid = (char*)get_raw_tx("new txid");
                                        utils_uint256_sethex((char*)hex_utxo_txid, (uint8_t*)tx_in->prevout.hash);
                                        tx_in->prevout.n = vout;
                                        break;
                                    case 3:
                                        printf("\nediting script signature:\n\n");
                                        input_to_sign = i;
                                        private_key_wif = (char*)get_private_key("private_key"); // ci5prbqz7jXyFPVWKkHhPq4a9N8Dag3TpeRfuqqC2Nfr7gSqx1fy
                                        script_pubkey = dogecoin_private_key_wif_to_pubkey_hash(private_key_wif);
                                        cstr_erase(tx_in->script_sig, 0, tx_in->script_sig->len);
                                        // 76a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac
                                        raw_hexadecimal_tx = cli_get_raw_transaction(txindex);
                                        printf("raw_hexadecimal_transaction: %s\n", raw_hexadecimal_tx);
                                        // 76a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac
                                        if (!sign_indexed_raw_transaction(txindex, input_to_sign, raw_hexadecimal_tx, script_pubkey, 1, private_key_wif)) {
                                            printf("signing indexed raw transaction failed!\n");
                                            }
                                        else printf("transaction input successfully signed!\n");
                                        dogecoin_free(script_pubkey);
                                        break;
                                }
                            i = i - i - 1; // reset loop to start
                            break;
                        case 2:
                            selected = -1; // set selected to number out of bounds for i
                            i = i - i - 1; // reset loop to start
                            break;
                    }
                }
            // if on last iteration, jump into switch case pausing loop
            // execution so user has ability to reset loop index in order
            // to target desired input to edit. otherwise set loop index to
            // length thus finishing final iteration and set running to 0 to
            // escape encompassing while loop so we return to previous menu
            if (i == length - 1) {
                printf("\n\n");
                printf("1. select input to edit\n");
                printf("2. main menu\n");
                switch (atoi(getl("\ncommand"))) {
                        case 1:
                            // tx_input submenu
                            selected = atoi(getl("vin index"));
                            i = i - i - 1;
                            break;
                        case 2:
                            i = length;
                            running_transaction_input_menu = 0;
                            break;
                    }
                }
            }
        }
    }

void transaction_output_menu(int txindex, int is_testnet) {
    int running_transaction_output_menu = 1;
    while (running_transaction_output_menu) {
        char* destinationaddress;
        char* coin_amount[21];
        dogecoin_mem_zero(coin_amount, 21);
        uint64_t koinu_amount;
        uint64_t tx_out_total = 0;
        const dogecoin_chainparams* chain = is_testnet ? &dogecoin_chainparams_test : &dogecoin_chainparams_main;
        working_transaction* tx = cli_find_transaction(txindex);
        int length = tx->transaction->vout->len;
        int selected = -1;
        printf("length: %d\n", length);
        for (int i = 0; i < length; i++) {
            dogecoin_tx_out* tx_out = vector_idx(tx->transaction->vout, i);
            tx_out_total += tx_out->value;
            printf("\n--------------------------------\n");
            printf("output index:       %d\n", i);
            printf("script public key:  %s\n", utils_uint8_to_hex((const uint8_t*)tx_out->script_pubkey->str, tx_out->script_pubkey->len));
            koinu_to_coins_str(tx_out->value, (char*)coin_amount);
            printf("amount:             %s\n", (char*)coin_amount);
            // selected should only equal anything other than -1 upon setting
            // loop index in conditional targetting last iteration:
            selected == i ? printf("selected:           [X]\n") : 0;
            if (selected == i) {
                printf("\n\n");
                printf("1. select field to edit\n");
                printf("2. finish editing\n");
                switch (atoi(getl("\ncommand"))) {
                        case 1:
                            // tx_input submenu
                            printf("1. script public key\n");
                            printf("2. amount\n");
                            switch (atoi(getl("field to edit"))) {
                                    case 1:
                                        destinationaddress = (char*)getl("new destination address");
                                        if (!verifyP2pkhAddress(destinationaddress, strlen(destinationaddress))) {
                                            printf("\ninvalid destination address!\n");
                                            break;
                                            }
                                        else {
                                            koinu_amount = coins_to_koinu_str((char*)coin_amount);
                                            vector_remove_idx(tx->transaction->vout, i);
                                            dogecoin_tx_add_address_out(tx->transaction, chain, koinu_amount, destinationaddress);
                                            }
                                        break;
                                    case 2:
                                        memcpy_safe(coin_amount, (char*)getl("new amount"), 21);
                                        koinu_amount = coins_to_koinu_str((char*)coin_amount);
                                        if (!koinu_amount) {
                                            printf("number is invalid or set to 0\n");
                                        } else tx_out->value = koinu_amount;
                                        break;
                                }
                            tx_out_total = 0;
                            i = i - i - 1; // reset loop to start
                            break;
                        case 2:
                            selected = -1; // set selected to number out of bounds for i
                            tx_out_total = 0;
                            i = i - i - 1; // reset loop to start
                            break;
                    }
                }
            // if on last iteration, jump into switch case pausing loop
            // execution so user has ability to reset loop index in order
            // to target desired input to edit. otherwise set loop index to
            // length thus finishing final iteration and set running to 0 to
            // escape encompassing while loop so we return to previous menu
            if (i == length - 1) {
                printf("\n\n");
                char* subtotal[21];
                dogecoin_mem_zero(subtotal, 21);
                koinu_to_coins_str(tx_out_total, (char*)subtotal);
                printf("subtotal - desired fee: %s\n", (char*)subtotal);
                printf("\n");
                printf("1. select output to edit\n");
                printf("2. main menu\n");
                switch (atoi(getl("\ncommand"))) {
                        case 1:
                            // tx_input submenu
                            selected = atoi(getl("vout index"));
                            tx_out_total = 0;
                            i = i - i - 1;
                            break;
                        case 2:
                            i = length;
                            running_transaction_output_menu = 0;
                            break;
                    }
                }
            }
        }
    }

void edit_menu(int txindex, int is_testnet) {
    int running_edit_menu = 1;
    while (running_edit_menu) {
        printf("\n");
        printf("1. edit input\n");
        printf("2. edit output\n");
        printf("3. main menu\n");
        switch (atoi(getl("\ncommand"))) {
                case 1:
                    transaction_input_menu(txindex, is_testnet);
                    break;
                case 2:
                    transaction_output_menu(txindex, is_testnet);
                    break;
                case 3:
                    running_edit_menu = 0;
                    break;
            }
        }
    }

int chainparams_menu(int is_testnet) {
    printf("\n1. mainnet\n");
    printf("2. testnet\n\n");
    switch (atoi(getl("command"))) {
            case 1:
                is_testnet = false;
                break;
            case 2:
                is_testnet = true;
                break;
        }
    return is_testnet;
    }

int is_testnet = true;

void main_menu() {
    int running = 1;
    struct working_transaction* s;
    int temp, txindex;
    wow();

    // load existing testnet transaction into memory for demonstration purposes.
    cli_save_raw_transaction(cli_start_transaction(), "0100000002746007aed61e8531faba1af6610f10a5422c70a2a7eb6ffb51cb7a7b7b5e45b40100000000ffffffffe216461c60c629333ac6b40d29b5b0b6d0ce241aea5903cf4329fc65dc3b11420100000000ffffffff020065cd1d000000001976a9144da2f8202789567d402f7f717c01d98837e4325488ac30b4b529000000001976a914d8c43e6f68ca4ea1e9b93da2d1e3a95118fa4a7c88ac00000000");
    while (running) {
        printf("\nsuch transaction: \n\n");
        printf(" 1. add transaction\n");
        printf(" 2. edit transaction by id\n");
        printf(" 3. find transaction\n");
        printf(" 4. sign transaction\n");
        printf(" 5. delete transaction\n");
        printf(" 6. delete all transactions\n");
        printf(" 7. print transactions\n");
        printf(" 8. import raw transaction (memory)\n");
#ifdef WITH_NET
        printf(" 9. broadcast transaction\n");
        printf(" 10. change network (current: %s)\n", is_testnet ? "testnet" : "mainnet");
        printf(" 11. quit\n");
#else
        printf(" 9. change network (current: %s)\n", is_testnet ? "testnet" : "mainnet");
        printf(" 10. quit\n");
#endif
        switch (atoi(getl("\ncommand"))) {
                case 1:
                    sub_menu(cli_start_transaction(), is_testnet);
                    break;
                case 2:
                    temp = atoi(getl("ID of transaction to edit"));
                    s = cli_find_transaction(temp);
                    if (s) {
                        edit_menu(temp, is_testnet);
                        }
                    else {
                        printf("\nno transaction found with that id. please try again!\n");
                        }
                    break;
                case 3:
                    s = cli_find_transaction(atoi(getl("ID to find")));
                    s ? printf("transaction: %s\n", cli_get_raw_transaction(s->idx)) : printf("\nno transaction found with that id. please try again!\n");
                    break;
                case 4:
                    temp = atoi(getl("ID of transaction to sign"));
                    s = cli_find_transaction(temp);
                    if (s) {
                        signing_menu(temp, is_testnet);
                        }
                    else {
                        printf("\nno transaction found with that id. please try again!\n");
                        }
                    break;
                case 5:
                    s = cli_find_transaction(atoi(getl("ID to delete")));
                    if (s) {
                        cli_remove_transaction(s);
                        }
                    else {
                        printf("\nno transaction found with that id. please try again!\n");
                        }
                    break;
                case 6:
                    cli_remove_all();
                    break;
                case 7:
                    count_transactions();
                    print_transactions();
                    break;
                case 8:
                    txindex = cli_start_transaction();
                    int res = cli_save_raw_transaction(txindex, get_raw_tx("raw transaction"));
                    if (!res) {
                        printf("error saving transaction!\n");
                        cli_clear_transaction(txindex);
                        }
                    else {
                        printf("successfully saved raw transaction to memory for the session!\n");
                        printf("working transaction id is: %d\n", txindex);
                        }
                    break;
#ifdef WITH_NET
                case 9:
                    temp = atoi(getl("ID of transaction to edit"));
                    s = cli_find_transaction(temp);
                    if (s) {
                        broadcasting_menu(temp, is_testnet);
                        }
                    else {
                        printf("\nno transaction found with that id. please try again!\n");
                        }
                    break;
                case 10:
                    is_testnet = chainparams_menu(is_testnet);
                    break;
                case 11:
                    running = 0;
                    break;
#else
                case 9:
                    is_testnet = chainparams_menu(is_testnet);
                    break;
                case 10:
                    running = 0;
                    break;
#endif
            }
        }
    cli_remove_all();
    }

// ******************************** END TRANSACTION MENU ********************************

// ******************************** CLI INTERFACE ********************************
static struct option long_options[] =
    {
        {"privkey", required_argument, NULL, 'p'},
        {"sk_file", required_argument, NULL, 0x100},
        {"sk-file", required_argument, NULL, 0x100},
        {"pubkey", required_argument, NULL, 'k'},
        {"derived_path", required_argument, NULL, 'm'},
        {"sighash", required_argument, NULL, 'h'},
        {"script", required_argument, NULL, 's'},
        {"input_index", required_argument, NULL, 'i'},
        {"raw_tx", required_argument, NULL, 'x'},
        {"entropy", required_argument, NULL, 'e'},
        {"entropy_size", required_argument, NULL, 'z'},
        {"mnemonic", required_argument, NULL, 'n'},
        {"pass_phrase", no_argument, NULL, 'a'},
        {"account_int", required_argument, NULL, 'o'},
        {"change_level", required_argument, NULL, 'g'},
        {"address_index", required_argument, NULL, 'i'},
        {"encrypted_file", required_argument, NULL, 'y'},
        {"use_tpm", no_argument, NULL, 'j'},
        {"command", required_argument, NULL, 'c'},
        {"silent", no_argument, NULL, 'b'},
        {"overwrite", no_argument, NULL, 'w'},
        {"testnet", no_argument, NULL, 't'},
        {"regtest", no_argument, NULL, 'r'},
        {"version", no_argument, NULL, 'v'},
        {NULL, 0, NULL, 0} };

static void print_version()
    {
    printf("Version: %s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
    }

static void print_usage()
    {
    print_version();
    printf("Usage: such -c <cmd> (-m|-derived_path <bip_derived_path>) (-k|-pubkey <publickey>) (-p|-privkey <privatekey>) (-h|-sighash <sighash type>) \
(-s|-script <script pubkey>) (-i|-input_index <input index>) (-x|-raw_tx <raw hex tx>) (-o|-account_int <account_int>) (-g|-change_level <change_level>) \
(-e|-entropy <hex_entropy>) (-n|-mnemonic <seed_phrase>) (-a|-pass_phrase) (-y|-encrypted_file <file_num 0-999>) (-w[--overwrite]) (-b[--silent]) \
(-z|-entropy_size <bit_size>) (-j[--use_tpm]) (-t[--testnet]) (-r[--regtest])\n");
    printf("Available commands:\n");
    printf("generate_public_key (requires -p <wif>),\n");
    printf("p2pkh (requires -k <public key hex>),\n");
    printf("generate_private_key,\n");
    printf("bip32_extended_master_key (-y <file_num>, -j (use_tpm), -w (overwrite) and -b (silent), all optional),\n");
    printf("generate_mnemonic (-e <hex_entropy> or -y <file_num>, -z <bit_size>, -j (use_tpm), -w (overwrite) and -b (silent), all optional),\n");
    printf("list_encryption_keys_in_tpm,\n");
    printf("decrypt_master_key (requires -y <file_num>, -j (use_tpm) optional),\n");
    printf("decrypt_mnemonic (requires -y <file_num>, -j (use_tpm) optional),\n");
    printf("seed_to_master_key (-y <file_num>, -j (use_tpm) optional),\n");
    printf("mnemonic_to_key (requires -n <seed_phrase> or -y <file_num>, -j (use_tpm), -o <account_int>, -g <change_level>, -i <address_index> and -a, all optional),\n");
    printf("mnemonic_to_addresses (requires -n <seed_phrase> or -y <file_num>, -j (use_tpm), -o <account_int>, -g <change_level>, -i <address_index> and -a, all optional),\n");
    printf("slip39_split (requires -x <secret_hex 16..32 bytes>, -o <threshold>, -i <share_count>),\n");
    printf("slip39_recover (requires -x <\"share1 mnemonic\",\"share2 mnemonic\",...>),\n");
    printf("print_keys (requires -p <private key hex>),\n");
    printf("derive_child_keys (requires -m <custom path> -p <public or private key>),\n");
    printf("sign (-x <raw hex tx> -s <script pubkey> -i <input index> -h <sighash type> -p <private key>),\n");
        printf("set_scriptsig (-x <raw hex tx> -i <input index> -s <scriptSig hex>),\n");
        printf("pqc_chunk_hex (-x <hex_payload> [-h <max_chunk_bytes, default 520>]),\n");
#ifdef USE_LIBOQS
    printf("tx_sighash32 (-x <raw hex tx> -s <script pubkey> -i <input index> -h <sighash type>),\n");
    printf("pqc_carrier_redeemscript,\n");
    printf("pqc_carrier_scriptpubkey,\n");
    printf("pqc_carrier_mkpart (-k <tag4_hex> -p <pqc_pubkey_hex> -s <pqc_signature_hex> -i <part_index>),\n");
    printf("pqc_carrier_parsepart (-x <scriptsig_hex>),\n");
#endif
    printf("comp2der (-s <compact signature>),\n");
    printf("bip32maintotest (-p <extended hd master key>),\n");
    printf("signmessage (-x '<message>' -p <private key>),\n");
    printf("verifymessage (-x '<message>' -s <signature (base64 encoded)> -k <address>),\n");
    printf("transaction,\n");
#ifdef USE_LIBOQS
    printf("falcon_keygen (generates Falcon-512 keypair),\n");
    printf("falcon_sign (requires -p <falcon_secret_key_hex>|--sk-file <path> and -x <message_hex|tx_sighash_hex>),\n");
    printf("falcon_verify (requires -k <falcon_public_key_hex> -x <message_hex|tx_sighash_hex> -s <signature_hex>),\n");
    printf("falcon_commit (requires -k <falcon_public_key_hex> -s <signature_hex>),\n");
    printf("dilithium2_keygen (generates Dilithium2 keypair),\n");
    printf("dilithium2_sign (requires -p <dilithium2_secret_key_hex>|--sk-file <path> and -x <message_hex|tx_sighash_hex>),\n");
    printf("dilithium2_verify (requires -k <dilithium2_public_key_hex> -x <message_hex|tx_sighash_hex> -s <signature_hex>),\n");
    printf("dilithium2_commit (requires -k <dilithium2_public_key_hex> -s <signature_hex>),\n");
#endif
#ifdef USE_RACCOON_G
    printf("raccoong_keygen (generates Raccoon-G-44 keypair),\n");
    printf("raccoong_sign (requires -p <raccoong_secret_key_hex>|--sk-file <path> and -x <message_hex|tx_sighash_hex>),\n");
    printf("raccoong_verify (requires -k <raccoong_public_key_hex> -x <message_hex|tx_sighash_hex> -s <signature_hex>),\n");
    printf("raccoong_commit (requires -k <raccoong_public_key_hex> -s <signature_hex>),\n");
    printf("raccoong_hd_derive (requires -p <raccoong_secret_key_hex>|--sk-file <path>, -s <chaincode_hex>, -i <child_index>, optional -g <0|1 hardened>),\n");
    printf("raccoong_hd_derive_pub (requires -k <raccoong_public_key_hex> -s <chaincode_hex> -i <child_index>),\n");
#endif
#ifdef USE_LIBOQS
    printf("falcon_add_commit_tx (requires -x <raw_tx_hex> -s <falcon_commitment_hex>),\n");
    printf("dilithium2_add_commit_tx (requires -x <raw_tx_hex> -s <dilithium2_commitment_hex>),\n");
#endif
#ifdef USE_RACCOON_G
    printf("raccoong_add_commit_tx (requires -x <raw_tx_hex> -s <raccoong_commitment_hex>),\n");
#endif
#ifdef USE_LIBOQS
    printf("falcon_add_commit_and_carrier_tx (requires -x <raw_tx_hex> -m <falcon_commitment_hex> -k <falcon_pubkey_hex> -s <falcon_signature_hex> [-h <carrier_value_koinu, default 100000000>]),\n");
    printf("dilithium2_add_commit_and_carrier_tx (requires -x <raw_tx_hex> -m <dilithium2_commitment_hex> -k <dilithium2_pubkey_hex> -s <dilithium2_signature_hex> [-h <carrier_value_koinu, default 100000000>]),\n");
#endif
#ifdef USE_RACCOON_G
    printf("raccoong_add_commit_and_carrier_tx (requires -x <raw_tx_hex> -m <raccoong_commitment_hex> -k <raccoong_pubkey_hex> -s <raccoong_signature_hex> [-h <carrier_value_koinu, default 100000000>]),\n");
#endif
#ifdef USE_ZK_CARRIER
    printf("zk_encode_payload (requires -m <mode 0=groth16|1=plonk|2=stark> -i <circuit_id_hex> -k <public_inputs_hex> -s <proof_hex>),\n");
    printf("zk_commit (requires -x <payload_hex>; emits SHA256d(payload) and the OP_RETURN script),\n");
    printf("zk_add_commit_and_carrier_tx (requires -x <raw_tx_hex> -m <mode 0|1|2> -s <payload_hex> [-h <carrier_value_koinu, default 100000000>]),\n");
    printf("zk_extract_carrier (requires -x <tx_r_hex>; reassembles ZKP1 payload),\n");
#endif
    printf("\nExamples: \n");
    printf("Generate a testnet private ec keypair wif/hex:\n");
    printf("> such -c generate_private_key\n\n");
    printf("> such -c generate_public_key -p QRYZwxVxBFKgKP4bWPEwWBJpN3C3cTN6fads8SgJTgaPTJhEWgLH\n\n");
    }

static bool showError(const char* er)
    {
    printf("Error: %s\n", er);
    dogecoin_ecc_stop();
    return 1;
    }

static void such_cstring_free_cb(void* data)
{
    cstr_free((cstring*)data, true);
}

static dogecoin_bool such_hex_payload_chunks(const char* payload_hex, size_t max_chunk_bytes, vector_t* chunks_out)
{
    if (!payload_hex || !chunks_out) {
        return false;
    }
    size_t payload_hex_len = strlen(payload_hex);
    if ((payload_hex_len % 2) != 0) {
        return false;
    }
    if (max_chunk_bytes == 0) {
        return false;
    }
    size_t chunk_hex_len = max_chunk_bytes * 2;
    if (chunk_hex_len == 0) {
        return false;
    }
    if (payload_hex_len == 0) {
        return true;
    }

    for (size_t off = 0; off < payload_hex_len; off += chunk_hex_len) {
        size_t take = payload_hex_len - off;
        if (take > chunk_hex_len) {
            take = chunk_hex_len;
        }
        cstring* chunk = cstr_new_sz(take + 1);
        if (!chunk) {
            return false;
        }
        cstr_append_buf(chunk, payload_hex + off, take);
        if (!vector_add(chunks_out, chunk)) {
            cstr_free(chunk, true);
            return false;
        }
    }
    return true;
}

#if defined(USE_LIBOQS) || defined(USE_RACCOON_G)
#if defined(__GNUC__) || defined(__clang__)
static dogecoin_bool such_tag4_hex_to_tag8(const char* tag4_hex, char out_tag8[8]) __attribute__((unused));
#endif
static dogecoin_bool such_tag4_hex_to_tag8(const char* tag4_hex, char out_tag8[8])
{
    if (!tag4_hex || !out_tag8 || strlen(tag4_hex) != 8) {
        return false;
    }
    uint8_t tag4[4];
    size_t outlen = 0;
    utils_hex_to_bin(tag4_hex, tag4, 8, &outlen);
    if (outlen != 4) {
        return false;
    }
    memcpy(out_tag8, tag4, 4);
    memcpy(out_tag8 + 4, "FULL", 4);
    return true;
}

static dogecoin_bool such_commit_hex_to_bytes32(const char* commit_hex, uint8_t out_commit32[32])
{
    if (!commit_hex || !out_commit32) {
        return false;
    }
    if (strlen(commit_hex) != 64) {
        return false;
    }
    for (size_t i = 0; i < 64; i++) {
        if (!isxdigit((unsigned char)commit_hex[i])) {
            return false;
        }
    }
    size_t commit_len = 0;
    utils_hex_to_bin(commit_hex, out_commit32, 64, &commit_len);
    return commit_len == 32;
}

/* Read a PQC secret key (hex) from a file. Caller owns the returned heap
   buffer and must release it with dogecoin_mem_zero() + dogecoin_free().
   Whitespace (newlines, spaces, tabs, CR) inside the file is ignored so a
   trailing newline from `echo "...hex..." > sk.hex` is accepted. Reading
   from a file avoids exposing secret bytes through argv / /proc/<pid>/cmdline.
   Returns a NUL-terminated hex string on success, NULL on any error. */
static char* such_read_sk_hex_from_file(const char* path)
{
    if (!path) return NULL;
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long raw_len = ftell(f);
    if (raw_len < 0 || raw_len > (1L << 22) /* 4 MiB hard cap */) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    char* raw = (char*)dogecoin_malloc((size_t)raw_len + 1);
    if (!raw) { fclose(f); return NULL; }
    size_t got = fread(raw, 1, (size_t)raw_len, f);
    fclose(f);
    if (got != (size_t)raw_len) {
        dogecoin_mem_zero(raw, (size_t)raw_len);
        dogecoin_free(raw);
        return NULL;
    }
    raw[raw_len] = '\0';

    char* out = (char*)dogecoin_malloc((size_t)raw_len + 1);
    if (!out) {
        dogecoin_mem_zero(raw, (size_t)raw_len);
        dogecoin_free(raw);
        return NULL;
    }
    size_t w = 0;
    for (long i = 0; i < raw_len; i++) {
        unsigned char c = (unsigned char)raw[i];
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        if (!isxdigit(c)) {
            dogecoin_mem_zero(raw, (size_t)raw_len);
            dogecoin_free(raw);
            dogecoin_mem_zero(out, (size_t)raw_len + 1);
            dogecoin_free(out);
            return NULL;
        }
        out[w++] = (char)c;
    }
    out[w] = '\0';
    dogecoin_mem_zero(raw, (size_t)raw_len);
    dogecoin_free(raw);
    if (w == 0 || (w % 2) != 0) {
        dogecoin_mem_zero(out, w);
        dogecoin_free(out);
        return NULL;
    }
    return out;
}

/* Resolve which secret-key hex string the PQC sign/derive commands should
   use. Prefers --sk-file (safer: not visible in /proc/<pid>/cmdline) over
   -p. On success returns a heap buffer the caller must release via
   such_release_sk_hex(); on failure returns NULL. If both -p and --sk-file
   are supplied -p wins for backward compatibility but a warning is printed
   so users know the argv path leaks the secret. */
static char* such_resolve_sk_hex(const char* pkey, const char* sk_file, dogecoin_bool* out_owned)
{
    if (out_owned) *out_owned = false;
    if (pkey) {
        if (sk_file) {
            fprintf(stderr,
                    "warning: both -p and --sk-file supplied; using -p. "
                    "Note: secret bytes passed on argv are visible to other "
                    "users via /proc/<pid>/cmdline — prefer --sk-file.\n");
        } else {
            fprintf(stderr,
                    "warning: PQC secret key passed via -p is visible to other "
                    "users via /proc/<pid>/cmdline. Prefer --sk-file <path>.\n");
        }
        return (char*)pkey;
    }
    if (sk_file) {
        char* loaded = such_read_sk_hex_from_file(sk_file);
        if (!loaded) return NULL;
        if (out_owned) *out_owned = true;
        return loaded;
    }
    return NULL;
}

static void such_release_sk_hex(char* sk_hex, dogecoin_bool owned)
{
    if (owned && sk_hex) {
        dogecoin_mem_zero(sk_hex, strlen(sk_hex));
        dogecoin_free(sk_hex);
    }
}

static dogecoin_bool such_tx_add_commit_and_carrier_outputs(
    dogecoin_tx* tx,
    const uint8_t commit32[32],
    dogecoin_bool (*add_commit_fn)(dogecoin_tx* tx, const uint8_t commitment32[32]),
    const char tag4[4],
    const char* pqc_pubkey_hex,
    const char* pqc_signature_hex,
    uint64_t carrier_value_koinu,
    cstring** out_carrier_spk,
    uint8_t* out_part_total,
    uint32_t* out_carrier_first_vout)
{
    if (!tx || !add_commit_fn || !tag4 || !pqc_pubkey_hex || !pqc_signature_hex ||
        !out_carrier_spk || !out_part_total || !out_carrier_first_vout) {
        return false;
    }
    if ((strlen(pqc_pubkey_hex) % 2) != 0 || (strlen(pqc_signature_hex) % 2) != 0) {
        return false;
    }
    size_t pk_len = strlen(pqc_pubkey_hex) / 2;
    size_t sig_len = strlen(pqc_signature_hex) / 2;
    if (pk_len == 0 || sig_len == 0) {
        return false;
    }
    uint8_t* pk = dogecoin_malloc(pk_len + 1);
    uint8_t* sig = dogecoin_malloc(sig_len + 1);
    if (!pk || !sig) {
        if (pk) dogecoin_free(pk);
        if (sig) dogecoin_free(sig);
        return false;
    }
    size_t outlen = 0;
    utils_hex_to_bin(pqc_pubkey_hex, pk, strlen(pqc_pubkey_hex), &outlen);
    if (outlen != pk_len) {
        dogecoin_free(pk);
        dogecoin_free(sig);
        return false;
    }
    utils_hex_to_bin(pqc_signature_hex, sig, strlen(pqc_signature_hex), &outlen);
    if (outlen != sig_len) {
        dogecoin_free(pk);
        dogecoin_free(sig);
        return false;
    }

    size_t full_len = pk_len + sig_len;
    uint8_t* full = dogecoin_malloc(full_len + 1);
    if (!full) {
        dogecoin_free(pk);
        dogecoin_free(sig);
        return false;
    }
    memcpy(full, pk, pk_len);
    memcpy(full + pk_len, sig, sig_len);
    dogecoin_free(pk);
    dogecoin_free(sig);

    if (!add_commit_fn(tx, commit32)) {
        dogecoin_free(full);
        return false;
    }

    cstring* redeem = NULL;
    cstring* carrier_spk = NULL;
    if (!dogecoin_pqc_carrier_build_redeemscript(&redeem)) {
        dogecoin_free(full);
        return false;
    }
    if (!dogecoin_pqc_carrier_build_p2sh_scriptpubkey(redeem, &carrier_spk)) {
        cstr_free(redeem, true);
        dogecoin_free(full);
        return false;
    }

    size_t part_payload_max = DOGECOIN_PQC_CARRIER_MAX_CHUNKS * DOGECOIN_PQC_CARRIER_CHUNK_MAX;
    uint8_t part_total = (uint8_t)((full_len + part_payload_max - 1) / part_payload_max);
    if (part_total == 0) {
        cstr_free(carrier_spk, true);
        cstr_free(redeem, true);
        dogecoin_free(full);
        return false;
    }

    uint32_t first_vout = (uint32_t)(tx->vout->len);
    if (!dogecoin_tx_add_pqc_carrier_outputs(tx, carrier_spk, carrier_value_koinu, part_total)) {
        cstr_free(carrier_spk, true);
        cstr_free(redeem, true);
        dogecoin_free(full);
        return false;
    }

    /* Deduct the total carrier cost from the first output (change/send-back)
       so that the miner fee stays intact instead of being consumed by carriers. */
    uint64_t carrier_total = (uint64_t)part_total * carrier_value_koinu;
    if (tx->vout->len > 0) {
        dogecoin_tx_out* change_out = vector_idx(tx->vout, 0);
        if ((uint64_t)change_out->value < carrier_total) {
            printf("Error: change output (%llu) too small for carrier total (%llu)\n",
                   (unsigned long long)change_out->value, (unsigned long long)carrier_total);
            cstr_free(carrier_spk, true);
            cstr_free(redeem, true);
            dogecoin_free(full);
            return false;
        }
        change_out->value -= carrier_total;
    }

    *out_carrier_spk = carrier_spk;
    *out_part_total = part_total;
    *out_carrier_first_vout = first_vout;
    cstr_free(redeem, true);
    dogecoin_free(full);
    return true;
}
#endif

int main(int argc, char* argv[])
    {
    setlocale(LC_CTYPE, "");
    int long_index = 0;
    int opt = 0;
    char* pkey = 0;
    /* Path to a file containing the PQC secret key as hex (one line). Used by
       PQC sign/derive commands as a safer alternative to -p, which exposes
       secret bytes through /proc/<pid>/cmdline on multi-user hosts and in CI
       runners. Mutually exclusive with passing the secret directly via -p. */
    char* sk_file = 0;
#if !defined(USE_LIBOQS) && !defined(USE_RACCOON_G)
    /* sk_file is consumed by PQC sign/derive command branches only; mark it
       read here so default builds without a PQC backend do not warn about
       a set-but-not-used variable. */
    (void)sk_file;
#endif
    char* pubkey = 0;
    char* cmd = 0;
    char* derived_path = 0;
    uint32_t account = BIP44_FIRST_ACCOUNT_NODE;   /* default account (BIP44_FIRST_ACCOUNT_NODE) */
    char* change_level = BIP44_CHANGE_EXTERNAL;    /* default external (BIP44_CHANGE_EXTERNAL) */
    char* mnemonic_in = 0;
    char* pass = 0;
    char* entropy = 0;
    char* entropy_size = "256";
    MNEMONIC mnemonic = {0};
    SEED seed = {0};
    dogecoin_bool tpm = false;
    dogecoin_bool encrypted = false;
    dogecoin_bool overwrite = false;
    dogecoin_bool silent = false;
    int file_num = NO_FILE;

    char* txhex = 0;
    char* scripthex = 0;
    uint32_t inputindex = 0;
    int sighashtype = 1;
    dogecoin_mem_zero(&pkey, sizeof(pkey));
    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    /* get arguments */
    while ((opt = getopt_long_only(argc, argv, "h:i:s:x:p:k:m:o:g:e:n:y:c:z:atrvbwj", long_options, &long_index)) != -1) {
        switch (opt) {
                case 'p':
                    pkey = optarg;
                    break;
                case 0x100:
                    sk_file = optarg;
                    break;
                case 'c':
                    cmd = optarg;
                    break;
                case 'm':
                    derived_path = optarg;
                    break;
                case 'o':
                    account = (int)strtol(optarg, (char**)NULL, 10);
                    break;
                case 'g':
                    change_level = optarg;
                    break;
                case 'e':
                    if (encrypted)
                        return showError("Parameter -e cannot be used with -y");
                    entropy = optarg;
                    if (entropy != NULL){
                        sprintf(entropy_size, "%zu", strlen(entropy) / HEX_CHARS_PER_BYTE * 8);
                    }

                    break;
                case 'z':
                    entropy_size = optarg;
                    break;
                case 'n':
                    mnemonic_in = optarg;
                    break;
                case 'a':
                    pass = getpass("BIP39 passphrase: \n");
                    break;
                case 'k':
                    pubkey = optarg;
                    break;
                case 't':
                    chain = &dogecoin_chainparams_test;
                    break;
                case 'r':
                    chain = &dogecoin_chainparams_regtest;
                    break;
                case 'v':
                    print_version();
                    exit(EXIT_SUCCESS);
                    break;
                case 'w':
                    if (!encrypted)
                        return showError("Overwrite can only be used with encrypted files");
                    overwrite = true;
                    break;
                case 'b':
                    if (!encrypted)
                        return showError("Silent can only be used with encrypted files");
                    silent = true;
                    break;
                case 'y':
                    if (entropy)
                        return showError("Parameter -y cannot be used with -e");
                    encrypted = true;
                    file_num = (int)strtol(optarg, (char**)NULL, 10);
                    break;
                case 'j':
                    if (!encrypted)
                        return showError("TPM can only be used with encrypted files");
                    tpm = true;
                    break;
                case 'x':
                    txhex = optarg;
                    break;
                case 's':
                    scripthex = optarg;
                    break;
                case 'i':
                    inputindex = (int)strtol(optarg, (char**)NULL, 10);
                    break;
                case 'h':
                    sighashtype = (int)strtol(optarg, (char**)NULL, 10);
                    break;
                default:
                    print_usage();
                    exit(EXIT_FAILURE);
            }
        }

    if (!cmd) {
        /* exit if no command was provided */
        print_usage();
        exit(EXIT_FAILURE);
        }

    /* start ECC context */
    dogecoin_ecc_start();

    /* Exercise the thread-safe context API (refcount mutex) in the `_ts`
       build. such has no long-lived context-owned object, so the context is
       created, queried and released here; the thread-safe transaction builder,
       transaction-context and eckey-context APIs are routed via the cli_*
       wrappers below. */
    cli_ts_context_finish(cli_ts_context_start("such", false));

    /* WIF / extended-key length sanity check for commands that consume -p as
       a base58-encoded private key.  PQC carrier and PQC signing commands
       reuse -p for raw hex of much larger keys (>>50 chars), so they are
       excluded.  Replaces the global guard that previously lived in
       `case 'p':` (removed when -p was repurposed for raw PQC hex).  Per-
       command rather than per-option so the semantics match the consumer. */
    {
        static const char* const pkey_raw_hex_cmds[] = {
            "pqc_carrier_mkpart",
            "falcon_sign", "falcon_verify", "falcon_commit",
            "dilithium2_sign", "dilithium2_verify", "dilithium2_commit",
            "raccoong_sign", "raccoong_verify", "raccoong_commit",
            "raccoong_hd_derive", "raccoong_hd_derive_pub",
            NULL
        };
        dogecoin_bool pkey_is_raw_hex = false;
        for (size_t i = 0; pkey_raw_hex_cmds[i] != NULL; i++) {
            if (strcmp(cmd, pkey_raw_hex_cmds[i]) == 0) { pkey_is_raw_hex = true; break; }
        }
        if (pkey && !pkey_is_raw_hex && strlen(pkey) < 50) {
            return showError("Private key must be WIF encoded");
        }
    }

    const char* pkey_error = "missing extended key (use -p)";

    if (strcmp(cmd, "generate_public_key") == 0) {
        /* output compressed hex pubkey from hex privkey */

        char pubkey_hex[PUBKEYHEXLEN];
        size_t sizeout = sizeof(pubkey_hex);

        if (!pkey)
            return showError(pkey_error);
        if (!pubkey_from_privatekey(chain, pkey, pubkey_hex, &sizeout))
            return showError("attempt to generate pubkey from privatekey failed");

        /* erase previous private key */
        dogecoin_mem_zero(pkey, strlen(pkey));

        /* generate public key hex from private key hex */
        printf("public key hex: %s\n", pubkey_hex);

        /* give out p2pkh address */
        char* address_p2pkh = dogecoin_char_vla(sizeout);
        addresses_from_pubkey(chain, pubkey_hex, address_p2pkh);
        printf("p2pkh address: %s\n", address_p2pkh);

        /* clean memory */
        dogecoin_mem_zero(pubkey_hex, strlen(pubkey_hex));
        dogecoin_mem_zero(address_p2pkh, strlen(address_p2pkh));
        free(address_p2pkh);
        /* Creating a new address from a public key. */
        }
    else if (strcmp(cmd, "p2pkh") == 0) {
        char address_p2pkh[P2PKHLEN];
        if (!pubkey)
            return showError("Missing public key (use -k)");
        if (!addresses_from_pubkey(chain, pubkey, address_p2pkh))
            return showError("Operation failed, invalid pubkey");
        printf("p2pkh address: %s\n", address_p2pkh);

        dogecoin_mem_zero(pubkey, strlen(pubkey));
        dogecoin_mem_zero(address_p2pkh, strlen(address_p2pkh));
        /* Generating a new private key and printing it out. */
        }
    else if (strcmp(cmd, "generate_private_key") == 0) {
        char newprivkey_wif[PRIVKEYWIFLEN];
        char newprivkey_hex[PRIVKEYHEXLEN];

        /* generate a new private key */
        gen_privatekey(chain, newprivkey_wif, sizeof(newprivkey_wif), newprivkey_hex);
        printf("private key wif: %s\n", newprivkey_wif);
        printf("private key hex: %s\n", newprivkey_hex);
        dogecoin_mem_zero(newprivkey_wif, strlen(newprivkey_wif));
        dogecoin_mem_zero(newprivkey_hex, strlen(newprivkey_hex));
        /* Generating a new master key. */
        }
    else if (strcmp(cmd, "bip32_extended_master_key") == 0) {
        char masterkey[HDKEYLEN];

        /* if tpm is enabled, use it to generate a new master key */
        if (encrypted) {

            /* if overwrite is enabled, ask for confirmation */
            if (overwrite) {
                printf("Overwrite? Y/N\n");

                char buffer[MAX_LEN];
                /* get user input */
                if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
                    if (buffer[0] != 'Y' && buffer[0] != 'y') {

                        /* if not confirmed, abort */
                        printf("aborted\n");
                        dogecoin_ecc_stop();
                        return 1;
                        }
                    }
                }

            /* generate a new master key and encrypt it */
            dogecoin_hdnode node;

            if (tpm) {
                /* generate and encrypt a new hd master key with TPM 2.0 */
                if (!dogecoin_generate_hdnode_encrypt_with_tpm(&node, file_num, overwrite)) {
                    printf("bip32_extended_master_key (-y <file_num>, -j (use_tpm) and -w (overwrite), all optional),\n");
                    return showError("Failed to generate/encrypt master key in TPM\n");
                    }
                }

            else {
                /* generate and encrypt a new hd master key with software */
                if (!dogecoin_generate_hdnode_encrypt_with_sw(&node, file_num, overwrite, NULL, NULL, NULL)) {
                    printf("bip32_extended_master_key (-y <file_num>, -j (use_tpm) and -w (overwrite), all optional),\n");
                    return showError("Failed to generate master key in sofware");
                    }
                }

            /* serialize the master key */
            dogecoin_hdnode_serialize_private (&node, chain, masterkey, sizeof(masterkey));
            }

        /* otherwise, generate a new master key from entropy */
        else {
            /* generate a new hd master key */
            hd_gen_master(chain, masterkey, sizeof(masterkey));
            }

        /* if silent is enabled, don't print the master key */
        if (!silent) {
            printf("bip32 extended master key: %s\n", masterkey);
            }

        dogecoin_mem_zero(masterkey, strlen(masterkey));
        }
    else if (strcmp(cmd, "print_keys") == 0) {
        if (!pkey)
            return showError("no extended key (-p)");
        if (!hd_print_node(chain, pkey))
            return showError("invalid extended key\n");
        }
    else if (strcmp(cmd, "derive_child_keys") == 0) {
        if (!pkey)
            return showError("no extended key (-p)");
        if (!derived_path)
            return showError("no derivation path (-m)");
        char newextkey[HDKEYLEN];

        //check if we derive a range of keys
        unsigned int maxlen = 1024;
        int posanum = -1;
        int posbnum = -1;
        int end = -1;
        uint64_t from = 0;
        uint64_t to = 0;

        static char digits[] = "0123456789";
        unsigned int i;
        for (i = 0; i < strlen(derived_path); i++) {
            if (i > maxlen) {
                break;
                }
            if (posanum > -1 && posbnum == -1) {
                if (derived_path[i] == '-') {
                    if (i - posanum >= 9) {
                        break;
                        }
                    posbnum = i + 1;
                    char buf[9] = { 0 };
                    memcpy_safe(buf, &derived_path[posanum], i - posanum);
                    from = strtoull(buf, NULL, 10);
                    }
                else if (!strchr(digits, derived_path[i])) {
                    posanum = -1;
                    break;
                    }
                }
            else if (posanum > -1 && posbnum > -1) {
                if (derived_path[i] == ']' || derived_path[i] == ')') {
                    if (i - posbnum >= 9) {
                        break;
                        }
                    char buf[9] = { 0 };
                    memcpy_safe(buf, &derived_path[posbnum], i - posbnum);
                    to = strtoull(buf, NULL, 10);
                    end = i + 1;
                    break;
                    }
                else if (!strchr(digits, derived_path[i])) {
                    // posbnum = -1; // value stored is never read
                    break;
                    }
                }
            if (derived_path[i] == '[' || derived_path[i] == '(') {
                posanum = i + 1;
                }
            }

        if (end > -1 && from <= to) {
            for (i = from; i <= to; i++) {
                char* keypathnew = dogecoin_char_vla(strlen(derived_path) + 16);
                memcpy_safe(keypathnew, derived_path, posanum - 1);
                char index[11] = { 0 };
                sprintf(index, "%lld", (long long)i);
                memcpy_safe(keypathnew + posanum - 1, index, strlen(index));
                memcpy_safe(keypathnew + posanum - 1 + strlen(index), &derived_path[end], strlen(derived_path) - end);

                if (!hd_derive(chain, pkey, keypathnew, newextkey, sizeof(newextkey)))
                    {
                    free(keypathnew);
                    return showError("Deriving child key failed\n");
                    }
                else
                    {
                    free(keypathnew);
                    hd_print_node(chain, newextkey);
                    }
                }
            }
        else {
            if (!hd_derive(chain, pkey, derived_path, newextkey, sizeof(newextkey)))
                return showError("Deriving child key failed\n");
            else
                hd_print_node(chain, newextkey);
            }
        }
    else if (strcmp(cmd, "sign") == 0) {
        // ./such -c sign -x <raw hex tx> -s <script pubkey> -i <input index> -h <sighash type> -p <private key>
        if (!txhex || !scripthex) {
            return showError("Missing tx-hex or script-hex (use -x, -s)\n");
            }

        if (strlen(txhex) > 1024 * 100) { //don't accept tx larger then 100kb
            return showError("tx too large (max 100kb)\n");
            }

        //deserialize transaction
        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex");
            }

        dogecoin_free(data_bin);

        if ((size_t)inputindex >= tx->vin->len) {
            dogecoin_tx_free(tx);
            return showError("Inputindex out of range");
            }

        uint8_t* script_data = dogecoin_uint8_vla(strlen(scripthex) / 2 + 1);
        utils_hex_to_bin(scripthex, script_data, strlen(scripthex), &outlen);
        cstring* script = cstr_new_buf(script_data, outlen);
        free(script_data);

        uint256_t sighash;
        dogecoin_mem_zero(sighash, sizeof(sighash));
        dogecoin_tx_sighash(tx, script, inputindex, sighashtype, sighash);

        char* hex = utils_uint8_to_hex(sighash, 32);
        utils_reverse_hex(hex, 64);

        enum dogecoin_tx_out_type type = dogecoin_script_classify(script, NULL);
        printf("script: %s\n", scripthex);
        printf("script-type: %s\n", dogecoin_tx_out_type_to_str(type));
        printf("inputindex: %d\n", inputindex);
        printf("sighashtype: %d\n", sighashtype);
        printf("hash: %s\n", hex);

        // sign
        dogecoin_bool sign = false;
        dogecoin_key key;
        dogecoin_privkey_init(&key);
        if (dogecoin_privkey_decode_wif(pkey, chain, &key)) {
            sign = true;
            }
        else {
            if (pkey) {
                if (strlen(pkey) > 50) {
                    dogecoin_tx_free(tx);
                    cstr_free(script, true);
                    return showError("Invalid wif privkey\n");
                    }
                }
            else {
                printf("No private key provided, signing will not happen\n");
                }
            }
        if (sign) {
            uint8_t sigcompact[64] = { 0 };
            size_t sigderlen = 74 + 1; //&hashtype
            uint8_t sigder_plus_hashtype[75] = { 0 };
            enum dogecoin_tx_sign_result res = dogecoin_tx_sign_input(tx, script, &key, inputindex, sighashtype, sigcompact, sigder_plus_hashtype, &sigderlen);
            cstr_free(script, true);

            if (res != DOGECOIN_SIGN_OK) {
                printf("!!!Sign error:%s\n", dogecoin_tx_sign_result_to_str(res));
                }

            char sigcompacthex[64 * 2 + 1] = { 0 };
            utils_bin_to_hex((unsigned char*)sigcompact, 64, sigcompacthex);

            char sigderhex[74 * 2 + 2 + 1]; //74 der, 2 hashtype, 1 nullbyte
            dogecoin_mem_zero(sigderhex, sizeof(sigderhex));
            utils_bin_to_hex((unsigned char*)sigder_plus_hashtype, sigderlen, sigderhex);

            printf("\nSignature created:\n");
            printf("signature compact: %s\n", sigcompacthex);
            printf("signature DER (+hashtype): %s\n", sigderhex);

            cstring* signed_tx = cstr_new_sz(1024);
            dogecoin_tx_serialize(signed_tx, tx);

            char* signed_tx_hex = dogecoin_char_vla(signed_tx->len * 2 + 1);
            utils_bin_to_hex((unsigned char*)signed_tx->str, signed_tx->len, signed_tx_hex);
            printf("signed TX: %s\n", signed_tx_hex);
            cstr_free(signed_tx, true);
            free(signed_tx_hex);
            }
        dogecoin_tx_free(tx);
        }
#ifdef USE_LIBOQS
    else if (strcmp(cmd, "pqc_carrier_redeemscript") == 0) {
        cstring* redeem = NULL;
        if (!dogecoin_pqc_carrier_build_redeemscript(&redeem)) {
            return showError("Failed to build carrier redeemScript");
        }
        char* hex = utils_uint8_to_hex((const uint8_t*)redeem->str, redeem->len);
        printf("redeemScript: %s\n", hex ? hex : "");
        cstr_free(redeem, true);
    }
    else if (strcmp(cmd, "pqc_carrier_scriptpubkey") == 0) {
        cstring* redeem = NULL;
        cstring* spk = NULL;
        if (!dogecoin_pqc_carrier_build_redeemscript(&redeem)) {
            return showError("Failed to build carrier redeemScript");
        }
        if (!dogecoin_pqc_carrier_build_p2sh_scriptpubkey(redeem, &spk)) {
            cstr_free(redeem, true);
            return showError("Failed to build carrier scriptPubKey");
        }
        char* hex = utils_uint8_to_hex((const uint8_t*)spk->str, spk->len);
        printf("carrier_p2sh_scriptpubkey: %s\n", hex ? hex : "");
        cstr_free(spk, true);
        cstr_free(redeem, true);
    }
    else if (strcmp(cmd, "pqc_carrier_mkpart") == 0) {
        /* CLI uses:
         * -k tag4 hex ("FLC1"/"DIL2"/"RCG4" as 8 hex chars),
         * -p PQ public key hex, -s PQ signature hex, -i part_index.
         * Note: -p/-s/-i reuse existing parser slots (pkey/scripthex/inputindex).
         */
        if (!pubkey || !pkey || !scripthex) {
            return showError("Missing tag4 (-k), pqc pubkey (-p), or pqc signature (-s)");
        }
        char tag8[8];
        if (!such_tag4_hex_to_tag8(pubkey, tag8)) {
            return showError("Invalid tag4 hex; expected 8 hex chars");
        }

        size_t pk_len = strlen(pkey) / 2;
        size_t sig_len = strlen(scripthex) / 2;
        if ((strlen(pkey) % 2) != 0 || (strlen(scripthex) % 2) != 0) {
            return showError("Invalid pubkey/signature hex");
        }
        uint8_t* pk = dogecoin_malloc(pk_len + 1);
        uint8_t* sig = dogecoin_malloc(sig_len + 1);
        if (!pk || !sig) {
            if (pk) dogecoin_free(pk);
            if (sig) dogecoin_free(sig);
            return showError("OOM");
        }
        size_t outlen = 0;
        utils_hex_to_bin(pkey, pk, strlen(pkey), &outlen);
        if (outlen != pk_len) {
            dogecoin_free(pk);
            dogecoin_free(sig);
            return showError("Invalid pubkey hex");
        }
        utils_hex_to_bin(scripthex, sig, strlen(scripthex), &outlen);
        if (outlen != sig_len) {
            dogecoin_free(pk);
            dogecoin_free(sig);
            return showError("Invalid signature hex");
        }

        size_t full_len = pk_len + sig_len;
        uint8_t* full = dogecoin_malloc(full_len + 1);
        if (!full) {
            dogecoin_free(pk);
            dogecoin_free(sig);
            return showError("OOM");
        }
        memcpy(full, pk, pk_len);
        memcpy(full + pk_len, sig, sig_len);
        dogecoin_free(pk);
        dogecoin_free(sig);

        size_t part_payload_max = DOGECOIN_PQC_CARRIER_MAX_CHUNKS * DOGECOIN_PQC_CARRIER_CHUNK_MAX;
        uint8_t part_total = (uint8_t)((full_len + part_payload_max - 1) / part_payload_max);
        uint8_t part_index = (uint8_t)inputindex; /* explicit part index from -i */
        if (part_total == 0 || part_index >= part_total) {
            dogecoin_free(full);
            return showError("part_index out of range");
        }
        size_t part_off = (size_t)part_index * part_payload_max;
        size_t part_len = full_len - part_off;
        if (part_len > part_payload_max) part_len = part_payload_max;

        cstring* redeem = NULL;
        cstring* scriptsig = NULL;
        cstring* carrier_spk = NULL;
        if (!dogecoin_pqc_carrier_build_redeemscript(&redeem)) {
            dogecoin_free(full);
            return showError("Failed to build carrier redeemScript");
        }
        if (!dogecoin_pqc_carrier_build_part_scriptsig(tag8, part_index, part_total, (uint16_t)pk_len, (uint16_t)full_len,
                                                       full + part_off, part_len, redeem, &scriptsig)) {
            cstr_free(redeem, true);
            dogecoin_free(full);
            return showError("Failed to build carrier part scriptsig");
        }
        if (!dogecoin_pqc_carrier_build_p2sh_scriptpubkey(redeem, &carrier_spk)) {
            cstr_free(scriptsig, true);
            cstr_free(redeem, true);
            dogecoin_free(full);
            return showError("Failed to build carrier scriptPubKey");
        }
        dogecoin_free(full);

        char* scriptsig_hex_tmp = utils_uint8_to_hex((const uint8_t*)scriptsig->str, scriptsig->len);
        char* scriptsig_hex = scriptsig_hex_tmp ? strdup(scriptsig_hex_tmp) : NULL;
        char* spk_hex_tmp = utils_uint8_to_hex((const uint8_t*)carrier_spk->str, carrier_spk->len);
        char* spk_hex = spk_hex_tmp ? strdup(spk_hex_tmp) : NULL;
        printf("carrier_part_total: %u\n", (unsigned)part_total);
        printf("carrier_part_index: %u\n", (unsigned)part_index);
        printf("carrier_p2sh_scriptpubkey: %s\n", spk_hex ? spk_hex : "");
        printf("carrier_part_scriptsig: %s\n", scriptsig_hex ? scriptsig_hex : "");
        if (scriptsig_hex) dogecoin_free(scriptsig_hex);
        if (spk_hex) dogecoin_free(spk_hex);

        cstr_free(carrier_spk, true);
        cstr_free(scriptsig, true);
        cstr_free(redeem, true);
    }
    else if (strcmp(cmd, "pqc_carrier_parsepart") == 0) {
        if (!txhex || (strlen(txhex) % 2) != 0) {
            return showError("Missing/invalid scriptsig hex (-x)");
        }
        size_t blen = strlen(txhex) / 2;
        uint8_t* b = dogecoin_malloc(blen + 1);
        if (!b) {
            return showError("OOM");
        }
        size_t outlen = 0;
        utils_hex_to_bin(txhex, b, strlen(txhex), &outlen);
        if (outlen != blen) {
            dogecoin_free(b);
            return showError("Invalid scriptsig hex");
        }
        cstring* scriptsig = cstr_new_buf(b, blen);
        dogecoin_free(b);
        if (!scriptsig) {
            return showError("OOM");
        }

        char tag8[9];
        uint8_t part_index = 0, part_total = 0;
        uint16_t pk_len = 0, full_len = 0;
        uint8_t* part_data = NULL;
        size_t part_data_len = 0;
        cstring* redeem = NULL;
        if (!dogecoin_pqc_carrier_parse_part_scriptsig(scriptsig, tag8, &part_index, &part_total, &pk_len, &full_len,
                                                       &part_data, &part_data_len, &redeem)) {
            cstr_free(scriptsig, true);
            return showError("Carrier part parse failed");
        }
        char* part_hex_tmp = utils_uint8_to_hex(part_data, part_data_len);
        char* part_hex = part_hex_tmp ? strdup(part_hex_tmp) : NULL;
        char* redeem_hex_tmp = utils_uint8_to_hex((const uint8_t*)redeem->str, redeem->len);
        char* redeem_hex = redeem_hex_tmp ? strdup(redeem_hex_tmp) : NULL;
        printf("tag8: %s\n", tag8);
        printf("part_index: %u\n", (unsigned)part_index);
        printf("part_total: %u\n", (unsigned)part_total);
        printf("pk_len: %u\n", (unsigned)pk_len);
        printf("full_len: %u\n", (unsigned)full_len);
        printf("part_data: %s\n", part_hex ? part_hex : "");
        printf("redeemScript: %s\n", redeem_hex ? redeem_hex : "");
        if (part_hex) dogecoin_free(part_hex);
        if (redeem_hex) dogecoin_free(redeem_hex);

        if (part_data) dogecoin_free(part_data);
        cstr_free(redeem, true);
        cstr_free(scriptsig, true);
    }
#endif
    else if (strcmp(cmd, "set_scriptsig") == 0) {
        if (!txhex || !scripthex) {
            return showError("Missing tx-hex or scriptSig-hex (use -x, -s)\n");
        }
        if ((strlen(txhex) % 2) != 0 || (strlen(scripthex) % 2) != 0) {
            return showError("Invalid tx/scriptSig hex\n");
        }
        if (strlen(txhex) > 1024 * 100) {
            return showError("tx too large (max 100kb)\n");
        }
        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex");
        }
        dogecoin_free(data_bin);
        if ((size_t)inputindex >= tx->vin->len) {
            dogecoin_tx_free(tx);
            return showError("Inputindex out of range");
        }
        dogecoin_tx_in* tx_in = vector_idx(tx->vin, inputindex);
        if (!tx_in->script_sig) {
            tx_in->script_sig = cstr_new_sz(32);
            if (!tx_in->script_sig) {
                dogecoin_tx_free(tx);
                return showError("Failed to allocate scriptSig");
            }
        }
        size_t ss_len = strlen(scripthex) / 2;
        uint8_t* ss_bin = dogecoin_malloc(ss_len + 1);
        if (!ss_bin) {
            dogecoin_tx_free(tx);
            return showError("OOM");
        }
        utils_hex_to_bin(scripthex, ss_bin, strlen(scripthex), &outlen);
        if (outlen != ss_len) {
            dogecoin_free(ss_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid scriptSig hex");
        }
        cstr_resize(tx_in->script_sig, 0);
        cstr_append_buf(tx_in->script_sig, ss_bin, ss_len);
        dogecoin_free(ss_bin);
        cstring* out_tx = cstr_new_sz(1024);
        dogecoin_tx_serialize(out_tx, tx);
        char* out_tx_hex = dogecoin_char_vla(out_tx->len * 2 + 1);
        utils_bin_to_hex((unsigned char*)out_tx->str, out_tx->len, out_tx_hex);
        printf("tx with scriptsig set: %s\n", out_tx_hex);
        cstr_free(out_tx, true);
        free(out_tx_hex);
        dogecoin_tx_free(tx);
    }
    else if (strcmp(cmd, "pqc_chunk_hex") == 0) {
        if (!txhex) {
            return showError("Missing payload hex (use -x)\n");
        }
        size_t max_chunk_bytes = sighashtype > 0 ? (size_t)sighashtype : 520;
        if (max_chunk_bytes == 0 || max_chunk_bytes > 520) {
            return showError("max_chunk_bytes must be in range 1..520 (use -h)");
        }

        vector_t* chunks = vector_new(8, such_cstring_free_cb);
        if (!such_hex_payload_chunks(txhex, max_chunk_bytes, chunks)) {
            vector_free(chunks, true);
            return showError("Failed to chunk payload hex");
        }
        printf("chunks: %zu\n", chunks->len);
        for (size_t i = 0; i < chunks->len; i++) {
            cstring* chunk = vector_idx(chunks, i);
            printf("chunk[%zu]: %s\n", i, chunk ? chunk->str : "");
        }
        vector_free(chunks, true);
    }
    /* tx_sighash32 is built unconditionally because the underlying helper
     * (dogecoin_tx_sighash32) lives in src/tx.c next to dogecoin_tx_sighash —
     * the ZK carrier needs it to compute the tx_base sighash that ZK proofs
     * are bound to as their `tx_binding` public input, mirroring the PQC
     * carrier signing model. */
    else if (strcmp(cmd, "tx_sighash32") == 0) {
        // ./such -c tx_sighash32 -x <raw hex tx> -s <script pubkey> -i <input index> -h <sighash type>
        if (!txhex || !scripthex) {
            return showError("Missing tx-hex or script-hex (use -x, -s)\n");
        }

        if (strlen(txhex) > 1024 * 100) { // don't accept tx larger than 100kb
            return showError("tx too large (max 100kb)\n");
        }

        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex");
        }
        dogecoin_free(data_bin);

        if ((size_t)inputindex >= tx->vin->len) {
            dogecoin_tx_free(tx);
            return showError("Inputindex out of range");
        }

        uint8_t* script_data = dogecoin_uint8_vla(strlen(scripthex) / 2 + 1);
        utils_hex_to_bin(scripthex, script_data, strlen(scripthex), &outlen);
        cstring* script = cstr_new_buf(script_data, outlen);
        free(script_data);

        uint8_t sighash32[32];
        dogecoin_mem_zero(sighash32, sizeof(sighash32));
        if (!dogecoin_tx_sighash32(tx, script, inputindex, sighashtype, sighash32)) {
            cstr_free(script, true);
            dogecoin_tx_free(tx);
            return showError("Failed to compute tx sighash");
        }

        char* sighash_hex = utils_uint8_to_hex(sighash32, sizeof(sighash32));
        printf("tx_sighash32: %s\n", sighash_hex);
        cstr_free(script, true);
        dogecoin_tx_free(tx);
    }
    else if (strcmp(cmd, "comp2der") == 0) {
        // ./such -c comp2der -s <compact signature>
        if (!scripthex || strlen(scripthex) != 128) {
            return showError("Missing signature or invalid length (use hex, 128 chars == 64 bytes)\n");
            }

        size_t outlen = 0;
        uint8_t sig_comp[65];
        printf("%s\n", scripthex);
        utils_hex_to_bin(scripthex, sig_comp, 128, &outlen);

        unsigned char sigder[74];
        size_t sigderlen = sizeof(sigder);

        dogecoin_ecc_compact_to_der_normalized(sig_comp, sigder, &sigderlen);
        char* hexbuf = dogecoin_char_vla(sigderlen * 2 + 1);
        utils_bin_to_hex(sigder, sigderlen, hexbuf);
        printf("DER: %s\n", hexbuf);
        free(hexbuf);
        }
    else if (strcmp(cmd, "bip32maintotest") == 0) { /* Creating a bip32 master key from a private key. */
        dogecoin_hdnode node;
        if (!dogecoin_hdnode_deserialize(pkey, chain, &node)) {
            return showError("dogecoin_hd_deserialize failed!\n");
            }
        char masterkeyhex[HDKEYLEN];
        int strsize = HDKEYLEN;
        dogecoin_hdnode_serialize_private(&node, &dogecoin_chainparams_test, masterkeyhex, strsize);
        printf("xpriv: %s\n", masterkeyhex);
        dogecoin_hdnode_serialize_public(&node, &dogecoin_chainparams_test, masterkeyhex, strsize);
        printf("xpub: %s\n", masterkeyhex);
        }
    else if (strcmp(cmd, "generate_mnemonic") == 0) { /* Creating a bip32 master key from a mnemonic. */

        /* if tpm is enabled, generate mnemonic with tpm */
        if (encrypted) {

            /* if overwrite is enabled, ask for confirmation */
            if (overwrite) {
                printf("Overwrite? Y/N\n");

                char buffer[MAX_LEN];
                /* get user input */
                if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
                    if (buffer[0] != 'Y' && buffer[0] != 'y') {

                        /* if not confirmed, abort */
                        printf("aborted\n");
                        dogecoin_ecc_stop();
                        return 1;
                        }
                    }
                }

            if (tpm) {
                /* Try to generate mnemonic with TPM first */
                if (!generateRandomEnglishMnemonicTPM(mnemonic, file_num, overwrite)) {
                    printf("generate_mnemonic -y <file_num>, -j (use_tpm), -w (overwrite), -b (silent),\n");
                    return showError("Failed to generate/encrypt mnemonic in TPM\n");
                    }
                }

            else {
                /* generate mnemonic with software */
                if (generateRandomEnglishMnemonicSW(mnemonic, file_num, overwrite, NULL, NULL) == false) {
                    printf("generate_mnemonic -y <file_num>, -j (use_tpm), -w (overwrite), -b (silent),\n");
                    return showError("Failed to generate/encrypt mnemonic in software");
                    }
                }
            }

        /* else generate mnemonic with ecc */
        else if (generateEnglishMnemonic(entropy, entropy_size, mnemonic) == -1) {
            printf("generate_mnemonic (-e <hex_entropy>, optional),\n");
            return showError("Failed to generate mnemonic\n");
            }

        /* if not silent, display mnemonic */
        if (!silent) {
            printf("%s\n", mnemonic);
            }
        }
    else if (strcmp(cmd, "list_encryption_keys_in_tpm") == 0) {

        /* list encryption keys in TPM */
        wchar_t *names[MAX_FILES] = {0};
        size_t count = 0;

        if (dogecoin_list_encryption_keys_in_tpm(names, &count) == false) {
            return showError("failed to list encryption keys in TPM\n");
            }

        /* display encryption key names */
        for (size_t i = 0; i < count; i++) {
            wprintf(L"%ls\n", names[i]);
            }
        /* free memory */
        for (size_t i = 0; i < count; i++) {
            dogecoin_free(names[i]);
            }
        }
    else if (strcmp(cmd, "decrypt_master_key") == 0) {

        /* if tpm is enabled, decrypt master key from tpm */
        if (encrypted) {
            printf("Decrypt master key? Y/N\n");

            char buffer[MAX_LEN];
            /* get user input */
            if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
                if (buffer[0] != 'Y' && buffer[0] != 'y') {

                    /* if not confirmed, abort */
                    printf("aborted\n");
                    dogecoin_ecc_stop();
                    return 1;
                    }
                }

            dogecoin_hdnode node;

            if (tpm) {
                /* decrypt master key from tpm */
                if (!dogecoin_decrypt_hdnode_with_tpm (&node, file_num)) {
                    printf("decrypt_master_key (requires -y <file_num>, -j (use_tpm) optional),\n");
                    return showError("Failed to decrypt master key in TPM\n");
                    }
                }

            else {
                /* decrypt master key from software */
                if (dogecoin_decrypt_hdnode_with_sw (&node, file_num, NULL, NULL) == false) {
                    printf("decrypt_master_key (requires -y <file_num>, -j (use_tpm) optional),\n");
                    return showError("failed to decrypt master key with software\n");
                    }
                }

            /* serialize the master key */
            char masterkey[HDKEYLEN];
            dogecoin_hdnode_serialize_private (&node, chain, masterkey, sizeof(masterkey));

            /* display the master key */
            printf("bip32 extended master key: %s\n", masterkey);
            dogecoin_mem_zero(masterkey, strlen(masterkey));
            }

        /* else display usage */
        else {
            return showError("decrypt_master_key (requires -y <file_num>, -j (use_tpm) optional\n");
            }
        }
    else if (strcmp(cmd, "decrypt_mnemonic") == 0) {

        /* if tpm is enabled, decrypt mnemonic from tpm */
        if (encrypted) {
            printf("Decrypt mnemonic? Y/N\n");

            char buffer[MAX_LEN];
            /* get user input */
            if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
                if (buffer[0] != 'Y' && buffer[0] != 'y') {

                    /* if not confirmed, abort */
                    printf("aborted\n");
                    dogecoin_ecc_stop();
                    return 1;
                    }
                }

            if (tpm) {
                /* decrypt mnemonic from tpm */
                if (!dogecoin_decrypt_mnemonic_with_tpm (mnemonic, file_num)) {
                    printf("decrypt_mnemonic (requires -y <file_num>, -j (use_tpm) optional),\n");
                    return showError("failed to decrypt mnemonic with tpm\n");
                    }
                }

            else {
                /* decrypt mnemonic from software */
                if (dogecoin_decrypt_mnemonic_with_sw (mnemonic, file_num, NULL, NULL) == false) {
                    printf("decrypt_mnemonic (requires -y <file_num>, -j (use_tpm) optional),\n");
                    return showError("failed to decrypt mnemonic with software\n");
                    }
                }

            /* display mnemonic */
            printf("%s\n", mnemonic);
            }

        /* else display usage */
        else {
            return showError("decrypt_mnemonic (requires -y <file_num>, -j (use_tpm) optional\n");
            }
        }
    else if (strcmp(cmd, "seed_to_master_key") == 0) { /* Creating a bip32 master key from a seed. */

        /* if tpm is enabled, get seed from tpm */
        if (encrypted) {
            printf("Decrypt seed for master key? Y/N\n");

            char buffer[MAX_LEN];
            /* get user input */
            if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
                if (buffer[0] != 'Y' && buffer[0] != 'y') {

                    /* if not confirmed, abort */
                    printf("aborted\n");
                    dogecoin_ecc_stop();
                    return 1;
                    }
                }

            if (tpm) {
                /* get seed from tpm */
                if (!dogecoin_decrypt_seed_with_tpm (seed, file_num)) {
                    printf("seed_to_master_key (requires -y <file_num>, -j (use_tpm) optional),\n");
                    return showError("failed to decrypt seed with tpm\n");
                    }
                }

            else {
                /* get seed from software */
                if (dogecoin_decrypt_seed_with_sw (seed, file_num, NULL, NULL) == false) {
                    printf("seed_to_master_key (requires -y <file_num>, -j (use_tpm) optional),\n");
                    return showError("failed to decrypt seed with software\n");
                    }
                }
            }

            /* print master key from seed */
            dogecoin_hdnode node;
            char masterkey[HDKEYLEN];
            dogecoin_hdnode_from_seed(seed, sizeof(seed), &node);
            dogecoin_hdnode_serialize_private(&node, chain, masterkey, sizeof(masterkey));
            printf("bip32 extended master key: %s\n", masterkey);
            dogecoin_mem_zero(masterkey, strlen(masterkey));
            dogecoin_mem_zero(seed, sizeof(seed));
        }
    else if (strcmp(cmd, "mnemonic_to_key") == 0) { /* Creating a bip32 master key from a mnemonic. */

        /* if tpm is enabled, get mnemonic from tpm */
        if (encrypted) {
            printf("Decrypt mnemonic for master key? Y/N\n");

            /* get user input */
            char c = getchar();
            if (c != 'Y' && c != 'y') {

                /* if not confirmed, abort */
                printf("aborted\n");
                dogecoin_ecc_stop();
                return 1;
                }

            if (tpm) {
                /* get mnemonic from tpm */
                if (!dogecoin_decrypt_mnemonic_with_tpm (mnemonic, file_num)) {
                    printf("mnemonic_to_key (requires -y <file_num>, -j (use_tpm) optional),\n");
                    return showError("failed to decrypt mnemonic with tpm\n");
                    }
                }

            else {
                /* get mnemonic from software */
                if (dogecoin_decrypt_mnemonic_with_sw (mnemonic, file_num, NULL, NULL) == false) {
                    printf("mnemonic_to_key (requires -y <file_num>, -j (use_tpm) optional),\n");
                    return showError("failed to decrypt mnemonic with software\n");
                    }
                }
            }
        /* else display usage */
        else if (!mnemonic_in) {
            return showError("mnemonic_to_key (-n <seed_phrase> or requires -y <file_num>, -j (use_tpm) optional\n");
            }

        /* generate private key from mnemonic */
        dogecoin_hdnode node;
        dogecoin_hdnode extended_key;
        SEED seed;
        KEY_PATH keypath;
        char wifstr[PRIVKEYWIFLEN];
        size_t wiflen = sizeof(wifstr);

        /* generate seed from mnemonic */
        if (dogecoin_seed_from_mnemonic(encrypted ? mnemonic : mnemonic_in, pass, seed) == -1) {
            printf("mnemonic_to_key (-n <seed_phrase> or requires -y <file_num>, -j (use_tpm) optional),\n");

            /* clear and free passphrase */
            if (pass) {
                dogecoin_mem_zero(pass, strlen(pass));
                dogecoin_free(pass);
                }
            return showError("failed to generate seed from mnemonic\n");
            }

        /* clear and free passphrase */
        if (pass) {
            dogecoin_mem_zero(pass, strlen(pass));
            dogecoin_free(pass);
            }

        /* generate master key from seed */
        dogecoin_hdnode_from_seed(seed, sizeof(seed), &node);

        /* derive bip44 extended key from master key */
        derive_bip44_extended_key(&node, &account, &inputindex, change_level, NULL, (chain == &dogecoin_chainparams_test), keypath, &extended_key);
        printf("keypath: %s\n", keypath);

        /* encode private key to wif */
        dogecoin_privkey_encode_wif((dogecoin_key*) extended_key.private_key, chain, wifstr, &wiflen);
        printf("private key (wif): %s\n", wifstr);

        }
    else if (strcmp(cmd, "mnemonic_to_addresses") == 0) { /* Creating wif addresses from a mnemonic via slip44. */

        char hd_pubkey_address[P2PKHLEN];

        /* if tpm is enabled, get mnemonic from tpm */
        if (encrypted) {
            printf("Decrypt mnemonic for addresses? Y/N\n");

            char buffer[MAX_LEN];
            /* get user input */
            if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
                if (buffer[0] != 'Y' && buffer[0] != 'y') {

                    /* if not confirmed, abort */
                    printf("aborted\n");
                    dogecoin_ecc_stop();
                    return 1;
                    }
                }

            if (tpm) {
                /* get mnemonic from tpm */
                if (!dogecoin_decrypt_mnemonic_with_tpm (mnemonic, file_num)) {
                    printf("mnemonic_to_addresses (requires -y <file_num>, -j (use_tpm), -o <account_int>, -g <change_level>, -i <address_index> and -a, all optional),\n");
                    return showError("failed to decrypt mnemonic with tpm\n");
                    }
                }

            else {
                /* get mnemonic from software */
                if (dogecoin_decrypt_mnemonic_with_sw (mnemonic, file_num, NULL, NULL) == false) {
                    printf("mnemonic_to_addresses (requires -y <file_num>, -j (use_tpm), -o <account_int>, -g <change_level>, -i <address_index> and -a, all optional),\n");
                    return showError("failed to decrypt mnemonic with software\n");
                    }
                }
            }

        /* else display usage */
        else if (!mnemonic_in) {
            return showError("mnemonic_to_addresses (requires -n <seed_phrase> or -y <file_num>, -j (use_tpm), -o <account_int>, -g <change_level>, -i <address_index> and -a (all optional))\n");
            }

        /* generate wif address for slip44 account, index, and change_level, from bip39 mnemonic and password (optional) */
        if (inputindex == 0) {

            /* Generate all addresses for the account. */
            for (int i = 0; i < 20; i++) {
                if (getDerivedHDAddressFromMnemonic(account, i, change_level, encrypted ? mnemonic : mnemonic_in, pass, hd_pubkey_address, (chain == &dogecoin_chainparams_test)) == -1) {

                    /* clear and free passphrase */
                    if (pass) {
                        dogecoin_mem_zero(pass, strlen(pass));
                        dogecoin_free(pass);
                        }
                    return showError("Failed to generate wif address from mnemonic\n");
                    }
                printf("Address %d: %s\n", i, hd_pubkey_address);
                }
            }
        else {

            /* Generate a single address for the account. */
            if (getDerivedHDAddressFromMnemonic(account, inputindex, change_level, encrypted ? mnemonic : mnemonic_in, pass, hd_pubkey_address, (chain == &dogecoin_chainparams_test)) == -1) {
                printf("mnemonic_to_addresses (requires -n <seed_phrase> or -y <file_num>, -j (use_tpm), -o <account_int>, -g <change_level>, -i <address_index> and -a, all optional),\n");

                /* clear and free passphrase */
                if (pass) {
                    dogecoin_mem_zero(pass, strlen(pass));
                    dogecoin_free(pass);
                    }
                return showError("Failed to generate wif address from mnemonic\n");
                }

            printf("Address %d: %s\n", inputindex, hd_pubkey_address);
            }

        /* clear and free passphrase */
        if (pass) {
            dogecoin_mem_zero(pass, strlen(pass));
            dogecoin_free(pass);
            }
        }
    else if (strcmp(cmd, "slip0039_split") == 0 || strcmp(cmd, "slip39_split") == 0) {
        /* ./such -c slip39_split -x <secret_hex> -o <threshold> -i <share_count> */
        const uint8_t s39_threshold   = (uint8_t)account;
        const uint8_t s39_share_count = (uint8_t)inputindex;

        if (!txhex || !account || !inputindex) {
            return showError("slip39_split requires -x <secret_hex>, -o <threshold>, -i <share_count>\n");
            }
        if (s39_threshold > SLIP0039_MAX_SHARES || s39_share_count > SLIP0039_MAX_SHARES ||
                s39_threshold > s39_share_count) {
            return showError("Invalid threshold or share_count for slip39_split\n");
            }

        size_t hlen = strlen(txhex);
        if (hlen == 0 || (hlen % 2) != 0 || hlen > (MAX_SEED_SIZE * 2)) {
            return showError("Invalid secret hex length for slip39_split\n");
            }
        for (size_t hi = 0; hi < hlen; ++hi) {
            if (utils_hex_digit(txhex[hi]) < 0) {
                return showError("Invalid secret hex data for slip39_split\n");
                }
            }

        uint8_t s39_secret[MAX_SEED_SIZE];
        dogecoin_mem_zero(s39_secret, sizeof(s39_secret));
        size_t s39_secret_len = 0;
        utils_hex_to_bin(txhex, s39_secret, hlen, &s39_secret_len);
        if (!s39_secret_len || s39_secret_len > MAX_SEED_SIZE) {
            return showError("Failed to parse secret hex for slip39_split\n");
            }

        SLIP0039_SHARE s39_shares[SLIP0039_MAX_SHARES];
        dogecoin_mem_zero(s39_shares, sizeof(s39_shares));
        if (dogecoin_slip0039_generate_shares(s39_secret, s39_secret_len, s39_threshold,
                                              s39_share_count, s39_shares) != 0) {
            dogecoin_mem_zero(s39_secret, sizeof(s39_secret));
            return showError("Failed to generate SLIP-0039 shares\n");
            }
        for (uint32_t si = 0; si < s39_share_count; ++si) {
            printf("%s\n", s39_shares[si]);
            }
        dogecoin_mem_zero(s39_secret, sizeof(s39_secret));
        dogecoin_mem_zero(s39_shares, sizeof(s39_shares));
        }
    else if (strcmp(cmd, "slip0039_recover") == 0 || strcmp(cmd, "slip39_recover") == 0) {
        /* ./such -c slip39_recover -x "<share1>,<share2>,..." */
        if (!txhex || strlen(txhex) == 0) {
            return showError("slip39_recover requires -x <share1,share2,...>\n");
            }

        size_t s39_csv_len = strlen(txhex);
        char* s39_csv = dogecoin_char_vla(s39_csv_len + 1);
        if (!s39_csv) {
            return showError("Failed to allocate memory for share list\n");
            }
        memcpy(s39_csv, txhex, s39_csv_len + 1);

        const char* s39_share_ptrs[SLIP0039_MAX_SHARES];
        size_t s39_share_count = 0;
        char* s39_tok = strtok(s39_csv, ",");
        while (s39_tok && s39_share_count < SLIP0039_MAX_SHARES) {
            while (*s39_tok == ' ') s39_tok++;
            s39_share_ptrs[s39_share_count++] = s39_tok;
            s39_tok = strtok(NULL, ",");
            }
        if (s39_tok != NULL) {
            dogecoin_mem_zero(s39_csv, s39_csv_len + 1);
            dogecoin_free(s39_csv);
            return showError("Too many shares for slip39_recover\n");
            }
        if (s39_share_count == 0) {
            dogecoin_mem_zero(s39_csv, s39_csv_len + 1);
            dogecoin_free(s39_csv);
            return showError("No shares supplied for slip39_recover\n");
            }

        uint8_t s39_recovered[MAX_SEED_SIZE];
        dogecoin_mem_zero(s39_recovered, sizeof(s39_recovered));
        size_t s39_recovered_len = sizeof(s39_recovered);
        if (dogecoin_slip0039_recover_secret(s39_share_ptrs, s39_share_count, NULL, 0,
                                             s39_recovered, &s39_recovered_len) != 0) {
            dogecoin_mem_zero(s39_csv, s39_csv_len + 1);
            dogecoin_free(s39_csv);
            dogecoin_mem_zero(s39_recovered, sizeof(s39_recovered));
            return showError("Failed to recover SLIP-0039 secret\n");
            }

        char s39_hex[(MAX_SEED_SIZE * 2) + 1];
        dogecoin_mem_zero(s39_hex, sizeof(s39_hex));
        utils_bin_to_hex(s39_recovered, s39_recovered_len, s39_hex);
        printf("%s\n", s39_hex);

        dogecoin_mem_zero(s39_hex, sizeof(s39_hex));
        dogecoin_mem_zero(s39_csv, s39_csv_len + 1);
        dogecoin_free(s39_csv);
        dogecoin_mem_zero(s39_recovered, sizeof(s39_recovered));
        }
    else if (strcmp(cmd, "signmessage") == 0) {
        // ./such -c signmessage -x "<message>" -p <private key>
        if (!txhex) {
            return showError("Missing message (use -x)\n");
            }

        if (strlen(txhex) > 1024 * 100) { //don't accept tx larger then 100kb
            return showError("tx too large (max 100kb)\n");
            }

        eckey* key = cli_eckey_from_privkey(pkey);
        char* sig = sign_message(key->private_key_wif, txhex);
        printf("message: %s\n", txhex);
        printf("content: %s\n", sig);
        printf("address: %s\n", key->address);
        dogecoin_free(key);
        dogecoin_free(sig);
        }
    else if (strcmp(cmd, "verifymessage") == 0) {
        // ./such -c verifymessage -x "<message>" -s <signature> -k <address>
        if (!txhex || !scripthex || !pubkey) {
            return showError("Missing message or signature or address (use -x, -s, -k)\n");
            }

        if (strlen(txhex) > 1024 * 100) { //don't accept tx larger then 100kb
            return showError("tx too large (max 100kb)\n");
            }

        if (verify_message(scripthex, txhex, pubkey)) {
            printf("Message is verified!\n");
        } else {
            printf("Message is not valid!\n");
        }
        }
    else if (strcmp(cmd, "transaction") == 0) {
        main_menu();
        }
#ifdef USE_LIBOQS
    else if (strcmp(cmd, "falcon_keygen") == 0) {
        // ./such -c falcon_keygen
        uint8_t *pk = NULL, *sk = NULL;
        size_t pk_len = 0, sk_len = 0;
        
        printf("Generating Falcon-512 keypair...\n");
        
        if (!dogecoin_falcon512_keypair(&pk, &pk_len, &sk, &sk_len)) {
            return showError("Failed to generate Falcon-512 keypair\n");
        }
        
        char* pk_hex = dogecoin_malloc(pk_len * 2 + 1);
        char* sk_hex = dogecoin_malloc(sk_len * 2 + 1);
        if (!pk_hex || !sk_hex) {
            if (pk_hex) dogecoin_free(pk_hex);
            if (sk_hex) dogecoin_free(sk_hex);
            dogecoin_free(pk);
            dogecoin_free(sk);
            return showError("Failed to allocate Falcon key hex buffers\n");
        }
        utils_bin_to_hex(pk, pk_len, pk_hex);
        utils_bin_to_hex(sk, sk_len, sk_hex);
        
        printf("\n=== Falcon-512 Keypair Generated ===\n");
        printf("public key:  %s\n", pk_hex);
        printf("secret key:  %s\n", sk_hex);
        printf("pk length:   %zu bytes\n", pk_len);
        printf("sk length:   %zu bytes\n", sk_len);
        printf("\n⚠️  Keep your secret key safe! Anyone with it can sign messages.\n");
        
        dogecoin_free(pk_hex);
        dogecoin_free(sk_hex);
        dogecoin_free(pk);
        dogecoin_free(sk);
        }
    else if (strcmp(cmd, "falcon_sign") == 0) {
        // ./such -c falcon_sign -p <secret_key_hex> -x <message_hex>
        // or:    -c falcon_sign --sk-file <path> -x <message_hex>
        dogecoin_bool sk_hex_owned = false;
        char* sk_hex = such_resolve_sk_hex(pkey, sk_file, &sk_hex_owned);
        if (!sk_hex) {
            return showError("Missing secret key (use -p <hex> or --sk-file <path>)\n");
        }
        if (!txhex) {
            such_release_sk_hex(sk_hex, sk_hex_owned);
            return showError("Missing message (use -x)\n");
        }
        
        printf("Signing message with Falcon-512...\n");
        
        if ((strlen(sk_hex) % 2) != 0) {
            such_release_sk_hex(sk_hex, sk_hex_owned);
            return showError("Invalid secret key hex\n");
        }
        size_t sk_len = strlen(sk_hex) / 2;
        uint8_t* sk = dogecoin_malloc(sk_len);
        size_t sk_outlen = 0;
        utils_hex_to_bin(sk_hex, sk, strlen(sk_hex), &sk_outlen);
        such_release_sk_hex(sk_hex, sk_hex_owned);
        if (sk_outlen != sk_len) {
            dogecoin_free(sk);
            return showError("Invalid secret key hex\n");
        }
        
        if ((strlen(txhex) % 2) != 0) {
            dogecoin_free(sk);
            return showError("Invalid message hex\n");
        }
        size_t msg_len = strlen(txhex) / 2;
        uint8_t* msg = dogecoin_malloc(msg_len);
        size_t msg_outlen = 0;
        utils_hex_to_bin(txhex, msg, strlen(txhex), &msg_outlen);
        if (msg_outlen != msg_len) {
            dogecoin_free(sk);
            dogecoin_free(msg);
            return showError("Invalid message hex\n");
        }
        
        // Sign (allocates new buffer that must be freed)
        uint8_t* sig = NULL;
        size_t sig_len = 0;
        
        if (!dogecoin_falcon512_sign(sk, sk_len, msg, msg_len, &sig, &sig_len)) {
            dogecoin_free(sk);
            dogecoin_free(msg);
            return showError("Failed to sign message with Falcon-512\n");
        }
        
        // utils_uint8_to_hex returns static buffer, don't free
        char* sig_hex = utils_uint8_to_hex(sig, sig_len);
        
        printf("\n=== Falcon-512 Signature Generated ===\n");
        printf("signature:   %s\n", sig_hex);
        printf("sig length:  %zu bytes\n", sig_len);
        printf("msg length:  %zu bytes\n", msg_len);
        
        dogecoin_free(sk);
        dogecoin_free(msg);
        dogecoin_free(sig);
        }
    else if (strcmp(cmd, "falcon_verify") == 0) {
        // ./such -c falcon_verify -k <public_key_hex> -x <message_hex> -s <signature_hex>
        if (!pubkey) {
            return showError("Missing public key (use -k)\n");
        }
        if (!txhex) {
            return showError("Missing message (use -x)\n");
        }
        if (!scripthex) {
            return showError("Missing signature (use -s)\n");
        }
        
        printf("Verifying Falcon-512 signature...\n");
        
        if ((strlen(pubkey) % 2) != 0) {
            return showError("Invalid public key hex\n");
        }
        size_t pk_len = strlen(pubkey) / 2;
        uint8_t* pk = dogecoin_malloc(pk_len);
        size_t pk_outlen = 0;
        utils_hex_to_bin(pubkey, pk, strlen(pubkey), &pk_outlen);
        if (pk_outlen != pk_len) {
            dogecoin_free(pk);
            return showError("Invalid public key hex\n");
        }
        
        if ((strlen(txhex) % 2) != 0) {
            dogecoin_free(pk);
            return showError("Invalid message hex\n");
        }
        size_t msg_len = strlen(txhex) / 2;
        uint8_t* msg = dogecoin_malloc(msg_len);
        size_t msg_outlen = 0;
        utils_hex_to_bin(txhex, msg, strlen(txhex), &msg_outlen);
        if (msg_outlen != msg_len) {
            dogecoin_free(pk);
            dogecoin_free(msg);
            return showError("Invalid message hex\n");
        }
        
        if ((strlen(scripthex) % 2) != 0) {
            dogecoin_free(pk);
            dogecoin_free(msg);
            return showError("Invalid signature hex\n");
        }
        size_t sig_len = strlen(scripthex) / 2;
        uint8_t* sig = dogecoin_malloc(sig_len);
        size_t sig_outlen = 0;
        utils_hex_to_bin(scripthex, sig, strlen(scripthex), &sig_outlen);
        if (sig_outlen != sig_len) {
            dogecoin_free(pk);
            dogecoin_free(msg);
            dogecoin_free(sig);
            return showError("Invalid signature hex\n");
        }
        
        // Verify
        dogecoin_bool verified = dogecoin_falcon512_verify(pk, pk_len, msg, msg_len, sig, sig_len);
        
        printf("\n=== Falcon-512 Verification Result ===\n");
        if (verified) {
            printf("✓ VERIFIED: Signature is valid!\n");
            printf("The signature is authentic for this message and public key.\n");
        } else {
            printf("✗ FAILED: Signature is invalid!\n");
            printf("The signature does NOT match the message/public key.\n");
        }
        
        if (!verified) {
            dogecoin_free(pk);
            dogecoin_free(msg);
            dogecoin_free(sig);
            dogecoin_ecc_stop();
            return 1;
        }
        dogecoin_free(pk);
        dogecoin_free(msg);
        dogecoin_free(sig);
        }
    else if (strcmp(cmd, "falcon_commit") == 0) {
        // ./such -c falcon_commit -k <public_key_hex> -s <signature_hex>
        if (!pubkey) {
            return showError("Missing public key (use -k)\n");
        }
        if (!scripthex) {
            return showError("Missing signature (use -s)\n");
        }
        
        printf("Generating Falcon-512 commitment...\n");
        
        if ((strlen(pubkey) % 2) != 0) {
            return showError("Invalid public key hex\n");
        }
        size_t pk_len = strlen(pubkey) / 2;
        uint8_t* pk = dogecoin_malloc(pk_len);
        size_t pk_outlen = 0;
        utils_hex_to_bin(pubkey, pk, strlen(pubkey), &pk_outlen);
        if (pk_outlen != pk_len) {
            dogecoin_free(pk);
            return showError("Invalid public key hex\n");
        }
        
        if ((strlen(scripthex) % 2) != 0) {
            dogecoin_free(pk);
            return showError("Invalid signature hex\n");
        }
        size_t sig_len = strlen(scripthex) / 2;
        uint8_t* sig = dogecoin_malloc(sig_len);
        size_t sig_outlen = 0;
        utils_hex_to_bin(scripthex, sig, strlen(scripthex), &sig_outlen);
        if (sig_outlen != sig_len) {
            dogecoin_free(pk);
            dogecoin_free(sig);
            return showError("Invalid signature hex\n");
        }
        
        // Generate commitment
        uint8_t commit[32];
        if (!dogecoin_falcon512_commit_bytes(pk, pk_len, sig, sig_len, commit)) {
            dogecoin_free(pk);
            dogecoin_free(sig);
            return showError("Failed to generate Falcon-512 commitment\n");
        }
        
        char commit_hex[65];
        utils_bin_to_hex(commit, 32, commit_hex);
        
        printf("\n=== Falcon-512 Commitment Generated ===\n");
        printf("commitment:  %s\n", commit_hex);
        printf("length:      32 bytes\n");
        printf("\nThis commitment can be included in an OP_RETURN output:\n");
        printf("OP_RETURN script: 6a24464c4331%s\n", commit_hex);
        printf("\nTo verify off-chain:\n");
        printf("1. Get the full signature from the signer\n");
        printf("2. Recompute: commit = SHA256(public_key || signature)\n");
        printf("3. Compare with this on-chain commitment\n");
        dogecoin_free(pk);
        dogecoin_free(sig);
        }
    else if (strcmp(cmd, "dilithium2_keygen") == 0) {
        uint8_t *pk = NULL, *sk = NULL;
        size_t pk_len = 0, sk_len = 0;
        printf("Generating Dilithium2 keypair...\n");
        if (!dogecoin_dilithium2_keypair(&pk, &pk_len, &sk, &sk_len)) {
            return showError("Failed to generate Dilithium2 keypair\n");
        }
        char* pk_hex = dogecoin_malloc(pk_len * 2 + 1);
        char* sk_hex = dogecoin_malloc(sk_len * 2 + 1);
        if (!pk_hex || !sk_hex) {
            if (pk_hex) dogecoin_free(pk_hex);
            if (sk_hex) dogecoin_free(sk_hex);
            dogecoin_free(pk);
            dogecoin_free(sk);
            return showError("Failed to allocate Dilithium2 key hex buffers\n");
        }
        utils_bin_to_hex(pk, pk_len, pk_hex);
        utils_bin_to_hex(sk, sk_len, sk_hex);
        printf("\n=== Dilithium2 Keypair Generated ===\n");
        printf("public key:  %s\n", pk_hex);
        printf("secret key:  %s\n", sk_hex);
        printf("pk length:   %zu bytes\n", pk_len);
        printf("sk length:   %zu bytes\n", sk_len);
        dogecoin_free(pk_hex);
        dogecoin_free(sk_hex);
        dogecoin_free(pk);
        dogecoin_free(sk);
    }
    else if (strcmp(cmd, "dilithium2_sign") == 0) {
        dogecoin_bool sk_hex_owned = false;
        char* sk_hex = such_resolve_sk_hex(pkey, sk_file, &sk_hex_owned);
        if (!sk_hex) return showError("Missing secret key (use -p <hex> or --sk-file <path>)\n");
        if (!txhex) { such_release_sk_hex(sk_hex, sk_hex_owned); return showError("Missing message (use -x)\n"); }
        if ((strlen(sk_hex) % 2) != 0) { such_release_sk_hex(sk_hex, sk_hex_owned); return showError("Invalid secret key hex\n"); }
        size_t sk_len = strlen(sk_hex) / 2;
        uint8_t* sk = dogecoin_malloc(sk_len);
        size_t sk_outlen = 0;
        utils_hex_to_bin(sk_hex, sk, strlen(sk_hex), &sk_outlen);
        such_release_sk_hex(sk_hex, sk_hex_owned);
        if (sk_outlen != sk_len) { dogecoin_free(sk); return showError("Invalid secret key hex\n"); }
        if ((strlen(txhex) % 2) != 0) { dogecoin_free(sk); return showError("Invalid message hex\n"); }
        size_t msg_len = strlen(txhex) / 2;
        uint8_t* msg = dogecoin_malloc(msg_len);
        size_t msg_outlen = 0;
        utils_hex_to_bin(txhex, msg, strlen(txhex), &msg_outlen);
        if (msg_outlen != msg_len) { dogecoin_free(sk); dogecoin_free(msg); return showError("Invalid message hex\n"); }
        uint8_t* sig = NULL; size_t sig_len = 0;
        if (!dogecoin_dilithium2_sign(sk, sk_len, msg, msg_len, &sig, &sig_len)) {
            dogecoin_free(sk); dogecoin_free(msg);
            return showError("Failed to sign message with Dilithium2\n");
        }
        char* sig_hex = utils_uint8_to_hex(sig, sig_len);
        printf("\n=== Dilithium2 Signature Generated ===\n");
        printf("signature:   %s\n", sig_hex);
        printf("sig length:  %zu bytes\n", sig_len);
        printf("msg length:  %zu bytes\n", msg_len);
        dogecoin_free(sk); dogecoin_free(msg); dogecoin_free(sig);
    }
    else if (strcmp(cmd, "dilithium2_verify") == 0) {
        if (!pubkey) return showError("Missing public key (use -k)\n");
        if (!txhex) return showError("Missing message (use -x)\n");
        if (!scripthex) return showError("Missing signature (use -s)\n");
        if ((strlen(pubkey) % 2) != 0) return showError("Invalid public key hex\n");
        size_t pk_len = strlen(pubkey) / 2;
        uint8_t* pk = dogecoin_malloc(pk_len);
        size_t pk_outlen = 0;
        utils_hex_to_bin(pubkey, pk, strlen(pubkey), &pk_outlen);
        if (pk_outlen != pk_len) { dogecoin_free(pk); return showError("Invalid public key hex\n"); }
        if ((strlen(txhex) % 2) != 0) { dogecoin_free(pk); return showError("Invalid message hex\n"); }
        size_t msg_len = strlen(txhex) / 2;
        uint8_t* msg = dogecoin_malloc(msg_len);
        size_t msg_outlen = 0;
        utils_hex_to_bin(txhex, msg, strlen(txhex), &msg_outlen);
        if (msg_outlen != msg_len) { dogecoin_free(pk); dogecoin_free(msg); return showError("Invalid message hex\n"); }
        if ((strlen(scripthex) % 2) != 0) { dogecoin_free(pk); dogecoin_free(msg); return showError("Invalid signature hex\n"); }
        size_t sig_len = strlen(scripthex) / 2;
        uint8_t* sig = dogecoin_malloc(sig_len);
        size_t sig_outlen = 0;
        utils_hex_to_bin(scripthex, sig, strlen(scripthex), &sig_outlen);
        if (sig_outlen != sig_len) { dogecoin_free(pk); dogecoin_free(msg); dogecoin_free(sig); return showError("Invalid signature hex\n"); }
        dogecoin_bool verified = dogecoin_dilithium2_verify(pk, pk_len, msg, msg_len, sig, sig_len);
        printf("\n=== Dilithium2 Verification Result ===\n");
        printf("%s\n", verified ? "✓ VERIFIED: Signature is valid!" : "✗ FAILED: Signature is invalid!");
        dogecoin_free(pk); dogecoin_free(msg); dogecoin_free(sig);
        if (!verified) { dogecoin_ecc_stop(); return 1; }
    }
    else if (strcmp(cmd, "dilithium2_commit") == 0) {
        if (!pubkey) return showError("Missing public key (use -k)\n");
        if (!scripthex) return showError("Missing signature (use -s)\n");
        if ((strlen(pubkey) % 2) != 0) return showError("Invalid public key hex\n");
        size_t pk_len = strlen(pubkey) / 2;
        uint8_t* pk = dogecoin_malloc(pk_len);
        size_t pk_outlen = 0;
        utils_hex_to_bin(pubkey, pk, strlen(pubkey), &pk_outlen);
        if (pk_outlen != pk_len) { dogecoin_free(pk); return showError("Invalid public key hex\n"); }
        if ((strlen(scripthex) % 2) != 0) { dogecoin_free(pk); return showError("Invalid signature hex\n"); }
        size_t sig_len = strlen(scripthex) / 2;
        uint8_t* sig = dogecoin_malloc(sig_len);
        size_t sig_outlen = 0;
        utils_hex_to_bin(scripthex, sig, strlen(scripthex), &sig_outlen);
        if (sig_outlen != sig_len) { dogecoin_free(pk); dogecoin_free(sig); return showError("Invalid signature hex\n"); }
        uint8_t commit[32];
        if (!dogecoin_dilithium2_commit_bytes(pk, pk_len, sig, sig_len, commit)) {
            dogecoin_free(pk); dogecoin_free(sig); return showError("Failed to generate Dilithium2 commitment\n");
        }
        char commit_hex[65];
        utils_bin_to_hex(commit, 32, commit_hex);
        printf("\n=== Dilithium2 Commitment Generated ===\n");
        printf("commitment:  %s\n", commit_hex);
        printf("length:      32 bytes\n");
        printf("\nThis commitment can be included in an OP_RETURN output:\n");
        printf("OP_RETURN script (prefix 6a24 + tag 44494c32='DIL2'): 6a2444494c32%s\n", commit_hex);
        dogecoin_free(pk); dogecoin_free(sig);
    }
#endif /* USE_LIBOQS (keygen/sign/verify/commit commands) */
#ifdef USE_RACCOON_G
    else if (strcmp(cmd, "raccoong_keygen") == 0) {
        uint8_t *pk = NULL, *sk = NULL;
        size_t pk_len = 0, sk_len = 0;
        printf("Generating Raccoon-G-44 keypair...\n");
        if (!dogecoin_raccoong44_keypair(&pk, &pk_len, &sk, &sk_len)) {
            return showError("Failed to generate Raccoon-G-44 keypair\n");
        }
        char* pk_hex = dogecoin_malloc(pk_len * 2 + 1);
        char* sk_hex = dogecoin_malloc(sk_len * 2 + 1);
        if (!pk_hex || !sk_hex) {
            if (pk_hex) dogecoin_free(pk_hex);
            if (sk_hex) dogecoin_free(sk_hex);
            dogecoin_free(pk);
            dogecoin_free(sk);
            return showError("Failed to allocate Raccoon-G key hex buffers\n");
        }
        utils_bin_to_hex(pk, pk_len, pk_hex);
        utils_bin_to_hex(sk, sk_len, sk_hex);
        printf("\n=== Raccoon-G-44 Keypair Generated ===\n");
        printf("public key:  %s\n", pk_hex);
        printf("secret key:  %s\n", sk_hex);
        printf("pk length:   %zu bytes\n", pk_len);
        printf("sk length:   %zu bytes\n", sk_len);
        dogecoin_free(pk_hex);
        dogecoin_free(sk_hex);
        dogecoin_free(pk);
        dogecoin_free(sk);
    }
    else if (strcmp(cmd, "raccoong_sign") == 0) {
        dogecoin_bool sk_hex_owned = false;
        char* sk_hex = such_resolve_sk_hex(pkey, sk_file, &sk_hex_owned);
        if (!sk_hex) return showError("Missing secret key (use -p <hex> or --sk-file <path>)\n");
        if (!txhex) { such_release_sk_hex(sk_hex, sk_hex_owned); return showError("Missing message (use -x)\n"); }
        if ((strlen(sk_hex) % 2) != 0) { such_release_sk_hex(sk_hex, sk_hex_owned); return showError("Invalid secret key hex\n"); }
        size_t sk_len = strlen(sk_hex) / 2;
        uint8_t* sk = dogecoin_malloc(sk_len);
        size_t sk_outlen = 0;
        utils_hex_to_bin(sk_hex, sk, strlen(sk_hex), &sk_outlen);
        such_release_sk_hex(sk_hex, sk_hex_owned);
        if (sk_outlen != sk_len) { dogecoin_free(sk); return showError("Invalid secret key hex\n"); }
        if ((strlen(txhex) % 2) != 0) { dogecoin_free(sk); return showError("Invalid message hex\n"); }
        size_t msg_len = strlen(txhex) / 2;
        uint8_t* msg = dogecoin_malloc(msg_len);
        size_t msg_outlen = 0;
        utils_hex_to_bin(txhex, msg, strlen(txhex), &msg_outlen);
        if (msg_outlen != msg_len) { dogecoin_free(sk); dogecoin_free(msg); return showError("Invalid message hex\n"); }
        uint8_t* sig = NULL; size_t sig_len = 0;
        if (!dogecoin_raccoong44_sign(sk, sk_len, msg, msg_len, &sig, &sig_len)) {
            dogecoin_free(sk); dogecoin_free(msg);
            return showError("Failed to sign message with Raccoon-G-44\n");
        }
        char* sig_hex = utils_uint8_to_hex(sig, sig_len);
        printf("\n=== Raccoon-G-44 Signature Generated ===\n");
        printf("signature:   %s\n", sig_hex);
        printf("sig length:  %zu bytes\n", sig_len);
        printf("msg length:  %zu bytes\n", msg_len);
        dogecoin_free(sk); dogecoin_free(msg); dogecoin_free(sig);
    }
    else if (strcmp(cmd, "raccoong_verify") == 0) {
        if (!pubkey) return showError("Missing public key (use -k)\n");
        if (!txhex) return showError("Missing message (use -x)\n");
        if (!scripthex) return showError("Missing signature (use -s)\n");
        if ((strlen(pubkey) % 2) != 0) return showError("Invalid public key hex\n");
        size_t pk_len = strlen(pubkey) / 2;
        uint8_t* pk = dogecoin_malloc(pk_len);
        size_t pk_outlen = 0;
        utils_hex_to_bin(pubkey, pk, strlen(pubkey), &pk_outlen);
        if (pk_outlen != pk_len) { dogecoin_free(pk); return showError("Invalid public key hex\n"); }
        if ((strlen(txhex) % 2) != 0) { dogecoin_free(pk); return showError("Invalid message hex\n"); }
        size_t msg_len = strlen(txhex) / 2;
        uint8_t* msg = dogecoin_malloc(msg_len);
        size_t msg_outlen = 0;
        utils_hex_to_bin(txhex, msg, strlen(txhex), &msg_outlen);
        if (msg_outlen != msg_len) { dogecoin_free(pk); dogecoin_free(msg); return showError("Invalid message hex\n"); }
        if ((strlen(scripthex) % 2) != 0) { dogecoin_free(pk); dogecoin_free(msg); return showError("Invalid signature hex\n"); }
        size_t sig_len = strlen(scripthex) / 2;
        uint8_t* sig = dogecoin_malloc(sig_len);
        size_t sig_outlen = 0;
        utils_hex_to_bin(scripthex, sig, strlen(scripthex), &sig_outlen);
        if (sig_outlen != sig_len) { dogecoin_free(pk); dogecoin_free(msg); dogecoin_free(sig); return showError("Invalid signature hex\n"); }
        dogecoin_bool verified = dogecoin_raccoong44_verify(pk, pk_len, msg, msg_len, sig, sig_len);
        printf("\n=== Raccoon-G-44 Verification Result ===\n");
        printf("%s\n", verified ? "✓ VERIFIED: Signature is valid!" : "✗ FAILED: Signature is invalid!");
        dogecoin_free(pk); dogecoin_free(msg); dogecoin_free(sig);
        if (!verified) { dogecoin_ecc_stop(); return 1; }
    }
    else if (strcmp(cmd, "raccoong_commit") == 0) {
        if (!pubkey) return showError("Missing public key (use -k)\n");
        if (!scripthex) return showError("Missing signature (use -s)\n");
        if ((strlen(pubkey) % 2) != 0) return showError("Invalid public key hex\n");
        size_t pk_len = strlen(pubkey) / 2;
        uint8_t* pk = dogecoin_malloc(pk_len);
        size_t pk_outlen = 0;
        utils_hex_to_bin(pubkey, pk, strlen(pubkey), &pk_outlen);
        if (pk_outlen != pk_len) { dogecoin_free(pk); return showError("Invalid public key hex\n"); }
        if ((strlen(scripthex) % 2) != 0) { dogecoin_free(pk); return showError("Invalid signature hex\n"); }
        size_t sig_len = strlen(scripthex) / 2;
        uint8_t* sig = dogecoin_malloc(sig_len);
        size_t sig_outlen = 0;
        utils_hex_to_bin(scripthex, sig, strlen(scripthex), &sig_outlen);
        if (sig_outlen != sig_len) { dogecoin_free(pk); dogecoin_free(sig); return showError("Invalid signature hex\n"); }
        uint8_t commit[32];
        if (!dogecoin_raccoong44_commit_bytes(pk, pk_len, sig, sig_len, commit)) {
            dogecoin_free(pk); dogecoin_free(sig); return showError("Failed to generate Raccoon-G-44 commitment\n");
        }
        char commit_hex[65];
        utils_bin_to_hex(commit, 32, commit_hex);
        printf("\n=== Raccoon-G-44 Commitment Generated ===\n");
        printf("commitment:  %s\n", commit_hex);
        printf("length:      32 bytes\n");
        printf("\nThis commitment can be included in an OP_RETURN output:\n");
        printf("OP_RETURN script (prefix 6a24 + tag 52434734='RCG4'): 6a2452434734%s\n", commit_hex);
        dogecoin_free(pk); dogecoin_free(sig);
    }
    else if (strcmp(cmd, "raccoong_hd_derive") == 0) {
        dogecoin_bool sk_hex_owned = false;
        char* sk_hex = such_resolve_sk_hex(pkey, sk_file, &sk_hex_owned);
        if (!sk_hex) return showError("Missing parent secret key (use -p <hex> or --sk-file <path>)\n");
        if (!pubkey) { such_release_sk_hex(sk_hex, sk_hex_owned); return showError("Missing parent public key (use -k)\n"); }
        if (!scripthex) { such_release_sk_hex(sk_hex, sk_hex_owned); return showError("Missing chaincode hex (use -s)\n"); }
        if ((strlen(scripthex) % 2) != 0 || strlen(scripthex) != 64) { such_release_sk_hex(sk_hex, sk_hex_owned); return showError("Chaincode must be 32 bytes (64 hex)\n"); }
        if ((strlen(sk_hex) % 2) != 0) { such_release_sk_hex(sk_hex, sk_hex_owned); return showError("Invalid parent secret key hex\n"); }
        if ((strlen(pubkey) % 2) != 0) { such_release_sk_hex(sk_hex, sk_hex_owned); return showError("Invalid parent public key hex\n"); }
        size_t psk_len = strlen(sk_hex) / 2;
        uint8_t* psk = dogecoin_malloc(psk_len);
        size_t psk_outlen = 0;
        utils_hex_to_bin(sk_hex, psk, strlen(sk_hex), &psk_outlen);
        such_release_sk_hex(sk_hex, sk_hex_owned);
        if (psk_outlen != psk_len) { dogecoin_free(psk); return showError("Invalid parent secret key hex\n"); }
        size_t ppk_len = strlen(pubkey) / 2;
        uint8_t* ppk = dogecoin_malloc(ppk_len);
        size_t ppk_outlen = 0;
        utils_hex_to_bin(pubkey, ppk, strlen(pubkey), &ppk_outlen);
        if (ppk_outlen != ppk_len) { dogecoin_free(psk); dogecoin_free(ppk); return showError("Invalid parent public key hex\n"); }
        uint8_t chaincode[DOGECOIN_PQC_RACCOON_CHAINCODE_LEN];
        size_t cc_outlen = 0;
        utils_hex_to_bin(scripthex, chaincode, strlen(scripthex), &cc_outlen);
        if (cc_outlen != DOGECOIN_PQC_RACCOON_CHAINCODE_LEN) { dogecoin_free(psk); dogecoin_free(ppk); return showError("Invalid chaincode hex\n"); }
        uint8_t* child_pk = NULL; uint8_t* child_sk = NULL;
        size_t child_pk_len = 0; size_t child_sk_len = 0;
        int hardened = 0;
        if (change_level) {
            hardened = atoi(change_level) ? 1 : 0;
        }
        if (!dogecoin_raccoong44_hd_derive_priv(psk, psk_len, ppk, ppk_len, chaincode, inputindex, hardened, &child_sk, &child_sk_len, &child_pk, &child_pk_len)) {
            dogecoin_free(psk);
            dogecoin_free(ppk);
            return showError("Raccoon-G-44 private child derivation failed\n");
        }
        char* child_pk_hex = dogecoin_malloc(child_pk_len * 2 + 1);
        char* child_sk_hex = dogecoin_malloc(child_sk_len * 2 + 1);
        if (!child_pk_hex || !child_sk_hex) {
            if (child_pk_hex) dogecoin_free(child_pk_hex);
            if (child_sk_hex) dogecoin_free(child_sk_hex);
            dogecoin_free(psk);
            dogecoin_free(ppk);
            dogecoin_free(child_pk);
            dogecoin_free(child_sk);
            return showError("Failed to allocate child key hex buffers\n");
        }
        utils_bin_to_hex(child_pk, child_pk_len, child_pk_hex);
        utils_bin_to_hex(child_sk, child_sk_len, child_sk_hex);
        printf("\n=== Raccoon-G-44 HD Child Key (Private Derivation) ===\n");
        printf("child index: %u%s\n", inputindex, hardened ? " (hardened)" : "");
        printf("child public key:  %s\n", child_pk_hex);
        printf("child secret key:  %s\n", child_sk_hex);
        dogecoin_free(psk);
        dogecoin_free(ppk);
        dogecoin_free(child_pk);
        dogecoin_free(child_sk);
        dogecoin_free(child_pk_hex);
        dogecoin_free(child_sk_hex);
    }
    else if (strcmp(cmd, "raccoong_hd_derive_pub") == 0) {
        if (!pubkey) return showError("Missing parent public key (use -k)\n");
        if (!scripthex) return showError("Missing chaincode hex (use -s)\n");
        if ((strlen(scripthex) % 2) != 0 || strlen(scripthex) != 64) return showError("Chaincode must be 32 bytes (64 hex)\n");
        if ((strlen(pubkey) % 2) != 0) return showError("Invalid parent public key hex\n");
        size_t ppk_len = strlen(pubkey) / 2;
        uint8_t* ppk = dogecoin_malloc(ppk_len);
        size_t ppk_outlen = 0;
        utils_hex_to_bin(pubkey, ppk, strlen(pubkey), &ppk_outlen);
        if (ppk_outlen != ppk_len) { dogecoin_free(ppk); return showError("Invalid parent public key hex\n"); }
        uint8_t chaincode[DOGECOIN_PQC_RACCOON_CHAINCODE_LEN];
        size_t cc_outlen = 0;
        utils_hex_to_bin(scripthex, chaincode, strlen(scripthex), &cc_outlen);
        if (cc_outlen != DOGECOIN_PQC_RACCOON_CHAINCODE_LEN) { dogecoin_free(ppk); return showError("Invalid chaincode hex\n"); }
        if (inputindex & 0x80000000U) {
            dogecoin_free(ppk);
            return showError("raccoong_hd_derive_pub does not support hardened indices\n");
        }
        uint8_t* child_pk = NULL;
        size_t child_pk_len = 0;
        if (!dogecoin_raccoong44_hd_derive_pub(ppk, ppk_len, chaincode, inputindex, &child_pk, &child_pk_len)) {
            dogecoin_free(ppk);
            return showError("Raccoon-G-44 public child derivation failed\n");
        }
        char* child_pk_hex = dogecoin_malloc(child_pk_len * 2 + 1);
        if (!child_pk_hex) {
            dogecoin_free(ppk);
            dogecoin_free(child_pk);
            return showError("Failed to allocate child public key hex buffer\n");
        }
        utils_bin_to_hex(child_pk, child_pk_len, child_pk_hex);
        printf("\n=== Raccoon-G-44 HD Child Key (Public Derivation) ===\n");
        printf("child index: %u\n", inputindex);
        printf("child public key:  %s\n", child_pk_hex);
        dogecoin_free(ppk);
        dogecoin_free(child_pk);
        dogecoin_free(child_pk_hex);
    }
    #endif /* USE_RACCOON_G */
#if defined(USE_LIBOQS) || defined(USE_RACCOON_G)
#ifdef USE_LIBOQS
    else if (strcmp(cmd, "falcon_add_commit_tx") == 0) {
        // ./such -c falcon_add_commit_tx -x <raw_tx_hex> -s <falcon_commitment_hex>
        if (!txhex || !scripthex) {
            return showError("Missing tx hex or commitment hex (use -x, -s)\n");
        }
        if ((strlen(txhex) % 2) != 0) {
            return showError("Raw transaction hex length must be even\n");
        }
        if (strlen(scripthex) != 64) {
            return showError("Commitment must be exactly 32 bytes (64 hex characters)\n");
        }
        for (size_t i = 0; i < strlen(scripthex); i++) {
            if (!isxdigit((unsigned char)scripthex[i])) {
                return showError("Commitment must be hex encoded\n");
            }
        }

        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex\n");
        }
        dogecoin_free(data_bin);

        uint8_t commit32[32];
        size_t commit_len = 0;
        utils_hex_to_bin(scripthex, commit32, strlen(scripthex), &commit_len);
        if (commit_len != sizeof(commit32)) {
            dogecoin_tx_free(tx);
            return showError("Failed to decode commitment\n");
        }

        if (!dogecoin_tx_add_falcon512_commit(tx, commit32)) {
            dogecoin_tx_free(tx);
            return showError("Failed to append Falcon commitment output\n");
        }

        cstring* tx_with_commit = cstr_new_sz(1024);
        dogecoin_tx_serialize(tx_with_commit, tx);
        char* tx_with_commit_hex = dogecoin_malloc(tx_with_commit->len * 2 + 1);
        if (!tx_with_commit_hex) {
            cstr_free(tx_with_commit, true);
            dogecoin_tx_free(tx);
            return showError("Failed to allocate memory for tx hex\n");
        }
        utils_bin_to_hex((unsigned char*)tx_with_commit->str, tx_with_commit->len, tx_with_commit_hex);

        printf("tx with commitment: %s\n", tx_with_commit_hex);

        cstr_free(tx_with_commit, true);
        dogecoin_free(tx_with_commit_hex);
        dogecoin_tx_free(tx);
    }
    else if (strcmp(cmd, "dilithium2_add_commit_tx") == 0) {
        if (!txhex || !scripthex) {
            return showError("Missing tx hex or commitment hex (use -x, -s)\n");
        }
        if ((strlen(txhex) % 2) != 0) {
            return showError("Raw transaction hex length must be even\n");
        }
        if (strlen(scripthex) != 64) {
            return showError("Commitment must be exactly 32 bytes (64 hex characters)\n");
        }
        for (size_t i = 0; i < strlen(scripthex); i++) {
            if (!isxdigit((unsigned char)scripthex[i])) {
                return showError("Commitment must be hex encoded\n");
            }
        }

        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex\n");
        }
        dogecoin_free(data_bin);

        uint8_t commit32[32];
        size_t commit_len = 0;
        utils_hex_to_bin(scripthex, commit32, strlen(scripthex), &commit_len);
        if (commit_len != sizeof(commit32)) {
            dogecoin_tx_free(tx);
            return showError("Failed to decode commitment\n");
        }

        if (!dogecoin_tx_add_dilithium2_commit(tx, commit32)) {
            dogecoin_tx_free(tx);
            return showError("Failed to append Dilithium2 commitment output\n");
        }

        cstring* tx_with_commit = cstr_new_sz(1024);
        dogecoin_tx_serialize(tx_with_commit, tx);
        char* tx_with_commit_hex = dogecoin_malloc(tx_with_commit->len * 2 + 1);
        if (!tx_with_commit_hex) {
            cstr_free(tx_with_commit, true);
            dogecoin_tx_free(tx);
            return showError("Failed to allocate memory for tx hex\n");
        }
        utils_bin_to_hex((unsigned char*)tx_with_commit->str, tx_with_commit->len, tx_with_commit_hex);
        printf("tx with commitment: %s\n", tx_with_commit_hex);
        cstr_free(tx_with_commit, true);
        dogecoin_free(tx_with_commit_hex);
        dogecoin_tx_free(tx);
    }
#endif /* USE_LIBOQS (falcon/dilithium add_commit_tx) */
#ifdef USE_RACCOON_G
    else if (strcmp(cmd, "raccoong_add_commit_tx") == 0) {
        if (!txhex || !scripthex) {
            return showError("Missing tx hex or commitment hex (use -x, -s)\n");
        }
        if ((strlen(txhex) % 2) != 0) {
            return showError("Raw transaction hex length must be even\n");
        }
        if (strlen(scripthex) != 64) {
            return showError("Commitment must be exactly 32 bytes (64 hex characters)\n");
        }
        for (size_t i = 0; i < strlen(scripthex); i++) {
            if (!isxdigit((unsigned char)scripthex[i])) {
                return showError("Commitment must be hex encoded\n");
            }
        }

        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex\n");
        }
        dogecoin_free(data_bin);

        uint8_t commit32[32];
        size_t commit_len = 0;
        utils_hex_to_bin(scripthex, commit32, strlen(scripthex), &commit_len);
        if (commit_len != sizeof(commit32)) {
            dogecoin_tx_free(tx);
            return showError("Failed to decode commitment\n");
        }

        if (!dogecoin_tx_add_raccoong44_commit(tx, commit32)) {
            dogecoin_tx_free(tx);
            return showError("Failed to append Raccoon-G-44 commitment output\n");
        }

        cstring* tx_with_commit = cstr_new_sz(1024);
        dogecoin_tx_serialize(tx_with_commit, tx);
        char* tx_with_commit_hex = dogecoin_malloc(tx_with_commit->len * 2 + 1);
        if (!tx_with_commit_hex) {
            cstr_free(tx_with_commit, true);
            dogecoin_tx_free(tx);
            return showError("Failed to allocate memory for tx hex\n");
        }
        utils_bin_to_hex((unsigned char*)tx_with_commit->str, tx_with_commit->len, tx_with_commit_hex);
        printf("tx with commitment: %s\n", tx_with_commit_hex);
        cstr_free(tx_with_commit, true);
        dogecoin_free(tx_with_commit_hex);
        dogecoin_tx_free(tx);
    }
#endif /* USE_RACCOON_G */
    else if (
#ifdef USE_LIBOQS
             strcmp(cmd, "falcon_add_commit_and_carrier_tx") == 0 ||
             strcmp(cmd, "dilithium2_add_commit_and_carrier_tx") == 0 ||
#endif
#ifdef USE_RACCOON_G
             strcmp(cmd, "raccoong_add_commit_and_carrier_tx") == 0 ||
#endif
             0) {
        if (!txhex || !derived_path || !pubkey || !scripthex) {
            return showError("Missing tx hex (-x), commitment hex (-m), pqc pubkey (-k), or pqc signature (-s)\n");
        }
        if ((strlen(txhex) % 2) != 0) {
            return showError("Raw transaction hex length must be even\n");
        }
        uint64_t carrier_value_koinu = (sighashtype > 0) ? (uint64_t)sighashtype : 100000000;

        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex\n");
        }
        dogecoin_free(data_bin);

        uint8_t commit32[32];
        if (!such_commit_hex_to_bytes32(derived_path, commit32)) {
            dogecoin_tx_free(tx);
            return showError("Commitment must be exactly 32 bytes (64 hex characters)\n");
        }

        dogecoin_bool (*add_commit_fn)(dogecoin_tx*, const uint8_t*) = NULL;
        const char* tag4_ascii = NULL;
#ifdef USE_LIBOQS
        if (strcmp(cmd, "falcon_add_commit_and_carrier_tx") == 0) {
            add_commit_fn = dogecoin_tx_add_falcon512_commit;
            tag4_ascii = "FLC1";
        } else if (strcmp(cmd, "dilithium2_add_commit_and_carrier_tx") == 0) {
            add_commit_fn = dogecoin_tx_add_dilithium2_commit;
            tag4_ascii = "DIL2";
        }
#endif
#ifdef USE_RACCOON_G
        if (strcmp(cmd, "raccoong_add_commit_and_carrier_tx") == 0) {
            add_commit_fn = dogecoin_tx_add_raccoong44_commit;
            tag4_ascii = "RCG4";
        }
#endif

        cstring* carrier_spk = NULL;
        uint8_t part_total = 0;
        uint32_t carrier_first_vout = 0;
        if (!such_tx_add_commit_and_carrier_outputs(tx, commit32, add_commit_fn, tag4_ascii, pubkey, scripthex,
                                                    carrier_value_koinu, &carrier_spk, &part_total, &carrier_first_vout)) {
            dogecoin_tx_free(tx);
            return showError("Failed to append commitment + carrier outputs\n");
        }

        size_t pk_len = strlen(pubkey) / 2;
        size_t sig_len = strlen(scripthex) / 2;
        uint8_t* pk = dogecoin_malloc(pk_len + 1);
        uint8_t* sig = dogecoin_malloc(sig_len + 1);
        if (!pk || !sig) {
            if (pk) dogecoin_free(pk);
            if (sig) dogecoin_free(sig);
            cstr_free(carrier_spk, true);
            dogecoin_tx_free(tx);
            return showError("OOM");
        }
        outlen = 0;
        utils_hex_to_bin(pubkey, pk, strlen(pubkey), &outlen);
        if (outlen != pk_len) {
            dogecoin_free(pk);
            dogecoin_free(sig);
            cstr_free(carrier_spk, true);
            dogecoin_tx_free(tx);
            return showError("Invalid pqc pubkey hex");
        }
        utils_hex_to_bin(scripthex, sig, strlen(scripthex), &outlen);
        if (outlen != sig_len) {
            dogecoin_free(pk);
            dogecoin_free(sig);
            cstr_free(carrier_spk, true);
            dogecoin_tx_free(tx);
            return showError("Invalid pqc signature hex");
        }
        size_t full_len = pk_len + sig_len;
        uint8_t* full = dogecoin_malloc(full_len + 1);
        if (!full) {
            dogecoin_free(pk);
            dogecoin_free(sig);
            cstr_free(carrier_spk, true);
            dogecoin_tx_free(tx);
            return showError("OOM");
        }
        memcpy(full, pk, pk_len);
        memcpy(full + pk_len, sig, sig_len);
        dogecoin_free(pk);
        dogecoin_free(sig);

        char tag8[DOGECOIN_PQC_CARRIER_TAG_LEN];
        memcpy(tag8, tag4_ascii, 4);
        memcpy(tag8 + 4, "FULL", 4);
        cstring* redeem = NULL;
        if (!dogecoin_pqc_carrier_build_redeemscript(&redeem)) {
            dogecoin_free(full);
            cstr_free(carrier_spk, true);
            dogecoin_tx_free(tx);
            return showError("Failed to build carrier redeemScript");
        }

        cstring* tx_out = cstr_new_sz(1024);
        dogecoin_tx_serialize(tx_out, tx);
        char* tx_out_hex = dogecoin_malloc(tx_out->len * 2 + 1);
        if (!tx_out_hex) {
            cstr_free(tx_out, true);
            cstr_free(redeem, true);
            dogecoin_free(full);
            cstr_free(carrier_spk, true);
            dogecoin_tx_free(tx);
            return showError("OOM");
        }
        utils_bin_to_hex((unsigned char*)tx_out->str, tx_out->len, tx_out_hex);
        char* carrier_spk_hex = utils_uint8_to_hex((const uint8_t*)carrier_spk->str, carrier_spk->len);
        printf("tx with commitment and carrier outputs: %s\n", tx_out_hex);
        printf("carrier_part_total: %u\n", (unsigned)part_total);
        printf("carrier_output_value_koinu: %llu\n", (unsigned long long)carrier_value_koinu);
        printf("carrier_first_vout: %u\n", carrier_first_vout);
        printf("carrier_p2sh_scriptpubkey: %s\n", carrier_spk_hex ? carrier_spk_hex : "");

        size_t part_payload_max = DOGECOIN_PQC_CARRIER_MAX_CHUNKS * DOGECOIN_PQC_CARRIER_CHUNK_MAX;
        for (uint8_t part_index = 0; part_index < part_total; part_index++) {
            size_t part_off = (size_t)part_index * part_payload_max;
            size_t part_len = full_len - part_off;
            if (part_len > part_payload_max) part_len = part_payload_max;
            cstring* part_scriptsig = NULL;
            if (!dogecoin_pqc_carrier_build_part_scriptsig(tag8, part_index, part_total, (uint16_t)pk_len, (uint16_t)full_len,
                                                           full + part_off, part_len, redeem, &part_scriptsig)) {
                dogecoin_free(tx_out_hex);
                cstr_free(tx_out, true);
                cstr_free(redeem, true);
                dogecoin_free(full);
                cstr_free(carrier_spk, true);
                dogecoin_tx_free(tx);
                return showError("Failed to build carrier part scriptsig");
            }
            char* ss_hex = utils_uint8_to_hex((const uint8_t*)part_scriptsig->str, part_scriptsig->len);
            printf("carrier_part_scriptsig[%u]: %s\n", (unsigned)part_index, ss_hex ? ss_hex : "");
            cstr_free(part_scriptsig, true);
        }

        dogecoin_free(tx_out_hex);
        cstr_free(tx_out, true);
        cstr_free(redeem, true);
        dogecoin_free(full);
        cstr_free(carrier_spk, true);
        dogecoin_tx_free(tx);
    }
#endif
#ifdef USE_ZK_CARRIER
    else if (strcmp(cmd, "zk_encode_payload") == 0) {
        // ./such -c zk_encode_payload -m <mode> -i <circuit_id_hex> -k <public_inputs_hex> -s <proof_hex>
        if (!derived_path || !pubkey || !scripthex) {
            return showError("Missing -m <mode>, -k <public_inputs_hex>, or -s <proof_hex>\n");
        }
        long mode_l = strtol(derived_path, NULL, 0);
        if (mode_l < 0 || mode_l > 0xFF) return showError("Invalid -m mode\n");
        uint32_t circuit_id = 0;
        if (inputindex > 0) circuit_id = (uint32_t)inputindex;

        if ((strlen(pubkey) % 2) != 0 || (strlen(scripthex) % 2) != 0) {
            return showError("public_inputs/proof hex must be even-length\n");
        }
        size_t pi_len = strlen(pubkey) / 2;
        size_t prf_len = strlen(scripthex) / 2;
        uint8_t* pi = dogecoin_malloc(pi_len ? pi_len : 1);
        uint8_t* prf = dogecoin_malloc(prf_len ? prf_len : 1);
        if (!pi || !prf) {
            if (pi) dogecoin_free(pi);
            if (prf) dogecoin_free(prf);
            return showError("OOM\n");
        }
        size_t outlen = 0;
        utils_hex_to_bin(pubkey, pi, strlen(pubkey), &outlen);
        if (outlen != pi_len) { dogecoin_free(pi); dogecoin_free(prf); return showError("Invalid public_inputs hex\n"); }
        outlen = 0;
        utils_hex_to_bin(scripthex, prf, strlen(scripthex), &outlen);
        if (outlen != prf_len) { dogecoin_free(pi); dogecoin_free(prf); return showError("Invalid proof hex\n"); }

        uint8_t* payload = NULL;
        size_t payload_len = 0;
        /* such -c zk_encode_payload does not currently take a vk argument from
         * the CLI; emit a v0 payload (no embedded vk).  The supported way to
         * produce a v1 (vk-included, self-contained-reveal) payload is
         * contrib/zk_carrier/witness_helper.py --vkey, which has the vk file
         * already on hand. */
        dogecoin_zk_err_t e = dogecoin_zk_encode_payload(
            (dogecoin_zk_mode_t)mode_l, circuit_id, pi, pi_len, prf, prf_len,
            NULL, 0,
            &payload, &payload_len);
        dogecoin_free(pi);
        dogecoin_free(prf);
        if (e != DOGECOIN_ZK_OK) return showError(dogecoin_zk_strerror(e));
        char* hex = dogecoin_malloc(payload_len * 2 + 1);
        utils_bin_to_hex(payload, payload_len, hex);
        printf("zk_payload: %s\n", hex);
        printf("zk_payload_len: %zu\n", payload_len);
        dogecoin_free(hex);
        dogecoin_free(payload);
    }
    else if (strcmp(cmd, "zk_commit") == 0) {
        // ./such -c zk_commit -x <payload_hex>
        if (!txhex) return showError("Missing -x <payload_hex>\n");
        if ((strlen(txhex) % 2) != 0) return showError("payload hex must be even-length\n");
        size_t plen = strlen(txhex) / 2;
        if (plen == 0) return showError("empty payload\n");
        uint8_t* p = dogecoin_malloc(plen);
        if (!p) return showError("OOM\n");
        size_t outlen = 0;
        utils_hex_to_bin(txhex, p, strlen(txhex), &outlen);
        if (outlen != plen) { dogecoin_free(p); return showError("Invalid payload hex\n"); }

        /* Decode mode out of the payload header so the OP_RETURN gets the right
         * mode byte without an extra flag. */
        dogecoin_zk_mode_t mode;
        uint32_t cid;
        const uint8_t* pi; size_t pi_len;
        const uint8_t* prf; size_t prf_len;
        const uint8_t* vk_ptr = NULL; size_t vk_len = 0;
        dogecoin_zk_err_t e = dogecoin_zk_decode_payload(p, plen, &mode, &cid,
                                                         &pi, &pi_len,
                                                         &prf, &prf_len,
                                                         &vk_ptr, &vk_len);
        if (e != DOGECOIN_ZK_OK) { dogecoin_free(p); return showError(dogecoin_zk_strerror(e)); }

        uint8_t commit[32];
        e = dogecoin_zk_get_commitment_hash(p, plen, commit);
        if (e != DOGECOIN_ZK_OK) { dogecoin_free(p); return showError(dogecoin_zk_strerror(e)); }
        char commit_hex[65];
        utils_bin_to_hex(commit, 32, commit_hex);

        cstring* spk = NULL;
        e = dogecoin_zk_build_opreturn_scriptpubkey(mode, commit, &spk);
        if (e != DOGECOIN_ZK_OK) { dogecoin_free(p); return showError(dogecoin_zk_strerror(e)); }
        char* spk_hex = utils_uint8_to_hex((const uint8_t*)spk->str, spk->len);

        printf("\n=== ZK Carrier Commitment ===\n");
        printf("mode:        %u\n", (unsigned)mode);
        printf("circuit_id:  0x%08x\n", (unsigned)cid);
        printf("public_inputs_len: %zu\n", pi_len);
        printf("proof_len:   %zu\n", prf_len);
        printf("vk_len:      %zu%s\n", vk_len,
               vk_len > 0 ? " (v1: self-contained reveal)" : " (v0: vk distributed out-of-band)");
        printf("commitment:  %s\n", commit_hex);
        printf("opreturn_spk: %s\n", spk_hex ? spk_hex : "");
        cstr_free(spk, true);
        dogecoin_free(p);
    }
    else if (strcmp(cmd, "zk_add_commit_and_carrier_tx") == 0) {
        // ./such -c zk_add_commit_and_carrier_tx -x <raw_tx_hex> -m <mode> -s <payload_hex> [-h <carrier_value_koinu>]
        if (!txhex || !derived_path || !scripthex) {
            return showError("Missing -x <raw_tx_hex>, -m <mode>, or -s <payload_hex>\n");
        }
        long mode_l = strtol(derived_path, NULL, 0);
        if (mode_l < 0 || mode_l > 0xFF) return showError("Invalid -m mode\n");
        uint64_t carrier_value_koinu = (sighashtype > 0) ? (uint64_t)sighashtype : 100000000;
        if ((strlen(txhex) % 2) != 0 || (strlen(scripthex) % 2) != 0) {
            return showError("hex must be even-length\n");
        }

        /* Deserialize tx. */
        dogecoin_tx* tx = dogecoin_tx_new();
        size_t tx_bin_len = strlen(txhex) / 2;
        uint8_t* tx_bin = dogecoin_malloc(tx_bin_len + 1);
        if (!tx || !tx_bin) {
            if (tx) dogecoin_tx_free(tx);
            if (tx_bin) dogecoin_free(tx_bin);
            return showError("OOM\n");
        }
        size_t outlen = 0;
        utils_hex_to_bin(txhex, tx_bin, strlen(txhex), &outlen);
        if (outlen != tx_bin_len || !dogecoin_tx_deserialize(tx_bin, outlen, tx, NULL)) {
            dogecoin_free(tx_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex\n");
        }
        dogecoin_free(tx_bin);

        /* Decode payload. */
        size_t payload_len = strlen(scripthex) / 2;
        uint8_t* payload = dogecoin_malloc(payload_len ? payload_len : 1);
        if (!payload) {
            dogecoin_tx_free(tx);
            return showError("OOM\n");
        }
        outlen = 0;
        utils_hex_to_bin(scripthex, payload, strlen(scripthex), &outlen);
        if (outlen != payload_len) {
            dogecoin_free(payload);
            dogecoin_tx_free(tx);
            return showError("Invalid payload hex\n");
        }

        cstring* carrier_spk = NULL;
        uint8_t part_total = 0;
        dogecoin_zk_err_t e = dogecoin_zk_build_carrier_tx_c(
            tx, payload, payload_len, (dogecoin_zk_mode_t)mode_l,
            carrier_value_koinu, &carrier_spk, &part_total);
        if (e != DOGECOIN_ZK_OK) {
            dogecoin_free(payload);
            dogecoin_tx_free(tx);
            return showError(dogecoin_zk_strerror(e));
        }

        /* Serialize TX_C. */
        cstring* tx_out = cstr_new_sz(1024);
        dogecoin_tx_serialize(tx_out, tx);
        char* tx_out_hex = dogecoin_malloc(tx_out->len * 2 + 1);
        utils_bin_to_hex((unsigned char*)tx_out->str, tx_out->len, tx_out_hex);
        char* carrier_spk_hex = utils_uint8_to_hex((const uint8_t*)carrier_spk->str, carrier_spk->len);

        /* Find the OP_RETURN vout (it's the one we just added before the carriers). */
        uint32_t carrier_first_vout = (uint32_t)tx->vout->len - part_total;
        uint32_t opret_vout = carrier_first_vout - 1;

        printf("tx with commitment and carrier outputs: %s\n", tx_out_hex);
        printf("zk_carrier_part_total: %u\n", (unsigned)part_total);
        printf("zk_carrier_output_value_koinu: %llu\n", (unsigned long long)carrier_value_koinu);
        printf("zk_carrier_first_vout: %u\n", (unsigned)carrier_first_vout);
        printf("zk_opreturn_vout: %u\n", (unsigned)opret_vout);
        printf("zk_carrier_p2sh_scriptpubkey: %s\n", carrier_spk_hex ? carrier_spk_hex : "");

        /* Emit per-part scriptSigs for TX_R. */
        cstring** sigs = NULL;
        uint8_t pt2 = 0;
        e = dogecoin_zk_build_carrier_tx_r_scriptsigs(payload, payload_len, &sigs, &pt2);
        if (e == DOGECOIN_ZK_OK && sigs) {
            for (uint8_t i = 0; i < pt2; i++) {
                char* ss_hex = utils_uint8_to_hex((const uint8_t*)sigs[i]->str, sigs[i]->len);
                printf("zk_carrier_part_scriptsig[%u]: %s\n", (unsigned)i, ss_hex ? ss_hex : "");
                cstr_free(sigs[i], true);
            }
            dogecoin_free(sigs);
        }

        dogecoin_free(tx_out_hex);
        cstr_free(tx_out, true);
        cstr_free(carrier_spk, true);
        dogecoin_free(payload);
        dogecoin_tx_free(tx);
    }
    else if (strcmp(cmd, "zk_extract_carrier") == 0) {
        // ./such -c zk_extract_carrier -x <tx_r_hex>
        if (!txhex) return showError("Missing -x <tx_r_hex>\n");
        if ((strlen(txhex) % 2) != 0) return showError("tx hex must be even-length\n");
        size_t bin_len = strlen(txhex) / 2;
        uint8_t* bin = dogecoin_malloc(bin_len + 1);
        size_t outlen = 0;
        utils_hex_to_bin(txhex, bin, strlen(txhex), &outlen);
        dogecoin_tx* tx = dogecoin_tx_new();
        if (!dogecoin_tx_deserialize(bin, outlen, tx, NULL)) {
            dogecoin_free(bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex\n");
        }
        dogecoin_free(bin);

        uint8_t* payload = NULL;
        size_t payload_len = 0;
        dogecoin_zk_err_t e = dogecoin_zk_extract_carrier_payload(tx, &payload, &payload_len);
        if (e != DOGECOIN_ZK_OK) {
            dogecoin_tx_free(tx);
            return showError(dogecoin_zk_strerror(e));
        }
        char* hex = dogecoin_malloc(payload_len * 2 + 1);
        utils_bin_to_hex(payload, payload_len, hex);

        dogecoin_zk_mode_t mode;
        uint32_t cid;
        const uint8_t* pi; size_t pi_len;
        const uint8_t* prf; size_t prf_len;
        const uint8_t* vk_ptr = NULL; size_t vk_len = 0;
        e = dogecoin_zk_decode_payload(payload, payload_len, &mode, &cid,
                                       &pi, &pi_len, &prf, &prf_len,
                                       &vk_ptr, &vk_len);

        printf("zk_payload: %s\n", hex);
        printf("zk_payload_len: %zu\n", payload_len);
        if (e == DOGECOIN_ZK_OK) {
            printf("zk_mode: %u\n", (unsigned)mode);
            printf("zk_circuit_id: 0x%08x\n", (unsigned)cid);
            printf("zk_public_inputs_len: %zu\n", pi_len);
            printf("zk_proof_len: %zu\n", prf_len);
            printf("zk_vk_len: %zu\n", vk_len);
            if (vk_len > 0) {
                /* v1 self-contained reveal: emit the vk bytes verbatim so
                 * downstream tooling (snarkjs verify) can validate the proof
                 * using only data extracted from the on-chain reveal. */
                char* vk_hex = dogecoin_malloc(vk_len * 2 + 1);
                utils_bin_to_hex((uint8_t*)vk_ptr, vk_len, vk_hex);
                printf("zk_vk_hex: %s\n", vk_hex);
                dogecoin_free(vk_hex);
            }
        }
        dogecoin_free(hex);
        dogecoin_free(payload);
        dogecoin_tx_free(tx);
    }
#endif
    else {
        print_usage();
        return showError("Unknown command\n");
    }

    dogecoin_ecc_stop();

    return 0;
    }
