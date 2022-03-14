/*

 The MIT License (MIT)

 Copyright (c) 2016 Jonas Schnelli
 Copyright (c) 2022 bluezr
 Copyright (c) 2022 The Dogecoin Foundation

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
#include <getopt.h>
#include <src/libdogecoin-config.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dogecoin/bip32.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/crypto/ecc.h>
#include <dogecoin/net/protocol.h>
#include <dogecoin/serialize.h>
#include <dogecoin/tool.h>
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>

/* This is a function that is used to parse the command line arguments. */
static struct option long_options[] =
    {
        {"privkey", required_argument, NULL, 'p'},
        {"pubkey", required_argument, NULL, 'k'},
        {"derived_path", required_argument, NULL, 'm'},
        {"command", required_argument, NULL, 'c'},
        {"testnet", no_argument, NULL, 't'},
        {"regtest", no_argument, NULL, 'r'},
        {"version", no_argument, NULL, 'v'},
        {"txhex", no_argument, NULL, 'x'},
        {"scripthex", no_argument, NULL, 's'},
        {"inputindex", no_argument, NULL, 'i'},
        {"sighashtype", no_argument, NULL, 'h'},
        {"amount", no_argument, NULL, 'a'},
        {NULL, 0, NULL, 0}
};

/**
 * Print_version() prints the version of the program
 */
static void print_version() {
    printf("Version: %s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
}

/**
 * This function prints the usage information for the program
 */
static void print_usage()
{
    print_version();
    printf("Usage: such (-m|-derived_path <bip_derived_path>) (-k|-pubkey <publickey>) (-p|-privkey <privatekey>) (-t[--testnet]) (-r[--regtest]) -c <command>\n");
    printf("Available commands: generate_public_key (requires -p <wif>), p2pkh (requires -k <public key hex>), generate_private_key, bip32_extended_master_key, print_keys (requires -p <private key hex>), derive_child_keys (requires -m <custom path> -p <private key>) \n");
    printf("\nExamples: \n");
    printf("Generate a testnet private ec keypair wif/hex:\n");
    printf("> such -c generate_private_key\n\n");
    printf("> such -c generate_public_key -p QRYZwxVxBFKgKP4bWPEwWBJpN3C3cTN6fads8SgJTgaPTJhEWgLH\n\n");
}

/**
 * It prints out the error message and then stops the ecc library
 * 
 * @param er The error message to display.
 * 
 * @return Nothing.
 */
static bool showError(const char* er)
{
    printf("Error: %s\n", er);
    dogecoin_ecc_stop();
    return 1;
}

int main(int argc, char* argv[])
{
    int long_index = 0;
    int opt = 0;
    char* pkey      = 0;
    char* pubkey    = 0;
    char* cmd       = 0;
    char* keypath   = 0;
    char* txhex     = 0;
    char* scripthex = 0;
    int inputindex  = 0;
    int sighashtype = 1;
    uint64_t amount = 0;
    dogecoin_mem_zero(&pkey, sizeof(pkey));
    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    /* get arguments */
    /* This code is parsing the command line arguments. */
    while ((opt = getopt_long_only(argc, argv, "h:i:s:x:p:k:a:m:c:trv", long_options, &long_index)) != -1) {
        switch (opt) {
        case 'p':
            pkey = optarg;
            if (strlen(pkey) < 50)
                return showError("Private key must be WIF encoded");
            break;
        case 'c':
            cmd = optarg;
            break;
        case 'm':
            keypath = optarg;
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
        case 'a':
            amount = (int)strtoll(optarg, (char**)NULL, 10);
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

    const char* pkey_error = "missing extended key (use -p)";

    /* Generating a public key from a private key. */
    if (strcmp(cmd, "generate_public_key") == 0) {
        /* output compressed hex pubkey from hex privkey */

        size_t sizeout = 128;
        char pubkey_hex[sizeout];
        if (!pkey)
            return showError(pkey_error);
        if (!pubkey_from_privatekey(chain, pkey, pubkey_hex, &sizeout))
            return showError("attempt to generate pubkey from privatekey failed");

        /* erase previous private key */
        dogecoin_mem_zero(pkey, strlen(pkey));

        /* generate public key hex from private key hex */
        printf("public key hex: %s\n", pubkey_hex);

        /* give out p2pkh address */
        char address_p2pkh[sizeout];
        char address_p2sh_p2wpkh[sizeout];
        char address_p2wpkh[sizeout];
        addresses_from_pubkey(chain, pubkey_hex, address_p2pkh, address_p2sh_p2wpkh, address_p2wpkh);
        printf("p2pkh address: %s\n", address_p2pkh);
        printf("p2sh-p2wpkh address: %s\n", address_p2sh_p2wpkh);

        /* clean memory */
        dogecoin_mem_zero(pubkey_hex, strlen(pubkey_hex));
        dogecoin_mem_zero(address_p2pkh, strlen(address_p2pkh));
        dogecoin_mem_zero(address_p2sh_p2wpkh, strlen(address_p2sh_p2wpkh));
    /* Creating a new address from a public key. */
    } else if (strcmp(cmd, "p2pkh") == 0) {
        /* get p2pkh address from pubkey */

        size_t sizeout = 128;
        char address_p2pkh[sizeout];
        char address_p2sh_p2wpkh[sizeout];
        char address_p2wpkh[sizeout];
        if (!pubkey)
            return showError("Missing public key (use -k)");
        if (!addresses_from_pubkey(chain, pubkey, address_p2pkh, address_p2sh_p2wpkh, address_p2wpkh))
            return showError("Operation failed, invalid pubkey");
        printf("p2pkh address: %s\n", address_p2pkh);
        printf("p2sh-p2wpkh address: %s\n", address_p2sh_p2wpkh);
        printf("p2wpkh (doge / bech32) address: %s\n", address_p2wpkh);

        dogecoin_mem_zero(pubkey, strlen(pubkey));
        dogecoin_mem_zero(address_p2pkh, strlen(address_p2pkh));
        dogecoin_mem_zero(address_p2sh_p2wpkh, strlen(address_p2sh_p2wpkh));
    /* Generating a new private key and printing it out. */
    } else if (strcmp(cmd, "generate_private_key") == 0) {
        size_t sizeout = 128;
        char newprivkey_wif[sizeout];
        char newprivkey_hex[sizeout];

        /* generate a new private key */
        gen_privatekey(chain, newprivkey_wif, sizeout, newprivkey_hex);
        printf("private key wif: %s\n", newprivkey_wif);
        printf("private key hex: %s\n", newprivkey_hex);
        dogecoin_mem_zero(newprivkey_wif, strlen(newprivkey_wif));
        dogecoin_mem_zero(newprivkey_hex, strlen(newprivkey_hex));
    /* Generating a new master key. */
    } else if (strcmp(cmd, "bip32_extended_master_key") == 0) {
        size_t sizeout = 128;
        char masterkey[sizeout];

        /* generate a new hd master key */
        hd_gen_master(chain, masterkey, sizeout);
        printf("bip32 extended master key: %s\n", masterkey);
        dogecoin_mem_zero(masterkey, strlen(masterkey));
    /* Printing the node keys. */
    } else if (strcmp(cmd, "print_keys") == 0) {
        if (!pkey)
            return showError("no extended key (-p)");
        if (!hd_print_node(chain, pkey))
            return showError("invalid extended key\n");
    /* Deriving a child key from the parent key. */
    } else if (strcmp(cmd, "derive_child_keys") == 0) {
        if (!pkey)
            return showError(pkey_error);
        if (!keypath)
            return showError("Missing keypath (use -m)");
        size_t sizeout = 128;
        char newextkey[sizeout];

        //check if we derive a range of keys
        unsigned int maxlen = 1024;
        int posanum = -1;
        int posbnum = -1;
        int end = -1;
        uint64_t from = 0;
        uint64_t to = 0;

        static char digits[] = "0123456789";
        unsigned int i;
        for (i = 0; i < strlen(keypath); i++) {
            if (i > maxlen) {
                break;
            }
            if (posanum > -1 && posbnum == -1) {
                if (keypath[i] == '-') {
                    if (i-posanum >= 9) {
                        break;
                    }
                    posbnum = i+1;
                    char buf[9] = {0};
                    memcpy (buf, &keypath[posanum], i-posanum);
                    from = strtoull(buf, NULL, 10);
                } else if (!strchr(digits, keypath[i])) {
                    posanum = -1;
                    break;
                }
            } else if (posanum > -1 && posbnum > -1) {
                if (keypath[i] == ']' || keypath[i] == ')') {
                    if (i-posbnum >= 9) {
                        break;
                    }
                    char buf[9] = {0};
                    memcpy (buf, &keypath[posbnum], i-posbnum);
                    to = strtoull(buf, NULL, 10);
                    end = i+1;
                    break;
                } else if (!strchr(digits, keypath[i])) {
                    // posbnum = -1; // value stored is never read
                    posanum = -1;
                    break;
                }
            }
            if (keypath[i] == '[' || keypath[i] == '(') {
                posanum = i+1;
            }
        }

        if (end > -1 && from <= to) {
            for (i = from; i <= to; i++) {
                char keypathnew[strlen(keypath)+16];
                memcpy(keypathnew, keypath, posanum-1);
                char index[9] = {0};
                sprintf(index, "%lld", (long long)i);
                memcpy(keypathnew+posanum-1, index, strlen(index));
                memcpy(keypathnew+posanum-1+strlen(index), &keypath[end], strlen(keypath)-end);


                if (!hd_derive(chain, pkey, keypathnew, newextkey, sizeout))
                    return showError("Deriving child key failed\n");
                else
                    hd_print_node(chain, newextkey);
            }
        }
        else {
            if (!hd_derive(chain, pkey, keypath, newextkey, sizeout))
                return showError("Deriving child key failed\n");
            else
                hd_print_node(chain, newextkey);
        }
    /* The below code is a simple command line tool that allows you to sign a transaction. */
    } else if (strcmp(cmd, "sign") == 0) {
        if(!txhex || !scripthex) {
            return showError("Missing tx-hex or script-hex (use -x, -s)\n");
        }

        if (strlen(txhex) > 1024*100) { //don't accept tx larger then 100kb
            return showError("tx too large (max 100kb)\n");
        }

        //deserialize transaction
        dogecoin_tx* tx = dogecoin_tx_new();
        uint8_t* data_bin = dogecoin_malloc(strlen(txhex) / 2 + 1);
        int outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);
        if (!dogecoin_tx_deserialize(data_bin, outlen, tx, NULL, true)) {
            dogecoin_free(data_bin);
            dogecoin_tx_free(tx);
            return showError("Invalid tx hex");
        }
        dogecoin_free(data_bin);

        if ((size_t)inputindex >= tx->vin->len) {
            dogecoin_tx_free(tx);
            return showError("Inputindex out of range");
        }

        vector_idx(tx->vin, inputindex);

        uint8_t script_data[strlen(scripthex) / 2 + 1];
        utils_hex_to_bin(scripthex, script_data, strlen(scripthex), &outlen);
        cstring* script = cstr_new_buf(script_data, outlen);

        uint256 sighash;
        dogecoin_mem_zero(sighash, sizeof(sighash));
        dogecoin_tx_sighash(tx, script, inputindex, sighashtype, 0, SIGVERSION_BASE, sighash);

        char *hex = utils_uint8_to_hex(sighash, 32);
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
        } else {
            if (pkey) {
                if (strlen(pkey) > 50) {
                    dogecoin_tx_free(tx);
                    cstr_free(script, true);
                    return showError("Invalid wif privkey\n");
                }
            } else {
                printf("No private key provided, signing will not happen\n");
            }
        }
        if (sign) {
            uint8_t sigcompact[64] = {0};
            int sigderlen = 74+1; //&hashtype
            uint8_t sigder_plus_hashtype[75] = {0};
            enum dogecoin_tx_sign_result res = dogecoin_tx_sign_input(tx, script, amount, &key, inputindex, sighashtype, sigcompact, sigder_plus_hashtype, &sigderlen);
            cstr_free(script, true);

            if (res != DOGECOIN_SIGN_OK) {
                printf("!!!Sign error:%s\n", dogecoin_tx_sign_result_to_str(res));
            }

            char sigcompacthex[64*2+1] = {0};
            utils_bin_to_hex((unsigned char *)sigcompact, 64, sigcompacthex);

            char sigderhex[74*2+2+1]; //74 der, 2 hashtype, 1 nullbyte
            dogecoin_mem_zero(sigderhex, sizeof(sigderhex));
            utils_bin_to_hex((unsigned char *)sigder_plus_hashtype, sigderlen, sigderhex);

            printf("\nSignature created:\n");
            printf("signature compact: %s\n", sigcompacthex);
            printf("signature DER (+hashtype): %s\n", sigderhex);

            cstring* signed_tx = cstr_new_sz(1024);
            dogecoin_tx_serialize(signed_tx, tx, true);

            char signed_tx_hex[signed_tx->len*2+1];
            utils_bin_to_hex((unsigned char *)signed_tx->str, signed_tx->len, signed_tx_hex);
            printf("signed TX: %s\n", signed_tx_hex);
            cstr_free(signed_tx, true);
        }
        dogecoin_tx_free(tx);
    } else if (strcmp(cmd, "comp2der") == 0) {
        if(!scripthex || strlen(scripthex) != 128) {
            return showError("Missing signature or invalid length (use hex, 128 chars == 64 bytes)\n");
        }

        int outlen = 0;
        uint8_t sig_comp[strlen(scripthex) / 2 + 1];
        printf("%s\n", scripthex);
        utils_hex_to_bin(scripthex, sig_comp, strlen(scripthex), &outlen);

        unsigned char sigder[74];
        size_t sigderlen = 74;

        dogecoin_ecc_compact_to_der_normalized(sig_comp, sigder, &sigderlen);
        char hexbuf[sigderlen*2 + 1];
        utils_bin_to_hex(sigder, sigderlen, hexbuf);
        printf("DER: %s\n", hexbuf);
    } else if (strcmp(cmd, "bip32maintotest") == 0) { /* Creating a bip32 master key from a private key. */
        dogecoin_hdnode node;
        if (!dogecoin_hdnode_deserialize(pkey, chain, &node))
            return false;

        char masterkeyhex[200];
        int strsize = 200;
        dogecoin_hdnode_serialize_private(&node, &dogecoin_chainparams_test, masterkeyhex, strsize);
        printf("xpriv: %s\n", masterkeyhex);
        dogecoin_hdnode_serialize_public(&node, &dogecoin_chainparams_test, masterkeyhex, strsize);
        printf("xpub: %s\n", masterkeyhex);
    }

    dogecoin_ecc_stop();

    return 0;
}
