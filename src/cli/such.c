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

#include "libdogecoin-config.h"

#include <dogecoin/bip32.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/crypto/ecc.h>
#include <dogecoin/serialize.h>
#include <dogecoin/tool.h>
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

static struct option long_options[] =
{
    {"privkey", required_argument, NULL, 'p'},
    {"pubkey", required_argument, NULL, 'k'},
    {"derived_path", required_argument, NULL, 'm'},
    {"command", required_argument, NULL, 'c'},
    {"testnet", no_argument, NULL, 't'},
    {"regtest", no_argument, NULL, 'r'},
    {"version", no_argument, NULL, 'v'},
    {NULL, 0, NULL, 0}
};

static void print_version() {
    printf("Version: %s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
}

static void print_usage() {
    print_version();
    printf("Usage: such (-m|-derived_path <bip_derived_path>) (-k|-pubkey <publickey>) (-p|-privkey <privatekey>) (-t[--testnet]) (-r[--regtest]) -c <command>\n");
    printf("Available commands: generate_public_key (requires -p <wif>), p2pkh (requires -k <public key hex>), generate_private_key, bip32_extended_master_key, print_keys (requires -p <private key hex>), derive_child_keys (requires -m <custom path> -p <private key>) \n");
    printf("\nExamples: \n");
    printf("Generate a testnet private ec keypair wif/hex:\n");
    printf("> such -c generate_private_key\n\n");
    printf("> such -c generate_public_key -p QRYZwxVxBFKgKP4bWPEwWBJpN3C3cTN6fads8SgJTgaPTJhEWgLH\n\n");
}

static bool showError(const char *er)
{
    printf("Error: %s\n", er);
    dogecoin_ecc_stop();
    return 1;
}

int main(int argc, char *argv[])
{
    int long_index = 0;
    int opt= 0;
    char* pkey      = 0;
    char* pubkey    = 0;
    char* cmd       = 0;
    char *derived_path = 0;
    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    /* get arguments */
    while ((opt = getopt_long_only(argc, argv,"p:k:m:c:trv", long_options, &long_index )) != -1) {
        switch (opt) {
            case 'p' :
                pkey = optarg;
                if (strlen(pkey) < 50)
                    return showError("Private key must be WIF encoded");
                break;
            case 'c' : cmd = optarg;
                break;
            case 'm' : derived_path = optarg;
                break;
            case 'k' : pubkey = optarg;
                break;
            case 't' :
                chain = &dogecoin_chainparams_test;
                break;
            case 'r' :
                chain = &dogecoin_chainparams_regtest;
                break;
            case 'v' :
                print_version();
                exit(EXIT_SUCCESS);
                break;
            default: print_usage();
                exit(EXIT_FAILURE);
        }
    }

    if (!cmd)
    {
        /* exit if no command was provided */
        print_usage();
        exit(EXIT_FAILURE);
    }

    /* start ECC context */
    dogecoin_ecc_start();

    const char *pkey_error = "missing extended key (use -p)";

    if (strcmp(cmd, "generate_public_key") == 0) {
        /* output compressed hex pubkey from hex privkey */

        size_t sizeout = 128;
        char pubkey_hex[sizeout];
        if (!pkey)
            return showError(pkey_error);
        if (!pubkey_from_privatekey(chain, pkey, pubkey_hex, &sizeout))
            return showError("Operation failed");

        /* clean memory of private key */
        memset(pkey, 0, strlen(pkey));

        /* give out hex pubkey */
        printf("pubkey: %s\n", pubkey_hex);

        /* give out p2pkh address */
        char address_p2pkh[sizeout];
        char address_p2sh_p2wpkh[sizeout];
        char address_p2wpkh[sizeout];
        addresses_from_pubkey(chain, pubkey_hex, address_p2pkh, address_p2sh_p2wpkh, address_p2wpkh);
        printf("p2pkh address: %s\n", address_p2pkh);
        printf("p2sh-p2wpkh address: %s\n", address_p2sh_p2wpkh);

        /* clean memory */
        memset(pubkey_hex, 0, strlen(pubkey_hex));
        memset(address_p2pkh, 0, strlen(address_p2pkh));
        memset(address_p2sh_p2wpkh, 0, strlen(address_p2sh_p2wpkh));
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

        memset(pubkey, 0, strlen(pubkey));
        memset(address_p2pkh, 0, strlen(address_p2pkh));
        memset(address_p2sh_p2wpkh, 0, strlen(address_p2sh_p2wpkh));
    } else if (strcmp(cmd, "generate_private_key") == 0) {
        size_t sizeout = 128;
        char newprivkey_wif[sizeout];
        char newprivkey_hex[sizeout];

        /* generate a new private key */
        gen_privatekey(chain, newprivkey_wif, sizeout, newprivkey_hex);
        printf("private key wif: %s\n", newprivkey_wif);
        printf("private key hex: %s\n", newprivkey_hex);
        memset(newprivkey_wif, 0, strlen(newprivkey_wif));
        memset(newprivkey_hex, 0, strlen(newprivkey_hex));
    } else if (strcmp(cmd, "bip32_extended_master_key") == 0) {
        size_t sizeout = 128;
        char masterkey[sizeout];

        /* generate a new hd master key */
        hd_gen_master(chain, masterkey, sizeout);
        printf("bip32 extended master key: %s\n", masterkey);
        memset(masterkey, 0, strlen(masterkey));
    } else if (strcmp(cmd, "print_keys") == 0) {
        if (!pkey)
            return showError("no extended key (-p)");
        if (!hd_print_node(chain, pkey))
            return showError("invalid extended key\n");
    } else if (strcmp(cmd, "derive_child_keys") == 0) {
        if (!pkey)
            return showError(pkey_error);
        if (!derived_path)
            return showError("Missing derived_path (use -m)");
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
        for (unsigned int i = 0; i<strlen(derived_path); i++) {
            if (i > maxlen) {
                break;
            }
            if (posanum > -1 && posbnum == -1) {
                if (derived_path[i] == '-') {
                    if (i-posanum >= 9) {
                        break;
                    }
                    posbnum = i+1;
                    char buf[9] = {0};
                    memcpy (buf, &derived_path[posanum], i-posanum);
                    from = strtoull(buf, NULL, 10);
                }
                else if (!strchr(digits, derived_path[i])) {
                    posanum = -1;
                    break;
                }
            }
            else if (posanum > -1 && posbnum > -1) {
                if (derived_path[i] == ']' || derived_path[i] == ')') {
                    if (i-posbnum >= 9) {
                        break;
                    }
                    char buf[9] = {0};
                    memcpy (buf, &derived_path[posbnum], i-posbnum);
                    to = strtoull(buf, NULL, 10);
                    end = i+1;
                    break;
                }
                else if (!strchr(digits, derived_path[i])) {
                    posbnum = -1;
                    posanum = -1;
                    break;
                }
            }
            if (derived_path[i] == '[' || derived_path[i] == '(') {
                posanum = i+1;
            }
        }

        if (end > -1 && from <= to) {
            for (uint64_t i = from; i <= to; i++) {
                char derived_pathnew[strlen(derived_path)+16];
                memcpy(derived_pathnew, derived_path, posanum-1);
                char index[9] = {0};
                sprintf(index, "%lld", (long long)i);
                memcpy(derived_pathnew+posanum-1, index, strlen(index));
                memcpy(derived_pathnew+posanum-1+strlen(index), &derived_path[end], strlen(derived_path)-end);


                if (!hd_derive(chain, pkey, derived_pathnew, newextkey, sizeout))
                    return showError("Deriving child key failed\n");
                else
                    hd_print_node(chain, newextkey);
            }
        }
        else {
            if (!hd_derive(chain, pkey, derived_path, newextkey, sizeout))
                return showError("Deriving child key failed\n");
            else
                hd_print_node(chain, newextkey);
        }
    } else if (strcmp(cmd, "bip32maintotest") == 0) {
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
