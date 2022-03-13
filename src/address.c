/*

 The MIT License (MIT)

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
#ifdef HAVE_CONFIG_H
#include <src/libdogecoin-config.h>
#endif
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _MSC_VER
#include <unistd.h>
#include <getopt.h>
#endif

#include <dogecoin/address.h>
#include <dogecoin/bip32.h>
#include <dogecoin/crypto/key.h>
#include <dogecoin/crypto/random.h>
#include <dogecoin/crypto/sha2.h>
#include <dogecoin/crypto/base58.h>
#include <dogecoin/tool.h>
#include <dogecoin/utils.h>

/**
 * Generate a new private key and public key pair
 * 
 * @param wif_privkey The private key in WIF format.
 * @param p2pkh_pubkey The public key that will be used to generate a p2pkh address.
 * @param is_testnet boolean, if true, use testnet parameters, otherwise use mainnet parameters
 * 
 * @return Nothing.
 */
int generatePrivPubKeypair(char* wif_privkey, char* p2pkh_pubkey, bool is_testnet)
{
    /* internal variables */
    size_t sizeout = 100;
    char wif_privkey_internal[sizeout];
    char p2pkh_pubkey_internal[sizeout];

    /* if nothing is passed in use internal variables */
    if (wif_privkey) {
        memcpy(wif_privkey_internal, wif_privkey, sizeout);
    }
    if (p2pkh_pubkey) {
        memcpy(p2pkh_pubkey_internal, p2pkh_pubkey, sizeout);
    }

    /* determine if mainnet or testnet/regtest */
    const dogecoin_chainparams* chain = is_testnet ? &dogecoin_chainparams_test : &dogecoin_chainparams_main;

    /* generate a new private key */
    dogecoin_key key;
    dogecoin_privkey_init(&key);
    dogecoin_privkey_gen(&key);
    dogecoin_privkey_encode_wif(&key, chain, wif_privkey_internal, &sizeout);

    /* generate a new public key and export hex */
    dogecoin_pubkey pubkey;
    dogecoin_pubkey_init(&pubkey);
    assert(dogecoin_pubkey_is_valid(&pubkey) == 0);
    dogecoin_pubkey_from_key(&key, &pubkey);

    /* export p2pkh_pubkey address */
    dogecoin_pubkey_getaddr_p2pkh(&pubkey, chain, p2pkh_pubkey_internal);

    if (wif_privkey) {
        memcpy(wif_privkey, wif_privkey_internal, sizeout);
    }
    if (p2pkh_pubkey) {
        memcpy(p2pkh_pubkey, p2pkh_pubkey_internal, sizeout);
    }

    /* reset internal variables */
    dogecoin_mem_zero(wif_privkey_internal, strlen(wif_privkey_internal));
    dogecoin_mem_zero(p2pkh_pubkey_internal, strlen(p2pkh_pubkey_internal));

    /* cleanup memory */
    dogecoin_pubkey_cleanse(&pubkey);
    dogecoin_privkey_cleanse(&key);
    return true;
}

/**
 * The function takes in a private key and returns a public key
 * 
 * @param wif_privkey_master The private key in WIF format.
 * @param p2pkh_pubkey_master The public key of the master HD wallet.
 * @param is_testnet If true, use the testnet chain parameters. If false, use the mainnet chain
 * parameters.
 * 
 * @return Nothing.
 */
int generateHDMasterPubKeypair(char* wif_privkey_master, char* p2pkh_pubkey_master, bool is_testnet)
{
    size_t strsize = 128;
    char hd_privkey_master[strsize];
    char hd_pubkey_master[strsize];

    /* if nothing is passed use internal variables */
    if (wif_privkey_master) {
        memcpy(hd_privkey_master, wif_privkey_master, strsize);
    }
    if (p2pkh_pubkey_master) {
        memcpy(hd_pubkey_master, p2pkh_pubkey_master, strsize);
    }

    /* determine if mainnet or testnet/regtest */
    const dogecoin_chainparams* chain = is_testnet ? &dogecoin_chainparams_test : &dogecoin_chainparams_main;

    /* generate a new hd master key */
    hd_gen_master(chain, hd_privkey_master, strsize);

    generateDerivedHDPubkey(hd_privkey_master, hd_pubkey_master);

    if (wif_privkey_master) {
        memcpy(wif_privkey_master, hd_privkey_master, strlen(hd_privkey_master));
    }
    if (p2pkh_pubkey_master) {
        memcpy(p2pkh_pubkey_master, hd_pubkey_master, strlen(hd_pubkey_master));
    }

    /* reset internal variables */
    dogecoin_mem_zero(hd_privkey_master, strlen(hd_privkey_master));
    dogecoin_mem_zero(hd_privkey_master, strlen(hd_privkey_master));
    
    return true;
}

/**
 * The function takes a private key and returns the public key
 * 
 * @param wif_privkey_master The private key in WIF format.
 * @param p2pkh_pubkey The public key in the format of a p2pkh address.
 * 
 * @return The public key hash of the derived HD public key.
 */
int generateDerivedHDPubkey(const char* wif_privkey_master, char* p2pkh_pubkey)
{
    /* require master key */
    if (!wif_privkey_master) {
        return false;
    }

    /* determine address prefix for network chainparams */
    char prefix[1];
    memcpy(prefix, wif_privkey_master, 1);
    const dogecoin_chainparams* chain = memcmp(prefix, "d", 1) == 0 ? &dogecoin_chainparams_main : &dogecoin_chainparams_test;

    size_t strsize = 128;
    char str[strsize];

    /* if nothing is passed in use internal variables */
    if (p2pkh_pubkey) {
        memcpy(str, p2pkh_pubkey, strsize);
    }

    dogecoin_hdnode* node = dogecoin_hdnode_new();
    dogecoin_hdnode_deserialize(wif_privkey_master, chain, node);

    dogecoin_hdnode_get_p2pkh_address(node, chain, str, strsize);

    /* pass back to external variable if exists */
    if (p2pkh_pubkey) {
        memcpy(p2pkh_pubkey, str, strsize);
    }

    /* reset internal variables */
    dogecoin_hdnode_free(node);
    dogecoin_mem_zero(str, strlen(str));

    return true;
}

/**
 * Verify that the provided private key is valid and that the public key derived from it matches the
 * provided public key
 * 
 * @param wif_privkey The private key in WIF format.
 * @param p2pkh_pubkey The public key you want to verify.
 * @param is_testnet whether or not the testnet or mainnet parameters should be used.
 * 
 * @return Nothing.
 */
int verifyPrivPubKeypair(char* wif_privkey, char* p2pkh_pubkey, bool is_testnet) {
    /* require both private and public key */
    if (!wif_privkey || !p2pkh_pubkey) return 0;

    /* set chain */
    const dogecoin_chainparams* chain = is_testnet ? &dogecoin_chainparams_test : &dogecoin_chainparams_main;
    size_t sizeout = 100;

    /* verify private key */
    dogecoin_key key;
    dogecoin_privkey_init(&key);
    dogecoin_privkey_decode_wif(wif_privkey, chain, &key);
    if (!dogecoin_privkey_is_valid(&key)) return 0;
    char new_wif_privkey[sizeout];
    dogecoin_privkey_encode_wif(&key, chain, new_wif_privkey, &sizeout);

    /* verify public key */
    dogecoin_pubkey pubkey;
    dogecoin_pubkey_init(&pubkey);
    dogecoin_pubkey_from_key(&key, &pubkey);
    if (!dogecoin_pubkey_is_valid(&pubkey)) return 0;

    /* verify address derived matches provided address */
    char new_p2pkh_pubkey[sizeout];
    dogecoin_pubkey_getaddr_p2pkh(&pubkey, chain, new_p2pkh_pubkey);
    if (strcmp(p2pkh_pubkey, new_p2pkh_pubkey)) return 0;

    dogecoin_pubkey_cleanse(&pubkey);
    dogecoin_privkey_cleanse(&key);
    return true;
}

/**
 * The function verifies that the given private key is a valid private key for the given public key
 * 
 * @param wif_privkey_master The private key in WIF format.
 * @param p2pkh_pubkey_master The public key of the master node.
 * @param is_testnet whether the network is testnet or mainnet
 * 
 * @return true if the public key derived from the private key matches the public key given.
 */
int verifyHDMasterPubKeypair(char* wif_privkey_master, char* p2pkh_pubkey_master, bool is_testnet) {
    /* require both private and public key */
    if (!wif_privkey_master || !p2pkh_pubkey_master) return false;

    /* determine if mainnet or testnet/regtest */
    const dogecoin_chainparams* chain = is_testnet ? &dogecoin_chainparams_test : &dogecoin_chainparams_main;

    /* calculate master pubkey from master privkey */
    dogecoin_hdnode node;
    dogecoin_hdnode_deserialize(wif_privkey_master, chain, &node);
    size_t sizeout = 128;
    char new_p2pkh_pubkey_master[sizeout];
    dogecoin_hdnode_get_p2pkh_address(&node, chain, new_p2pkh_pubkey_master, sizeout);

    /* compare derived and given pubkeys */
    if (strcmp(p2pkh_pubkey_master, new_p2pkh_pubkey_master)) return false;

    return true;
}

/**
 * The function verifies a P2PKH address
 * 
 * @param p2pkh_pubkey The public key to be verified.
 * @param len The length of the address in bytes.
 * 
 * @return A boolean value.
 */
int verifyP2pkhAddress(char* p2pkh_pubkey, uint8_t len) {
    if (!p2pkh_pubkey || !len) return false;
    /* check length */
    unsigned char dec[len], d1[SHA256_DIGEST_LENGTH], d2[SHA256_DIGEST_LENGTH];
    if (!dogecoin_base58_decode_check(p2pkh_pubkey, dec, len)) {
        return false;
    }
    /* check validity */
    sha256_raw(dec, 21, d1);
    sha256_raw(d1, SHA256_DIGEST_LENGTH, d2);
    if (memcmp(dec + 21, d2, 4) != 0) {
        return false;
    }
    return true;
}