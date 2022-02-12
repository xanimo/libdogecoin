/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 * Copyright (c) 2015 Douglas J. Bakkumk
 * Copyright (c) 2022 bluezr
 * Copyright (c) 2022 The Dogecoin Foundation
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

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dogecoin/bip32.h>
#include <dogecoin/crypto/base58.h>
#include <dogecoin/crypto/common.h>
#include <dogecoin/crypto/ecc.h>
#include <dogecoin/crypto/hash.h>
#include <dogecoin/crypto/key.h>
#include <dogecoin/crypto/rmd160.h>
#include <dogecoin/crypto/sha2.h>
#include <dogecoin/mem.h>
#include <dogecoin/utils.h>

/**
 * It allocates memory for a dogecoin_hdnode and returns a pointer to it
 * 
 * @return A pointer to a new dogecoin_hdnode object.
 */
dogecoin_hdnode* dogecoin_hdnode_new()
{
    dogecoin_hdnode* hdnode;
    hdnode = dogecoin_calloc(1, sizeof(*hdnode));
    return hdnode;
}

/**
 * Create a new dogecoin_hdnode from an existing one
 * 
 * @param hdnode The node to copy.
 * 
 * @return A new dogecoin_hdnode object.
 */
dogecoin_hdnode* dogecoin_hdnode_copy(const dogecoin_hdnode* hdnode)
{
    dogecoin_hdnode* newnode = dogecoin_hdnode_new();

    newnode->depth = hdnode->depth;
    newnode->fingerprint = hdnode->fingerprint;
    newnode->child_num = hdnode->child_num;
    memcpy(newnode->chain_code, hdnode->chain_code, sizeof(hdnode->chain_code));
    memcpy(newnode->private_key, hdnode->private_key, sizeof(hdnode->private_key));
    memcpy(newnode->public_key, hdnode->public_key, sizeof(hdnode->public_key));

    return newnode;
}

/**
 * It takes a pointer to a dogecoin_hdnode struct, and sets all the values in the struct to zero
 * 
 * @param hdnode The HDNode to free.
 */
void dogecoin_hdnode_free(dogecoin_hdnode* hdnode)
{
    memset(hdnode->chain_code, 0, sizeof(hdnode->chain_code));
    memset(hdnode->private_key, 0, sizeof(hdnode->private_key));
    memset(hdnode->public_key, 0, sizeof(hdnode->public_key));
    dogecoin_free(hdnode);
}

/**
 * The function takes a seed and generates a private key and chain code
 * 
 * @param seed The seed to generate the master node from.
 * @param seed_len The length of the seed.
 * @param out The HDNode struct that will be filled with the derived key.
 * 
 * @return Nothing.
 */
dogecoin_bool dogecoin_hdnode_from_seed(const uint8_t* seed, int seed_len, dogecoin_hdnode* out)
{
    uint8_t I[DOGECOIN_ECKEY_PKEY_LENGTH + DOGECOIN_BIP32_CHAINCODE_SIZE];
    memset(out, 0, sizeof(dogecoin_hdnode));
    out->depth = 0;
    out->fingerprint = 0x00000000;
    out->child_num = 0;
    hmac_sha512((const uint8_t*)"Dogecoin seed", 12, seed, seed_len, I);
    memcpy(out->private_key, I, DOGECOIN_ECKEY_PKEY_LENGTH);

    if (!dogecoin_ecc_verify_privatekey(out->private_key)) {
        memset(I, 0, sizeof(I));
        return false;
    }

    memcpy(out->chain_code, I + DOGECOIN_ECKEY_PKEY_LENGTH, DOGECOIN_BIP32_CHAINCODE_SIZE);
    dogecoin_hdnode_fill_public_key(out);
    memset(I, 0, sizeof(I));
    return true;
}


/**
 * The function takes in a dogecoin_hdnode, a uint32_t, and a bool. The function returns a bool. The
 * function takes the dogecoin_hdnode, and the uint32_t, and uses them to derive a child node. The
 * function then returns a bool
 * 
 * @param inout The HDNode to be modified.
 * @param i The index of the child key.
 * 
 * @return Nothing.
 */
dogecoin_bool dogecoin_hdnode_public_ckd(dogecoin_hdnode* inout, uint32_t i)
{
    uint8_t data[1 + 32 + 4];
    uint8_t I[32 + DOGECOIN_BIP32_CHAINCODE_SIZE];
    uint8_t fingerprint[32];

    if (i & 0x80000000) { // private derivation
        return false;
    } else { // public derivation
        memcpy(data, inout->public_key, DOGECOIN_ECKEY_COMPRESSED_LENGTH);
    }
    write_be32(data + DOGECOIN_ECKEY_COMPRESSED_LENGTH, i);

    sha256_raw(inout->public_key, DOGECOIN_ECKEY_COMPRESSED_LENGTH, fingerprint);
    rmd160(fingerprint, 32, fingerprint);
    inout->fingerprint = (fingerprint[0] << 24) + (fingerprint[1] << 16) + (fingerprint[2] << 8) + fingerprint[3];

    memset(inout->private_key, 0, 32);

    int failed = 0;
    hmac_sha512(inout->chain_code, 32, data, sizeof(data), I);
    memcpy(inout->chain_code, I + 32, DOGECOIN_BIP32_CHAINCODE_SIZE);


    if (!dogecoin_ecc_public_key_tweak_add(inout->public_key, I))
        failed = false;

    if (!failed) {
        inout->depth++;
        inout->child_num = i;
    }

    // Wipe all stack data.
    memset(data, 0, sizeof(data));
    memset(I, 0, sizeof(I));
    memset(fingerprint, 0, sizeof(fingerprint));

    return failed ? false : true;
}


/**
 * The function takes in a private key and a child number, and returns a new private key
 * 
 * @param inout The hdnode object to be modified.
 * @param i The index of the child node.
 * 
 * @return Nothing.
 */
dogecoin_bool dogecoin_hdnode_private_ckd(dogecoin_hdnode* inout, uint32_t i)
{
    uint8_t data[1 + DOGECOIN_ECKEY_PKEY_LENGTH + 4];
    uint8_t I[DOGECOIN_ECKEY_PKEY_LENGTH + DOGECOIN_BIP32_CHAINCODE_SIZE];
    uint8_t fingerprint[DOGECOIN_BIP32_CHAINCODE_SIZE];
    uint8_t p[DOGECOIN_ECKEY_PKEY_LENGTH], z[DOGECOIN_ECKEY_PKEY_LENGTH];

    if (i & 0x80000000) { // private derivation
        data[0] = 0;
        memcpy(data + 1, inout->private_key, DOGECOIN_ECKEY_PKEY_LENGTH);
    } else { // public derivation
        memcpy(data, inout->public_key, DOGECOIN_ECKEY_COMPRESSED_LENGTH);
    }
    write_be32(data + DOGECOIN_ECKEY_COMPRESSED_LENGTH, i);

    sha256_raw(inout->public_key, DOGECOIN_ECKEY_COMPRESSED_LENGTH, fingerprint);
    rmd160(fingerprint, 32, fingerprint);
    inout->fingerprint = (fingerprint[0] << 24) + (fingerprint[1] << 16) +
                         (fingerprint[2] << 8) + fingerprint[3];

    memset(fingerprint, 0, sizeof(fingerprint));
    memcpy(p, inout->private_key, DOGECOIN_ECKEY_PKEY_LENGTH);

    hmac_sha512(inout->chain_code, DOGECOIN_BIP32_CHAINCODE_SIZE, data, sizeof(data), I);
    memcpy(inout->chain_code, I + DOGECOIN_ECKEY_PKEY_LENGTH, DOGECOIN_BIP32_CHAINCODE_SIZE);
    memcpy(inout->private_key, I, DOGECOIN_ECKEY_PKEY_LENGTH);

    memcpy(z, inout->private_key, DOGECOIN_ECKEY_PKEY_LENGTH);

    int failed = 0;
    if (!dogecoin_ecc_verify_privatekey(z)) {
        failed = 1;
        return false;
    }

    memcpy(inout->private_key, p, DOGECOIN_ECKEY_PKEY_LENGTH);
    if (!dogecoin_ecc_private_key_tweak_add(inout->private_key, z)) {
        failed = 1;
    }

    if (!failed) {
        inout->depth++;
        inout->child_num = i;
        dogecoin_hdnode_fill_public_key(inout);
    }

    memset(data, 0, sizeof(data));
    memset(I, 0, sizeof(I));
    memset(p, 0, sizeof(p));
    memset(z, 0, sizeof(z));
    return true;
}


/**
 * It takes a private key and generates a public key
 * 
 * @param node The dogecoin_hdnode struct to fill.
 */
void dogecoin_hdnode_fill_public_key(dogecoin_hdnode* node)
{
    size_t outsize = DOGECOIN_ECKEY_COMPRESSED_LENGTH;
    dogecoin_ecc_get_pubkey(node->private_key, node->public_key, &outsize, true);
}


/**
 * This function serializes a dogecoin_hdnode struct into a base58 string
 * 
 * @param node The dogecoin_hdnode struct that holds the node's data.
 * @param version The version byte.
 * @param use_public Whether to use the public or private key.
 * @param str The string to be encoded.
 * @param strsize The size of the string that will be returned.
 */
static void dogecoin_hdnode_serialize(const dogecoin_hdnode* node, uint32_t version, char use_public, char* str, int strsize)
{
    uint8_t node_data[78];
    write_be32(node_data, version);
    node_data[4] = node->depth;
    write_be32(node_data + 5, node->fingerprint);
    write_be32(node_data + 9, node->child_num);
    memcpy(node_data + 13, node->chain_code, DOGECOIN_BIP32_CHAINCODE_SIZE);
    if (use_public) {
        memcpy(node_data + 45, node->public_key, DOGECOIN_ECKEY_COMPRESSED_LENGTH);
    } else {
        node_data[45] = 0;
        memcpy(node_data + 46, node->private_key, DOGECOIN_ECKEY_PKEY_LENGTH);
    }
    dogecoin_base58_encode_check(node_data, 78, str, strsize);
}


/**
 * It takes a dogecoin_hdnode, a dogecoin_chainparams, a buffer, and a buffer size. It serializes the
 * dogecoin_hdnode into the buffer, using the dogecoin_chainparams to determine the format of the
 * serialization
 * 
 * @param node The dogecoin_hdnode struct to serialize.
 * @param chain The chain parameters to use.
 * @param str the string to be filled with the serialized data
 * @param strsize The size of the string to be returned.
 */
void dogecoin_hdnode_serialize_public(const dogecoin_hdnode* node, const dogecoin_chainparams* chain, char* str, int strsize)
{
    dogecoin_hdnode_serialize(node, chain->b58prefix_bip32_pubkey, 1, str, strsize);
}


/**
 * Given a dogecoin_hdnode, a dogecoin_chainparams, and a buffer, serialize the dogecoin_hdnode into
 * the buffer
 * 
 * @param node The dogecoin_hdnode struct to serialize.
 * @param chain The chain parameters to use.
 * @param str the string to be filled with the serialized data
 * @param strsize The size of the string to be returned.
 */
void dogecoin_hdnode_serialize_private(const dogecoin_hdnode* node, const dogecoin_chainparams* chain, char* str, int strsize)
{
    dogecoin_hdnode_serialize(node, chain->b58prefix_bip32_privkey, 0, str, strsize);
}


/**
 * Given a dogecoin_hdnode, return the hash160 of the compressed public key
 * 
 * @param node The HDNode struct that contains the public key and chain code.
 * @param hash160_out The hash160 of the public key.
 */
void dogecoin_hdnode_get_hash160(const dogecoin_hdnode* node, uint160 hash160_out)
{
    uint256 hashout;
    dogecoin_hash_sngl_sha256(node->public_key, DOGECOIN_ECKEY_COMPRESSED_LENGTH, hashout);
    rmd160(hashout, sizeof(hashout), hash160_out);
}

/**
 * Given a node, return the p2pkh address for that node
 * 
 * @param node The HD node.
 * @param chain The chain parameters to use.
 * @param str The string to encode.
 * @param strsize The size of the string to be returned.
 */
void dogecoin_hdnode_get_p2pkh_address(const dogecoin_hdnode* node, const dogecoin_chainparams* chain, char* str, int strsize)
{
    uint8_t hash160[sizeof(uint160) + 1];
    hash160[0] = chain->b58prefix_pubkey_address;
    dogecoin_hdnode_get_hash160(node, hash160 + 1);
    dogecoin_base58_encode_check(hash160, sizeof(hash160), str, strsize);
}

/**
 * Given a dogecoin_hdnode, return the public key in hexadecimal format
 * 
 * @param node The HDNode struct that you want to get the public key from.
 * @param str The string to store the hex value of the public key in.
 * @param strsize The size of the string that will be returned.
 * 
 * @return The public key in hex format.
 */
dogecoin_bool dogecoin_hdnode_get_pub_hex(const dogecoin_hdnode* node, char* str, size_t* strsize)
{
    dogecoin_pubkey pubkey;
    dogecoin_pubkey_init(&pubkey);
    memcpy(&pubkey.pubkey, node->public_key, DOGECOIN_ECKEY_COMPRESSED_LENGTH);
    pubkey.compressed = true;

    return dogecoin_pubkey_get_hex(&pubkey, str, strsize);
}

// check for validity of curve point in case of public data not performed
/**
 * The function takes a string of base58 characters and converts it to a byte array. It then checks the
 * first 4 bytes of the byte array to see if it matches the public or private key prefix. If it matches
 * the public key prefix, it copies the public key to the node. If it matches the private key prefix,
 * it copies the private key to the node and then fills in the public key
 * 
 * @param str The base58 string to decode
 * @param chain The chain parameters.
 * @param node the dogecoin_hdnode struct to be filled
 * 
 * @return Nothing.
 */
dogecoin_bool dogecoin_hdnode_deserialize(const char* str, const dogecoin_chainparams* chain, dogecoin_hdnode* node)
{
    if (!str || !chain || !node) return false;
    const size_t ndlen = sizeof(uint8_t) * sizeof(dogecoin_hdnode);
    uint8_t* node_data = (uint8_t*)dogecoin_calloc(1, ndlen);
    memset(node, 0, sizeof(dogecoin_hdnode));
    if (!dogecoin_base58_decode_check(str, node_data, ndlen)) {
        dogecoin_free(node_data);
        return false;
    }
    uint32_t version = read_be32(node_data);
    if (version == chain->b58prefix_bip32_pubkey) { // public node
        memcpy(node->public_key, node_data + 45, DOGECOIN_ECKEY_COMPRESSED_LENGTH);
    } else if (version == chain->b58prefix_bip32_privkey) { // private node
        if (node_data[45]) {                                // invalid data
            dogecoin_free(node_data);
            return false;
        }
        memcpy(node->private_key, node_data + 46, DOGECOIN_ECKEY_PKEY_LENGTH);
        dogecoin_hdnode_fill_public_key(node);
    } else {
        dogecoin_free(node_data);
        return false; // invalid version
    }
    node->depth = node_data[4];
    node->fingerprint = read_be32(node_data + 5);
    node->child_num = read_be32(node_data + 9);
    memcpy(node->chain_code, node_data + 13, DOGECOIN_BIP32_CHAINCODE_SIZE);
    dogecoin_free(node_data);
    return true;
}

/**
 * We have a list of
 * nodes, and we want to find the node that contains the first non-zero
 * value of the key
 * 
 * @param node The HDNode struct that will be filled with the derived key.
 * @param keypath The path to the key you want to derive.
 * @param keymaster The keymaster is the key that is used to generate the child key.
 * @param chaincode The chaincode is a 32-byte value that is used to derive the public key and private
 * key.
 * @param usepubckd If true, use the public key derivation function. If false, use the private key
 * derivation function.
 * 
 * @return Nothing.
 */
dogecoin_bool dogecoin_hd_generate_key(dogecoin_hdnode* node, const char* keypath, const uint8_t* keymaster, const uint8_t* chaincode, dogecoin_bool usepubckd)
{
    static char delim[] = "/";
    static char prime[] = "phH\'";
    static char digits[] = "0123456789";
    uint64_t idx = 0;
    assert(strlens(keypath) < 1024);
    char *pch, *kp = dogecoin_calloc(1, strlens(keypath) + 1);

    if (!kp) {
        return false;
    }

    if (strlens(keypath) < strlens("m/")) {
        goto err;
    }

    memset(kp, 0, strlens(keypath) + 1);
    memcpy(kp, keypath, strlens(keypath));

    if (kp[0] != 'm' || kp[1] != '/') {
        goto err;
    }

    node->depth = 0;
    node->child_num = 0;
    node->fingerprint = 0;
    memcpy(node->chain_code, chaincode, DOGECOIN_BIP32_CHAINCODE_SIZE);
    if (usepubckd == true) {
        memcpy(node->public_key, keymaster, DOGECOIN_ECKEY_COMPRESSED_LENGTH);
    } else {
        memcpy(node->private_key, keymaster, DOGECOIN_ECKEY_PKEY_LENGTH);
        dogecoin_hdnode_fill_public_key(node);
    }

    pch = strtok(kp + 2, delim);
    while (pch != NULL) {
        size_t i = 0;
        int prm = 0;
        for (; i < strlens(pch); i++) {
            if (strchr(prime, pch[i])) {
                if ((i != strlens(pch) - 1) || usepubckd == true) {
                    goto err;
                }
                prm = 1;
            } else if (!strchr(digits, pch[i])) {
                goto err;
            }
        }

        idx = strtoull(pch, NULL, 10);
        if (idx > UINT32_MAX) {
            goto err;
        }

        if (prm) {
            if (dogecoin_hdnode_private_ckd_prime(node, idx) != true) {
                goto err;
            }
        } else {
            if ((usepubckd == true ? dogecoin_hdnode_public_ckd(node, idx) : dogecoin_hdnode_private_ckd(node, idx)) != true) {
                goto err;
            }
        }
        pch = strtok(NULL, delim);
    }
    dogecoin_free(kp);
    return true;

err:
    dogecoin_free(kp);
    return false;
}

/**
 * Check if the HD node has a private key.
 * 
 * @param node The HDNode to check.
 * 
 * @return A boolean value.
 */
dogecoin_bool dogecoin_hdnode_has_privkey(dogecoin_hdnode* node)
{
    int i;
    for (i = 0; i < DOGECOIN_ECKEY_PKEY_LENGTH; ++i) {
        if (node->private_key[i] != 0)
            return true;
    }
    return false;
}
