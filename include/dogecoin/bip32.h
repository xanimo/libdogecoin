/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 * Copyright (c) 2015 Douglas J. Bakkumk
 * Copyright (c) 2015 Jonas Schnelli
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

#ifndef __LIBDOGECOIN_BIP32_H__
#define __LIBDOGECOIN_BIP32_H__

#include <stdint.h>

#include <dogecoin/chainparams.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/core.h>

#define DOGECOIN_BIP32_CHAINCODE_SIZE 32

LIBDOGECOIN_BEGIN_DECL

typedef struct
{
    uint32_t depth;
    uint32_t fingerprint;
    uint32_t child_num;
    uint8_t chain_code[DOGECOIN_BIP32_CHAINCODE_SIZE];
    uint8_t private_key[DOGECOIN_ECKEY_PKEY_LENGTH];
    uint8_t public_key[DOGECOIN_ECKEY_COMPRESSED_LENGTH];
} dogecoin_hdnode;

#define dogecoin_hdnode_private_ckd_prime(X, I) dogecoin_hdnode_private_ckd((X), ((I) | 0x80000000))

LIBDOGECOIN_API dogecoin_hdnode* dogecoin_hdnode_new();
LIBDOGECOIN_API dogecoin_hdnode* dogecoin_hdnode_copy(const dogecoin_hdnode* hdnode);
LIBDOGECOIN_API void dogecoin_hdnode_free(dogecoin_hdnode* node);
LIBDOGECOIN_API dogecoin_bool dogecoin_hdnode_public_ckd(dogecoin_hdnode* inout, uint32_t i);
LIBDOGECOIN_API dogecoin_bool dogecoin_hdnode_from_seed(const uint8_t* seed, int seed_len, dogecoin_hdnode* out);
LIBDOGECOIN_API dogecoin_bool dogecoin_hdnode_private_ckd(dogecoin_hdnode* inout, uint32_t i);
LIBDOGECOIN_API void dogecoin_hdnode_fill_public_key(dogecoin_hdnode* node);
LIBDOGECOIN_API void dogecoin_hdnode_serialize_public(const dogecoin_hdnode* node, const dogecoin_chainparams* chain, char* str, size_t strsize);
LIBDOGECOIN_API void dogecoin_hdnode_serialize_private(const dogecoin_hdnode* node, const dogecoin_chainparams* chain, char* str, size_t strsize);

/* gives out the raw sha256/ripemd160 hash */
LIBDOGECOIN_API void dogecoin_hdnode_get_hash160(const dogecoin_hdnode* node, uint160 hash160_out);
LIBDOGECOIN_API void dogecoin_hdnode_get_p2pkh_address(const dogecoin_hdnode* node, const dogecoin_chainparams* chain, char* str, size_t strsize);
LIBDOGECOIN_API dogecoin_bool dogecoin_hdnode_get_pub_hex(const dogecoin_hdnode* node, char* str, size_t* strsize);
LIBDOGECOIN_API dogecoin_bool dogecoin_hdnode_deserialize(const char* str, const dogecoin_chainparams* chain, dogecoin_hdnode* node);

//!derive dogecoin_hdnode from extended private or extended public key orkey
//if you use pub child key derivation, pass usepubckd=true
LIBDOGECOIN_API dogecoin_bool dogecoin_hd_generate_key(dogecoin_hdnode* node, const char* keypath, const uint8_t* keymaster, const uint8_t* chaincode, dogecoin_bool usepubckd);

//!checks if a node has the according private key (or if its a pubkey only node)
LIBDOGECOIN_API dogecoin_bool dogecoin_hdnode_has_privkey(dogecoin_hdnode* node);

/*** bip32-entropy-length BIP32 Seed Entropy Lengths */
#define BIP32_ENTROPY_LEN_128 16 /** 128 bits */
#define BIP32_ENTROPY_LEN_256 32 /** 256 bits */
#define BIP32_ENTROPY_LEN_512 64 /** 512 bits */

/** Length of a BIP32 key fingerprint */
#define BIP32_KEY_FINGERPRINT_LEN 4

/** Length of an ext_key serialized using BIP32 format */
#define BIP32_SERIALIZED_LEN 78

/** Child number of the first hardened child */
#define BIP32_INITIAL_HARDENED_CHILD 0x80000000

/** The maximum number of path elements allowed in a path */
#define BIP32_PATH_MAX_LEN 255

/* Length of a BIP32 chain code  */
#define DOGECOIN_BIP32_CHAIN_CODE_LEN 32

/* Length of Elements' pubkey tweak sum */
#define DOGECOIN_BIP32_TWEAK_SUM_LEN 32

/*** bip32-flags BIP32 Derivation Flags */
/** Indicate that we want to derive a private key in `bip32_key_from_parent` */
#define BIP32_FLAG_KEY_PRIVATE 0x0
/** Indicate that we want to derive a public key in `bip32_key_from_parent` */
#define BIP32_FLAG_KEY_PUBLIC  0x1
/** Indicate that we want to skip hash calculation when deriving a key in `bip32_key_from_parent` */
#define BIP32_FLAG_SKIP_HASH 0x2
/** Elements: Indicate that we want the pub tweak to be added to the calculation when deriving a key in `bip32_key_from_parent` */
#define BIP32_FLAG_KEY_TWEAK_SUM 0x4
/** Allow a wildcard ``*`` or ``*'``/``*h`` in BIP32 path string expressions */
#define BIP32_FLAG_STR_WILDCARD 0x8
/** Do not allow a leading ``m``/``M`` or ``/`` in BIP32 path string expressions */
#define BIP32_FLAG_STR_BARE 0x10
/** Allow upper as well as lower case ``M``/``H`` in BIP32 path string expressions */
#define BIP32_FLAG_ALLOW_UPPER 0x20


/*** bip32-version-codes BIP32 extended key versions */
#define BIP32_VER_MAIN_PUBLIC  0x0488B21E /** Mainnet, public key */
#define BIP32_VER_MAIN_PRIVATE 0x0488ADE4 /** Mainnet, private key */
#define BIP32_VER_TEST_PUBLIC  0x043587CF /** Testnet, public key */
#define BIP32_VER_TEST_PRIVATE 0x04358394 /** Testnet, private key */

#ifdef SWIG
struct ext_key;
#else
/** An extended key */
struct ext_key {
    /** The chain code for this key */
    unsigned char chain_code[32];
    /** The Hash160 of this keys parent */
    unsigned char parent160[20];
    /** The depth of this key */
    uint8_t depth;
    unsigned char pad1[10];
    /** The private key with prefix byte 0 */
    unsigned char priv_key[33];
    /** The child number of the parent key that this key represents */
    uint32_t child_num;
    /** The Hash160 of this key */
    unsigned char hash160[20];
    /** The version code for this key indicating main/testnet and private/public */
    uint32_t version;
    unsigned char pad2[3];
    /** The public key with prefix byte 0x2 or 0x3 */
    unsigned char pub_key[33];
#ifdef BUILD_ELEMENTS
    unsigned char pub_key_tweak_sum[32];
#endif /* BUILD_ELEMENTS */
};
#endif /* SWIG */

#ifndef SWIG_PYTHON
/**
 * Free a key allocated by `bip32_key_from_seed_alloc`,
 * `bip32_key_from_seed_custom` or `bip32_key_unserialize_alloc`.
 *
 * :param hdkey: Key to free.
 */
LIBDOGECOIN_API int bip32_key_free(
    const struct ext_key *hdkey);
#endif /* SWIG_PYTHON */

/**
 * Initialize a key.
 */
LIBDOGECOIN_API int bip32_key_init(
    uint32_t version,
    uint32_t depth,
    uint32_t child_num,
    const unsigned char *chain_code,
    size_t chain_code_len,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *priv_key,
    size_t priv_key_len,
    const unsigned char *hash160,
    size_t hash160_len,
    const unsigned char *parent160,
    size_t parent160_len,
    struct ext_key *output);

/**
 * As per `bip32_key_init`, but allocates the key.
 */
LIBDOGECOIN_API int bip32_key_init_alloc(
    uint32_t version,
    uint32_t depth,
    uint32_t child_num,
    const unsigned char *chain_code,
    size_t chain_code_len,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *priv_key,
    size_t priv_key_len,
    const unsigned char *hash160,
    size_t hash160_len,
    const unsigned char *parent160,
    size_t parent160_len,
    struct ext_key **output);

/**
 * Create a new master extended key from entropy.
 *
 * This creates a new master key, i.e. the root of a new HD tree.
 * The entropy passed in may produce an invalid key. If this happens,
 * DOGECOIN_ERROR will be returned and the caller should retry with
 * new entropy.
 *
 * :param bytes: Entropy to use.
 * :param bytes_len: Size of ``bytes`` in bytes. Must be one of the :ref:`bip32-entropy-length`
 * :param version: Either `BIP32_VER_MAIN_PRIVATE` or `BIP32_VER_TEST_PRIVATE`,
 *|     indicating mainnet or testnet/regtest respectively.
 * :param hmac_key: Custom data to HMAC-SHA512 with ``bytes`` before creating the key. Pass
 *|             NULL to use the default BIP32 key of "Bitcoin seed".
 * :param hmac_key_len: Size of ``hmac_key`` in bytes, or 0 if ``hmac_key`` is NULL.
 * :param flags: Either `BIP32_FLAG_SKIP_HASH` to skip hash160 calculation, or 0.
 * :param output: Destination for the resulting master extended key.
 */
LIBDOGECOIN_API int bip32_key_from_seed_custom(
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t version,
    const unsigned char *hmac_key,
    size_t hmac_key_len,
    uint32_t flags,
    struct ext_key *output);

/**
 * As per `bip32_key_from_seed_custom` With the default BIP32 seed.
 */
LIBDOGECOIN_API int bip32_key_from_seed(
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t version,
    uint32_t flags,
    struct ext_key *output);

/**
 * As per `bip32_key_from_seed_custom`, but allocates the key.
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
LIBDOGECOIN_API int bip32_key_from_seed_custom_alloc(
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t version,
    const unsigned char *hmac_key,
    size_t hmac_key_len,
    uint32_t flags,
    struct ext_key **output);

/**
 * As per `bip32_key_from_seed`, but allocates the key.
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
LIBDOGECOIN_API int bip32_key_from_seed_alloc(
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t version,
    uint32_t flags,
    struct ext_key **output);

/**
 * Serialize an extended key to memory using BIP32 format.
 *
 * :param hdkey: The extended key to serialize.
 * :param flags: :ref:`bip32-flags` indicating which key to serialize. You can not
 *|        serialize a private extended key from a public extended key.
 * :param bytes_out: Destination for the serialized key.
 * FIXED_SIZED_OUTPUT(len, bytes_out, BIP32_SERIALIZED_LEN)
 */
LIBDOGECOIN_API int bip32_key_serialize(
    const struct ext_key *hdkey,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);


/**
 * Un-serialize an extended key from memory.
 *
 * :param bytes: Storage holding the serialized key.
 * :param bytes_len: Size of ``bytes`` in bytes. Must be `BIP32_SERIALIZED_LEN`.
 * :param output: Destination for the resulting extended key.
 */
LIBDOGECOIN_API int bip32_key_unserialize(
    const unsigned char *bytes,
    size_t bytes_len,
    struct ext_key *output);

/**
 * As per `bip32_key_unserialize`, but allocates the key.
 *
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
LIBDOGECOIN_API int bip32_key_unserialize_alloc(
    const unsigned char *bytes,
    size_t bytes_len,
    struct ext_key **output);

/**
 * Create a new child extended key from a parent extended key.
 *
 * :param hdkey: The parent extended key.
 * :param child_num: The child number to create. Numbers greater
 *|           than or equal to `BIP32_INITIAL_HARDENED_CHILD` represent
 *|           hardened keys that cannot be created from public parent
 *|           extended keys.
 * :param flags: :ref:`bip32-flags` indicating the type of derivation wanted.
 *|       You can not derive a private child extended key from a public
 *|       parent extended key.
 * :param output: Destination for the resulting child extended key.
 */
LIBDOGECOIN_API int bip32_key_from_parent(
    const struct ext_key *hdkey,
    uint32_t child_num,
    uint32_t flags,
    struct ext_key *output);

/**
 * As per `bip32_key_from_parent`, but allocates the key.
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
LIBDOGECOIN_API int bip32_key_from_parent_alloc(
    const struct ext_key *hdkey,
    uint32_t child_num,
    uint32_t flags,
    struct ext_key **output);

/**
 * Create a new child extended key from a parent extended key and a path.
 *
 * :param hdkey: The parent extended key.
 * :param child_path: The path of child numbers to create.
 * :param child_path_len: The number of child numbers in ``child_path``.
 * :param flags: :ref:`bip32-flags` indicating the type of derivation wanted.
 * :param output: Destination for the resulting child extended key.
 *
 * .. note:: If ``child_path`` contains hardened child numbers, then ``hdkey``
 *|    must be an extended private key or this function will fail.
 */
LIBDOGECOIN_API int bip32_key_from_parent_path(
    const struct ext_key *hdkey,
    const uint32_t *child_path,
    size_t child_path_len,
    uint32_t flags,
    struct ext_key *output);

/**
 * As per `bip32_key_from_parent_path`, but allocates the key.
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
LIBDOGECOIN_API int bip32_key_from_parent_path_alloc(
    const struct ext_key *hdkey,
    const uint32_t *child_path,
    size_t child_path_len,
    uint32_t flags,
    struct ext_key **output);

/**
 * Create a new child extended key from a parent extended key and a path string.
 *
 * :param hdkey: The parent extended key.
 * :param path_str: The BIP32 path string of child numbers to create.
 * :param child_num: The child number to use if ``path_str`` contains a ``*`` wildcard.
 * :param flags: :ref:`bip32-flags` indicating the type of derivation wanted.
 * :param output: Destination for the resulting child extended key.
 *
 * .. note:: If ``child_path`` contains hardened child numbers, then ``hdkey``
 *|    must be an extended private key or this function will fail.
 */
LIBDOGECOIN_API int bip32_key_from_parent_path_str(
    const struct ext_key *hdkey,
    const char *path_str,
    uint32_t child_num,
    uint32_t flags,
    struct ext_key *output);

/**
 * Create a new child extended key from a parent extended key and a known-length path string.
 *
 * See `bip32_key_from_parent_path_str`.
 */
LIBDOGECOIN_API int bip32_key_from_parent_path_str_n(
    const struct ext_key *hdkey,
    const char *path_str,
    size_t path_str_len,
    uint32_t child_num,
    uint32_t flags,
    struct ext_key *output);

/**
 * As per `bip32_key_from_parent_path_str`, but allocates the key.
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
LIBDOGECOIN_API int bip32_key_from_parent_path_str_alloc(
    const struct ext_key *hdkey,
    const char *path_str,
    uint32_t child_num,
    uint32_t flags,
    struct ext_key **output);

/**
 * As per `bip32_key_from_parent_path_str_n`, but allocates the key.
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
LIBDOGECOIN_API int bip32_key_from_parent_path_str_n_alloc(
    const struct ext_key *hdkey,
    const char *path_str,
    size_t path_str_len,
    uint32_t child_num,
    uint32_t flags,
    struct ext_key **output);

/**
 * Convert an extended key to base58.
 *
 * :param hdkey: The extended key.
 * :param flags: :ref:`bip32-flags` indicating which key to serialize. You can not
 *|        serialize a private extended key from a public extended key.
 * :param output: Destination for the resulting key in base58.
 *|    The string returned should be freed using `dogecoin_free_string`.
 */
LIBDOGECOIN_API int bip32_key_to_base58(
    const struct ext_key *hdkey,
    uint32_t flags,
    char **output);

/**
 * Convert a base58 encoded extended key to an extended key.
 *
 * :param base58: The extended key in base58.
 * :param output: Destination for the resulting extended key.
 */
LIBDOGECOIN_API int bip32_key_from_base58(
    const char *base58,
    struct ext_key *output);

/**
 * Convert a known-length base58 encoded extended key to an extended key.
 *
 * See `bip32_key_from_base58`.
 */
LIBDOGECOIN_API int bip32_key_from_base58_n(
    const char *base58,
    size_t base58_len,
    struct ext_key *output);

/**
 * As per `bip32_key_from_base58`, but allocates the key.
 *
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
LIBDOGECOIN_API int bip32_key_from_base58_alloc(
    const char *base58,
    struct ext_key **output);

/**
 * As per `bip32_key_from_base58_n`, but allocates the key.
 *
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
LIBDOGECOIN_API int bip32_key_from_base58_n_alloc(
    const char *base58,
    size_t base58_len,
    struct ext_key **output);

/**
 * Converts a private extended key to a public extended key. Afterwards, only public child extended
 * keys can be derived, and only the public serialization can be created.
 * If the provided key is already public, nothing will be done.
 *
 * :param hdkey: The extended key to convert.
 */
LIBDOGECOIN_API int bip32_key_strip_private_key(
    struct ext_key *hdkey);

/**
 * Get the BIP32 fingerprint for an extended key. Performs hash160 calculation
 * if previously skipped with `BIP32_FLAG_SKIP_HASH`.
 *
 * :param hdkey: The extended key.
 * :param bytes_out: Destination for the fingerprint.
 * FIXED_SIZED_OUTPUT(len, bytes_out, BIP32_KEY_FINGERPRINT_LEN)
 */
LIBDOGECOIN_API int bip32_key_get_fingerprint(
    struct ext_key *hdkey,
    unsigned char *bytes_out,
    size_t len);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_BIP32_H__
