/*

 The MIT License (MIT)

 Copyright (c) 2012-2015 The Bitcoin Core developers
 Copyright (c) 2024 bluezr
 Copyright (c) 2024 The Dogecoin Foundation

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

/**
 * @file bloom.h
 * @brief BIP37 Bloom filter implementation for SPV nodes.
 *
 * Implements Bloom filters as specified in BIP37, enabling SPV nodes
 * to request only transactions relevant to their watched addresses
 * rather than downloading full blocks.
 *
 * Reference: https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki
 */

#ifndef __LIBDOGECOIN_BLOOM_H__
#define __LIBDOGECOIN_BLOOM_H__

#include <dogecoin/cstr.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/tx.h>
#include <dogecoin/vector.h>

LIBDOGECOIN_BEGIN_DECL

/** Maximum bloom filter size in bytes (per BIP37: 36,000 bytes) */
#define MAX_BLOOM_FILTER_SIZE 36000

/** Maximum number of hash functions (per BIP37: 50) */
#define MAX_BLOOM_FILTER_HASH_FUNCS 50

/** BIP37 seed constant for MurmurHash3 hash generation */
#define BLOOM_UPDATE_SEED 0xFBA4C795UL

/**
 * @brief Bloom filter update flags (per BIP37).
 *
 * Controls how the filter is updated when a match is found in a transaction.
 */
enum bloomflags {
    /** Filter is not adjusted when a match is found */
    BLOOM_UPDATE_NONE           = 0,
    /** Filter is updated with the outpoint for all matching outputs */
    BLOOM_UPDATE_ALL            = 1,
    /** Filter is updated only for pay-to-pubkey or pay-to-multisig outputs */
    BLOOM_UPDATE_P2PUBKEY_ONLY  = 2,
    /** Mask for the update flag bits */
    BLOOM_UPDATE_MASK           = 3,
};

/**
 * @brief BIP37 Bloom filter structure.
 *
 * The filter is a bit-vector with multiple hash functions derived from
 * MurmurHash3. It provides probabilistic set membership testing for
 * transaction filtering in SPV mode.
 */
typedef struct dogecoin_bloom_filter_ {
    uint8_t* vdata;          /**< Filter bit array */
    uint32_t vdata_size;     /**< Size of the filter in bytes */
    uint32_t n_hash_funcs;   /**< Number of hash functions */
    uint32_t n_tweak;        /**< Random tweak for hash generation */
    uint8_t  n_flags;        /**< Bloom update flags (enum bloomflags) */
    dogecoin_bool is_full;   /**< True if every bit is set */
    dogecoin_bool is_empty;  /**< True if no bit is set */
} dogecoin_bloom_filter;

/* =================================== */
/* MURMURHASH3                         */
/* =================================== */

/**
 * @brief MurmurHash3 x86 32-bit hash function.
 *
 * Used internally for computing bloom filter hash indices per BIP37.
 *
 * @param seed      Hash seed value.
 * @param data      Input data to hash.
 * @param len       Length of input data.
 * @return          32-bit hash value.
 */
LIBDOGECOIN_API uint32_t murmurhash3(uint32_t seed, const uint8_t* data, size_t len);

/* =================================== */
/* BLOOM FILTER API                    */
/* =================================== */

/**
 * @brief Create a new bloom filter with optimal BIP37 parameters.
 *
 * Computes optimal filter size and number of hash functions based on
 * the expected number of elements and desired false positive rate.
 *
 * filter_size = min(-1.0 / LN2SQUARED * n_elements * log(fp_rate), MAX_BLOOM_FILTER_SIZE * 8) / 8
 * n_hash_funcs = min(filter_size * 8 / n_elements * LN2, MAX_BLOOM_FILTER_HASH_FUNCS)
 *
 * @param n_elements    Expected number of elements to insert.
 * @param fp_rate       Desired false positive rate (e.g., 0.0001).
 * @param n_tweak       Random tweak nonce for hash generation.
 * @param n_flags       Bloom update flags (enum bloomflags).
 * @return              New bloom filter, or NULL on failure.
 */
LIBDOGECOIN_API dogecoin_bloom_filter* dogecoin_bloom_filter_new(
    uint32_t n_elements,
    double fp_rate,
    uint32_t n_tweak,
    uint8_t n_flags);

/**
 * @brief Free a bloom filter and its resources.
 *
 * @param filter    Bloom filter to free.
 */
LIBDOGECOIN_API void dogecoin_bloom_filter_free(dogecoin_bloom_filter* filter);

/**
 * @brief Insert data into the bloom filter.
 *
 * Sets the appropriate bits in the filter for the given data.
 *
 * @param filter    The bloom filter.
 * @param data      Data to insert.
 * @param len       Length of the data.
 */
LIBDOGECOIN_API void dogecoin_bloom_filter_insert(dogecoin_bloom_filter* filter, const uint8_t* data, size_t len);

/**
 * @brief Test if data is possibly in the bloom filter.
 *
 * @param filter    The bloom filter.
 * @param data      Data to test.
 * @param len       Length of the data.
 * @return          true if the data may be in the set, false if definitely not.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_bloom_filter_contains(const dogecoin_bloom_filter* filter, const uint8_t* data, size_t len);

/**
 * @brief Test if a transaction matches the bloom filter (BIP37 matching).
 *
 * Implements the full BIP37 transaction matching algorithm:
 * 1. Test the transaction hash
 * 2. For each output, test data pushes in the scriptPubKey
 * 3. For each input, test the prevout hash:index and script_sig data pushes
 *
 * When a match is found in an output, the filter may be auto-updated
 * with the outpoint depending on the n_flags setting.
 *
 * @param filter    The bloom filter.
 * @param tx        Transaction to test.
 * @return          true if the transaction matches the filter.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_bloom_filter_matches_tx(dogecoin_bloom_filter* filter, const dogecoin_tx* tx);

/* =================================== */
/* SERIALIZATION                       */
/* =================================== */

/**
 * @brief Serialize bloom filter to BIP37 wire format.
 *
 * Wire format: varint(vdata_size) + vdata + u32(n_hash_funcs) + u32(n_tweak) + u8(n_flags)
 *
 * @param filter    The bloom filter.
 * @param buf       Output cstring to append serialized data to.
 */
LIBDOGECOIN_API void dogecoin_bloom_filter_serialize(const dogecoin_bloom_filter* filter, cstring* buf);

/**
 * @brief Deserialize bloom filter from BIP37 wire format.
 *
 * @param buf       Input buffer containing serialized data.
 * @return          New bloom filter, or NULL on failure.
 */
LIBDOGECOIN_API dogecoin_bloom_filter* dogecoin_bloom_filter_deserialize(struct const_buffer* buf);

/* =================================== */
/* P2P MESSAGES (requires WITH_NET)    */
/* =================================== */

#ifdef WITH_NET

/**
 * @brief Create a BIP37 "filterload" P2P message.
 *
 * @param filter    The bloom filter to send.
 * @param netmagic  Network magic bytes (4 bytes).
 * @return          New cstring containing the complete P2P message, or NULL on failure.
 *                  Caller must free with cstr_free().
 */
LIBDOGECOIN_API cstring* dogecoin_bloom_filter_msg_filterload(const dogecoin_bloom_filter* filter, const unsigned char netmagic[4]);

/**
 * @brief Create a BIP37 "filteradd" P2P message.
 *
 * @param data      Data element to add to the remote peer's filter.
 * @param len       Length of the data element.
 * @param netmagic  Network magic bytes (4 bytes).
 * @return          New cstring containing the complete P2P message, or NULL on failure.
 *                  Caller must free with cstr_free().
 */
LIBDOGECOIN_API cstring* dogecoin_bloom_filter_msg_filteradd(const uint8_t* data, size_t len, const unsigned char netmagic[4]);

/**
 * @brief Create a BIP37 "filterclear" P2P message.
 *
 * @param netmagic  Network magic bytes (4 bytes).
 * @return          New cstring containing the complete P2P message, or NULL on failure.
 *                  Caller must free with cstr_free().
 */
LIBDOGECOIN_API cstring* dogecoin_bloom_filter_msg_filterclear(const unsigned char netmagic[4]);

#endif /* WITH_NET */

LIBDOGECOIN_END_DECL

#endif /* __LIBDOGECOIN_BLOOM_H__ */
