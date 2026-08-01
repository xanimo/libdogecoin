/*

 The MIT License (MIT)

 Copyright (c) 2018 Bitcoin Core developers
 Copyright (c) 2026 bluezr
 Copyright (c) 2026 The Dogecoin Foundation

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
 * @file golomb.h
 * @brief BIP 158 Golomb-Coded Set (GCS) compact block filter implementation.
 *
 * Implements Golomb-Rice coded sets as specified in BIP 158, enabling
 * compact probabilistic set membership testing for block filtering.
 * Combined with BIP 157 (client-side block filtering protocol), this
 * allows light clients to efficiently determine whether a block contains
 * transactions relevant to their wallet without downloading full blocks.
 *
 * The basic filter type (0x00) indexes all scriptPubKeys from outputs
 * and all scriptPubKeys spent by inputs (prevout scripts), using
 * SipHash-2-4 for hashing and Golomb-Rice coding with P=19, M=784931.
 *
 * References:
 *   - BIP 158: https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
 *   - BIP 157: https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki
 */

#ifndef __LIBDOGECOIN_GOLOMB_H__
#define __LIBDOGECOIN_GOLOMB_H__

#include <dogecoin/buffer.h>
#include <dogecoin/cstr.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/hash.h>
#include <dogecoin/tx.h>
#include <dogecoin/vector.h>

LIBDOGECOIN_BEGIN_DECL

/* ================================================================ */
/*  BIP 158 Constants                                               */
/* ================================================================ */

/** Basic filter type as defined in BIP 158 */
#define GCS_BASIC_FILTER_TYPE 0x00

/** Golomb-Rice coding parameter P (19 bits) for basic filters */
#define GCS_BASIC_FILTER_P 19

/** False positive rate parameter M = 1 << P * 1.497137 ≈ 784931 */
#define GCS_BASIC_FILTER_M 784931

/** SipHash key size in bytes (16 bytes = 2 × uint64_t) */
#define GCS_SIPHASH_KEY_SIZE 16

/* ================================================================ */
/*  Bitwriter - bit-level serialization for Golomb-Rice coding      */
/* ================================================================ */

/**
 * @brief Bit-level writer for building Golomb-Rice encoded data.
 *
 * Accumulates bits into a cstring buffer, writing full bytes as
 * they become available and flushing remaining bits on finalization.
 */
typedef struct gcs_bitwriter_ {
    cstring *data;       /**< Output buffer for serialized bits */
    uint8_t accumulator; /**< Bit accumulator for partial byte */
    int     n_bits;      /**< Number of valid bits in accumulator (0-7) */
} gcs_bitwriter;

/**
 * @brief Bit-level reader for decoding Golomb-Rice encoded data.
 *
 * Reads bits from a const_buffer, maintaining a bit-level cursor.
 */
typedef struct gcs_bitreader_ {
    struct const_buffer data; /**< Input buffer with encoded data */
    uint8_t accumulator;     /**< Bit accumulator for partial byte reads */
    int     n_bits;          /**< Number of valid bits remaining in accumulator */
} gcs_bitreader;

/* ================================================================ */
/*  GCS Filter Structure                                            */
/* ================================================================ */

/**
 * @brief A Golomb-Coded Set filter (BIP 158).
 *
 * Contains the encoded filter data along with metadata needed for
 * querying. The filter is constructed from a set of data elements
 * using SipHash-2-4 for hashing and Golomb-Rice coding for compression.
 */
typedef struct gcs_filter_ {
    uint8_t   filter_type;  /**< Filter type (GCS_BASIC_FILTER_TYPE for basic) */
    uint32_t  N;            /**< Number of elements in the filter */
    uint64_t  F;            /**< Range of the filter (N * M) */
    uint8_t   P;            /**< Golomb-Rice coding parameter */
    uint64_t  M;            /**< Inverse false positive rate */
    uint8_t   key[GCS_SIPHASH_KEY_SIZE]; /**< SipHash key derived from block hash */
    cstring  *encoded;      /**< The Golomb-Rice encoded filter data */
} gcs_filter;

/* ================================================================ */
/*  Bitwriter Functions                                             */
/* ================================================================ */

/**
 * @brief Initialize a bitwriter with a pre-allocated output buffer.
 * @param writer The bitwriter to initialize.
 * @param initial_size Initial capacity hint for the output buffer.
 */
LIBDOGECOIN_API void gcs_bitwriter_init(gcs_bitwriter *writer, size_t initial_size);

/**
 * @brief Write a single bit to the bitwriter.
 * @param writer The bitwriter.
 * @param bit The bit value (0 or 1).
 */
LIBDOGECOIN_API void gcs_bitwriter_write_bit(gcs_bitwriter *writer, uint8_t bit);

/**
 * @brief Write multiple bits from a 64-bit value (MSB first).
 * @param writer The bitwriter.
 * @param value The value containing the bits to write.
 * @param n_bits Number of bits to write from value (1-64).
 */
LIBDOGECOIN_API void gcs_bitwriter_write_bits_be(gcs_bitwriter *writer, uint64_t value, int n_bits);

/**
 * @brief Flush any remaining bits in the accumulator, padding with zeros.
 * @param writer The bitwriter.
 */
LIBDOGECOIN_API void gcs_bitwriter_flush(gcs_bitwriter *writer);

/* ================================================================ */
/*  Bitreader Functions                                             */
/* ================================================================ */

/**
 * @brief Initialize a bitreader from encoded data.
 * @param reader The bitreader to initialize.
 * @param data Pointer to the encoded filter data.
 * @param len Length of the encoded filter data.
 */
LIBDOGECOIN_API void gcs_bitreader_init(gcs_bitreader *reader, const void *data, size_t len);

/**
 * @brief Read a single bit from the bitreader.
 * @param reader The bitreader.
 * @return The bit value (0 or 1), or -1 on end-of-data.
 */
LIBDOGECOIN_API int gcs_bitreader_read_bit(gcs_bitreader *reader);

/**
 * @brief Read multiple bits and return them as a 64-bit value (MSB first).
 * @param reader The bitreader.
 * @param n_bits Number of bits to read (1-64).
 * @param out Output value.
 * @return true on success, false on end-of-data.
 */
LIBDOGECOIN_API dogecoin_bool gcs_bitreader_read_bits_be(gcs_bitreader *reader, int n_bits, uint64_t *out);

/* ================================================================ */
/*  Golomb-Rice Coding                                              */
/* ================================================================ */

/**
 * @brief Encode a value using Golomb-Rice coding.
 * @param writer Bitwriter to write encoded data to.
 * @param value The value to encode.
 * @param P The Golomb-Rice parameter (number of remainder bits).
 */
LIBDOGECOIN_API void golomb_rice_encode(gcs_bitwriter *writer, uint64_t value, int P);

/**
 * @brief Decode a Golomb-Rice encoded value.
 * @param reader Bitreader to read encoded data from.
 * @param P The Golomb-Rice parameter (number of remainder bits).
 * @param out Output value.
 * @return true on success, false on end-of-data.
 */
LIBDOGECOIN_API dogecoin_bool golomb_rice_decode(gcs_bitreader *reader, int P, uint64_t *out);

/* ================================================================ */
/*  GCS Filter Construction and Querying                            */
/* ================================================================ */

/**
 * @brief Derive the SipHash key from a block hash (first 16 bytes).
 *
 * Per BIP 158, the SipHash key is the first 16 bytes of the block hash
 * in standard byte order.
 *
 * @param blockhash The 32-byte block hash.
 * @param key Output 16-byte SipHash key.
 */
LIBDOGECOIN_API void gcs_derive_key(const uint256_t blockhash, uint8_t key[GCS_SIPHASH_KEY_SIZE]);

/**
 * @brief Hash a data element to a uint64_t value within the filter range.
 *
 * Uses SipHash-2-4 with the given key, then maps the result into [0, F)
 * using modular reduction: (siphash(data) * F) >> 64.
 *
 * @param key The 16-byte SipHash key.
 * @param F The filter range (N * M).
 * @param data Pointer to the data element.
 * @param data_len Length of the data element.
 * @return The hashed value in [0, F).
 */
LIBDOGECOIN_API uint64_t gcs_hash_element(const uint8_t key[GCS_SIPHASH_KEY_SIZE], uint64_t F, const uint8_t *data, size_t data_len);

/**
 * @brief Create a new empty GCS filter.
 * @return Pointer to a new gcs_filter, or NULL on allocation failure.
 */
LIBDOGECOIN_API gcs_filter* gcs_filter_new(void);

/**
 * @brief Free a GCS filter and all associated memory.
 * @param filter The filter to free.
 */
LIBDOGECOIN_API void gcs_filter_free(gcs_filter *filter);

/**
 * @brief Build a GCS filter from a set of data elements.
 *
 * Takes a vector of raw byte elements (each element is a cstring*),
 * hashes them, sorts the hashes, computes deltas, and Golomb-Rice
 * encodes the result.
 *
 * @param filter The filter to populate (must be newly created).
 * @param filter_type The filter type (GCS_BASIC_FILTER_TYPE).
 * @param blockhash The block hash for key derivation.
 * @param elements Vector of cstring* elements to include in the filter.
 * @return true on success, false on failure.
 */
LIBDOGECOIN_API dogecoin_bool gcs_filter_build(gcs_filter *filter, uint8_t filter_type, const uint256_t blockhash, const vector_t *elements);

/**
 * @brief Check if a single element may be in the filter.
 *
 * @param filter The GCS filter to query.
 * @param data Pointer to the element data.
 * @param data_len Length of the element data.
 * @return true if the element may be in the set (possible false positive),
 *         false if it is definitely not in the set.
 */
LIBDOGECOIN_API dogecoin_bool gcs_filter_match(const gcs_filter *filter, const uint8_t *data, size_t data_len);

/**
 * @brief Check if any element from a set may be in the filter.
 *
 * @param filter The GCS filter to query.
 * @param elements Vector of cstring* elements to check.
 * @return true if any element may be in the set, false if none match.
 */
LIBDOGECOIN_API dogecoin_bool gcs_filter_match_any(const gcs_filter *filter, const vector_t *elements);

/**
 * @brief Construct a BIP 158 basic filter for a full block.
 *
 * Collects all scriptPubKeys from outputs in the block's transactions
 * and all scriptPubKeys being spent by inputs (from previous outputs),
 * then builds a GCS filter from them.
 *
 * @param filter The filter to populate.
 * @param blockhash The block hash.
 * @param txs Vector of dogecoin_tx* (all transactions in the block).
 * @param prev_output_scripts Vector of cstring* for scripts of prevouts
 *        spent by inputs (one per non-coinbase input). May be NULL if
 *        building from a node with UTXO access. For light clients
 *        receiving filters, this is not needed.
 * @return true on success.
 */
LIBDOGECOIN_API dogecoin_bool gcs_build_basic_filter(gcs_filter *filter, const uint256_t blockhash, const vector_t *txs, const vector_t *prev_output_scripts);

/**
 * @brief Compute the filter header for a GCS filter.
 *
 * Per BIP 157, the filter header is:
 *   hash(filter_hash || prev_filter_header)
 * where filter_hash = dbl-sha256(encoded_filter).
 *
 * @param filter The GCS filter.
 * @param prev_header The previous filter header (32 bytes, zero for genesis).
 * @param header_out Output 32-byte filter header.
 * @return true on success.
 */
LIBDOGECOIN_API dogecoin_bool gcs_filter_compute_header(const gcs_filter *filter, const uint256_t prev_header, uint256_t header_out);

/**
 * @brief Serialize a GCS filter for wire transmission.
 *
 * Serializes as: N (CompactSize) || encoded_filter_data.
 *
 * @param filter The filter to serialize.
 * @param out Output cstring.
 */
LIBDOGECOIN_API void gcs_filter_serialize(const gcs_filter *filter, cstring *out);

/**
 * @brief Deserialize a GCS filter from wire format.
 *
 * @param filter The filter to populate.
 * @param filter_type The expected filter type.
 * @param blockhash The block hash (for key derivation).
 * @param buf Input buffer.
 * @return true on success.
 */
LIBDOGECOIN_API dogecoin_bool gcs_filter_deserialize(gcs_filter *filter, uint8_t filter_type, const uint256_t blockhash, struct const_buffer *buf);

LIBDOGECOIN_END_DECL

#endif /* __LIBDOGECOIN_GOLOMB_H__ */
