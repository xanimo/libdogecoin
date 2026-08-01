/*

 The MIT License (MIT)

 Copyright (c) 2016 Matt Corallo
 Copyright (c) 2024 bluezr
 Copyright (c) 2024-2026 The Dogecoin Foundation

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
 * @file compact_block.h
 * @brief BIP152 Compact Block Relay implementation for Dogecoin.
 *
 * Implements Compact Blocks as specified in BIP152, enabling more
 * efficient block propagation by sending compact representations
 * containing short transaction IDs instead of full transactions.
 *
 * Message types:
 *   - sendcmpct: Negotiate compact block support with peers
 *   - cmpctblock: Compact block representation with short tx IDs
 *   - getblocktxn: Request specific missing transactions
 *   - blocktxn: Response with requested transactions
 *
 * Reference: https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
 */

#ifndef __LIBDOGECOIN_COMPACT_BLOCK_H__
#define __LIBDOGECOIN_COMPACT_BLOCK_H__

#include <dogecoin/block.h>
#include <dogecoin/buffer.h>
#include <dogecoin/cstr.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/hash.h>
#include <dogecoin/serialize.h>
#include <dogecoin/tx.h>
#include <dogecoin/vector.h>

LIBDOGECOIN_BEGIN_DECL

/* ================================================================ */
/*  BIP152 Constants                                                */
/* ================================================================ */

/** BIP152 compact block version (low-bandwidth relaying) */
#define CMPCTBLOCK_VERSION 1

/** Short transaction ID length in bytes (6 bytes = 48 bits) */
#define SHORTTXID_LENGTH 6

/* ================================================================ */
/*  BIP152 Data Structures                                          */
/* ================================================================ */

/**
 * @brief A prefilled transaction in a compact block.
 *
 * Used for the coinbase and possibly other transactions that the
 * sender expects the receiver to not already have in mempool.
 *
 * The index is differentially encoded in the serialized form.
 */
typedef struct dogecoin_prefilled_tx_ {
    uint32_t index;       /**< Original index of the transaction in the block */
    dogecoin_tx *tx;      /**< The full transaction */
} dogecoin_prefilled_tx;

/**
 * @brief BIP152 Compact Block header + short IDs.
 *
 * Contains the block header, a nonce for computing short IDs,
 * the short transaction IDs for transactions the receiver likely
 * has in their mempool, and pre-filled transactions (at minimum
 * the coinbase).
 */
typedef struct dogecoin_compact_block_ {
    dogecoin_block_header header;    /**< Block header (80 bytes, no auxpow serialized) */
    uint64_t nonce;                  /**< Random nonce for SipHash key derivation */
    uint64_t sipkey_k0;              /**< SipHash key 0 (derived from header + nonce) */
    uint64_t sipkey_k1;              /**< SipHash key 1 (derived from header + nonce) */
    uint32_t short_ids_count;        /**< Number of short transaction IDs */
    uint8_t *short_ids;              /**< Array of 6-byte short IDs (short_ids_count * 6) */
    uint32_t prefilled_count;        /**< Number of prefilled transactions */
    dogecoin_prefilled_tx *prefilled_txs; /**< Array of prefilled transactions */
} dogecoin_compact_block;

/**
 * @brief BIP152 getblocktxn request.
 *
 * Sent by a node that received a compact block but is missing
 * some transactions. Contains the block hash and the indices
 * of requested transactions (differentially encoded).
 */
typedef struct dogecoin_getblocktxn_ {
    uint256_t blockhash;             /**< Hash of the compact block */
    uint32_t indices_count;          /**< Number of requested tx indices */
    uint32_t *indices;               /**< Array of requested tx indices (differentially encoded) */
} dogecoin_getblocktxn;

/**
 * @brief BIP152 blocktxn response.
 *
 * Response to getblocktxn containing the requested full transactions.
 */
typedef struct dogecoin_blocktxn_ {
    uint256_t blockhash;             /**< Hash of the block */
    uint32_t txs_count;              /**< Number of transactions */
    dogecoin_tx **txs;               /**< Array of full transactions */
} dogecoin_blocktxn;

/**
 * @brief Per-node compact block state.
 *
 * Tracks BIP152 negotiation state and pending compact blocks
 * for a given peer.
 */
typedef struct dogecoin_compact_block_state_ {
    dogecoin_bool compact_blocks_enabled;      /**< Peer supports compact blocks */
    dogecoin_bool high_bandwidth_mode;         /**< High-bandwidth mode requested */
    uint64_t compact_block_version;            /**< Negotiated compact block version */

    /* Pending compact block waiting for missing txs */
    dogecoin_compact_block *pending_cmpctblock; /**< Compact block awaiting completion */
    dogecoin_tx **available_txs;                /**< Resolved transactions (NULL for missing) */
    uint32_t available_txs_count;               /**< Total tx count (shortids + prefilled) */
    uint32_t *missing_indices;                  /**< Indices of missing transactions */
    uint32_t missing_count;                     /**< Number of missing transactions */
} dogecoin_compact_block_state;

/* ================================================================ */
/*  Constructor / Destructor                                        */
/* ================================================================ */

/**
 * @brief Create a new compact block object.
 * @return Allocated compact block, or NULL on failure.
 */
LIBDOGECOIN_API dogecoin_compact_block *dogecoin_compact_block_new(void);

/**
 * @brief Free a compact block object.
 * @param cmpctblock The compact block to free.
 */
LIBDOGECOIN_API void dogecoin_compact_block_free(dogecoin_compact_block *cmpctblock);

/**
 * @brief Create a new getblocktxn request.
 * @return Allocated getblocktxn, or NULL on failure.
 */
LIBDOGECOIN_API dogecoin_getblocktxn *dogecoin_getblocktxn_new(void);

/**
 * @brief Free a getblocktxn request.
 * @param req The request to free.
 */
LIBDOGECOIN_API void dogecoin_getblocktxn_free(dogecoin_getblocktxn *req);

/**
 * @brief Create a new blocktxn response.
 * @return Allocated blocktxn, or NULL on failure.
 */
LIBDOGECOIN_API dogecoin_blocktxn *dogecoin_blocktxn_new(void);

/**
 * @brief Free a blocktxn response.
 * @param resp The response to free.
 */
LIBDOGECOIN_API void dogecoin_blocktxn_free(dogecoin_blocktxn *resp);

/**
 * @brief Create a new per-node compact block state.
 * @return Allocated state, or NULL on failure.
 */
LIBDOGECOIN_API dogecoin_compact_block_state *dogecoin_compact_block_state_new(void);

/**
 * @brief Free a per-node compact block state.
 * @param state The state to free.
 */
LIBDOGECOIN_API void dogecoin_compact_block_state_free(dogecoin_compact_block_state *state);

/* ================================================================ */
/*  Short Transaction ID Computation                                */
/* ================================================================ */

/**
 * @brief Derive the SipHash keys from a block header and nonce.
 *
 * Per BIP152: SHA256(block_header || nonce) produces k0 and k1 as
 * the first two little-endian 64-bit integers of the hash.
 *
 * @param header     Serialized block header (80 bytes).
 * @param nonce      The compact block nonce.
 * @param k0_out     Output: SipHash key 0.
 * @param k1_out     Output: SipHash key 1.
 */
LIBDOGECOIN_API void dogecoin_compact_block_derive_sipkeys(
    const dogecoin_block_header *header,
    uint64_t nonce,
    uint64_t *k0_out,
    uint64_t *k1_out);

/**
 * @brief Compute a 6-byte short transaction ID.
 *
 * Per BIP152: SipHash-2-4(k0, k1, txid) truncated to 6 bytes (LE).
 *
 * @param k0         SipHash key 0.
 * @param k1         SipHash key 1.
 * @param txhash     The transaction hash (txid).
 * @param short_id   Output: 6-byte short ID.
 */
LIBDOGECOIN_API void dogecoin_compact_block_compute_short_id(
    uint64_t k0,
    uint64_t k1,
    const uint256_t txhash,
    uint8_t short_id[SHORTTXID_LENGTH]);

/* ================================================================ */
/*  Serialization / Deserialization                                 */
/* ================================================================ */

/**
 * @brief Serialize a compact block to a cstring.
 * @param s         Output cstring.
 * @param cmpctblk  The compact block to serialize.
 */
LIBDOGECOIN_API void dogecoin_compact_block_serialize(cstring *s, const dogecoin_compact_block *cmpctblk);

/**
 * @brief Deserialize a compact block from a buffer.
 * @param cmpctblk  Output compact block.
 * @param buf       Input buffer.
 * @param params    Chain parameters (for header deserialization).
 * @return true on success, false on failure.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_compact_block_deserialize(
    dogecoin_compact_block *cmpctblk,
    struct const_buffer *buf,
    const dogecoin_chainparams *params);

/**
 * @brief Serialize a getblocktxn request.
 * @param s    Output cstring.
 * @param req  The request to serialize.
 */
LIBDOGECOIN_API void dogecoin_getblocktxn_serialize(cstring *s, const dogecoin_getblocktxn *req);

/**
 * @brief Deserialize a getblocktxn request from a buffer.
 * @param req  Output request.
 * @param buf  Input buffer.
 * @return true on success.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_getblocktxn_deserialize(
    dogecoin_getblocktxn *req,
    struct const_buffer *buf);

/**
 * @brief Serialize a blocktxn response.
 * @param s     Output cstring.
 * @param resp  The response to serialize.
 */
LIBDOGECOIN_API void dogecoin_blocktxn_serialize(cstring *s, const dogecoin_blocktxn *resp);

/**
 * @brief Deserialize a blocktxn response from a buffer.
 * @param resp   Output response.
 * @param buf    Input buffer.
 * @return true on success.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_blocktxn_deserialize(
    dogecoin_blocktxn *resp,
    struct const_buffer *buf);

/* ================================================================ */
/*  P2P Message Construction (requires WITH_NET)                    */
/* ================================================================ */

#ifdef WITH_NET

#include <dogecoin/protocol.h>

/**
 * @brief Build a sendcmpct P2P message.
 *
 * Announces compact block support to a peer.
 *
 * @param netmagic         Network magic bytes.
 * @param high_bandwidth   true = request high-bandwidth mode.
 * @param version          Compact block version (1 for BIP152 v1).
 * @return P2P message cstring, or NULL on failure. Caller frees.
 */
/**
 * @brief Parse a sendcmpct payload: fAnnounce(1) | nCmpctVersion(8 LE).
 *
 * Both outputs are only written on success.  Dogecoin is pre-SegWit, so the
 * caller is expected to ignore any version other than CMPCTBLOCK_VERSION:
 * version 2 short ids are computed over the wtxid, which does not exist here.
 *
 * @param high_bandwidth_out  Receives the peer's fAnnounce preference.
 * @param version_out         Receives the announced compact block version.
 * @param buf                 Message payload.
 * @return true if the payload was well formed.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_p2p_msg_sendcmpct_deser(
    dogecoin_bool *high_bandwidth_out,
    uint64_t *version_out,
    struct const_buffer *buf);

LIBDOGECOIN_API cstring *dogecoin_p2p_msg_sendcmpct(
    const unsigned char netmagic[4],
    dogecoin_bool high_bandwidth,
    uint64_t version);

/**
 * @brief Build a cmpctblock P2P message.
 * @param netmagic   Network magic bytes.
 * @param cmpctblk   The compact block to send.
 * @return P2P message cstring. Caller frees.
 */
LIBDOGECOIN_API cstring *dogecoin_p2p_msg_cmpctblock(
    const unsigned char netmagic[4],
    const dogecoin_compact_block *cmpctblk);

/**
 * @brief Build a getblocktxn P2P message.
 * @param netmagic  Network magic bytes.
 * @param req       The getblocktxn request.
 * @return P2P message cstring. Caller frees.
 */
LIBDOGECOIN_API cstring *dogecoin_p2p_msg_getblocktxn(
    const unsigned char netmagic[4],
    const dogecoin_getblocktxn *req);

/**
 * @brief Build a blocktxn P2P message.
 * @param netmagic  Network magic bytes.
 * @param resp      The blocktxn response.
 * @return P2P message cstring. Caller frees.
 */
LIBDOGECOIN_API cstring *dogecoin_p2p_msg_blocktxn(
    const unsigned char netmagic[4],
    const dogecoin_blocktxn *resp);

#endif /* WITH_NET */

/* ================================================================ */
/*  Compact Block Processing                                        */
/* ================================================================ */

/**
 * @brief Attempt to reconstruct a full block from a compact block
 *        and known transactions (e.g., from mempool).
 *
 * Fills state->available_txs with resolved transactions and sets
 * state->missing_indices / missing_count for any that are unknown.
 *
 * @param cmpctblk         The received compact block.
 * @param state            Per-node compact block state (output).
 * @param known_txs        Array of known transactions.
 * @param known_txs_count  Number of known transactions.
 * @return true if all transactions were resolved (block is complete).
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_compact_block_reconstruct(
    const dogecoin_compact_block *cmpctblk,
    dogecoin_compact_block_state *state,
    dogecoin_tx **known_txs,
    uint32_t known_txs_count);

/**
 * @brief Fill in missing transactions from a blocktxn response.
 *
 * @param state    Per-node compact block state (updated).
 * @param resp     The blocktxn response with the missing txs.
 * @return true if the block is now fully reconstructed.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_compact_block_fill_missing(
    dogecoin_compact_block_state *state,
    const dogecoin_blocktxn *resp);

LIBDOGECOIN_END_DECL

#endif /* __LIBDOGECOIN_COMPACT_BLOCK_H__ */
