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
 * @file compact_filter.h
 * @brief BIP 157 Client Side Block Filtering protocol implementation.
 *
 * Implements the P2P protocol messages for fetching compact block filters
 * (BIP 158) from full nodes, as specified in BIP 157. This enables light
 * clients to download and query compact filters to efficiently determine
 * which blocks contain transactions relevant to their wallet.
 *
 * Protocol message types:
 *   - getcfilters:  Request a range of compact filters
 *   - cfilter:      A single compact filter response
 *   - getcfheaders: Request filter headers for a range of blocks
 *   - cfheaders:    Filter headers response
 *   - getcfcheckpt: Request evenly-spaced filter header checkpoints
 *   - cfcheckpt:    Filter header checkpoints response
 *
 * References:
 *   - BIP 157: https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki
 *   - BIP 158: https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
 */

#ifndef __LIBDOGECOIN_COMPACT_FILTER_H__
#define __LIBDOGECOIN_COMPACT_FILTER_H__

#include <dogecoin/buffer.h>
#include <dogecoin/cf_checkpoints.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/cstr.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/golomb.h>
#include <dogecoin/vector.h>

LIBDOGECOIN_BEGIN_DECL

/* ================================================================ */
/*  BIP 157 Constants                                               */
/* ================================================================ */

/** Maximum number of filters that can be requested at once */
#define MAX_GETCFILTERS_SIZE 1000

/** Maximum number of filter headers that can be requested at once */
#define MAX_GETCFHEADERS_SIZE 2000

/** Checkpoint interval for cfcheckpt messages (every 1000 blocks) */
#define CFCHECKPT_INTERVAL 1000

/** Interval at which filter header checkpoints are exported during full sync.
 *  Matches CFCHECKPT_INTERVAL so every BIP 157 checkpoint boundary is logged. */
#define CF_EXPORT_INTERVAL CFCHECKPT_INTERVAL

/* ================================================================ */
/*  BIP 157 Message Structures                                      */
/* ================================================================ */

/**
 * @brief getcfilters request message (BIP 157).
 *
 * Requests compact filters for blocks in the range
 * [start_height, stop_hash].
 */
typedef struct dogecoin_getcfilters_msg_ {
    uint8_t   filter_type;   /**< Filter type (0x00 for basic) */
    uint32_t  start_height;  /**< Start block height */
    uint256_t stop_hash;     /**< Block hash of the last desired filter */
} dogecoin_getcfilters_msg;

/**
 * @brief cfilter response message (BIP 157).
 *
 * Contains a single compact filter for one block.
 */
typedef struct dogecoin_cfilter_msg_ {
    uint8_t    filter_type;  /**< Filter type (0x00 for basic) */
    uint256_t  block_hash;   /**< Block hash this filter covers */
    cstring   *filter_data;  /**< Raw encoded filter bytes (N || filter) */
} dogecoin_cfilter_msg;

/**
 * @brief getcfheaders request message (BIP 157).
 *
 * Requests compact filter headers for blocks in the range
 * [start_height, stop_hash].
 */
typedef struct dogecoin_getcfheaders_msg_ {
    uint8_t   filter_type;   /**< Filter type (0x00 for basic) */
    uint32_t  start_height;  /**< Start block height */
    uint256_t stop_hash;     /**< Block hash of the last desired header */
} dogecoin_getcfheaders_msg;

/**
 * @brief cfheaders response message (BIP 157).
 *
 * Contains filter headers for a range of blocks.
 */
typedef struct dogecoin_cfheaders_msg_ {
    uint8_t    filter_type;        /**< Filter type */
    uint256_t  stop_hash;          /**< Block hash of the last header in the range */
    uint256_t  prev_filter_header; /**< The filter header preceding the first in the range */
    vector_t  *filter_hashes;      /**< Vector of uint256_t* filter hashes */
} dogecoin_cfheaders_msg;

/**
 * @brief getcfcheckpt request message (BIP 157).
 *
 * Requests evenly-spaced filter header checkpoints.
 */
typedef struct dogecoin_getcfcheckpt_msg_ {
    uint8_t   filter_type;   /**< Filter type */
    uint256_t stop_hash;     /**< Block hash of the last desired checkpoint */
} dogecoin_getcfcheckpt_msg;

/**
 * @brief cfcheckpt response message (BIP 157).
 *
 * Contains filter header checkpoints at every CFCHECKPT_INTERVAL blocks.
 */
typedef struct dogecoin_cfcheckpt_msg_ {
    uint8_t    filter_type;        /**< Filter type */
    uint256_t  stop_hash;          /**< Block hash of the last checkpoint */
    vector_t  *filter_headers;     /**< Vector of uint256_t* checkpoint filter headers */
} dogecoin_cfcheckpt_msg;

/* ================================================================ */
/*  Parallel cfilter download support structures                    */
/* ================================================================ */

/** One buffered cfilter record held before in-order disk flush. */
typedef struct cf_par_record_ {
    uint256_t  block_hash;
    cstring   *filter_data;   /**< NULL = slot not yet received */
} cf_par_record;

/** In-flight getcfilters batch for one parallel worker node. */
typedef struct cf_par_buf_ {
    int            node_id;     /**< dogecoin_node.nodeid owning this slot; -1 = free */
    uint32_t       batch_start;
    uint32_t       batch_end;
    cf_par_record *records;     /**< array[batch_end - batch_start + 1] */
    uint32_t       received;    /**< number of records received so far */
    dogecoin_bool  complete;    /**< true when received == batch size */
    int64_t        assign_time; /**< unix time when this slot was last assigned */
} cf_par_buf;

/* ================================================================ */
/*  BIP 157 Per-Peer Compact Filter State                           */
/* ================================================================ */

/**
 * @brief Compact filter sync state for an SPV client.
 *
 * Tracks the progress of fetching and validating compact filters
 * from peers, including checkpoints and headers-first validation.
 */
typedef struct dogecoin_compact_filter_state_ {
    dogecoin_bool enabled;                /**< Whether compact filter sync is active */
    uint8_t       filter_type;            /**< Filter type being synced */
    uint32_t      cfheaders_tip_height;   /**< Height of last verified cfheader */
    uint256_t     cfheaders_tip_hash;     /**< Filter header at cfheaders_tip_height */
    vector_t     *filter_headers;         /**< Vector of verified filter headers (uint256_t*) */
    vector_t     *checkpoints;            /**< Vector of checkpoint filter headers (uint256_t*) */
    uint32_t      cfheaders_base_height;   /**< Block height of filter_headers[0]; usually 1 or chainbottom_height */
    uint32_t      filters_tip_height;     /**< Height of last received filter */
    uint32_t      cfilter_batch_end;      /**< Last height expected in current getcfilters batch (re-request when filters_tip_height reaches this) */
    uint32_t      pending_start_height;   /**< Start of current outstanding request */
    uint256_t     pending_stop_hash;      /**< Stop hash of current outstanding request */
    dogecoin_bool awaiting_response;      /**< Whether a request is outstanding */
    uint64_t      last_request_time;      /**< Timestamp of last cfilter request (for timeout) */
    uint256_t     genesis_filter_header;  /**< Filter header for genesis block (height 0); set from cfheaders.prev_filter_header on first batch */
    vector_t     *watched_scripts;        /**< ScriptPubKeys to match against filters (cstring*) */
    vector_t     *matched_block_hashes;   /**< Block hashes where filter matched (uint256_t*) */
    vector_t     *matched_block_heights;  /**< Heights corresponding to matched_block_hashes (uint32_t*) */
    uint32_t      matched_blocks_fetched; /**< Number of matched blocks already received */
    dogecoin_bool cf_block_fetch_active;  /**< True while fetching full blocks for BIP157 matches */

    /* Parallel cfilter download (par_num_workers > 1 activates parallel mode). */
    uint8_t       par_num_workers;   /**< 0/1 = sequential; >1 = parallel worker count */
    uint32_t      par_next_height;   /**< Next height not yet assigned to any worker */
    uint32_t      par_flush_height;  /**< Next height that must be flushed to disk next */
    cf_par_buf   *par_bufs;          /**< Worker buffer array [par_num_workers], NULL in sequential mode */

    /* Parallel cfheaders download (cfh_par_n > 0 activates parallel mode).
     * Each worker downloads a disjoint height range; validation uses cfcheckpt
     * anchors so workers are independent.  When all complete, filter_headers
     * is populated from cfh_par_data and the normal cfilter scan begins. */
    uint8_t        cfh_par_n;        /**< Number of parallel cfheader workers (0 = sequential) */
    uint8_t        cfh_par_done;     /**< Count of completed workers */
    uint8_t       *cfh_par_data;     /**< Flat 32*N_total byte array of filter headers */
    uint32_t       cfh_par_base;     /**< Height of first entry in cfh_par_data */
    uint32_t       cfh_par_total;    /**< Total number of filter headers in cfh_par_data */
    struct cfh_par_chunk_ *cfh_par_chunks; /**< Per-worker state [cfh_par_n] */

    /* Flat filter-header array owned after parallel cfheader download completes.
     * When non-NULL, cfilter validation uses this instead of the filter_headers vector. */
    uint8_t       *filter_headers_flat;      /**< 32*N contiguous filter headers */
    uint32_t       filter_headers_flat_base; /**< Height of index 0 in filter_headers_flat */
    uint32_t       filter_headers_flat_len;  /**< Number of entries in filter_headers_flat */
    dogecoin_bool  rescan_done;              /**< True after a full cached-filter rescan; suppresses duplicate rescan in cfh_par_finish */
    uint32_t       cf_scan_start_height;    /**< Actual height cfilter scan began (chainbottom or 1); used for accurate progress logging */
} dogecoin_compact_filter_state;

/** Per-worker state for parallel cfheaders download. */
typedef struct cfh_par_chunk_ {
    int      node_id;     /**< dogecoin_node.nodeid; -1 = unassigned; -2 = no work */
    uint32_t start;       /**< first height this worker handles */
    uint32_t end;         /**< last height this worker handles */
    uint32_t req_next;    /**< next height to request in a GETCFHEADERS batch */
    uint8_t  prev_fh[32];/**< filter header immediately before start (cfcheckpt anchor) */
    uint32_t n_received;  /**< filter headers received so far for this chunk */
    dogecoin_bool complete;
} cfh_par_chunk;

/* ================================================================ */
/*  Message Serialization                                           */
/* ================================================================ */

/**
 * @brief Serialize a getcfilters message.
 * @param msg The message to serialize.
 * @param out Output cstring (payload only, no P2P header).
 */
LIBDOGECOIN_API void dogecoin_p2p_msg_getcfilters_ser(const dogecoin_getcfilters_msg *msg, cstring *out);

/**
 * @brief Serialize a getcfheaders message.
 * @param msg The message to serialize.
 * @param out Output cstring (payload only).
 */
LIBDOGECOIN_API void dogecoin_p2p_msg_getcfheaders_ser(const dogecoin_getcfheaders_msg *msg, cstring *out);

/**
 * @brief Serialize a getcfcheckpt message.
 * @param msg The message to serialize.
 * @param out Output cstring (payload only).
 */
LIBDOGECOIN_API void dogecoin_p2p_msg_getcfcheckpt_ser(const dogecoin_getcfcheckpt_msg *msg, cstring *out);

/* ================================================================ */
/*  Message Deserialization                                         */
/* ================================================================ */

/**
 * @brief Deserialize a cfilter response message.
 * @param msg The message to populate (filter_data will be allocated).
 * @param buf Input buffer.
 * @return true on success.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_p2p_msg_cfilter_deser(dogecoin_cfilter_msg *msg, struct const_buffer *buf);

/**
 * @brief Deserialize a cfheaders response message.
 * @param msg The message to populate (filter_hashes will be allocated).
 * @param buf Input buffer.
 * @return true on success.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_p2p_msg_cfheaders_deser(dogecoin_cfheaders_msg *msg, struct const_buffer *buf);

/**
 * @brief Deserialize a cfcheckpt response message.
 * @param msg The message to populate (filter_headers will be allocated).
 * @param buf Input buffer.
 * @return true on success.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_p2p_msg_cfcheckpt_deser(dogecoin_cfcheckpt_msg *msg, struct const_buffer *buf);

/* ================================================================ */
/*  Message Lifecycle                                               */
/* ================================================================ */

/**
 * @brief Initialize a cfilter message.
 * @param msg The message to initialize.
 */
LIBDOGECOIN_API void dogecoin_cfilter_msg_init(dogecoin_cfilter_msg *msg);

/**
 * @brief Free a cfilter message's internal allocations.
 * @param msg The message to free.
 */
LIBDOGECOIN_API void dogecoin_cfilter_msg_free(dogecoin_cfilter_msg *msg);

/**
 * @brief Initialize a cfheaders message.
 * @param msg The message to initialize.
 */
LIBDOGECOIN_API void dogecoin_cfheaders_msg_init(dogecoin_cfheaders_msg *msg);

/**
 * @brief Free a cfheaders message's internal allocations.
 * @param msg The message to free.
 */
LIBDOGECOIN_API void dogecoin_cfheaders_msg_free(dogecoin_cfheaders_msg *msg);

/**
 * @brief Initialize a cfcheckpt message.
 * @param msg The message to initialize.
 */
LIBDOGECOIN_API void dogecoin_cfcheckpt_msg_init(dogecoin_cfcheckpt_msg *msg);

/**
 * @brief Free a cfcheckpt message's internal allocations.
 * @param msg The message to free.
 */
LIBDOGECOIN_API void dogecoin_cfcheckpt_msg_free(dogecoin_cfcheckpt_msg *msg);

/* ================================================================ */
/*  Compact Filter State Management                                 */
/* ================================================================ */

/**
 * @brief Create a new compact filter state.
 * @return Pointer to a new state, or NULL on failure.
 */
LIBDOGECOIN_API dogecoin_compact_filter_state* dogecoin_compact_filter_state_new(void);

/**
 * @brief Free a compact filter state and all associated memory.
 * @param state The state to free.
 */
LIBDOGECOIN_API void dogecoin_compact_filter_state_free(dogecoin_compact_filter_state *state);

/**
 * @brief Reset the compact filter state for a fresh sync.
 * @param state The state to reset.
 */
LIBDOGECOIN_API void dogecoin_compact_filter_state_reset(dogecoin_compact_filter_state *state);

/* ================================================================ */
/*  Compact Filter Sync Helpers                                     */
/* ================================================================ */

/**
 * @brief Validate a cfilter against a previously verified filter header.
 *
 * Computes the filter hash from the received filter data, chains it
 * with the previous filter header, and compares against the expected
 * filter header.
 *
 * @param filter_data The raw encoded filter data.
 * @param prev_filter_header The filter header of the previous block.
 * @param expected_filter_header The expected filter header for this block.
 * @return true if the filter is valid.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_compact_filter_validate(const cstring *filter_data, const uint256_t prev_filter_header, const uint256_t expected_filter_header);

/**
 * @brief Compute a filter header from filter data and previous header.
 *
 * filter_header = dbl_sha256(filter_hash || prev_filter_header)
 * where filter_hash = dbl_sha256(filter_data)
 *
 * @param filter_data The raw encoded filter data.
 * @param prev_filter_header The previous filter header.
 * @param header_out Output 32-byte filter header.
 */
LIBDOGECOIN_API void dogecoin_compact_filter_compute_header(const cstring *filter_data, const uint256_t prev_filter_header, uint256_t header_out);

/* ================================================================ */
/*  BIP 157 Hardcoded Checkpoint Helpers                            */
/* ================================================================ */

/**
 * @brief Look up hardcoded cf checkpoints for a given chain.
 *
 * Returns the per-network array of known-good BIP 158 filter header
 * checkpoints, used to validate peer-provided data and to bootstrap
 * BIP 157 sync without a getcfcheckpt peer exchange.
 *
 * @param chain The chain params to look up.
 * @param count_out Output: number of checkpoints in the returned array.
 * @return Pointer to the checkpoint array, or NULL if none available.
 */
LIBDOGECOIN_API const dogecoin_cf_checkpoint* dogecoin_cf_get_checkpoints(
    const dogecoin_chainparams *chain, size_t *count_out);

/**
 * @brief Validate peer-provided cfcheckpt data against hardcoded checkpoints.
 *
 * Compares checkpoints from a peer's cfcheckpt response with the
 * hardcoded checkpoint array for the given chain. Returns true if
 * all overlapping checkpoints match, or if no hardcoded checkpoints
 * are available (no validation possible).
 *
 * @param chain The chain params.
 * @param peer_checkpoints Vector of uint256_t* filter headers from peer.
 * @return true if valid (or if no hardcoded data to compare against).
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_cf_validate_checkpoints(
    const dogecoin_chainparams *chain, const vector_t *peer_checkpoints);

/**
 * @brief Load hardcoded cf checkpoints into a compact filter state.
 *
 * Copies hardcoded checkpoint filter headers into the state's
 * checkpoints vector, enabling cfheaders validation without
 * a peer cfcheckpt exchange.
 *
 * @param state The compact filter state to populate.
 * @param chain The chain params.
 * @return Number of checkpoints loaded, or 0 if none available.
 */
LIBDOGECOIN_API size_t dogecoin_cf_load_hardcoded_checkpoints(
    dogecoin_compact_filter_state *state, const dogecoin_chainparams *chain);

/**
 * @brief Look up the compiled-in filter header for a height, if one exists.
 *
 * This is the authoritative anchor for cfheaders validation. A peer's cfcheckpt
 * response must never be the thing a filter header is checked against: a peer
 * that answers with a short list is only validated over the prefix it chose to
 * send, and anything above that would be accepted unanchored.
 *
 * Searches rather than indexing. Checkpoint spacing is not the same on every
 * chain -- mainnet is one per CFCHECKPT_INTERVAL, testnet is one per ten of
 * them, because testnet3 is ~65M blocks deep against mainnet's ~6.3M -- so
 * `height / CFCHECKPT_INTERVAL - 1` is only ever right for one of them.
 *
 * @param chain      The chain params.
 * @param height     Block height to look up.
 * @param header_out Receives the filter header in internal byte order.
 * @return true if a compiled-in checkpoint exists at exactly @p height.
 */
LIBDOGECOIN_API dogecoin_bool dogecoin_cf_hardcoded_checkpoint_at(
    const dogecoin_chainparams *chain, uint32_t height, uint256_t header_out);

LIBDOGECOIN_END_DECL

#endif /* __LIBDOGECOIN_COMPACT_FILTER_H__ */
