/*

 The MIT License (MIT)

 Copyright (c) 2015 Jonas Schnelli
 Copyright (c) 2023 bluezr
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

#ifndef __LIBDOGECOIN_SPV_H__
#define __LIBDOGECOIN_SPV_H__

#include <dogecoin/dogecoin.h>
#include <dogecoin/blockchain.h>
#include <dogecoin/compact_filter.h>
#include <dogecoin/headersdb.h>
#include <dogecoin/net.h>
#include <dogecoin/tx.h>

#define SPV_STATS_RING 4096

LIBDOGECOIN_BEGIN_DECL

enum SPV_CLIENT_STATE {
    SPV_HEADER_SYNC_FLAG        = (1 << 0),
    SPV_FULLBLOCK_SYNC_FLAG     = (1 << 1),
    SPV_CFILTER_SYNC_FLAG       = (1 << 2),
};

typedef struct spv_block_sample_
{
    uint32_t ts;        // block timestamp
    uint32_t txs;       // number of transactions
    uint32_t outputs;   // number of outputs
    uint64_t out_value; // total output value
    uint32_t size;      // block size
    uint64_t fees;      // total fees
} spv_block_sample;

typedef struct dogecoin_spv_client_
{
    dogecoin_node_group *nodegroup;
    uint64_t last_headersrequest_time;
    uint64_t oldest_item_of_interest;
    dogecoin_bool use_checkpoints;
    const dogecoin_chainparams *chainparams;
    int stateflags;
    uint64_t last_statecheck_time;
    dogecoin_bool called_sync_completed;
    void *headers_db_ctx;
    const dogecoin_headers_db_interface *headers_db;
    uint64_t last_block_size;
    uint64_t last_block_tx_count;
    uint64_t last_block_total_tx_size;
    spv_block_sample stats_ring[SPV_STATS_RING];
    int stats_ring_len;
    int stats_ring_head;
    uint64_t stats_blocks_total;
    uint64_t stats_txs_total;
    uint64_t stats_outputs_total;
    uint64_t stats_out_value_total;
    uint64_t stats_fees_total;
    uint64_t stats_block_bytes_total;
    uint64_t start_ts;

    void* smpv_ctx;
    dogecoin_bool smpv_enabled;

    /* BIP37 bloom filter (optional). When set, getdata requests are rewritten
       to request FILTERED_BLOCK so peers answer with merkleblock + matched tx. */
    uint8_t* bloom_filter;
    uint32_t bloom_filter_len;
    uint32_t bloom_nhashfunc;
    uint32_t bloom_ntweak;
    uint8_t  bloom_flags;
    char*    bloom_filter_debug_dump;

   /* merkleblock -> matched tx state
      stored as a btree keyed by txid so tx lookup is O(log n) */
   void*      merkle_match_tree;
   uint32_t   merkle_match_pending;
    dogecoin_bool merkle_match_active;
    dogecoin_blockindex* merkle_match_blockindex;

    /* historical rescan progress counters */
    uint64_t rescan_total;      /* total merkle blocks received during rescan */
    uint64_t rescan_matched;    /* merkle blocks with at least one matched tx */
    int32_t  filtered_history_last_end_height; /* highest historical height already requested via getdata(FILTERED_BLOCK) */
    uint8_t  filtered_history_tail_rerequest_count; /* bounded historical tail re-requests after new matches to catch spends */
    uint256_t filtered_history_last_rerequest_txid; /* dedupe repeated tail re-requests for the same matched tx */
    int32_t  filtered_history_last_rerequest_height;

    /* Comma-separated "host:port" strings supplied by the caller via
     * dogecoin_spv_client_discover_peers().  When non-NULL, the reconnect
     * callback reuses these peers instead of querying DNS seeds, so the
     * client stays connected to the explicitly-named hosts only. */
    char *peer_ips;

    /* BIP157 genesis-filter support: optional read-only secondary headers DB
     * used only for block-hash lookup at early heights when the primary DB is
     * checkpoint-based.  Populated via --filter-hash-db CLI option. */
    void                                *aux_hash_db_ctx; /**< Context for aux block-hash lookup DB */
    const dogecoin_headers_db_interface *aux_hash_db;     /**< Interface for aux block-hash lookup DB */

    /* When non-zero, overrides the cfheaders start height (auto default:
     * chainbottom for checkpoint-based sync, 1 for genesis sync). */
    uint32_t cf_start_height;

    /* Number of parallel getcfilters workers (independent TCP connections).
     * 0 or 1 means sequential (default); >1 activates parallel mode. */
    uint8_t cf_num_workers;

    /* BIP157: compact filter sync state */
    dogecoin_bool compact_filters_enabled; /**< Whether compact filter sync is active */
    dogecoin_compact_filter_state *cfilter_state; /**< BIP157 per-client compact filter state */

    /* BIP158 filter header computation during full block sync */
    uint256_t cf_prev_filter_header;   /**< Running filter header chain for BIP158 */
    uint32_t  cf_computed_height;      /**< Last height for which a filter header was computed */
    dogecoin_bool cf_export_enabled;   /**< Log filter header checkpoints during sync */

    /* callbacks */
    /* ========= */
    void (*header_connected)(struct dogecoin_spv_client_ *client);
    void (*sync_completed)(struct dogecoin_spv_client_ *client);
    dogecoin_bool (*header_message_processed)(struct dogecoin_spv_client_ *client, dogecoin_node *node, dogecoin_blockindex *newtip);
    void (*sync_transaction)(void *ctx, dogecoin_tx *tx, unsigned int pos, dogecoin_blockindex *blockindex);
    void *sync_transaction_ctx;

    /* Per-client pending PQC OP_RETURN commitments awaiting carrier TX_R match.
       Opaque pointer (spv_pqc_pending_commit_t* internally); NULL when no PQC
       backends are compiled in. Owned by the client and freed on
       dogecoin_spv_client_free so multiple clients do not share state. */
    void* pqc_pending_commits;

    /* Per-client pending ZK OP_RETURN commitments awaiting carrier TX_R match.
       Opaque pointer (spv_zk_pending_commit_t* internally); NULL when the ZK
       carrier module is not compiled in. Owned by the client and freed on
       dogecoin_spv_client_free so multiple clients do not share state and so
       a long-running node cannot accumulate unbounded entries from cheap
       OP_RETURN spam (capped + LRU-evicted by spv_zk_add_pending). */
    void* zk_pending_commits;
} dogecoin_spv_client;

LIBDOGECOIN_API dogecoin_spv_client* dogecoin_spv_client_new(const dogecoin_chainparams *params, dogecoin_bool debug, dogecoin_bool headers_memonly, dogecoin_bool use_checkpoints, dogecoin_bool full_sync, int maxnodes, const char *http_server);
LIBDOGECOIN_API void dogecoin_spv_client_free(dogecoin_spv_client *client);
LIBDOGECOIN_API dogecoin_bool dogecoin_spv_client_load(dogecoin_spv_client *client, const char *file_path, dogecoin_bool prompt);
LIBDOGECOIN_API void dogecoin_spv_client_discover_peers(dogecoin_spv_client *client, const char *ips);
LIBDOGECOIN_API void dogecoin_spv_client_runloop(dogecoin_spv_client *client);
LIBDOGECOIN_API dogecoin_bool dogecoin_net_spv_request_headers(dogecoin_spv_client *client);
LIBDOGECOIN_API void dogecoin_net_spv_node_request_headers_or_blocks(dogecoin_node *node, dogecoin_bool blocks);

LIBDOGECOIN_API void dogecoin_spv_enable_smpv(dogecoin_spv_client* client, dogecoin_bool enable);
LIBDOGECOIN_API dogecoin_bool dogecoin_spv_handle_mempool_tx_hex(dogecoin_spv_client* client, const char* raw_tx_hex);
LIBDOGECOIN_API void dogecoin_spv_get_smpv_stats(dogecoin_spv_client* client, uint32_t* total_txs, uint32_t* watched_addrs);
LIBDOGECOIN_API void dogecoin_net_spv_request_mempool(dogecoin_spv_client *client);
LIBDOGECOIN_API void dogecoin_net_spv_request_filtered_history(dogecoin_spv_client *client, int depth);

/* BIP37: caller supplies a bloom filter payload (as built elsewhere).
   Insert script-relevant data (e.g. pubkey hashes, script bytes, outpoints),
   not base58 address strings. txids/outpoints are only useful when known. */
LIBDOGECOIN_API dogecoin_bool dogecoin_spv_client_filterload(
    dogecoin_spv_client* client,
    const uint8_t* filter,
    uint32_t filter_len,
    uint32_t nHashFuncs,
    uint32_t nTweak,
    uint8_t flags);

LIBDOGECOIN_API dogecoin_bool dogecoin_spv_client_filteradd(
    dogecoin_spv_client* client,
    const uint8_t* data,
    uint32_t data_len);

LIBDOGECOIN_API dogecoin_bool dogecoin_spv_client_filterclear(dogecoin_spv_client* client);

/* BIP157: enable or disable compact filter sync for this client */
LIBDOGECOIN_API void dogecoin_spv_enable_compact_filters(dogecoin_spv_client *client, dogecoin_bool enable);

/* BIP157: send getcfcheckpt, getcfheaders, getcfilters to a peer */
LIBDOGECOIN_API dogecoin_bool dogecoin_spv_request_cfcheckpt(dogecoin_spv_client *client, dogecoin_node *node);
LIBDOGECOIN_API dogecoin_bool dogecoin_spv_request_cfheaders(dogecoin_spv_client *client, dogecoin_node *node, uint32_t start_height, const uint256_t stop_hash);
LIBDOGECOIN_API dogecoin_bool dogecoin_spv_request_cfilters(dogecoin_spv_client *client, dogecoin_node *node, uint32_t start_height, const uint256_t stop_hash);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_SPV_H__
