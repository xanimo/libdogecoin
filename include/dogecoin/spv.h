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
#include <dogecoin/headersdb.h>
#include <dogecoin/net.h>
#include <dogecoin/tx.h>

#define SPV_STATS_RING 4096

LIBDOGECOIN_BEGIN_DECL

enum SPV_CLIENT_STATE {
    SPV_HEADER_SYNC_FLAG        = (1 << 0),
    SPV_FULLBLOCK_SYNC_FLAG     = (1 << 1),
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

    /* callbacks */
    /* ========= */
    void (*header_connected)(struct dogecoin_spv_client_ *client);
    void (*sync_completed)(struct dogecoin_spv_client_ *client);
    dogecoin_bool (*header_message_processed)(struct dogecoin_spv_client_ *client, dogecoin_node *node, dogecoin_blockindex *newtip);
    void (*sync_transaction)(void *ctx, dogecoin_tx *tx, unsigned int pos, dogecoin_blockindex *blockindex);
    void *sync_transaction_ctx;
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

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_SPV_H__
