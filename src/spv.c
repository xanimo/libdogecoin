/*

 The MIT License (MIT)

 Copyright (c) 2016 Jonas Schnelli
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

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <conio.h>
#else
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <math.h>

#include <dogecoin/block.h>
#include <dogecoin/bip37.h>
#include <dogecoin/blockchain.h>
#include <dogecoin/headersdb.h>
#include <dogecoin/headersdb_file.h>
#include <dogecoin/net.h>
#include <dogecoin/protocol.h>
#include <dogecoin/serialize.h>
#include <dogecoin/spv.h>
#include <dogecoin/smpv.h>
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>
#include <dogecoin/vector.h>
#include <dogecoin/pqc_carrier.h>
#include <dogecoin/pqc_dilithium.h>
#include <dogecoin/pqc_falcon.h>
#include <dogecoin/rmd160.h>
#ifdef USE_RACCOON_G
#include <dogecoin/pqc_raccoon.h>
#endif
#include <event2/event.h>

/* Optional liboqs (Falcon-only) presence check; compile with -DUSE_LIBOQS */
#ifdef USE_LIBOQS
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include <oqs/sig.h>
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
#endif

#define DOGECOIN_KOINU_PER_COIN 100000000ULL
/* Dogecoin block subsidy has been 10,000 DOGE for years; good for 24h stats */
#define DOGECOIN_CURRENT_SUBSIDY_KOINU (10000ULL * DOGECOIN_KOINU_PER_COIN)
#define SPV_VARINT_MAX_LEN 9 /* compactSize max bytes; we reserve max for simple one-pass allocation */
#define SPV_FILTERLOAD_FIXED_FIELDS_LEN 9 /* 4-byte nHashFuncs + 4-byte nTweak + 1-byte flags */
#define SPV_TXID_HEX_LEN 65 /* 32-byte hash => 64 hex chars + NUL */
#define SPV_FILTER_HISTORY_MAX_REQUEST_PEERS 5
/* Build and send filterload directly from SPV/network context. */
static dogecoin_bool spv_send_filterload_to_node(dogecoin_node* node,
                                                 const uint8_t* filter,
                                                 uint32_t filter_len,
                                                 uint32_t nHashFuncs,
                                                 uint32_t nTweak,
                                                 uint8_t flags)
{
    if (!node || !filter || filter_len == 0) return false;

    cstring* payload = cstr_new_sz((size_t)filter_len + SPV_VARINT_MAX_LEN + SPV_FILTERLOAD_FIXED_FIELDS_LEN);
    if (!payload) return false;

    ser_varlen(payload, filter_len);
    ser_bytes(payload, filter, filter_len);
    ser_u32(payload, nHashFuncs);
    ser_u32(payload, nTweak);
    ser_bytes(payload, &flags, 1);

    cstring* msg = dogecoin_p2p_message_new(
        node->nodegroup->chainparams->netmagic,
        DOGECOIN_MSG_FILTERLOAD,
        (const uint8_t*)payload->str,
        payload->len
    );
    dogecoin_node_send(node, msg);
    cstr_free(msg, true);
    cstr_free(payload, true);
    return true;
}

static dogecoin_bool spv_lookup_headersdb_height_by_hash(dogecoin_spv_client* client,
                                                         const uint8_t hash[32],
                                                         uint32_t* out_height)
{
    dogecoin_headers_db* hdb;
    long old_pos;
    dogecoin_bool can_restore_pos;
    uint8_t rec[SPV_HEADERS_FILE_REC_LEN];

    if (!client || !hash || !out_height) return false;
    hdb = (dogecoin_headers_db*)client->headers_db_ctx;
    if (!hdb || !hdb->headers_tree_file) return false;

    old_pos = ftell(hdb->headers_tree_file);
    can_restore_pos = (old_pos >= 0);
    if (fseek(hdb->headers_tree_file, SPV_HEADERS_FILE_HDR_LEN, SEEK_SET) != 0) {
        if (can_restore_pos) fseek(hdb->headers_tree_file, old_pos, SEEK_SET);
        return false;
    }

    uint8_t hash_rev[32];
    size_t ri;
    for (ri = 0; ri < sizeof(hash_rev); ri++) {
        hash_rev[ri] = hash[sizeof(hash_rev) - 1 - ri];
    }

    while (fread(rec, sizeof(rec), 1, hdb->headers_tree_file) == 1) {
        struct const_buffer rec_buf = { rec, sizeof(rec) };
        uint256_t rec_hash;
        uint32_t rec_height = 0;
        uint256_t rec_chainwork_unused;
        deser_u256(rec_hash, &rec_buf);
        deser_u32(&rec_height, &rec_buf);
        deser_u256(rec_chainwork_unused, &rec_buf);
        UNUSED(rec_chainwork_unused);
        if (memcmp(rec_hash, hash, sizeof(uint256_t)) == 0 ||
            memcmp(rec_hash, hash_rev, sizeof(uint256_t)) == 0) {
            *out_height = rec_height;
            if (can_restore_pos) fseek(hdb->headers_tree_file, old_pos, SEEK_SET);
            return true;
        }
    }

    if (can_restore_pos) fseek(hdb->headers_tree_file, old_pos, SEEK_SET);
    return false;
}

typedef struct spv_merkle_log_ctx_ {
    dogecoin_spv_client* client;
    const dogecoin_blockindex* pindex;
} spv_merkle_log_ctx;

static dogecoin_bool spv_log_merkle_match(const uint8_t txid[32], uint32_t pos, dogecoin_bool consumed, void* ctx)
{
    spv_merkle_log_ctx* c = (spv_merkle_log_ctx*)ctx;
    if (!c || !c->client || !c->client->nodegroup || !c->client->nodegroup->log_write_cb) return false;

    char txid_hex[SPV_TXID_HEX_LEN];
    utils_bin_to_hex((unsigned char*)txid, 32, txid_hex);
    int match_height = c->pindex ? (int)c->pindex->height : -1;
    c->client->nodegroup->log_write_cb("[merkle][decode] block_height=%d txid=%s pos=%u consumed=%d\n",
        match_height, txid_hex, pos, consumed ? 1 : 0);
    return true;
}

static const unsigned int HEADERS_MAX_RESPONSE_TIME = 120;
static const unsigned int MIN_TIME_DELTA_FOR_STATE_CHECK = 5;
static const unsigned int BLOCK_GAP_TO_DEDUCT_TO_START_SCAN_FROM = 5;
static const unsigned int BLOCKS_DELTA_IN_S = 60;
static const unsigned int COMPLETED_WHEN_NUM_NODES_AT_SAME_HEIGHT = 2;

#if defined(USE_LIBOQS) || defined(USE_RACCOON_G)
/* Maximum number of pending PQC OP_RETURN commitments buffered per client
   for cross-TX carrier validation (TX_C has OP_RETURN, TX_R has scriptSig).
   Cap enforced via LRU eviction in spv_pqc_add_pending so a peer flooding
   cheap OP_RETURN commits cannot balloon SPV node memory. */
#define SPV_PQC_PENDING_MAX 16

typedef struct spv_pqc_pending_commit {
    uint8_t commit[32];           /* 32-byte commit hash - used as hash key */
    dogecoin_pqc_algo_t algo;
    uint32_t txpos;
    uint32_t height;              /* block height where TX_C was seen */
    uint8_t* txc_raw;             /* serialized TX_C for signature verification */
    size_t txc_raw_len;
    UT_hash_handle hh;            /* makes this structure hashable */
} spv_pqc_pending_commit_t;

/* Per-client pending-commit table accessor. Stored as an opaque void* in
   dogecoin_spv_client so the header does not need to expose uthash types.
   uthash tracks insertion order in its hh.next/hh.prev chain, which gives
   us O(1) LRU eviction of the oldest entry without an extra linked list. */
static inline spv_pqc_pending_commit_t* spv_pqc_table(const dogecoin_spv_client* client) {
    return client ? (spv_pqc_pending_commit_t*)client->pqc_pending_commits : NULL;
}

/* Helper: find pending commit by commit hash within this client's table. */
static spv_pqc_pending_commit_t* spv_pqc_find_pending(dogecoin_spv_client* client, const uint8_t* commit) {
    spv_pqc_pending_commit_t* head = spv_pqc_table(client);
    spv_pqc_pending_commit_t* found = NULL;
    if (!head || !commit) return NULL;
    HASH_FIND(hh, head, commit, 32, found);
    return found;
}

/* Helper: add pending commit to this client's hash table. De-duplicates by
   commit hash and enforces SPV_PQC_PENDING_MAX via LRU eviction of the
   oldest insertion (uthash's iteration order is insertion order). */
static void spv_pqc_add_pending(dogecoin_spv_client* client, spv_pqc_pending_commit_t* entry) {
    if (!client || !entry) return;
    spv_pqc_pending_commit_t* head = spv_pqc_table(client);
    /* Replace existing entry with the same commit hash to avoid stale state. */
    spv_pqc_pending_commit_t* existing = NULL;
    if (head) HASH_FIND(hh, head, entry->commit, 32, existing);
    if (existing) {
        HASH_DEL(head, existing);
        if (existing->txc_raw) dogecoin_free(existing->txc_raw);
        dogecoin_free(existing);
    }
    /* Enforce cap: evict oldest entries until there is room for the new one.
       uthash links entries in insertion order via `hh.next` with a tail
       pointer for O(1) append (see UT_hash_table::tail / "tail hh in app
       order, for fast append" in uthash.h). HASH_ITER walks head→tail in
       insertion order, so the table head is always the oldest still-alive
       entry — exact LRU under our usage where we only add and (on TX_R
       match) delete by key. */
    while (head && HASH_COUNT(head) >= SPV_PQC_PENDING_MAX) {
        spv_pqc_pending_commit_t* oldest = head; /* head == oldest insertion */
        HASH_DEL(head, oldest);
        if (oldest->txc_raw) dogecoin_free(oldest->txc_raw);
        dogecoin_free(oldest);
    }
    HASH_ADD(hh, head, commit, 32, entry);
    client->pqc_pending_commits = head;
}

/* Note: a removal helper used to live here but every call site needs
   special-case logic (the TX_R match path moves out `txc_raw` before
   freeing, the free-all path runs inside a HASH_ITER), so HASH_DEL is
   inlined at the call sites and the helper was removed to avoid dead
   code. */

#endif /* USE_LIBOQS || USE_RACCOON_G (pqc pending) */

static dogecoin_bool dogecoin_net_spv_node_timer_callback(dogecoin_node *node, uint64_t *now);
void dogecoin_net_spv_post_cmd(dogecoin_node *node, dogecoin_p2p_msg_hdr *hdr, struct const_buffer *buf);
void dogecoin_net_spv_node_handshake_done(dogecoin_node *node);

void dogecoin_node_connection_state_changed_cb(dogecoin_node *node) {
    if (node->nodegroup->should_connect_to_more_nodes_cb) {
        if (node->nodegroup->should_connect_to_more_nodes_cb(node)) {
            dogecoin_spv_client_discover_peers((dogecoin_spv_client*)node->nodegroup->ctx, NULL);
            dogecoin_node_group_connect_next_nodes(node->nodegroup);
        }
    }
}

/**
 * @brief This function deterimines if we should connect to more nodes.
 *
 * @param node the node that we are connected to.
 *
 * @return dogecoin_bool (uint8_t)
 */
dogecoin_bool dogecoin_node_should_connect_to_more_cb(dogecoin_node* node) {
    int connected_amount = dogecoin_node_group_amount_of_connected_nodes(node->nodegroup, NODE_CONNECTED) + dogecoin_node_group_amount_of_connected_nodes(node->nodegroup, NODE_CONNECTING);
    node->nodegroup->log_write_cb("check if more nodes are required (connected to already: %d): %s\n", connected_amount, connected_amount < node->nodegroup->desired_amount_connected_nodes ? "true" : "false");
    if (connected_amount < node->nodegroup->desired_amount_connected_nodes) {
        return true;
    }
    return false;
}

/**
 * The function sets the nodegroup's postcmd_cb to dogecoin_net_spv_post_cmd,
 * the nodegroup's handshake_done_cb to dogecoin_net_spv_node_handshake_done,
 * the nodegroup's node_connection_state_changed_cb to NULL, and the
 * nodegroup's periodic_timer_cb to dogecoin_net_spv_node_timer_callback
 *
 * @param nodegroup The nodegroup to set the callbacks for.
 */
void dogecoin_net_set_spv(dogecoin_node_group *nodegroup)
{
    nodegroup->postcmd_cb = dogecoin_net_spv_post_cmd;
    nodegroup->handshake_done_cb = dogecoin_net_spv_node_handshake_done;
    nodegroup->should_connect_to_more_nodes_cb = dogecoin_node_should_connect_to_more_cb;
    nodegroup->node_connection_state_changed_cb = dogecoin_node_connection_state_changed_cb;
    nodegroup->periodic_timer_cb = dogecoin_net_spv_node_timer_callback;
}

/**
 * The function creates a new dogecoin_spv_client object and initializes it
 *
 * @param params The chainparams struct that we created earlier.
 * @param debug If true, the node will print out debug messages to stdout.
 * @param headers_memonly If true, the headers database will not be loaded from disk.
 * @param use_checkpoints If true, the client will use checkpoints.
 * @param full_sync If true, the client will do a full sync.
 * @param maxnodes The maximum amount of nodes that the client will connect to.
 * @param http_server The IP and port for the HTTP server; if NULL, the HTTP server will not be initialized.
 *
 * @return A pointer to a dogecoin_spv_client object.
 */
dogecoin_spv_client* dogecoin_spv_client_new(const dogecoin_chainparams *params, dogecoin_bool debug, dogecoin_bool headers_memonly, dogecoin_bool use_checkpoints, dogecoin_bool full_sync, int maxnodes, const char* http_server)
{
    dogecoin_spv_client* client;
    client = dogecoin_calloc(1, sizeof(*client));

    client->last_headersrequest_time = 0; //!< time when we requested the last header package
    client->last_statecheck_time = 0;
    client->oldest_item_of_interest = time(NULL)-5*60;
    client->stateflags = full_sync ? SPV_FULLBLOCK_SYNC_FLAG : SPV_HEADER_SYNC_FLAG;

    client->chainparams = params;

    client->nodegroup = dogecoin_node_group_new(params);
    client->nodegroup->ctx = client;
    if (maxnodes > 120) {
        maxnodes = 120;
    }
    client->nodegroup->desired_amount_connected_nodes = maxnodes;

    dogecoin_net_set_spv(client->nodegroup);

    if (debug) {
        client->nodegroup->log_write_cb = net_write_log_printf;
    }

#ifdef USE_LIBOQS
    // Log what PQC variants are present at runtime (minimal, no hard dependency).
    if (client->nodegroup && client->nodegroup->log_write_cb) {
        client->nodegroup->log_write_cb(
            "[oqs] falcon_512=%s falcon_1024=%s ml_dsa_44=%s (liboqs)\n",
            OQS_SIG_alg_is_enabled(OQS_SIG_alg_falcon_512) ? "enabled" : "disabled",
            OQS_SIG_alg_is_enabled(OQS_SIG_alg_falcon_1024) ? "enabled" : "disabled",
            OQS_SIG_alg_is_enabled(OQS_SIG_alg_ml_dsa_44) ? "enabled" : "disabled");
    }
#endif
#ifdef USE_RACCOON_G
    /* Raccoon-G is provided by the in-tree src/raccoon_g/ implementation,
       not by the liboqs fork (which no longer ships Raccoon-G). Log it on
       its own line so the source of the backend is unambiguous. */
    if (client->nodegroup && client->nodegroup->log_write_cb) {
        client->nodegroup->log_write_cb("[raccoon_g] raccoon_g_44=enabled (in-tree)\n");
    }
#endif

    if (params && (strcmp(params->chainname, "main") == 0 ||
                   strcmp(params->chainname, "testnet3") == 0)) {
        client->use_checkpoints = use_checkpoints;
    }
    client->headers_db = &dogecoin_headers_db_interface_file;
    client->headers_db_ctx = client->headers_db->init(params, headers_memonly);

    // set callbacks
    client->header_connected = NULL;
    client->called_sync_completed = false;
    client->sync_completed = NULL;
    client->header_message_processed = NULL;
    client->sync_transaction = NULL;
    client->sync_transaction_ctx = NULL;

    // BIP37 filter state (off by default)
    client->bloom_filter = NULL;
    client->bloom_filter_len = 0;
    client->bloom_nhashfunc = 0;
    client->bloom_ntweak = 0;
    client->bloom_flags = 0;
    client->bloom_filter_debug_dump = NULL;

    // merkleblock -> matched tx state (btree keyed by txid)
    client->merkle_match_tree = NULL;
    client->merkle_match_pending = 0;
    client->merkle_match_active = false;
    client->merkle_match_blockindex = NULL;
    client->rescan_total = 0;
    client->rescan_matched = 0;
    client->filtered_history_last_end_height = -1; /* -1 means no historical filtered range has been requested yet */
    client->filtered_history_tail_rerequest_count = 0;
    dogecoin_hash_clear(client->filtered_history_last_rerequest_txid);
    client->filtered_history_last_rerequest_height = -1;

    if (http_server) {
        // split ip and port
        char* http_server_copy = strdup(http_server);
        char* ip = strtok(http_server_copy, ":");
        char* port = strtok(NULL, ":");

        // HTTP server initialization
        dogecoin_http_server_init(client->nodegroup, ip, atoi(port));
        client->nodegroup->log_write_cb("HTTP server initialized\n");
        free(http_server_copy);
    }

    client->stats_ring_len = 0;
    client->stats_ring_head = 0;
    client->stats_blocks_total = 0;
    client->stats_txs_total = 0;
    client->stats_outputs_total = 0;
    client->stats_out_value_total = 0;
    client->stats_fees_total = 0;
    client->stats_block_bytes_total = 0;
    client->start_ts = (uint64_t)time(NULL);

    // SMPV default off
    client->smpv_ctx = NULL;
    client->smpv_enabled = false;

    return client;
}

/**
 * It adds peers to the nodegroup.
 *
 * @param client the dogecoin_spv_client object
 * @param ips A comma-separated list of IPs or seeds to connect to.
 */
void dogecoin_spv_client_discover_peers(dogecoin_spv_client* client, const char *ips)
{
#ifndef _WIN32
    // set stdin to non-blocking for quit command
    int stdin_flags = fcntl(STDIN_FILENO, F_GETFL);
    fcntl(STDIN_FILENO, F_SETFL, stdin_flags | O_NONBLOCK);
#endif

    dogecoin_node_group_add_peers_by_ip_or_seed(client->nodegroup, ips);
}

/**
 * The function loops through all the nodes in the node group and connects to the next nodes in the
 * node group
 *
 * @param client The dogecoin_spv_client object.
 */
void dogecoin_spv_client_runloop(dogecoin_spv_client* client)
{
    dogecoin_node_group_connect_next_nodes(client->nodegroup);
    dogecoin_node_group_event_loop(client->nodegroup);
}

/**
 * It frees the memory allocated for the client
 *
 * @param client The client object to be freed.
 *
 * @return Nothing.
 */
void dogecoin_spv_client_free(dogecoin_spv_client *client)
{
    if (!client)
        return;

#ifndef _WIN32
    // set stdin to back to blocking
    int stdin_flags = fcntl(STDIN_FILENO, F_GETFL);
    if (stdin_flags != -1 && (stdin_flags & O_NONBLOCK))
    {
        fcntl(STDIN_FILENO, F_SETFL, stdin_flags & ~O_NONBLOCK);
    }
#endif

    if (client->smpv_enabled && client->smpv_ctx) {
        dogecoin_smpv_stop((dogecoin_smpv_client*)client->smpv_ctx);
        dogecoin_smpv_client_free((dogecoin_smpv_client*)client->smpv_ctx);
        client->smpv_ctx = NULL;
        client->smpv_enabled = false;
    }

    if (client->bloom_filter) {
        dogecoin_free(client->bloom_filter);
        client->bloom_filter = NULL;
    }
    client->bloom_filter_len = 0;
    client->bloom_nhashfunc = 0;
    client->bloom_ntweak = 0;
    client->bloom_flags = 0;
    if (client->bloom_filter_debug_dump) {
        dogecoin_free(client->bloom_filter_debug_dump);
        client->bloom_filter_debug_dump = NULL;
    }

    if (client->merkle_match_tree) {
        dogecoin_btree_tdestroy(client->merkle_match_tree, dogecoin_free);
        client->merkle_match_tree = NULL;
    }
    client->merkle_match_pending = 0;
    client->merkle_match_active = false;
    client->merkle_match_blockindex = NULL;

    if (client->headers_db)
    {
        if (client->headers_db_ctx)
        {
            client->headers_db->free(client->headers_db_ctx);
        }
        client->headers_db_ctx = NULL;
        client->headers_db = NULL;
    }

    if (client->nodegroup) {
        dogecoin_node_group_free(client->nodegroup);
        client->nodegroup = NULL;
    }

#if defined(USE_LIBOQS) || defined(USE_RACCOON_G)
    /* Release any pending PQC carrier commits that were never matched by a TX_R.
       Only the table owned by this client is freed — other live clients keep
       their own per-client tables intact. */
    {
        spv_pqc_pending_commit_t* head = spv_pqc_table(client);
        spv_pqc_pending_commit_t* entry;
        spv_pqc_pending_commit_t* tmp;
        HASH_ITER(hh, head, entry, tmp) {
            HASH_DEL(head, entry);
            if (entry->txc_raw) dogecoin_free(entry->txc_raw);
            dogecoin_free(entry);
        }
        client->pqc_pending_commits = NULL;
    }
#endif

    dogecoin_free(client);
}

/**
 * Loads the headers database from a file
 *
 * @param client the client object
 * @param file_path The path to the headers database file.
 * @param prompt If true, the user will be prompted to confirm loading the database.
 *
 * @return A boolean value.
 */
dogecoin_bool dogecoin_spv_client_load(dogecoin_spv_client *client, const char *file_path, dogecoin_bool prompt)
{
    if (!client)
        return false;

    if (!client->headers_db)
        return false;

    return client->headers_db->load(client->headers_db_ctx, file_path, prompt);

}

/**
 * If we are in the header sync state, we request headers from a random node
 *
 * @param node the node that we are checking
 * @param now The current time in seconds.
 */
void dogecoin_net_spv_periodic_statecheck(dogecoin_node *node, uint64_t *now)
{
    /* statecheck logic */
    /* ================ */

    dogecoin_spv_client *client = (dogecoin_spv_client*)node->nodegroup->ctx;
    dogecoin_blockindex *pindex = client->headers_db->getchaintip(client->headers_db_ctx);
    client->nodegroup->log_write_cb("Statecheck: amount of connected nodes: %d\nchaintip hash: %s\nchaintip height: %d\n", dogecoin_node_group_amount_of_connected_nodes(client->nodegroup, NODE_CONNECTED), hash_to_string(pindex->hash), pindex->height);

    if (client->last_headersrequest_time > 0 && *now > client->last_headersrequest_time)
    {
        int64_t timedetla = *now - client->last_headersrequest_time;
        client->nodegroup->log_write_cb("No header response in time (used %d) for node %d\n", timedetla, node->nodeid);
        if (timedetla > HEADERS_MAX_RESPONSE_TIME)
        {
            node->state &= ~NODE_HEADERSYNC;
            dogecoin_node_misbehave(node);
        }
    }
    if (node->time_last_request > 0 && *now > node->time_last_request)
    {
        // we are downloading blocks from this peer
        int64_t timedelta = *now - node->time_last_request;
        client->nodegroup->log_write_cb("No block response in time (used %d) for node %d\n", timedelta, node->nodeid);
        if (timedelta > HEADERS_MAX_RESPONSE_TIME)
        {
            node->state &= ~NODE_BLOCKSYNC;
            dogecoin_node_misbehave(node);
        }
    }

    if ((client->stateflags & SPV_HEADER_SYNC_FLAG) == SPV_HEADER_SYNC_FLAG)
    {
        client->last_headersrequest_time = 0;
        dogecoin_net_spv_request_headers(client);
    }

    if ((client->stateflags & SPV_FULLBLOCK_SYNC_FLAG) == SPV_FULLBLOCK_SYNC_FLAG)
    {
        node->time_last_request = 0;
        dogecoin_net_spv_request_headers(client);
    }

    client->last_statecheck_time = *now;
}

/**
 * This function is called by the dogecoin_node_timer_callback function.
 *
 * It checks if the last_statecheck_time is greater than the minimum time delta for state checks.
 *
 * If it is, it calls the dogecoin_net_spv_periodic_statecheck function.
 *
 * The dogecoin_net_spv_periodic_statecheck function checks if the node is connected to the network.
 *
 * @param node The node that the timer is being called on.
 * @param now the current time in seconds since the epoch
 *
 * @return A boolean value.
 */
static dogecoin_bool dogecoin_net_spv_node_timer_callback(dogecoin_node *node, uint64_t *now)
{
    dogecoin_spv_client *client = (dogecoin_spv_client*)node->nodegroup->ctx;

    if (client->last_statecheck_time + MIN_TIME_DELTA_FOR_STATE_CHECK < *now)
    {
        dogecoin_net_spv_periodic_statecheck(node, now);
    }

    return true;
}

/**
 * Fill up the blocklocators vector_t with the blocklocators from the headers database
 *
 * @param client the spv client
 * @param blocklocators a vector_t of block hashes that we want to scan from
 *
 * @return The blocklocators are being returned.
 */
void dogecoin_net_spv_fill_block_locator(dogecoin_spv_client *client, vector_t *blocklocators) {
    int64_t min_timestamp = client->oldest_item_of_interest - BLOCK_GAP_TO_DEDUCT_TO_START_SCAN_FROM * BLOCKS_DELTA_IN_S; /* ensure we going back ~300 blocks */
    if (client->headers_db->getchaintip(client->headers_db_ctx)->height == 0) {
        if (client->use_checkpoints && client->oldest_item_of_interest > BLOCK_GAP_TO_DEDUCT_TO_START_SCAN_FROM * BLOCKS_DELTA_IN_S) {
            dogecoin_bool is_main = (client->chainparams && strcmp(client->chainparams->chainname, "main") == 0);
            const dogecoin_checkpoint *checkpoint = is_main ? dogecoin_mainnet_checkpoint_array : dogecoin_testnet_checkpoint_array;
            size_t mainnet_checkpoint_size = sizeof(dogecoin_mainnet_checkpoint_array) / sizeof(dogecoin_mainnet_checkpoint_array[0]);
            size_t testnet_checkpoint_size = sizeof(dogecoin_testnet_checkpoint_array) / sizeof(dogecoin_testnet_checkpoint_array[0]);
            size_t length = is_main ? mainnet_checkpoint_size : testnet_checkpoint_size;
            int i;
            for (i = (int)length - 1; i >= 0; i--) {
                if (checkpoint[i].timestamp < min_timestamp) {
                    uint256_t *hash = dogecoin_calloc(1, sizeof(uint256_t));
                    utils_uint256_sethex((char *)checkpoint[i].hash, (uint8_t *)hash);
                    vector_add(blocklocators, (void *)hash);
                    if (!client->headers_db->has_checkpoint_start(client->headers_db_ctx)) {
                        arith_uint256 checkpoint_chainwork;
                        uint_to_arith(&checkpoint_chainwork, &client->chainparams->minimumchainwork);
                        client->headers_db->set_checkpoint_start(client->headers_db_ctx, *hash, checkpoint[i].height, checkpoint_chainwork);
                    }
                }
            }
            if (blocklocators->len > 0) return; // return if we could fill up the blocklocator with checkpoints
        }
        uint256_t *hash = dogecoin_calloc(1, sizeof(uint256_t));
        memcpy_safe(hash, &client->chainparams->genesisblockhash, sizeof(uint256_t));
        vector_add(blocklocators, (void *)hash);
        client->nodegroup->log_write_cb("Setting blocklocator with genesis block\n");
    } else {
        client->headers_db->fill_blocklocator_tip(client->headers_db_ctx, blocklocators);
    }
}

/**
 * This function is called when a node is in headers sync state. It will request the next block headers
 * from the node
 *
 * @param node The node that is requesting headers or blocks.
 * @param blocks boolean, true if we want to request blocks, false if we want to request headers
 */
void dogecoin_net_spv_node_request_headers_or_blocks(dogecoin_node *node, dogecoin_bool blocks)
{
    // request next headers
    vector_t *blocklocators = vector_new(1, free);

    dogecoin_net_spv_fill_block_locator((dogecoin_spv_client *)node->nodegroup->ctx, blocklocators);

    cstring *getheader_msg = cstr_new_sz(256);
    dogecoin_p2p_msg_getheaders(blocklocators, NULL, getheader_msg);

    cstring *p2p_msg = dogecoin_p2p_message_new(node->nodegroup->chainparams->netmagic, (blocks ? DOGECOIN_MSG_GETBLOCKS : DOGECOIN_MSG_GETHEADERS), getheader_msg->str, getheader_msg->len);
    cstr_free(getheader_msg, true);

    dogecoin_node_send(node, p2p_msg);
    node->state |= ( blocks ? NODE_BLOCKSYNC : NODE_HEADERSYNC);

    if (blocks) {
        node->time_last_request = time(NULL);
    } else {
        ((dogecoin_spv_client*)node->nodegroup->ctx)->last_headersrequest_time = time(NULL);
    }

    vector_free(blocklocators, true);
    cstr_free(p2p_msg, true);
}

/**
 * If we have not yet reached the height of the blockchain tip, we request headers from a peer. If we
 * have reached the height of the blockchain tip, we request blocks from a peer
 *
 * @param client the spv client
 *
 * @return dogecoin_bool
 */
dogecoin_bool dogecoin_net_spv_request_headers(dogecoin_spv_client *client)
{
    size_t i;
    dogecoin_bool new_headers_available = false;
    for(i = 0; i < client->nodegroup->nodes->len; ++i)
    {
        dogecoin_node *check_node = vector_idx(client->nodegroup->nodes, i);
        if (((check_node->state & NODE_HEADERSYNC) == NODE_HEADERSYNC || (check_node->state & NODE_BLOCKSYNC) == NODE_BLOCKSYNC) && (check_node->state & NODE_CONNECTED) == NODE_CONNECTED) { return true; }
    }

    // If in header or block sync state, request headers or blocks from the node with the longest chain
    if ((client->stateflags & SPV_HEADER_SYNC_FLAG) == SPV_HEADER_SYNC_FLAG || (client->stateflags & SPV_FULLBLOCK_SYNC_FLAG) == SPV_FULLBLOCK_SYNC_FLAG)
    {
        dogecoin_node *node_with_longest_chain = NULL;
        unsigned int longest_chain_height = 0;
        for(i = 0; i < client->nodegroup->nodes->len; ++i)
        {
            dogecoin_node *check_node = vector_idx(client->nodegroup->nodes, i);
        if (((check_node->state & NODE_CONNECTED) == NODE_CONNECTED) && check_node->version_handshake)
            {
                if (check_node->bestknownheight > longest_chain_height)
                {
                    longest_chain_height = check_node->bestknownheight;
                    node_with_longest_chain = check_node;
                }
            }
        }

        // Request headers or blocks from the node with the longest chain
        if (node_with_longest_chain != NULL) {
            dogecoin_net_spv_node_request_headers_or_blocks(node_with_longest_chain, (client->stateflags & SPV_FULLBLOCK_SYNC_FLAG) == SPV_FULLBLOCK_SYNC_FLAG);
            new_headers_available = true;
        }
    }

    // Fallback: original logic for handling cases where no suitable node was found
    unsigned int nodes_at_same_height = 0;
    if (!new_headers_available && client->headers_db->getchaintip(client->headers_db_ctx)->header.timestamp < client->oldest_item_of_interest - (BLOCK_GAP_TO_DEDUCT_TO_START_SCAN_FROM * BLOCKS_DELTA_IN_S) && client->stateflags == SPV_HEADER_SYNC_FLAG)
    {
        for(i = 0; i < client->nodegroup->nodes->len; i++)
        {
            dogecoin_node *check_node = vector_idx(client->nodegroup->nodes, i);
            if (((check_node->state & NODE_CONNECTED) == NODE_CONNECTED) && check_node->version_handshake)
            {
                if (check_node->bestknownheight > client->headers_db->getchaintip(client->headers_db_ctx)->height) {
                    dogecoin_net_spv_node_request_headers_or_blocks(check_node, false);
                    new_headers_available = true;
                    break;
                } else if (check_node->bestknownheight == client->headers_db->getchaintip(client->headers_db_ctx)->height) {
                    nodes_at_same_height++;
                }
            }
        }
    }
    if (!new_headers_available && (dogecoin_node_group_amount_of_connected_nodes(client->nodegroup, NODE_CONNECTED) > 0) && client->stateflags == SPV_FULLBLOCK_SYNC_FLAG) {
        // try to fetch blocks if no new headers are available but connected nodes are reachable
        for(i = 0; i< client->nodegroup->nodes->len; i++)
        {
            dogecoin_node *check_node = vector_idx(client->nodegroup->nodes, i);
            if (((check_node->state & NODE_CONNECTED) == NODE_CONNECTED) && check_node->version_handshake)
            {
                if (check_node->bestknownheight == client->headers_db->getchaintip(client->headers_db_ctx)->height) {
                    nodes_at_same_height++;
                }
                dogecoin_net_spv_node_request_headers_or_blocks(check_node, true);
                new_headers_available = true;
            }
        }
    }

    if (nodes_at_same_height >= COMPLETED_WHEN_NUM_NODES_AT_SAME_HEIGHT && !client->called_sync_completed && client->sync_completed)
    {
        client->sync_completed(client);
        client->called_sync_completed = true;
    }

    return new_headers_available;
}

/**
 * When the handshake is done, we request the headers
 *
 * @param node The node that just completed the handshake.
 */
void dogecoin_net_spv_node_handshake_done(dogecoin_node *node)
{
    dogecoin_spv_client* client = (dogecoin_spv_client*)node->nodegroup->ctx;

    /* If a BIP37 filter is configured, load it on this peer before requesting blocks. */
    if (client && client->bloom_filter && client->bloom_filter_len > 0) {
        if (spv_send_filterload_to_node(node,
                                        client->bloom_filter,
                                        client->bloom_filter_len,
                                        client->bloom_nhashfunc,
                                        client->bloom_ntweak,
                                        client->bloom_flags) &&
            client->nodegroup && client->nodegroup->log_write_cb) {
            client->nodegroup->log_write_cb("[spv] sent filterload to node %d (len=%u)\n", node->nodeid, client->bloom_filter_len);
        }
    }

    dogecoin_net_spv_request_headers((dogecoin_spv_client*)node->nodegroup->ctx);
}

/**
 * The function is called when a new message is received from a peer
 *
 * @param node
 * @param hdr
 * @param buf
 *
 * @return Nothing.
 */
void dogecoin_net_spv_post_cmd(dogecoin_node *node, dogecoin_p2p_msg_hdr *hdr, struct const_buffer *buf)
{
    dogecoin_spv_client *client = (dogecoin_spv_client *)node->nodegroup->ctx;

    if (strcmp(hdr->command, DOGECOIN_MSG_INV) == 0 && (node->state & NODE_BLOCKSYNC) == NODE_BLOCKSYNC)
    {
        struct const_buffer original_inv = { buf->p, buf->len };
        uint32_t varlen;
        deser_varlen(&varlen, buf);
        dogecoin_bool contains_block = false;
        dogecoin_bool contains_tx = false;

        client->nodegroup->log_write_cb("Get inv request with %d items\n", varlen);

        unsigned int i;
        for (i = 0; i < varlen; i++)
        {
            uint32_t type;
            deser_u32(&type, buf);
            if (type == DOGECOIN_INV_TYPE_BLOCK && ((varlen >= 500) || (client->headers_db->getchaintip(client->headers_db_ctx)->height > node->bestknownheight - 1440))) {
                contains_block = true;
                deser_u256(node->last_requested_inv, buf);
           } else if (type == DOGECOIN_INV_TYPE_TX) {
                contains_tx = true;
                deser_skip(buf, 32);
            } else {
                deser_skip(buf, 32);
            }
        }

        if (contains_block) {
            node->time_last_request = time(NULL);

            dogecoin_bool use_filtered = (client->bloom_filter && client->bloom_filter_len > 0);

            if (use_filtered) {
                /* Rebuild getdata payload, rewriting BLOCK -> FILTERED_BLOCK so peer answers:
                   merkleblock + (matched) tx messages, and we drive sync_transaction only for matches. */
                uint8_t* out = NULL;
                uint32_t out_len = 0;
                uint32_t n = 0;
                if (!dogecoin_bip37_build_filtered_getdata_payload(&original_inv, &out, &out_len, &n)) {
                    node->state &= ~NODE_BLOCKSYNC;
                    node->nodegroup->node_connection_state_changed_cb(node);
                    return;
                }

                client->nodegroup->log_write_cb("Requesting %d filtered blocks (merkleblock+tx)\n", n);
                cstring *p2p_msg = dogecoin_p2p_message_new(
                    node->nodegroup->chainparams->netmagic,
                    DOGECOIN_MSG_GETDATA,
                    out,
                    out_len
                );
                dogecoin_node_send(node, p2p_msg);
                cstr_free(p2p_msg, true);
                dogecoin_free(out);
            } else {
                client->nodegroup->log_write_cb("Requesting %d blocks\n", varlen);
                cstring *p2p_msg = dogecoin_p2p_message_new(node->nodegroup->chainparams->netmagic, DOGECOIN_MSG_GETDATA, original_inv.p, original_inv.len);
                dogecoin_node_send(node, p2p_msg);
                cstr_free(p2p_msg, true);
            }
        }

        if (contains_tx && client->smpv_enabled) {
            client->nodegroup->log_write_cb("Requesting %d tx (mempool INV)\n", varlen);
            cstring *p2p_msg = dogecoin_p2p_message_new(
                node->nodegroup->chainparams->netmagic,
                DOGECOIN_MSG_GETDATA,
                original_inv.p, original_inv.len);
            dogecoin_node_send(node, p2p_msg);
            cstr_free(p2p_msg, true);
        }
    }

    if (strcmp(hdr->command, DOGECOIN_MSG_BLOCK) == 0)
    {
        dogecoin_bool connected;
        dogecoin_blockindex *pindex = client->headers_db->connect_hdr(client->headers_db_ctx, buf, false, &connected);

        node->time_last_request = time(NULL);

        if (connected) {
            if (client->header_connected) { client->header_connected(client); }

            // for now, turn of stall checks if we are near the tip
            if (pindex->header.timestamp > node->time_last_request - 30*60) {
                node->time_last_request = 0;
            }

            time_t lasttime = pindex->header.timestamp;
            char s[1000];
            time_t t = lasttime;
            struct tm *p = localtime(&t);
            strftime(s, sizeof s, "%F %T", p);
            char *ctime_no_newline;
            ctime_no_newline = strtok(s, "\n");
            printf("%s|%d|%s|%d\n", hash_to_string(pindex->hash), pindex->height, ctime_no_newline, hdr->data_len);
            uint64_t start = time(NULL);

            uint32_t amount_of_txs;
            if (!deser_varlen(&amount_of_txs, buf)) {
                if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                    dogecoin_free(pindex);
                }
                client->nodegroup->log_write_cb("Error deserializing amount of transactions from node %d\n", node->nodeid);
                node->state &= ~NODE_BLOCKSYNC;
                node->nodegroup->node_connection_state_changed_cb(node);
                return;
            }

            client->nodegroup->log_write_cb("Start parsing %d transactions...\n", (int)amount_of_txs);

            // update the last block info for the client
            client->last_block_tx_count = amount_of_txs;
            client->last_block_size = hdr->data_len;

            uint64_t total_tx_size = 0;

            // per-block accumulation for stats
            uint64_t block_outputs_value = 0;
            uint32_t block_outputs_count = 0;
            uint64_t coinbase_value = 0;

            size_t consumedlength = 0;
            unsigned int i;
            for (i = 0; i < amount_of_txs; i++)
            {
                const unsigned char* tx_raw = (const unsigned char*)buf->p;

                dogecoin_tx* tx = dogecoin_tx_new();
                if (!dogecoin_tx_deserialize(buf->p, buf->len, tx, &consumedlength)) {
                    client->nodegroup->log_write_cb("Error deserializing transaction\n");
                    if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                        dogecoin_free(pindex);
                    }
                    dogecoin_tx_free(tx);
                    node->state &= ~NODE_BLOCKSYNC;
                    node->nodegroup->node_connection_state_changed_cb(node);
                    return;
                }

                deser_skip(buf, consumedlength);

                // update smpv status for this tx as confirmed in a block
                if (client->smpv_enabled && client->smpv_ctx) {
                    uint256_t h;
                    dogecoin_dblhash(tx_raw, consumedlength, h);
                    char txid_hex[65];
                    utils_bin_to_hex((unsigned char*)h, 32, txid_hex);
                    utils_reverse_hex(txid_hex, 64);
                    char block_hash_hex[65];
                    utils_bin_to_hex((unsigned char*)pindex->hash, 32, block_hash_hex);
                    utils_reverse_hex(block_hash_hex, 64);
                    dogecoin_smpv_update_tx_status(
                        (dogecoin_smpv_client*)client->smpv_ctx,
                        txid_hex,
                        true,
                        block_hash_hex,
                        (uint32_t)pindex->height
                    );
                }

                if (client->sync_transaction) { client->sync_transaction(client->sync_transaction_ctx, tx, i, pindex); }
                
#if defined(USE_LIBOQS) || defined(USE_RACCOON_G)
                /* --- Phase 1: Detect OP_RETURN commitments --- */
#ifdef USE_LIBOQS
                /* Falcon-512: buffer for cross-TX carrier match (TX_C → pending, TX_R validates) */
                uint8_t falcon_commit_data[32];
                if (dogecoin_tx_extract_falcon512_commit(tx, falcon_commit_data)) {
                    char falcon_commit_hex[65];
                    utils_bin_to_hex(falcon_commit_data, 32, falcon_commit_hex);
                    client->nodegroup->log_write_cb("[falcon-commit] Pending at height=%d txpos=%u commit=%s source=op_return\n",
                                                     pindex->height, i, falcon_commit_hex);
                    spv_pqc_pending_commit_t* entry = dogecoin_calloc(1, sizeof(spv_pqc_pending_commit_t));
                    if (entry) {
                        memcpy(entry->commit, falcon_commit_data, 32);
                        entry->algo = DOGECOIN_PQC_ALGO_FALCON;
                        entry->txpos = i;
                        entry->height = pindex->height;
                        entry->txc_raw = dogecoin_malloc(consumedlength);
                        if (entry->txc_raw) {
                            memcpy(entry->txc_raw, tx_raw, consumedlength);
                            entry->txc_raw_len = consumedlength;
                        }
                        spv_pqc_add_pending(client, entry);
                    }
                }
                /* Dilithium2: buffer for cross-TX carrier match (TX_C → pending, TX_R validates via multi-part carrier) */
                uint8_t dilithium_commit_data[32];
                if (dogecoin_tx_extract_dilithium2_commit(tx, dilithium_commit_data)) {
                    char dilithium_commit_hex[65];
                    utils_bin_to_hex(dilithium_commit_data, 32, dilithium_commit_hex);
                    client->nodegroup->log_write_cb("[dilithium-commit] Pending at height=%d txpos=%u commit=%s source=op_return\n",
                                                     pindex->height, i, dilithium_commit_hex);
                    spv_pqc_pending_commit_t* entry = dogecoin_calloc(1, sizeof(spv_pqc_pending_commit_t));
                    if (entry) {
                        memcpy(entry->commit, dilithium_commit_data, 32);
                        entry->algo = DOGECOIN_PQC_ALGO_DILITHIUM;
                        entry->txpos = i;
                        entry->height = pindex->height;
                        entry->txc_raw = dogecoin_malloc(consumedlength);
                        if (entry->txc_raw) {
                            memcpy(entry->txc_raw, tx_raw, consumedlength);
                            entry->txc_raw_len = consumedlength;
                        }
                        spv_pqc_add_pending(client, entry);
                    }
                }
                /* Raccoon-G-44: buffer for cross-TX carrier match (TX_C → pending, TX_R validates via multi-part carrier) */
#endif /* USE_LIBOQS Falcon/Dilithium Phase 1 */
#ifdef USE_RACCOON_G
                uint8_t raccoong_commit_data[32];
                if (dogecoin_tx_extract_raccoong44_commit(tx, raccoong_commit_data)) {
                    char raccoong_commit_hex[65];
                    utils_bin_to_hex(raccoong_commit_data, 32, raccoong_commit_hex);
                    client->nodegroup->log_write_cb("[raccoong-commit] Pending at height=%d txpos=%u commit=%s source=op_return\n",
                                                     pindex->height, i, raccoong_commit_hex);
                    spv_pqc_pending_commit_t* entry = dogecoin_calloc(1, sizeof(spv_pqc_pending_commit_t));
                    if (entry) {
                        memcpy(entry->commit, raccoong_commit_data, 32);
                        entry->algo = DOGECOIN_PQC_ALGO_RACCOONG;
                        entry->txpos = i;
                        entry->height = pindex->height;
                        entry->txc_raw = dogecoin_malloc(consumedlength);
                        if (entry->txc_raw) {
                            memcpy(entry->txc_raw, tx_raw, consumedlength);
                            entry->txc_raw_len = consumedlength;
                        }
                        spv_pqc_add_pending(client, entry);
                    }
                }
#endif

                /* --- Phase 2: Scan every TX for carrier-format scriptSigs (cross-TX carrier match) --- */
                {
                    dogecoin_pqc_algo_t carrier_algo;
                    const uint8_t* carrier_pk = NULL;
                    const uint8_t* carrier_sig = NULL;
                    size_t carrier_pk_len = 0, carrier_sig_len = 0, carrier_vin = 0;
                    uint8_t* carrier_buf = NULL;
                    size_t carrier_buf_len = 0;
                    if (dogecoin_pqc_carrier_extract_scriptsig(tx, &carrier_algo, &carrier_pk, &carrier_pk_len,
                                                      &carrier_sig, &carrier_sig_len, &carrier_vin,
                                                      &carrier_buf, &carrier_buf_len)) {
                        /* Compute TX_R (reveal) txid for logging (display byte order) */
                        uint256_t txr_hash;
                        dogecoin_tx_hash(tx, txr_hash);
                        uint8_t txr_hash_rev[32];
                        for (int rb = 0; rb < 32; rb++) txr_hash_rev[rb] = ((uint8_t*)txr_hash)[31 - rb];
                        char txr_txid_hex[65];
                        utils_bin_to_hex(txr_hash_rev, 32, txr_txid_hex);

                        uint8_t computed_commit[32];
                        const char* algo_label = (carrier_algo == DOGECOIN_PQC_ALGO_FALCON) ? "falcon-commit" :
                                                 (carrier_algo == DOGECOIN_PQC_ALGO_DILITHIUM) ? "dilithium-commit" :
#ifdef USE_RACCOON_G
                                                 (carrier_algo == DOGECOIN_PQC_ALGO_RACCOONG) ? "raccoong-commit" :
#endif
                                                 "unknown-pqc";
                        dogecoin_bool commit_ok = false;
#ifdef USE_LIBOQS
                        if (carrier_algo == DOGECOIN_PQC_ALGO_FALCON)
                            commit_ok = dogecoin_falcon512_commit_bytes(carrier_pk, carrier_pk_len, carrier_sig, carrier_sig_len, computed_commit);
                        else if (carrier_algo == DOGECOIN_PQC_ALGO_DILITHIUM)
                            commit_ok = dogecoin_dilithium2_commit_bytes(carrier_pk, carrier_pk_len, carrier_sig, carrier_sig_len, computed_commit);
#endif
#ifdef USE_RACCOON_G
                        if (carrier_algo == DOGECOIN_PQC_ALGO_RACCOONG)
                            commit_ok = dogecoin_raccoong44_commit_bytes(carrier_pk, carrier_pk_len, carrier_sig, carrier_sig_len, computed_commit);
#endif

                        if (commit_ok) {
                            char commit_hex[65];
                            utils_bin_to_hex(computed_commit, 32, commit_hex);
                            char pk_prefix_hex[33] = {0};
                            size_t pk_prefix_len = carrier_pk_len < 16 ? carrier_pk_len : 16;
                            utils_bin_to_hex((unsigned char*)carrier_pk, pk_prefix_len, pk_prefix_hex);
                            char sig_prefix_hex[33] = {0};
                            size_t sig_prefix_len = carrier_sig_len < 16 ? carrier_sig_len : 16;
                            utils_bin_to_hex((unsigned char*)carrier_sig, sig_prefix_len, sig_prefix_hex);

                            /* Cross-validate: O(1) hash table lookup for matching OP_RETURN commitment */
                            spv_pqc_pending_commit_t* matched_entry = spv_pqc_find_pending(client, computed_commit);
                            dogecoin_bool matched = (matched_entry != NULL && matched_entry->algo == carrier_algo);
                            uint32_t matched_txpos = 0;
                            uint8_t* matched_txc_raw = NULL;
                            size_t matched_txc_raw_len = 0;
                            if (matched) {
                                matched_txpos = matched_entry->txpos;
                                matched_txc_raw = matched_entry->txc_raw;
                                matched_txc_raw_len = matched_entry->txc_raw_len;
                                /* Remove from hash table but don't free txc_raw yet (used below) */
                                matched_entry->txc_raw = NULL;
                                {
                                    spv_pqc_pending_commit_t* head = spv_pqc_table(client);
                                    HASH_DEL(head, matched_entry);
                                    client->pqc_pending_commits = head;
                                }
                                dogecoin_free(matched_entry);
                            }

                            if (matched) {
                                client->nodegroup->log_write_cb("[%s] Valid at height=%d txpos=%u commit=%s carrier_vin=%zu source=carrier_scriptsig matched_txc_txpos=%u pk_len=%zu sig_len=%zu pk_prefix=%s sig_prefix=%s txr_txid=%s\n",
                                                                 algo_label, pindex->height, i, commit_hex, carrier_vin, matched_txpos, carrier_pk_len, carrier_sig_len, pk_prefix_hex, sig_prefix_hex, txr_txid_hex);

                                /* Phase 2: Verify PQC signature over TX_C sighash32 (via pqc_carrier module) */
                                if (matched_txc_raw && matched_txc_raw_len > 0) {
                                    uint8_t verify_sighash[32] = {0};
                                    dogecoin_bool sig_verified = dogecoin_pqc_carrier_verify_reveal(
                                        (dogecoin_pqc_algo_t)carrier_algo,
                                        matched_txc_raw, matched_txc_raw_len,
                                        carrier_pk, carrier_pk_len,
                                        carrier_sig, carrier_sig_len,
                                        verify_sighash);
                                    char sighash_hex[65];
                                    utils_bin_to_hex(verify_sighash, 32, sighash_hex);
                                    client->nodegroup->log_write_cb("[%s] PQC signature verification %s at height=%d txpos=%u sighash=%s\n",
                                        algo_label, sig_verified ? "PASSED" : "FAILED", pindex->height, i, sighash_hex);
                                    if (sig_verified) {
                                        client->nodegroup->log_write_cb("[%s] Reveal validated: TX_R=%s commit=%s pk_len=%zu sig_len=%zu height=%d\n",
                                            algo_label, txr_txid_hex, commit_hex, carrier_pk_len, carrier_sig_len, pindex->height);
                                    }
                                    dogecoin_free(matched_txc_raw);
                                }
                            } else {
                                client->nodegroup->log_write_cb("[%s] Unmatched at height=%d txpos=%u commit=%s carrier_vin=%zu source=carrier_scriptsig pk_len=%zu sig_len=%zu pk_prefix=%s sig_prefix=%s txr_txid=%s\n",
                                                                 algo_label, pindex->height, i, commit_hex, carrier_vin, carrier_pk_len, carrier_sig_len, pk_prefix_hex, sig_prefix_hex, txr_txid_hex);
                            }
                        } else {
                            client->nodegroup->log_write_cb("[%s] carrier found but commit_bytes failed at height=%d txpos=%u carrier_vin=%zu pk_len=%zu sig_len=%zu buf_len=%zu\n",
                                                             algo_label, pindex->height, i, carrier_vin, carrier_pk_len, carrier_sig_len, carrier_buf_len);
                        }
                        if (carrier_buf) dogecoin_free(carrier_buf);
                    }
                }
#endif
                
                total_tx_size += consumedlength;

                // accumulate outputs for this tx
                uint64_t tx_out_sum = 0;
                unsigned int oi;
                for (oi = 0; oi < tx->vout->len; oi++)
                {
                    dogecoin_tx_out *txout = vector_idx(tx->vout, oi);
                    tx_out_sum += txout->value;
                    block_outputs_value += txout->value;
                    block_outputs_count++;
                }
                if (i == 0 && dogecoin_tx_is_coinbase(tx)) {
                    coinbase_value = tx_out_sum; // coinbase tx is always the first tx in a block
                }
                dogecoin_tx_free(tx);
            }
            client->last_block_total_tx_size = total_tx_size;

            // update smpv tip
            if (client->smpv_enabled && client->smpv_ctx) {
                dogecoin_smpv_tip_update(
                    (dogecoin_smpv_client*)client->smpv_ctx,
                    (uint32_t)pindex->height
                );
            }

            // approximate fees (OK for recent blocks where subsidy is 10k0 DOGE)
            uint64_t block_fees = 0;
            if (coinbase_value > DOGECOIN_CURRENT_SUBSIDY_KOINU) {
                block_fees = coinbase_value - DOGECOIN_CURRENT_SUBSIDY_KOINU;
            }

            // session totals
            client->stats_blocks_total++;
            client->stats_txs_total += amount_of_txs;
            client->stats_outputs_total += block_outputs_count;
            client->stats_out_value_total += block_outputs_value;
            client->stats_fees_total += block_fees;
            client->stats_block_bytes_total += hdr->data_len;

            // ring insert (latest)
            spv_block_sample *smp = &client->stats_ring[client->stats_ring_head];
            smp->ts = pindex->header.timestamp;
            smp->txs = amount_of_txs;
            smp->outputs = block_outputs_count;
            smp->out_value = block_outputs_value;
            smp->size = hdr->data_len;
            smp->fees = block_fees;

            client->stats_ring_head = (client->stats_ring_head + 1) % SPV_STATS_RING;
            if (client->stats_ring_len < SPV_STATS_RING) {
                client->stats_ring_len++;
            }

            client->nodegroup->log_write_cb("done (took %lld secs)\n", (unsigned long long)(time(NULL) - start));
        }
        else
        {
            client->nodegroup->log_write_cb("Got invalid block (not in sequence) from node %d\n", node->nodeid);
            node->state &= ~NODE_BLOCKSYNC;
            node->nodegroup->node_connection_state_changed_cb(node);
            dogecoin_free(pindex);
            return;
        }

        if (dogecoin_hash_equal((uint8_t *)node->last_requested_inv, (uint8_t *)pindex->hash)) {
            // instead of querying whether the last connected header timestamp is greater than the oldest item of interest
            // we check if the height is greater than or equal to the node's bestknown height minus 5 minutes
            if (client->headers_db->getchaintip(client->headers_db_ctx)->height >= node->bestknownheight - 5) {
                // last requested block reached, consider stop syncing
                if (!client->called_sync_completed && client->sync_completed) {
                    // enable mempool requests if smpv is enabled
                    if (client->smpv_enabled) dogecoin_net_spv_request_mempool(client);
                    client->sync_completed(client);
                    client->called_sync_completed = true;
                }
            } else if (client->headers_db->getchaintip(client->headers_db_ctx)->height < node->bestknownheight - 1440) {
                node->time_last_request = time(NULL);
                dogecoin_net_spv_node_request_headers_or_blocks(node, true);
            }
        }
    }

    if (strcmp(hdr->command, DOGECOIN_MSG_HEADERS) == 0)
    {
        uint32_t amount_of_headers;
        if (!deser_varlen(&amount_of_headers, buf)) return;
        uint64_t now = time(NULL);
        client->nodegroup->log_write_cb("Got %d headers (took %d s) from node %d\n", amount_of_headers, now - client->last_headersrequest_time, node->nodeid);

        // flag off the request stall check
        client->last_headersrequest_time = 0;

        unsigned int connected_headers = 0;
        unsigned int i;
        for (i = 0; i < amount_of_headers; i++)
        {
            dogecoin_bool connected;
            dogecoin_blockindex *pindex = client->headers_db->connect_hdr(client->headers_db_ctx, buf, false, &connected);
            if (!pindex)
            {
                client->nodegroup->log_write_cb("Header deserialization failed (node %d)\n", node->nodeid);
            }
            if (!deser_skip(buf, 1)) {
                client->nodegroup->log_write_cb("Header deserialization (tx count skip) failed (node %d)\n", node->nodeid);
            }

            if (!connected)
            {
                client->nodegroup->log_write_cb("Got invalid headers (not in sequence) from node %d\n", node->nodeid);
                node->state &= ~NODE_HEADERSYNC;
                node->nodegroup->node_connection_state_changed_cb(node);
                dogecoin_free(pindex);
                break;
            } else {
                if (client->header_connected) { client->header_connected(client); }
                connected_headers++;
                if (pindex->height >= node->bestknownheight - 5) {
                    client->stateflags &= ~SPV_HEADER_SYNC_FLAG;
                    client->stateflags |= SPV_FULLBLOCK_SYNC_FLAG;
                    node->state &= ~NODE_HEADERSYNC;
                    node->state |= NODE_BLOCKSYNC;
                    client->nodegroup->log_write_cb("start loading block from node %d at height %d at time: %ld\n", node->nodeid, client->headers_db->getchaintip(client->headers_db_ctx)->height, client->headers_db->getchaintip(client->headers_db_ctx)->header.timestamp);
                    dogecoin_net_spv_node_request_headers_or_blocks(node, true);
                    break;
                }
            }
        }
        dogecoin_blockindex *chaintip = client->headers_db->getchaintip(client->headers_db_ctx);

        client->nodegroup->log_write_cb("Connected %d headers\n", connected_headers);
        client->nodegroup->log_write_cb("Chaintip at height %d\n", chaintip->height);

        if (client->header_message_processed && client->header_message_processed(client, node, chaintip) == false)
            return;

        if (amount_of_headers == MAX_HEADERS_RESULTS && ((node->state & NODE_BLOCKSYNC) != NODE_BLOCKSYNC))
        {
            time_t lasttime = chaintip->header.timestamp;
            client->nodegroup->log_write_cb("chain size: %d, last time %s", chaintip->height, ctime(&lasttime));
            dogecoin_net_spv_node_request_headers_or_blocks(node, false);
        }
    }

    if (strcmp(hdr->command, DOGECOIN_MSG_MERKLEBLOCK) == 0) {
        dogecoin_bool connected = false;
        if (client->bloom_filter_debug_dump && client->nodegroup && client->nodegroup->log_write_cb) {
            client->nodegroup->log_write_cb("%s", client->bloom_filter_debug_dump);
        }

        /* connect header first (advances buf past 80-byte header) */
        const unsigned char* merkleblock_start = (const unsigned char*)buf->p;
        dogecoin_blockindex *pindex = client->headers_db->connect_hdr(client->headers_db_ctx, buf, false, &connected);
        node->time_last_request = time(NULL);

        /* If not newly connected, the block may already be in the chain (historical rescan).
           Look it up to get the real blockindex with correct height. */
        dogecoin_bool is_historical = false;
        if (!connected && pindex) {
            dogecoin_headers_db* db = (dogecoin_headers_db*)client->headers_db_ctx;
            dogecoin_blockindex* found = dogecoin_headersdb_find(db, pindex->hash);
            dogecoin_bool recovered_historical_height = false;
            if (found) {
                dogecoin_free(pindex);
                pindex = found;
            } else if (client->filtered_history_last_end_height >= 0 && client->bloom_filter) {
                uint32_t historical_height = 0;
                if (spv_lookup_headersdb_height_by_hash(client, pindex->hash, &historical_height)) {
                    pindex->height = historical_height;
                    recovered_historical_height = true;
                }
            }
            /* During filtered-history rescans, allow processing even if the header is pruned from in-memory tree. */
            if (found || recovered_historical_height) {
                is_historical = true;
            }
        }

        if (!connected && !is_historical) {
            if (!pindex) {
                client->nodegroup->log_write_cb("Got invalid merkleblock (not in sequence) from node %d\n", node->nodeid);
            } else {
                client->nodegroup->log_write_cb("Got unknown merkleblock from node %d\n", node->nodeid);
            }
            node->state &= ~NODE_BLOCKSYNC;
            node->nodegroup->node_connection_state_changed_cb(node);
            if (pindex && !is_historical) dogecoin_free(pindex);
            return;
        }

        if (client->header_connected && connected) { client->header_connected(client); }

        /* reset prior match state */
        if (client->merkle_match_tree) {
            dogecoin_btree_tdestroy(client->merkle_match_tree, dogecoin_free);
            client->merkle_match_tree = NULL;
        }
        client->merkle_match_pending = 0;
        client->merkle_match_active = false;
        client->merkle_match_blockindex = NULL;

        /* header merkle root (from original 80-byte header at message start) */
        uint256_t header_merkle;
        memcpy(header_merkle, merkleblock_start + 36, 32);

        /* after connect_hdr, buf points at nTx (uint32) */
        uint32_t nTx = 0;
        if (!deser_u32(&nTx, buf)) {
            if (!is_historical) {
                if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                    dogecoin_free(pindex);
                }
            }
            client->nodegroup->log_write_cb("Merkleblock nTx deser failed (node %d)\n", node->nodeid);
            node->state &= ~NODE_BLOCKSYNC;
            node->nodegroup->node_connection_state_changed_cb(node);
            return;
        }

        uint32_t hashCount = 0;
        if (!deser_varlen(&hashCount, buf) || hashCount == 0) {
            if (!is_historical) {
                if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                    dogecoin_free(pindex);
                }
            }
            client->nodegroup->log_write_cb("Merkleblock hashCount deser failed/zero (node %d)\n", node->nodeid);
            node->state &= ~NODE_BLOCKSYNC;
            node->nodegroup->node_connection_state_changed_cb(node);
            return;
        }

        uint256_t* hashes = (uint256_t*)dogecoin_calloc(hashCount, sizeof(uint256_t));
        if (!hashes) {
            if (!is_historical) {
                if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                    dogecoin_free(pindex);
                }
            }
            node->state &= ~NODE_BLOCKSYNC;
            node->nodegroup->node_connection_state_changed_cb(node);
            return;
        }

        unsigned int i;
        for (i = 0; i < hashCount; i++) {
            if (!deser_u256(hashes[i], buf)) {
                dogecoin_free(hashes);
                if (!is_historical) {
                    if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                        dogecoin_free(pindex);
                    }
                }
                client->nodegroup->log_write_cb("Merkleblock hash deser failed (node %d)\n", node->nodeid);
                node->state &= ~NODE_BLOCKSYNC;
                node->nodegroup->node_connection_state_changed_cb(node);
                return;
            }
        }

        uint32_t flags_len = 0;
        if (!deser_varlen(&flags_len, buf) || flags_len == 0 || flags_len > buf->len) {
            dogecoin_free(hashes);
            if (!is_historical) {
                if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                    dogecoin_free(pindex);
                }
            }
            client->nodegroup->log_write_cb("Merkleblock flags deser failed/badlen (node %d)\n", node->nodeid);
            node->state &= ~NODE_BLOCKSYNC;
            node->nodegroup->node_connection_state_changed_cb(node);
            return;
        }

        uint8_t* flags = (uint8_t*)dogecoin_calloc(flags_len, 1);
        if (!flags) {
            dogecoin_free(hashes);
            if (!is_historical) {
                if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                    dogecoin_free(pindex);
                }
            }
            node->state &= ~NODE_BLOCKSYNC;
            node->nodegroup->node_connection_state_changed_cb(node);
            return;
        }
        memcpy(flags, buf->p, flags_len);
        if (!deser_skip(buf, flags_len)) {
            dogecoin_free(flags);
            dogecoin_free(hashes);
            if (!is_historical) {
                if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                    dogecoin_free(pindex);
                }
            }
            node->state &= ~NODE_BLOCKSYNC;
            node->nodegroup->node_connection_state_changed_cb(node);
            return;
        }

        if (!dogecoin_bip37_merkle_extract_match_tree(nTx,
                                                      (const uint8_t*)hashes,
                                                      hashCount,
                                                      flags,
                                                      flags_len,
                                                      header_merkle,
                                                      (const uint8_t*)pindex->hash,
                                                      (int)pindex->height,
                                                      client->bloom_filter_debug_dump,
                                                      &client->merkle_match_tree,
                                                      &client->merkle_match_pending,
                                                      client->nodegroup ? client->nodegroup->log_write_cb : NULL)) {
            if (client->merkle_match_tree) {
                dogecoin_btree_tdestroy(client->merkle_match_tree, dogecoin_free);
                client->merkle_match_tree = NULL;
            }
            client->merkle_match_pending = 0;
            client->merkle_match_active = false;
            client->merkle_match_blockindex = NULL;

            dogecoin_free(flags);
            dogecoin_free(hashes);

            if (!is_historical) {
                if (!client->headers_db->disconnect_tip(client->headers_db_ctx)) {
                    dogecoin_free(pindex);
                }
            }

            client->nodegroup->log_write_cb("Merkleblock verify failed (node %d)\n", node->nodeid);
            node->state &= ~NODE_BLOCKSYNC;
            node->nodegroup->node_connection_state_changed_cb(node);
            return;
        }

        client->merkle_match_active = (client->merkle_match_pending > 0);
        client->merkle_match_blockindex = pindex;

        if (client->merkle_match_pending > 0 && client->nodegroup && client->nodegroup->log_write_cb) {
            spv_merkle_log_ctx log_ctx;
            log_ctx.client = client;
            log_ctx.pindex = pindex;
            dogecoin_bip37_merkle_for_each_match(client->merkle_match_tree, spv_log_merkle_match, &log_ctx);
        }

        /* Update rescan progress counters. */
        client->rescan_total++;
        static const uint64_t early_rescan_log_threshold = 50;
        static const uint64_t periodic_rescan_log_interval = 1000;
        if (client->merkle_match_pending > 0) {
            client->rescan_matched++;
            /* Log individual blocks only when they have matches. */
            client->nodegroup->log_write_cb("[merkle] MATCH at height %d: nTx=%u matched=%u\n",
                pindex->height, nTx, client->merkle_match_pending);
        } else if (client->nodegroup->log_write_cb &&
                   client->filtered_history_last_end_height >= 0 &&
                   (client->rescan_total <= early_rescan_log_threshold ||
                    (client->rescan_total % periodic_rescan_log_interval) == 0)) {
            /* During historical scans, emit early + periodic parse logs so we can confirm merkleblocks are being processed. */
            client->nodegroup->log_write_cb("[merkle] parsed height %d: nTx=%u matched=0 (scanned=%llu)\n",
                pindex->height, nTx, (unsigned long long)client->rescan_total);
        }
        /* Log periodic progress every 10,000 blocks. */
        if (client->rescan_total % 10000 == 0) {
            client->nodegroup->log_write_cb("[merkle] progress: %llu blocks scanned, %llu with matches\n",
                (unsigned long long)client->rescan_total,
                (unsigned long long)client->rescan_matched);
        }

        /* Advance bounded historical scan windows only after the current
           requested end-height has actually been parsed. This avoids
           pre-queuing many future windows with a stale bloom filter state. */
        if (client->called_sync_completed &&
            client->headers_db &&
            client->bloom_filter && client->bloom_filter_len > 0 &&
            client->filtered_history_last_end_height >= 0 &&
            !client->merkle_match_active &&
            client->merkle_match_pending == 0 &&
            pindex &&
            (int32_t)pindex->height >= client->filtered_history_last_end_height) {
            dogecoin_blockindex* tip_now = client->headers_db->getchaintip(client->headers_db_ctx);
            if (tip_now && (uint32_t)client->filtered_history_last_end_height < tip_now->height) {
                client->filtered_history_tail_rerequest_count = 0;
                dogecoin_hash_clear(client->filtered_history_last_rerequest_txid);
                client->filtered_history_last_rerequest_height = -1;
                dogecoin_net_spv_request_filtered_history(client, 0);
            }
        }

        dogecoin_free(flags);
        dogecoin_free(hashes);

        if (dogecoin_hash_equal((uint8_t *)node->last_requested_inv, (uint8_t *)pindex->hash)) {
            if (client->headers_db->getchaintip(client->headers_db_ctx)->height >= node->bestknownheight - 5) {
                if (!client->called_sync_completed && client->sync_completed) {
                    if (client->smpv_enabled) dogecoin_net_spv_request_mempool(client);
                    client->sync_completed(client);
                    client->called_sync_completed = true;
                }
            } else if (client->headers_db->getchaintip(client->headers_db_ctx)->height < node->bestknownheight - 1440) {
                node->time_last_request = time(NULL);
                dogecoin_net_spv_node_request_headers_or_blocks(node, true);
            }
        }
    }

    if (strcmp(hdr->command, DOGECOIN_MSG_TX) == 0) {
        if (client && client->merkle_match_active && client->merkle_match_pending > 0 &&
            client->merkle_match_tree && client->sync_transaction) {
            size_t consumedlength = 0;
            dogecoin_tx* tx = dogecoin_tx_new();
            if (tx && dogecoin_tx_deserialize(buf->p, buf->len, tx, &consumedlength)) {
                uint256_t txid;
                dogecoin_tx_hash(tx, txid);

                char txid_hex[65];
                utils_bin_to_hex(txid, 32, txid_hex);
                client->nodegroup->log_write_cb("[merkle-tx] received tx %s (match_pending=%u)\n",
                    txid_hex, client->merkle_match_pending);

                uint32_t match_pos = 0;
                if (dogecoin_bip37_merkle_match_consume(&client->merkle_match_tree,
                                                        &client->merkle_match_pending,
                                                        txid,
                                                        &match_pos)) {
                    unsigned int pos = (unsigned int)match_pos;
                    dogecoin_blockindex* bi = client->merkle_match_blockindex;
                    uint32_t vout_i = 0;

                    if (client->bloom_filter && client->bloom_filter_len > 0) {
                        for (vout_i = 0; vout_i < (uint32_t)tx->vout->len; vout_i++) {
                            uint8_t outpoint[36];
                            unsigned int b = 0;
                            /* COutPoint serializes txid little-endian on the wire. */
                            for (b = 0; b < 32; b++) outpoint[b] = txid[31 - b];
                            outpoint[32] = (uint8_t)(vout_i & 0xffu);
                            outpoint[33] = (uint8_t)((vout_i >> 8) & 0xffu);
                            outpoint[34] = (uint8_t)((vout_i >> 16) & 0xffu);
                            outpoint[35] = (uint8_t)((vout_i >> 24) & 0xffu);
                            dogecoin_spv_client_filteradd(client, outpoint, (uint32_t)sizeof(outpoint));
                        }
                    }

                    client->nodegroup->log_write_cb("[merkle-tx] MATCH at pos %u, calling sync_transaction (height=%d)\n",
                        pos, bi ? (int)bi->height : -1);
                    client->sync_transaction(client->sync_transaction_ctx, tx, pos, bi);

                    if (client->filtered_history_tail_rerequest_count < 8 &&
                        client->filtered_history_last_end_height >= 0 &&
                        bi &&
                        (int32_t)bi->height < client->filtered_history_last_end_height) {
                        dogecoin_blockindex* tip_now = client->headers_db->getchaintip(client->headers_db_ctx);
                        if (tip_now) {
                            int64_t height_delta = (int64_t)tip_now->height - (int64_t)bi->height;
                            if (height_delta > 0) {
                                dogecoin_bool is_duplicate_tail_trigger =
                                    (client->filtered_history_last_rerequest_height >= 0) &&
                                    ((int32_t)bi->height == client->filtered_history_last_rerequest_height) &&
                                    (memcmp(client->filtered_history_last_rerequest_txid, txid, sizeof(uint256_t)) == 0);
                                if (is_duplicate_tail_trigger) {
                                    if (client->nodegroup && client->nodegroup->log_write_cb) {
                                        client->nodegroup->log_write_cb("[spv] skipping duplicate historical tail re-request for tx at height %d\n",
                                            (int)bi->height);
                                    }
                                } else {
                                int32_t previous_end = client->filtered_history_last_end_height;
                                int depth_to_tip = (height_delta > (int64_t)INT_MAX) ? INT_MAX : (int)height_delta;
                                client->filtered_history_tail_rerequest_count++;
                                dogecoin_hash_set(client->filtered_history_last_rerequest_txid, txid);
                                client->filtered_history_last_rerequest_height = (int32_t)bi->height;
                                client->filtered_history_last_end_height = (int32_t)bi->height;
                                if (client->nodegroup && client->nodegroup->log_write_cb) {
                                    client->nodegroup->log_write_cb("[spv] re-requesting historical tail heights %d-%d after new matched tx to catch spends (attempt %u/8)\n",
                                        (int)bi->height + 1, (int)previous_end,
                                        (unsigned int)client->filtered_history_tail_rerequest_count);
                                }
                                if (depth_to_tip > 0) {
                                    dogecoin_net_spv_request_filtered_history(client, depth_to_tip);
                                }
                                }
                            }
                        }
                    }

                    if (client->merkle_match_pending == 0) {
                        client->merkle_match_active = false;
                        client->merkle_match_blockindex = NULL;
                        if (client->merkle_match_tree) {
                            dogecoin_btree_tdestroy(client->merkle_match_tree, dogecoin_free);
                            client->merkle_match_tree = NULL;
                        }
                    }
                } else {
                    client->nodegroup->log_write_cb("[merkle-tx] tx NOT found in match tree\n");
                }
            }
            if (tx) dogecoin_tx_free(tx);
        }

        if (client && client->smpv_enabled && client->smpv_ctx) {
            // allocate hex buffer (2 chars per byte + NUL)
            size_t hex_len = ((size_t)hdr->data_len * 2) + 1;
            char* hex = (char*)dogecoin_calloc(1, hex_len);
            if (hex) {
                // convert raw bytes to hex using utils.c
                utils_bin_to_hex((unsigned char*)buf->p, (size_t)hdr->data_len, hex);

                dogecoin_bool ok = dogecoin_spv_handle_mempool_tx_hex(client, hex);

                if (client->nodegroup && client->nodegroup->log_write_cb) {
                    client->nodegroup->log_write_cb(
                        "[smpv] mempool tx seen len=%u dispatched=%s\n",
                        hdr->data_len, ok ? "true" : "false"
                    );
                }
                dogecoin_free(hex);
            } else {
                if (client->nodegroup && client->nodegroup->log_write_cb) {
                    client->nodegroup->log_write_cb(
                        "[smpv] hex alloc failed for len=%u\n",
                        hdr->data_len
                    );
                }
            }
        }
    }

    // Check for a 'Q' or 'q' on stdin, to quit.
#ifdef _WIN32
    if (_kbhit()) {
        char c = fgetc(stdin);
        if (c == 'Q' || c == 'q') {
            printf("Disconnecting...\n");
            dogecoin_node_group_shutdown(client->nodegroup);

        // exit the event loop immediately
        if (client->nodegroup && client->nodegroup->event_base)
            event_base_loopbreak(client->nodegroup->event_base);
        }
    }
#else
    char c = fgetc(stdin);
    if (c == 'Q' || c == 'q') {
        // Reset standard input back to blocking mode
        int stdin_flags = fcntl(STDIN_FILENO, F_GETFL);
        fcntl(STDIN_FILENO, F_SETFL, stdin_flags & ~O_NONBLOCK);

        printf("Disconnecting...\n");
        dogecoin_node_group_shutdown(client->nodegroup);

        // exit the event loop immediately
        if (client->nodegroup && client->nodegroup->event_base)
            event_base_loopbreak(client->nodegroup->event_base);
    }
#endif
}

static void smpv_tx_cb(const dogecoin_smpv_tx* tx, const char* addr, void* user)
{
    dogecoin_spv_client* client = (dogecoin_spv_client*)user;
    if (!client || !client->nodegroup || !client->nodegroup->log_write_cb || !tx) return;

    client->nodegroup->log_write_cb(
        "[smpv] tx=%s size=%lluB vin=%u vout=%u coinbase=%d "
        "outval=%llu koinu types{p2pk=%u,p2pkh=%u,p2sh=%u,multi=%u,opret=%u,nonstd=%u}%s%s\n",
        tx->txid ? tx->txid : "(null)",
        (unsigned long long)tx->size,
        tx->vin_count, tx->vout_count,
        tx->is_coinbase ? 1 : 0,
        (unsigned long long)tx->total_output_value,
        tx->pubkey_out, tx->p2pkh_out, tx->p2sh_out,
        tx->multisig_out, tx->opreturn_out, tx->nonstandard_out,
        addr ? " addr=" : "", addr ? addr : ""
    );
}

LIBDOGECOIN_API void dogecoin_spv_enable_smpv(dogecoin_spv_client* client, dogecoin_bool enable)
{
    if (!client) return;

    if (enable && !client->smpv_enabled) {
        client->smpv_ctx = dogecoin_smpv_client_new(client->chainparams);
        if (client->smpv_ctx && dogecoin_smpv_start((dogecoin_smpv_client*)client->smpv_ctx)) {
            client->smpv_enabled = true;
            if (client->nodegroup && client->nodegroup->log_write_cb)
                client->nodegroup->log_write_cb("[smpv] enabled\n");
        } else {
            if (client->nodegroup && client->nodegroup->log_write_cb)
                client->nodegroup->log_write_cb("[smpv] failed to enable (alloc/start)\n");
            if (client->smpv_ctx) {
                dogecoin_smpv_client_free((dogecoin_smpv_client*)client->smpv_ctx);
                client->smpv_ctx = NULL;
            }
        }
        return;
    }

    if (!enable && client->smpv_enabled) {
        if (client->nodegroup && client->nodegroup->log_write_cb)
            client->nodegroup->log_write_cb("[smpv] disabling\n");
        dogecoin_smpv_stop((dogecoin_smpv_client*)client->smpv_ctx);
        dogecoin_smpv_client_free((dogecoin_smpv_client*)client->smpv_ctx);
        client->smpv_ctx = NULL;
        client->smpv_enabled = false;
    }
}

LIBDOGECOIN_API dogecoin_bool dogecoin_spv_handle_mempool_tx_hex(dogecoin_spv_client* client, const char* raw_tx_hex)
{
    if (!client || !client->smpv_enabled || !client->smpv_ctx || !raw_tx_hex) return false;
    return dogecoin_smpv_process_tx(
        (dogecoin_smpv_client*)client->smpv_ctx,
        raw_tx_hex,
        smpv_tx_cb,
        client
    );
}

LIBDOGECOIN_API void dogecoin_spv_get_smpv_stats(dogecoin_spv_client* client, uint32_t* total_txs, uint32_t* watched_addrs)
{
    if (total_txs) *total_txs = 0;
    if (watched_addrs) *watched_addrs = 0;
    if (!client || !client->smpv_enabled || !client->smpv_ctx) return;
    dogecoin_smpv_get_stats(
        (dogecoin_smpv_client*)client->smpv_ctx,
        total_txs, watched_addrs);
}

LIBDOGECOIN_API void dogecoin_net_spv_request_mempool(dogecoin_spv_client *client)
{
    if (!client || !client->nodegroup || !client->nodegroup->nodes) return;
    vector_t* nodes = client->nodegroup->nodes;
    for (unsigned int i = 0; i < (unsigned int)nodes->len; i++) {
        dogecoin_node* n = (dogecoin_node*)vector_idx(nodes, i);
        if (!n) continue;
        cstring* payload = cstr_new_sz(0);
        cstring* msg = dogecoin_p2p_message_new(
            n->nodegroup->chainparams->netmagic,
            DOGECOIN_MSG_MEMPOOL,
            payload->str,
            payload->len
        );
        cstr_free(payload, true);
        dogecoin_node_send(n, msg);
        cstr_free(msg, true);
    }
    if (client->nodegroup && client->nodegroup->log_write_cb)
        client->nodegroup->log_write_cb("[spv] sent 'mempool' to peers\n");
}

LIBDOGECOIN_API void dogecoin_net_spv_request_filtered_history(dogecoin_spv_client *client, int depth)
{
    /* BIP37-oriented historical scan: only request FILTERED_BLOCK when bloom is active. */
    if (!client || !client->nodegroup || !client->nodegroup->nodes) return;
    if (!client->bloom_filter || client->bloom_filter_len == 0) return;

    /* Walk backwards from the chain tip collecting block hashes. */
    dogecoin_blockindex *tip = client->headers_db->getchaintip(client->headers_db_ctx);
    if (!tip) return;

    int tip_height = (int)tip->height;
    int request_end_height = tip_height;
    int start_height = tip_height;
    dogecoin_blockindex* cur = tip;

    /* depth <= 0 means "scan all available blocks (to checkpoint/genesis)". */
    if (depth > 0) {
        start_height = tip_height - depth + 1;
        if (start_height < 0) start_height = 0;
    } else {
        dogecoin_headers_db* hdb = (dogecoin_headers_db*)client->headers_db_ctx;
        int file_start_height = -1;

        while (cur && cur->prev) cur = cur->prev;
        if (cur) start_height = (int)cur->height;

        if (hdb && hdb->headers_tree_file) {
            long old_pos = ftell(hdb->headers_tree_file);
            dogecoin_bool can_restore_pos = (old_pos >= 0);
            uint8_t rec[SPV_HEADERS_FILE_REC_LEN];
            if (fseek(hdb->headers_tree_file, SPV_HEADERS_FILE_HDR_LEN, SEEK_SET) == 0 &&
                fread(rec, sizeof(rec), 1, hdb->headers_tree_file) == 1) {
                struct const_buffer rec_buf = { rec, sizeof(rec) };
                uint256_t first_block_hash;
                uint32_t h = 0;
                uint256_t first_block_chainwork;
                deser_u256(first_block_hash, &rec_buf);
                deser_u32(&h, &rec_buf);
                deser_u256(first_block_chainwork, &rec_buf);
                file_start_height = (int)h;
            }
            if (can_restore_pos) fseek(hdb->headers_tree_file, old_pos, SEEK_SET);
        }
        if (file_start_height >= 0 && file_start_height < start_height) start_height = file_start_height;
        cur = tip;
    }

    /* Avoid re-requesting historical filtered blocks already requested in this process. */
    if (client->filtered_history_last_end_height >= start_height) {
        start_height = client->filtered_history_last_end_height + 1;
    }
    if (start_height > tip_height) return;

    int total = (tip_height - start_height) + 1;
    if (total == 0) return;

    /* Bound each historical request window so peers can realistically serve it. */
    {
        const int max_historical_request_blocks = 50000;
        if (total > max_historical_request_blocks) {
            request_end_height = start_height + max_historical_request_blocks - 1;
            total = max_historical_request_blocks;
        }
    }

    /* Find one connected bloom-capable peer and keep historical requests serialized on it.
       This avoids interleaved merkleblock streams that can constantly reset match state. */
    dogecoin_node* history_peer = NULL;
    unsigned int ni;
    for (ni = 0; ni < (unsigned int)client->nodegroup->nodes->len; ni++) {
        dogecoin_node* n = (dogecoin_node*)vector_idx(client->nodegroup->nodes, ni);
        if (!n || ((n->state & NODE_CONNECTED) != NODE_CONNECTED) ||
            ((n->state & NODE_MISSBEHAVED) == NODE_MISSBEHAVED) ||
            !n->version_handshake) continue;
        if ((n->services & DOGECOIN_NODE_BLOOM) != 0) {
            history_peer = n;
            break;
        }
    }
    if (!history_peer) {
        if (client->nodegroup->log_write_cb) {
            client->nodegroup->log_write_cb("[spv] skipped historical filtered request: no connected bloom-capable peer available\n");
        }
        return;
    }

    /* Ensure selected historical peer has our current bloom filter loaded. */
    spv_send_filterload_to_node(history_peer,
                                client->bloom_filter,
                                client->bloom_filter_len,
                                client->bloom_nhashfunc,
                                client->bloom_ntweak,
                                client->bloom_flags);

    /* Reset rescan progress counters. */
    client->rescan_total = 0;
    client->rescan_matched = 0;

    if (client->nodegroup->log_write_cb) {
        client->nodegroup->log_write_cb("[spv] scanning %d historical blocks for UTXO discovery (only matches will be logged)\n", total);
    }

    /* Persist requested historical end before dispatching getdata so
       follow-up tail re-requests can be scheduled immediately from
       early matched transactions. */
    client->filtered_history_last_end_height = request_end_height;

    /* Send getdata in batches to avoid huge allocations and messages.
       We walk backwards collecting a batch of hashes, reverse them (oldest first),
       then send and repeat. */
    int batch_max = 500;
    cur = tip;
    while (cur && (int)cur->height > request_end_height) cur = cur->prev;

    /* Collect block hashes oldest->newest for requested range. */
    uint8_t* block_hashes = (uint8_t*)dogecoin_calloc((size_t)total, 32);
    if (!block_hashes) return;

    dogecoin_bool collected = true;
    cur = tip;
    while (cur && (int)cur->height > request_end_height) cur = cur->prev;
    int idx = total - 1;
    while (cur && idx >= 0) {
        if ((int)cur->height < start_height) break;
        memcpy(block_hashes + ((size_t)idx * 32), cur->hash, 32);
        idx--;
        cur = cur->prev;
    }

    /* If in-memory chain is truncated, backfill range from headers file records. */
    if (idx >= 0) {
        dogecoin_headers_db* hdb = (dogecoin_headers_db*)client->headers_db_ctx;
        uint8_t* slot_filled = NULL;
        int found = 0;

        collected = false;
        if (hdb && hdb->headers_tree_file) {
            long old_pos = ftell(hdb->headers_tree_file);
            dogecoin_bool can_restore_pos = (old_pos >= 0);
            uint8_t rec[SPV_HEADERS_FILE_REC_LEN];
            slot_filled = (uint8_t*)dogecoin_calloc((size_t)total, 1);
            if (slot_filled && fseek(hdb->headers_tree_file, SPV_HEADERS_FILE_HDR_LEN, SEEK_SET) == 0) {
                while (fread(rec, sizeof(rec), 1, hdb->headers_tree_file) == 1) {
                    struct const_buffer rec_buf = { rec, sizeof(rec) };
                    uint256_t hash;
                    uint32_t h = 0;
                    uint256_t cw_unused;
                    int offset;
                    deser_u256(hash, &rec_buf);
                    deser_u32(&h, &rec_buf);
                    deser_u256(cw_unused, &rec_buf);
                    if ((int)h < start_height || (int)h > request_end_height) continue;
                    offset = (int)h - start_height;
                    if (!slot_filled[offset]) {
                        memcpy(block_hashes + ((size_t)offset * 32), hash, 32);
                        slot_filled[offset] = 1;
                        found++;
                        if (found == total) break;
                    }
                }
            }
            if (can_restore_pos) fseek(hdb->headers_tree_file, old_pos, SEEK_SET);
            if (found == total) collected = true;
        }
        if (slot_filled) dogecoin_free(slot_filled);
    }
    if (!collected) {
        if (client->nodegroup->log_write_cb) {
            client->nodegroup->log_write_cb("[spv] skipped historical filtered request due to incomplete local header range (start_height=%d, end=%d)\n",
                start_height, request_end_height);
        }
        dogecoin_free(block_hashes);
        return;
    }

    {
        int blocks_sent = 0;
        while (blocks_sent < total) {
            int batch = total - blocks_sent;
            if (batch > batch_max) batch = batch_max;

            /* Build getdata payload: varint(count) + count * (uint32 type + uint256 hash) */
            cstring* payload = cstr_new_sz(9 + (size_t)batch * 36);
            if (!payload) break;

            ser_varlen(payload, (uint32_t)batch);

            int bi;
            for (bi = 0; bi < batch; bi++) {
                uint32_t type = DOGECOIN_INV_TYPE_FILTERED_BLOCK;
                ser_u32(payload, type);
                ser_bytes(payload, block_hashes + ((size_t)(blocks_sent + bi) * 32), 32);
            }

            cstring *p2p_msg = dogecoin_p2p_message_new(
                history_peer->nodegroup->chainparams->netmagic,
                DOGECOIN_MSG_GETDATA,
                (const uint8_t*)payload->str, payload->len);
            dogecoin_node_send(history_peer, p2p_msg);
            cstr_free(p2p_msg, true);
            cstr_free(payload, true);

            blocks_sent += batch;
        }
    }

    if (client->nodegroup->log_write_cb) {
        client->nodegroup->log_write_cb("[spv] requested %d historical filtered blocks (heights %d-%d) via bloom peer %d\n",
            total, start_height, request_end_height, history_peer->nodeid);
    }

    dogecoin_free(block_hashes);
}

LIBDOGECOIN_API dogecoin_bool dogecoin_spv_client_filterload(
    dogecoin_spv_client* client,
    const uint8_t* filter,
    uint32_t filter_len,
    uint32_t nHashFuncs,
    uint32_t nTweak,
    uint8_t flags)
{
    if (!client || !filter || filter_len == 0) return false;

    if (client->bloom_filter) {
        dogecoin_free(client->bloom_filter);
        client->bloom_filter = NULL;
    }

    client->bloom_filter = (uint8_t*)dogecoin_calloc(filter_len, 1);
    if (!client->bloom_filter) return false;

    memcpy(client->bloom_filter, filter, filter_len);
    client->bloom_filter_len = filter_len;
    client->bloom_nhashfunc = nHashFuncs;
    client->bloom_ntweak = nTweak;
    client->bloom_flags = flags;

    if (!client->nodegroup || !client->nodegroup->nodes) return true;

    for (unsigned int i = 0; i < (unsigned int)client->nodegroup->nodes->len; i++) {
        dogecoin_node* n = (dogecoin_node*)vector_idx(client->nodegroup->nodes, i);
        if (!n) continue;
        if (((n->state & NODE_CONNECTED) != NODE_CONNECTED) || !n->version_handshake) continue;
        spv_send_filterload_to_node(n, filter, filter_len, nHashFuncs, nTweak, flags);
    }

    if (client->nodegroup && client->nodegroup->log_write_cb)
        client->nodegroup->log_write_cb("[spv] filterload set (len=%u)\n", filter_len);

    return true;
}

LIBDOGECOIN_API dogecoin_bool dogecoin_spv_client_filteradd(
    dogecoin_spv_client* client,
    const uint8_t* data,
    uint32_t data_len)
{
    if (!client || !data || data_len == 0) return false;
    if (client->bloom_filter && client->bloom_filter_len > 0) {
        dogecoin_bip37_filter local_filter;
        memset(&local_filter, 0, sizeof(local_filter));
        local_filter.data = client->bloom_filter;
        local_filter.data_len = client->bloom_filter_len;
        local_filter.n_hash_funcs = client->bloom_nhashfunc;
        local_filter.n_tweak = client->bloom_ntweak;
        local_filter.n_flags = client->bloom_flags;
        dogecoin_bip37_filter_add(&local_filter, data, data_len);
    }
    if (!client->nodegroup || !client->nodegroup->nodes) return true;

    cstring* payload = cstr_new_sz((size_t)data_len + SPV_VARINT_MAX_LEN);
    if (!payload) return false;

    ser_varlen(payload, data_len);
    ser_bytes(payload, data, data_len);

    for (unsigned int i = 0; i < (unsigned int)client->nodegroup->nodes->len; i++) {
        dogecoin_node* n = (dogecoin_node*)vector_idx(client->nodegroup->nodes, i);
        if (!n) continue;
        if (((n->state & NODE_CONNECTED) != NODE_CONNECTED) || !n->version_handshake) continue;

        cstring* msg = dogecoin_p2p_message_new(
            n->nodegroup->chainparams->netmagic,
            DOGECOIN_MSG_FILTERADD,
            (const uint8_t*)payload->str,
            payload->len
        );
        dogecoin_node_send(n, msg);
        cstr_free(msg, true);
    }

    cstr_free(payload, true);

    if (client->nodegroup && client->nodegroup->log_write_cb)
        client->nodegroup->log_write_cb("[spv] sent filteradd (len=%u)\n", data_len);

    return true;
}

LIBDOGECOIN_API dogecoin_bool dogecoin_spv_client_filterclear(dogecoin_spv_client* client)
{
    if (!client) return false;

    if (client->bloom_filter) {
        dogecoin_free(client->bloom_filter);
        client->bloom_filter = NULL;
    }
    client->bloom_filter_len = 0;
    client->bloom_nhashfunc = 0;
    client->bloom_ntweak = 0;
    client->bloom_flags = 0;

    if (!client->nodegroup || !client->nodegroup->nodes) return true;

    for (unsigned int i = 0; i < (unsigned int)client->nodegroup->nodes->len; i++) {
        dogecoin_node* n = (dogecoin_node*)vector_idx(client->nodegroup->nodes, i);
        if (!n) continue;
        if (((n->state & NODE_CONNECTED) != NODE_CONNECTED) || !n->version_handshake) continue;

        cstring* payload = cstr_new_sz(0);
        cstring* msg = dogecoin_p2p_message_new(
            n->nodegroup->chainparams->netmagic,
            DOGECOIN_MSG_FILTERCLEAR,
            payload->str,
            payload->len
        );
        cstr_free(payload, true);
        dogecoin_node_send(n, msg);
        cstr_free(msg, true);
    }

    if (client->nodegroup && client->nodegroup->log_write_cb)
        client->nodegroup->log_write_cb("[spv] sent filterclear\n");

    return true;
}
