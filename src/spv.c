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
#include <dogecoin/compact_filter.h>
#include <dogecoin/golomb.h>
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
#ifdef USE_ZK_CARRIER
#include <dogecoin/zk_carrier.h>
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

static uint32_t spv_elapsed(const dogecoin_spv_client *client) {
    return (uint32_t)((uint64_t)time(NULL) - client->start_ts);
}

/* ------------------------------------------------------------------ */
/* Assign the next getcfilters batch to a parallel worker node.        */
/* Returns true if a batch was assigned and getcfilters was sent.      */
/* ------------------------------------------------------------------ */
static dogecoin_bool spv_cf_par_assign(dogecoin_spv_client *client, dogecoin_node *node)
{
    dogecoin_compact_filter_state *cfstate = client->cfilter_state;
    uint32_t start = cfstate->par_next_height;
    uint32_t tip   = cfstate->cfheaders_tip_height;

    if (start > tip) return false;

    /* Find a free slot */
    int slot = -1;
    uint8_t pi;
    for (pi = 0; pi < cfstate->par_num_workers; pi++) {
        if (cfstate->par_bufs[pi].node_id == -1) { slot = (int)pi; break; }
    }
    if (slot < 0) return false;

    uint32_t end = start + MAX_GETCFILTERS_SIZE - 1;
    if (end > tip) end = tip;

    uint32_t count = end - start + 1;
    cf_par_buf *buf = &cfstate->par_bufs[slot];
    buf->node_id    = node->nodeid;
    buf->batch_start = start;
    buf->batch_end   = end;
    buf->received    = 0;
    buf->complete    = false;
    buf->records     = (cf_par_record *)dogecoin_calloc(count, sizeof(cf_par_record));
    if (!buf->records) { buf->node_id = -1; return false; }

    node->cf_batch_start = start;
    node->cf_batch_end   = end;
    node->cf_cur_height  = start;
    cfstate->par_next_height = end + 1;

    /* Resolve stop hash */
    uint256_t stop_hash;
    dogecoin_blockindex *tip_bi = client->headers_db->getchaintip(client->headers_db_ctx);
    if (tip_bi && end == (uint32_t)tip_bi->height) {
        memcpy(stop_hash, tip_bi->hash, 32);
    } else {
        dogecoin_headers_db *hdb = (dogecoin_headers_db *)client->headers_db_ctx;
        if (!dogecoin_headers_db_get_block_hash_at_height(hdb, end, stop_hash)) {
            dogecoin_bool aux_found = false;
            if (client->aux_hash_db && client->aux_hash_db_ctx) {
                dogecoin_headers_db *aux = (dogecoin_headers_db *)client->aux_hash_db_ctx;
                aux_found = dogecoin_headers_db_get_block_hash_at_height(aux, end, stop_hash);
            }
            if (!aux_found && tip_bi) memcpy(stop_hash, tip_bi->hash, 32);
        }
    }

    dogecoin_getcfilters_msg gcf_msg;
    gcf_msg.filter_type  = GCS_BASIC_FILTER_TYPE;
    gcf_msg.start_height = start;
    memcpy(gcf_msg.stop_hash, stop_hash, 32);

    cstring *payload = cstr_new_sz(64);
    dogecoin_p2p_msg_getcfilters_ser(&gcf_msg, payload);
    cstring *p2pmsg = dogecoin_p2p_message_new(
        node->nodegroup->chainparams->netmagic, DOGECOIN_MSG_GETCFILTERS,
        payload->str, payload->len);
    cstr_free(payload, true);
    dogecoin_node_send(node, p2pmsg);
    cstr_free(p2pmsg, true);

    if (client->nodegroup && client->nodegroup->log_write_cb)
        client->nodegroup->log_write_cb(
            "[bip157-par] node %d: getcfilters [%u..%u] [%us elapsed]\n",
            node->nodeid, start, end, spv_elapsed(client));
    return true;
}

/* ------------------------------------------------------------------ */
/* Flush contiguous complete batches to disk in height order.          */
/* ------------------------------------------------------------------ */
static void spv_cf_par_try_flush(dogecoin_spv_client *client)
{
    dogecoin_compact_filter_state *cfstate = client->cfilter_state;
    uint8_t n = cfstate->par_num_workers;
    dogecoin_bool flushed;

    do {
        flushed = false;
        uint8_t pi;
        for (pi = 0; pi < n; pi++) {
            cf_par_buf *buf = &cfstate->par_bufs[pi];
            if (buf->node_id == -1 || !buf->complete) continue;
            if (buf->batch_start != cfstate->par_flush_height) continue;

            /* Flush this batch sequentially */
            uint32_t count = buf->batch_end - buf->batch_start + 1;
            uint32_t ri;
            for (ri = 0; ri < count; ri++) {
                uint32_t h = buf->batch_start + ri;
                cf_par_record *rec = &buf->records[ri];
                if (rec->filter_data) {
                    if (client->cfilters_db)
                        dogecoin_cfilters_db_write(client->cfilters_db, h,
                                                   rec->block_hash, rec->filter_data);
                    cstr_free(rec->filter_data, true);
                    rec->filter_data = NULL;
                }
            }

            cfstate->filters_tip_height = buf->batch_end;
            cfstate->par_flush_height   = buf->batch_end + 1;

            if (client->nodegroup && client->nodegroup->log_write_cb)
                client->nodegroup->log_write_cb(
                    "[bip157-par] flushed [%u..%u], progress %u/%u [%us elapsed]\n",
                    buf->batch_start, buf->batch_end,
                    buf->batch_end, cfstate->cfheaders_tip_height,
                    spv_elapsed(client));

            dogecoin_free(buf->records);
            buf->records  = NULL;
            buf->node_id  = -1;
            buf->complete = false;
            flushed = true;
            break;
        }
    } while (flushed);

    if (cfstate->filters_tip_height >= cfstate->cfheaders_tip_height) {
        if (client->nodegroup && client->nodegroup->log_write_cb)
            client->nodegroup->log_write_cb(
                "[bip157] all filters processed: %u matched blocks [%us elapsed]\n",
                (unsigned int)cfstate->matched_block_hashes->len, spv_elapsed(client));
        cfstate->awaiting_response = false;
        client->stateflags &= ~SPV_CFILTER_SYNC_FLAG;
        if (!client->called_sync_completed && client->sync_completed) {
            if (client->smpv_enabled) dogecoin_net_spv_request_mempool(client);
            client->sync_completed(client);
            client->called_sync_completed = true;
        }
    }
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
static const unsigned int CF_RESPONSE_TIMEOUT = 30;
static const unsigned int BLOCK_GAP_TO_DEDUCT_TO_START_SCAN_FROM = 5;
static const unsigned int BLOCKS_DELTA_IN_S = 60;
static const unsigned int COMPLETED_WHEN_NUM_NODES_AT_SAME_HEIGHT = 2;

#if defined(USE_LIBOQS) || defined(USE_RACCOON_G)
/* Maximum number of pending PQC OP_RETURN commitments buffered per client
   for cross-TX carrier validation (TX_C has OP_RETURN, TX_R has scriptSig).
   Cap enforced via LRU eviction in spv_pqc_add_pending so a peer flooding
   cheap OP_RETURN commits cannot balloon SPV node memory. */
#define SPV_PQC_PENDING_MAX 16

/* Maximum serialized TX_C size (bytes) we will buffer per pending entry.
   Without this, a peer can submit a max-size P2P message (~4 MiB) and pin
   SPV_PQC_PENDING_MAX * DOGECOIN_MAX_P2P_MSG_SIZE of memory per client.
   Carrier TX_Cs are minimal OP_RETURN-bearing transactions and have no
   legitimate need to approach standardness limits; 100 KiB matches the
   classic standardness MAX_STANDARD_TX_WEIGHT/4 ceiling and bounds total
   buffered carrier memory at SPV_PQC_PENDING_MAX * 100 KiB = 1.6 MiB per
   client per algorithm family. */
#define SPV_PQC_PENDING_TXC_RAW_MAX (100u * 1024u)

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

/* Build & insert a pending PQC commit, enforcing both the count cap (via
   spv_pqc_add_pending's LRU eviction) and the per-entry TX_C raw size cap
   SPV_PQC_PENDING_TXC_RAW_MAX. Returns 1 on insert, 0 if the entry was
   refused (oversize tx_raw or alloc failure). Centralising this avoids
   the four near-identical alloc/copy/insert blocks at the call sites and
   ensures every future carrier algorithm picks up the same caps for free. */
static int spv_pqc_buffer_pending(dogecoin_spv_client* client,
                                  const uint8_t commit[32],
                                  dogecoin_pqc_algo_t algo,
                                  uint32_t txpos, uint32_t height,
                                  const uint8_t* tx_raw, size_t tx_raw_len,
                                  const char* log_tag) {
    if (!client || !commit || !tx_raw) return 0;
    if (tx_raw_len == 0 || tx_raw_len > SPV_PQC_PENDING_TXC_RAW_MAX) {
        if (client->nodegroup && client->nodegroup->log_write_cb) {
            client->nodegroup->log_write_cb(
                "[%s] Skip pending: TX_C size %zu exceeds cap %u\n",
                log_tag ? log_tag : "pqc-commit",
                (size_t)tx_raw_len, (unsigned)SPV_PQC_PENDING_TXC_RAW_MAX);
        }
        return 0;
    }
    spv_pqc_pending_commit_t* entry = dogecoin_calloc(1, sizeof(*entry));
    if (!entry) return 0;
    entry->txc_raw = dogecoin_malloc(tx_raw_len);
    if (!entry->txc_raw) { dogecoin_free(entry); return 0; }
    memcpy(entry->commit, commit, 32);
    entry->algo = algo;
    entry->txpos = txpos;
    entry->height = height;
    memcpy(entry->txc_raw, tx_raw, tx_raw_len);
    entry->txc_raw_len = tx_raw_len;
    spv_pqc_add_pending(client, entry);
    return 1;
}

/* Note: a removal helper used to live here but every call site needs
   special-case logic (the TX_R match path moves out `txc_raw` before
   freeing, the free-all path runs inside a HASH_ITER), so HASH_DEL is
   inlined at the call sites and the helper was removed to avoid dead
   code. */

#endif /* USE_LIBOQS || USE_RACCOON_G (pqc pending) */

#ifdef USE_ZK_CARRIER
/* Maximum number of pending ZK OP_RETURN commitments buffered per client
   for cross-TX carrier validation (TX_C has OP_RETURN, TX_R has scriptSig).
   Cap enforced via LRU eviction in spv_zk_add_pending so a peer flooding
   cheap OP_RETURN commits cannot balloon SPV node memory. Mirrors the
   PQC SPV_PQC_PENDING_MAX cap to keep both carriers' memory ceilings
   identical and to make the LRU semantics easy to audit. */
#define SPV_ZK_PENDING_MAX 16

/* Per-entry TX_C raw size cap (bytes). Mirrors SPV_PQC_PENDING_TXC_RAW_MAX
   so both carrier families share the same per-entry memory ceiling and
   the combined SPV per-client carrier memory is bounded at
   2 * SPV_*_PENDING_MAX * 100 KiB ≈ 3.2 MiB. */
#define SPV_ZK_PENDING_TXC_RAW_MAX (100u * 1024u)

/* Hash table of pending TX_C OP_RETURN commitments awaiting their TX_R
   reveal.  Mirrors the PQC per-client pending table (key: 32-byte commit)
   so the SPV validator can cross-validate ZK carriers in O(1) when the
   reveal arrives in a later block.  Kept separate from the PQC table to
   minimise blast radius — the two key spaces are independent and combining
   them would force every PQC enum case to also know about ZK modes. */
typedef struct spv_zk_pending_commit {
    uint8_t commit[32];                /* 32-byte commit hash - hash key */
    dogecoin_zk_mode_t mode;
    uint32_t txpos;
    uint32_t height;                   /* block height where TX_C was seen */
    uint8_t* txc_raw;                  /* serialized TX_C, kept for diagnostics */
    size_t txc_raw_len;
    UT_hash_handle hh;
} spv_zk_pending_commit_t;

/* Per-client pending-commit table accessor.  Stored as an opaque void* in
   dogecoin_spv_client so the header does not need to expose uthash types. */
static inline spv_zk_pending_commit_t* spv_zk_table(const dogecoin_spv_client* client) {
    return client ? (spv_zk_pending_commit_t*)client->zk_pending_commits : NULL;
}

static spv_zk_pending_commit_t* spv_zk_find_pending(dogecoin_spv_client* client, const uint8_t* commit) {
    spv_zk_pending_commit_t* head = spv_zk_table(client);
    spv_zk_pending_commit_t* found = NULL;
    if (!head || !commit) return NULL;
    HASH_FIND(hh, head, commit, 32, found);
    return found;
}

/* Add pending commit to this client's hash table.  De-duplicates by commit
   hash and enforces SPV_ZK_PENDING_MAX via LRU eviction of the oldest
   insertion (uthash's iteration order is insertion order — see the matching
   note on spv_pqc_add_pending above). */
static void spv_zk_add_pending(dogecoin_spv_client* client, spv_zk_pending_commit_t* entry) {
    if (!client || !entry) return;
    spv_zk_pending_commit_t* head = spv_zk_table(client);
    /* Replace existing entry with the same commit hash to avoid stale state. */
    spv_zk_pending_commit_t* existing = NULL;
    if (head) HASH_FIND(hh, head, entry->commit, 32, existing);
    if (existing) {
        HASH_DEL(head, existing);
        if (existing->txc_raw) dogecoin_free(existing->txc_raw);
        dogecoin_free(existing);
    }
    while (head && HASH_COUNT(head) >= SPV_ZK_PENDING_MAX) {
        spv_zk_pending_commit_t* oldest = head; /* head == oldest insertion */
        HASH_DEL(head, oldest);
        if (oldest->txc_raw) dogecoin_free(oldest->txc_raw);
        dogecoin_free(oldest);
    }
    HASH_ADD(hh, head, commit, 32, entry);
    client->zk_pending_commits = head;
}

static void spv_zk_remove_pending(dogecoin_spv_client* client, spv_zk_pending_commit_t* entry) {
    if (!client || !entry) return;
    spv_zk_pending_commit_t* head = spv_zk_table(client);
    HASH_DEL(head, entry);
    if (entry->txc_raw) dogecoin_free(entry->txc_raw);
    dogecoin_free(entry);
    client->zk_pending_commits = head;
}

/* Build & insert a pending ZK commit, enforcing both the count cap and
   SPV_ZK_PENDING_TXC_RAW_MAX. Mirrors spv_pqc_buffer_pending; see that
   helper for rationale. Returns 1 on insert, 0 if refused. */
static int spv_zk_buffer_pending(dogecoin_spv_client* client,
                                 const uint8_t commit[32],
                                 dogecoin_zk_mode_t mode,
                                 uint32_t txpos, uint32_t height,
                                 const uint8_t* tx_raw, size_t tx_raw_len) {
    if (!client || !commit || !tx_raw) return 0;
    if (tx_raw_len == 0 || tx_raw_len > SPV_ZK_PENDING_TXC_RAW_MAX) {
        if (client->nodegroup && client->nodegroup->log_write_cb) {
            client->nodegroup->log_write_cb(
                "[zk-commit] Skip pending: TX_C size %zu exceeds cap %u\n",
                (size_t)tx_raw_len, (unsigned)SPV_ZK_PENDING_TXC_RAW_MAX);
        }
        return 0;
    }
    spv_zk_pending_commit_t* entry = dogecoin_calloc(1, sizeof(*entry));
    if (!entry) return 0;
    entry->txc_raw = dogecoin_malloc(tx_raw_len);
    if (!entry->txc_raw) { dogecoin_free(entry); return 0; }
    memcpy(entry->commit, commit, 32);
    entry->mode = mode;
    entry->txpos = txpos;
    entry->height = height;
    memcpy(entry->txc_raw, tx_raw, tx_raw_len);
    entry->txc_raw_len = tx_raw_len;
    spv_zk_add_pending(client, entry);
    return 1;
}

#endif /* USE_ZK_CARRIER */

static dogecoin_bool dogecoin_net_spv_node_timer_callback(dogecoin_node *node, uint64_t *now);
void dogecoin_net_spv_post_cmd(dogecoin_node *node, dogecoin_p2p_msg_hdr *hdr, struct const_buffer *buf);
void dogecoin_net_spv_node_handshake_done(dogecoin_node *node);
void par_hdr_assign(dogecoin_spv_client *client, dogecoin_node *node);
void par_hdr_free(dogecoin_spv_client *client);
static void par_hdr_recv(dogecoin_spv_client *client, dogecoin_node *node,
                         struct const_buffer *buf, uint32_t count);

void dogecoin_node_connection_state_changed_cb(dogecoin_node *node) {
    if (node->nodegroup->should_connect_to_more_nodes_cb) {
        if (node->nodegroup->should_connect_to_more_nodes_cb(node)) {
            dogecoin_spv_client *client = (dogecoin_spv_client*)node->nodegroup->ctx;
            /* Use explicit peer IPs when provided; fall back to DNS seeds otherwise. */
            dogecoin_spv_client_discover_peers(client, client->peer_ips);
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

    // BIP157 compact filter sync (on by default; disable with --no_cfilters)
    client->compact_filters_enabled = true;
    client->cfilter_state = dogecoin_compact_filter_state_new();
    if (client->cfilter_state) {
        client->cfilter_state->enabled = true;
    }
    dogecoin_mem_zero(client->cf_prev_filter_header, sizeof(uint256_t));
    client->cf_computed_height = 0;
    client->cf_export_enabled = false;

    /* BIP157 persistent filter storage (opened in dogecoin_spv_client_load) */
    client->cfheaders_db = NULL;
    client->cfilters_db  = NULL;

    client->peer_ips = NULL;

    client->aux_hash_db_ctx = NULL;
    client->aux_hash_db = NULL;
    client->cf_start_height = 0;
    client->cf_num_workers = 0;

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

    /* Remember explicit peer IPs so reconnects reuse them instead of DNS seeds. */
    if (ips) {
        if (client->peer_ips) dogecoin_free(client->peer_ips);
        client->peer_ips = strdup(ips);
    }


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

    if (client->cfilter_state) {
        dogecoin_compact_filter_state_free(client->cfilter_state);
        client->cfilter_state = NULL;
    }
    client->compact_filters_enabled = false;

    if (client->cfheaders_db) {
        dogecoin_cfheaders_db_free(client->cfheaders_db);
        client->cfheaders_db = NULL;
    }
    if (client->cfilters_db) {
        dogecoin_cfilters_db_free(client->cfilters_db);
        client->cfilters_db = NULL;
    }

    if (client->peer_ips) {
        dogecoin_free(client->peer_ips);
        client->peer_ips = NULL;
    }

    if (client->aux_hash_db && client->aux_hash_db_ctx) {
        client->aux_hash_db->free(client->aux_hash_db_ctx);
        client->aux_hash_db_ctx = NULL;
        client->aux_hash_db = NULL;
    }

    par_hdr_free(client);

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

#ifdef USE_ZK_CARRIER
    /* Release any pending ZK carrier commits that were never matched by a TX_R.
       Only the table owned by this client is freed — other live clients keep
       their own per-client tables intact. */
    {
        spv_zk_pending_commit_t* head = spv_zk_table(client);
        spv_zk_pending_commit_t* entry;
        spv_zk_pending_commit_t* tmp;
        HASH_ITER(hh, head, entry, tmp) {
            HASH_DEL(head, entry);
            if (entry->txc_raw) dogecoin_free(entry->txc_raw);
            dogecoin_free(entry);
        }
        client->zk_pending_commits = NULL;
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

    // Do NOT reset client->last_headersrequest_time / node->time_last_request
    // before requesting headers here. These timestamps are the basis for the
    // response-timeout checks above; zeroing them on every periodic statecheck
    // made the "no response in time" detection fire immediately on the next
    // tick regardless of how much time had actually elapsed. They are updated
    // only when an actual request is sent (see dogecoin_net_spv_request_headers
    // and the getheaders/getdata send paths).
    if ((client->stateflags & SPV_HEADER_SYNC_FLAG) == SPV_HEADER_SYNC_FLAG)
    {
        dogecoin_net_spv_request_headers(client);
    }

    if ((client->stateflags & SPV_FULLBLOCK_SYNC_FLAG) == SPV_FULLBLOCK_SYNC_FLAG)
    {
        dogecoin_net_spv_request_headers(client);
    }

    /* BIP157: recover from stalled awaiting_response when a peer disconnected
     * mid-download without clearing the flag. */
    if (client->compact_filters_enabled && client->cfilter_state) {
        dogecoin_compact_filter_state *cfstate = client->cfilter_state;
        dogecoin_bool cf_incomplete =
            ((uint32_t)pindex->height > 0) &&
            (cfstate->cfheaders_tip_height < (uint32_t)pindex->height ||
             cfstate->filters_tip_height  < cfstate->cfheaders_tip_height);
        /* Only retry here when not already in a live parallel cfilter download. */
        dogecoin_bool par_active = (cfstate->par_num_workers > 0 &&
            cfstate->filters_tip_height < cfstate->cfheaders_tip_height);
        if (cf_incomplete && !par_active && cfstate->awaiting_response) {
            /* Fast-path: if no CF-capable peer is connected right now, the peer
             * we sent the request to has disconnected.  Clear awaiting_response
             * immediately so the postcmd trigger can fire as soon as any CF peer
             * reconnects — no need to wait the full CF_RESPONSE_TIMEOUT. */
            dogecoin_bool any_cf_connected = false;
            for (unsigned int ni = 0; ni < client->nodegroup->nodes->len; ni++) {
                dogecoin_node *n = (dogecoin_node *)vector_idx(client->nodegroup->nodes, ni);
                if ((n->state & NODE_CONNECTED) &&
                    (n->services & DOGECOIN_NODE_COMPACT_FILTERS)) {
                    any_cf_connected = true;
                    break;
                }
            }
            if (!any_cf_connected) {
                client->nodegroup->log_write_cb(
                    "[bip157] CF peer gone — clearing awaiting_response to retry on reconnect\n");
                cfstate->awaiting_response = false;
            } else if (cfstate->last_request_time > 0 &&
                       *now > cfstate->last_request_time + CF_RESPONSE_TIMEOUT) {
                /* Full timeout: CF peer is connected but not responding. */
                client->nodegroup->log_write_cb(
                    "[bip157] CF response timeout after %us — retrying\n",
                    (unsigned int)(*now - cfstate->last_request_time));
                cfstate->awaiting_response = false;
                dogecoin_node *cf_node = NULL;
                for (unsigned int ni = 0; ni < client->nodegroup->nodes->len; ni++) {
                    dogecoin_node *n = (dogecoin_node *)vector_idx(client->nodegroup->nodes, ni);
                    if ((n->state & NODE_CONNECTED) &&
                        (n->services & DOGECOIN_NODE_COMPACT_FILTERS)) {
                        cf_node = n;
                        break;
                    }
                }
                if (cf_node)
                    dogecoin_spv_request_cfcheckpt(client, cf_node);
            }
        }
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
    /* Parallel genesis headers in progress — don't interfere. */
    if (client->par_hdr && client->par_hdr->active) return true;

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

    dogecoin_spv_client *hsclient = (dogecoin_spv_client*)node->nodegroup->ctx;
    if (hsclient->par_hdr && hsclient->par_hdr->active)
        par_hdr_assign(hsclient, node);
    else
        dogecoin_net_spv_request_headers(hsclient);
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
                    spv_pqc_buffer_pending(client, falcon_commit_data,
                                           DOGECOIN_PQC_ALGO_FALCON,
                                           i, pindex->height,
                                           tx_raw, consumedlength,
                                           "falcon-commit");
                }
                /* Dilithium2: buffer for cross-TX carrier match (TX_C → pending, TX_R validates via multi-part carrier) */
                uint8_t dilithium_commit_data[32];
                if (dogecoin_tx_extract_dilithium2_commit(tx, dilithium_commit_data)) {
                    char dilithium_commit_hex[65];
                    utils_bin_to_hex(dilithium_commit_data, 32, dilithium_commit_hex);
                    client->nodegroup->log_write_cb("[dilithium-commit] Pending at height=%d txpos=%u commit=%s source=op_return\n",
                                                     pindex->height, i, dilithium_commit_hex);
                    spv_pqc_buffer_pending(client, dilithium_commit_data,
                                           DOGECOIN_PQC_ALGO_DILITHIUM,
                                           i, pindex->height,
                                           tx_raw, consumedlength,
                                           "dilithium-commit");
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
                    spv_pqc_buffer_pending(client, raccoong_commit_data,
                                           DOGECOIN_PQC_ALGO_RACCOONG,
                                           i, pindex->height,
                                           tx_raw, consumedlength,
                                           "raccoong-commit");
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

#ifdef USE_ZK_CARRIER
                /* --- ZK Phase 1: Detect TX_C OP_RETURN commitments --- */
                {
                    dogecoin_zk_mode_t zk_mode = DOGECOIN_ZK_MODE_GROTH16;
                    uint8_t zk_commit_data[32];
                    if (dogecoin_tx_extract_zk_commit(tx, &zk_mode, zk_commit_data)) {
                        char zk_commit_hex[65];
                        utils_bin_to_hex(zk_commit_data, 32, zk_commit_hex);
                        client->nodegroup->log_write_cb("[zk-commit] Pending at height=%d txpos=%u commit=%s mode=%u source=op_return\n",
                                                         pindex->height, i, zk_commit_hex, (unsigned)zk_mode);
                        spv_zk_buffer_pending(client, zk_commit_data, zk_mode,
                                              i, pindex->height,
                                              tx_raw, consumedlength);
                    }
                }

                /* --- ZK Phase 2: Detect TX_R carrier scriptSigs and validate --- */
                {
                    uint8_t* zk_payload = NULL;
                    size_t zk_payload_len = 0;
                    if (dogecoin_zk_extract_carrier_payload(tx, &zk_payload, &zk_payload_len) == DOGECOIN_ZK_OK
                        && zk_payload && zk_payload_len > 0) {
                        /* Compute TX_R (reveal) txid for logging (display byte order) */
                        uint256_t txr_hash;
                        dogecoin_tx_hash(tx, txr_hash);
                        uint8_t txr_hash_rev[32];
                        for (int rb = 0; rb < 32; rb++) txr_hash_rev[rb] = ((uint8_t*)txr_hash)[31 - rb];
                        char txr_txid_hex[65];
                        utils_bin_to_hex(txr_hash_rev, 32, txr_txid_hex);

                        uint8_t computed_commit[32];
                        if (dogecoin_zk_get_commitment_hash(zk_payload, zk_payload_len, computed_commit) == DOGECOIN_ZK_OK) {
                            char commit_hex[65];
                            utils_bin_to_hex(computed_commit, 32, commit_hex);

                            spv_zk_pending_commit_t* matched_entry = spv_zk_find_pending(client, computed_commit);
                            if (matched_entry) {
                                uint32_t matched_txpos = matched_entry->txpos;
                                dogecoin_zk_mode_t matched_mode = matched_entry->mode;
                                /* Mirror the PQC path above: stash txc_raw / txc_raw_len
                                 * locally, NULL them out on the entry so spv_zk_remove_pending
                                 * doesn't free the buffer we still need for the tx_binding
                                 * recompute below, then drop the hash-table entry. The
                                 * stashed buffer is freed at the end of this branch. */
                                uint8_t* matched_txc_raw     = matched_entry->txc_raw;
                                size_t   matched_txc_raw_len = matched_entry->txc_raw_len;
                                matched_entry->txc_raw = NULL;
                                matched_entry->txc_raw_len = 0;
                                spv_zk_remove_pending(client, matched_entry);
                                matched_entry = NULL; /* poison: do NOT dereference past this point. */

                                client->nodegroup->log_write_cb("[zk-commit] Valid at height=%d txpos=%u commit=%s mode=%u source=carrier_scriptsig matched_txc_txpos=%u payload_len=%zu txr_txid=%s\n",
                                                                 pindex->height, i, commit_hex, (unsigned)matched_mode, matched_txpos, zk_payload_len, txr_txid_hex);

                                /* Fully decode and log every ZKP1 field for log-level auditability.
                                   The reveal payload format is:
                                       magic(4) || mode(1) || reserved(1) || circuit_id(4 BE) ||
                                       public_len(2 BE) || public_inputs[public_len] ||
                                       proof_len(4 BE)  || proof[proof_len]
                                   Each field is dumped as hex (with an ASCII preview when the
                                   bytes are printable, e.g. snarkjs JSON proofs). */
                                /* tx_binding outcome:
                                 *   0 = not checked (decode failed, no cached TX_C, sighash
                                 *       recompute failed, or fewer than 3 public inputs —
                                 *       legacy / payload predates tx-base binding)
                                 *   1 = matched
                                 *  -1 = mismatch (proof was lifted from another funding tx and
                                 *       replayed under this commit)
                                 *
                                 * Threaded out of the decode block so the gating below the
                                 * verify_proof call can refuse to log "Reveal validated" on a
                                 * mismatch.  Without this, a replayed historic proof with the
                                 * right commit32 would still print Reveal validated whenever
                                 * the verifier returned DELEGATED — negating the BIP's only
                                 * replay-protection mechanism for the no-in-process-verifier
                                 * (mobile / spv-only) build configuration. */
                                int zk_binding_state = 0;
                                {
                                    dogecoin_zk_mode_t dec_mode = (dogecoin_zk_mode_t)0;
                                    uint32_t dec_circuit_id = 0;
                                    const uint8_t* dec_pub = NULL; size_t dec_pub_len = 0;
                                    const uint8_t* dec_proof = NULL; size_t dec_proof_len = 0;
                                    const uint8_t* dec_vk = NULL; size_t dec_vk_len = 0;
                                    if (dogecoin_zk_decode_payload(zk_payload, zk_payload_len,
                                                                   &dec_mode, &dec_circuit_id,
                                                                   &dec_pub, &dec_pub_len,
                                                                   &dec_proof, &dec_proof_len,
                                                                   &dec_vk, &dec_vk_len) == DOGECOIN_ZK_OK) {
                                        uint8_t reserved_byte = zk_payload[DOGECOIN_ZK_CARRIER_MAGIC_LEN + 1];
                                        const char* mode_label =
                                            (dec_mode == DOGECOIN_ZK_MODE_GROTH16) ? "groth16-bn254" :
                                            (dec_mode == DOGECOIN_ZK_MODE_PLONK) ? "plonk" :
                                            (dec_mode == DOGECOIN_ZK_MODE_STARK_S2) ? "stark-s2" : "unknown";
                                        client->nodegroup->log_write_cb(
                                            "[zk-commit] reveal_decoded: magic=\"ZKP1\" mode=%u(%s) version=0x%02x circuit_id=0x%08x public_len=%zu proof_len=%zu vk_len=%zu total_payload_len=%zu txr_txid=%s\n",
                                            (unsigned)dec_mode, mode_label, (unsigned)reserved_byte,
                                            (unsigned)dec_circuit_id, dec_pub_len, dec_proof_len,
                                            dec_vk_len, zk_payload_len, txr_txid_hex);

                                        /* Helper: dump up to N bytes as hex + ASCII preview onto the log. */
                                        #define ZK_LOG_DUMP_FIELD(label, ptr, len) do { \
                                            const uint8_t* _p = (const uint8_t*)(ptr); size_t _l = (size_t)(len); \
                                            size_t _hex_max = 256; /* full dump up to 256 bytes; head+tail beyond */ \
                                            if (_l == 0) { \
                                                client->nodegroup->log_write_cb("[zk-commit] reveal_decoded.%s: len=0 (empty)\n", (label)); \
                                            } else if (_l <= _hex_max) { \
                                                char* _hex = (char*)dogecoin_calloc(1, _l * 2 + 1); \
                                                char* _asc = (char*)dogecoin_calloc(1, _l + 1); \
                                                if (_hex && _asc) { \
                                                    utils_bin_to_hex((unsigned char*)_p, _l, _hex); \
                                                    int _printable = 1; \
                                                    for (size_t _ai = 0; _ai < _l; _ai++) { \
                                                        unsigned char _c = _p[_ai]; \
                                                        if (_c == '\n' || _c == '\t' || _c == '\r') _asc[_ai] = ' '; \
                                                        else if (_c >= 0x20 && _c < 0x7f) _asc[_ai] = (char)_c; \
                                                        else { _asc[_ai] = '.'; _printable = 0; } \
                                                    } \
                                                    if (_printable) { \
                                                        client->nodegroup->log_write_cb("[zk-commit] reveal_decoded.%s: len=%zu hex=%s ascii=\"%s\"\n", (label), _l, _hex, _asc); \
                                                    } else { \
                                                        client->nodegroup->log_write_cb("[zk-commit] reveal_decoded.%s: len=%zu hex=%s\n", (label), _l, _hex); \
                                                    } \
                                                } \
                                                dogecoin_free(_hex); dogecoin_free(_asc); \
                                            } else { \
                                                /* Long field: emit head+tail hex (64 bytes each) plus ASCII head. */ \
                                                size_t _head = 64, _tail = 64; \
                                                char _hh[129] = {0}; char _tt[129] = {0}; \
                                                utils_bin_to_hex((unsigned char*)_p, _head, _hh); \
                                                utils_bin_to_hex((unsigned char*)(_p + _l - _tail), _tail, _tt); \
                                                size_t _ascii_n = _l < 96 ? _l : 96; \
                                                char _asc[97] = {0}; int _printable = 1; \
                                                for (size_t _ai = 0; _ai < _ascii_n; _ai++) { \
                                                    unsigned char _c = _p[_ai]; \
                                                    if (_c == '\n' || _c == '\t' || _c == '\r') _asc[_ai] = ' '; \
                                                    else if (_c >= 0x20 && _c < 0x7f) _asc[_ai] = (char)_c; \
                                                    else { _asc[_ai] = '.'; _printable = 0; } \
                                                } \
                                                if (_printable) { \
                                                    client->nodegroup->log_write_cb("[zk-commit] reveal_decoded.%s: len=%zu hex_head=%s hex_tail=%s ascii_head=\"%s\"\n", (label), _l, _hh, _tt, _asc); \
                                                } else { \
                                                    client->nodegroup->log_write_cb("[zk-commit] reveal_decoded.%s: len=%zu hex_head=%s hex_tail=%s\n", (label), _l, _hh, _tt); \
                                                } \
                                            } \
                                        } while (0)

                                        ZK_LOG_DUMP_FIELD("public_inputs", dec_pub, dec_pub_len);
                                        ZK_LOG_DUMP_FIELD("proof", dec_proof, dec_proof_len);
                                        if (dec_vk_len > 0) {
                                            ZK_LOG_DUMP_FIELD("vk", dec_vk, dec_vk_len);
                                        }

                                        /* tx_binding replay-protection check.
                                         * Mirroring the PQC carrier model where the signature is
                                         * over a tx_base sighash, the ZK proof's third snarkjs
                                         * public input is the same tx_base sighash (zero-top-byte
                                         * 248-bit BN254 field element).  Recompute it from the
                                         * matched TX_C bytes the SPV node cached during phase-1
                                         * pending-commit detection, parse the third element of the
                                         * snarkjs public.json array out of `dec_pub`, and compare.
                                         * A mismatch means the proof was lifted from another
                                         * funding tx and replayed under this commit — we log it
                                         * loudly so the operator (and any external auditor) can
                                         * see the binding match independent of the snarkjs verify
                                         * step. */
                                        if (matched_txc_raw && matched_txc_raw_len > 0) {
                                            dogecoin_tx* txc = dogecoin_tx_new();
                                            size_t txc_consumed = 0;
                                            if (txc && dogecoin_tx_deserialize(matched_txc_raw, matched_txc_raw_len, txc, &txc_consumed)) {
                                                cstring* signer_spk = dogecoin_zk_extract_signer_p2pkh_spk(txc);
                                                cstring* carrier_spk = NULL;
                                                /* Re-derive the canonical 23-byte P2SH carrier spk for
                                                 * the matched payload.  The carrier scriptPubKey is
                                                 * payload-independent — it only depends on the fixed
                                                 * carrier redeem script — so build it directly via the
                                                 * PQC helpers instead of allocating a throwaway tx and
                                                 * appending OP_RETURN + 0-value P2SH outputs to it. */
                                                cstring* carrier_redeem = NULL;
                                                if (dogecoin_pqc_carrier_build_redeemscript(&carrier_redeem) && carrier_redeem) {
                                                    if (!dogecoin_pqc_carrier_build_p2sh_scriptpubkey(carrier_redeem, &carrier_spk)) {
                                                        carrier_spk = NULL;
                                                    }
                                                    cstr_free(carrier_redeem, true);
                                                }
                                                if (signer_spk && carrier_spk) {
                                                    uint8_t recomputed[32];
                                                    if (dogecoin_zk_compute_tx_base_sighash(txc, signer_spk, carrier_spk, recomputed) == DOGECOIN_ZK_OK) {
                                                        char recomputed_hex[65] = {0};
                                                        utils_bin_to_hex(recomputed, 32, recomputed_hex);
                                                        /* Parse the snarkjs public-inputs array and pick out the
                                                         * 3rd quoted string (index 2) — the canonical tx_binding
                                                         * field element, see the BIP §"Phase 1: Base Transaction
                                                         * Binding".  Layout: ["...","...","<decimal>"]. */
                                                        uint8_t parsed[32] = {0};
                                                        size_t binding_token_count = 0;
                                                        dogecoin_zk_err_t bind_e = dogecoin_zk_parse_public_input_be32(
                                                            dec_pub, dec_pub_len, 2, parsed, &binding_token_count);
                                                        if (bind_e == DOGECOIN_ZK_OK) {
                                                            char parsed_hex[65] = {0};
                                                            utils_bin_to_hex(parsed, 32, parsed_hex);
                                                            int match = (memcmp(parsed, recomputed, 32) == 0);
                                                            zk_binding_state = match ? 1 : -1;
                                                            client->nodegroup->log_write_cb(
                                                                "[zk-commit] tx_binding %s txr_txid=%s recomputed=%s public_input[2]=%s\n",
                                                                match ? "match" : "mismatch",
                                                                txr_txid_hex, recomputed_hex, parsed_hex);
                                                        } else {
                                                            client->nodegroup->log_write_cb(
                                                                "[zk-commit] tx_binding skipped: expected >=3 public inputs (got %zu) — payload predates tx-base binding\n",
                                                                binding_token_count);
                                                        }
                                                    } else {
                                                        client->nodegroup->log_write_cb(
                                                            "[zk-commit] tx_binding skipped: tx_base sighash recompute failed for txr_txid=%s\n",
                                                            txr_txid_hex);
                                                    }
                                                } else {
                                                    client->nodegroup->log_write_cb(
                                                        "[zk-commit] tx_binding skipped: cannot extract signer/carrier spk from cached TX_C (txr_txid=%s)\n",
                                                        txr_txid_hex);
                                                }
                                                if (signer_spk) cstr_free(signer_spk, true);
                                                if (carrier_spk) cstr_free(carrier_spk, true);
                                            }
                                            if (txc) dogecoin_tx_free(txc);
                                        }

                                        #undef ZK_LOG_DUMP_FIELD
                                    } else {
                                        client->nodegroup->log_write_cb(
                                            "[zk-commit] reveal_decoded: decode_failed payload_len=%zu txr_txid=%s\n",
                                            zk_payload_len, txr_txid_hex);
                                    }
                                }

                                /* In-process proof verification uses only bytes carried by the
                                   reveal payload (v1 embedded vk). Without a compiled verifier
                                   this returns DOGECOIN_ZK_ERR_NOT_IMPLEMENTED / DELEGATED. */
                                dogecoin_zk_err_t verify_e = dogecoin_zk_verify_proof(
                                    zk_payload, zk_payload_len, NULL, 0);
                                const char* verify_status =
                                    (verify_e == DOGECOIN_ZK_OK) ? "PASSED" :
                                    (verify_e == DOGECOIN_ZK_ERR_VERIFY_FAIL) ? "FAILED" :
                                    (verify_e == DOGECOIN_ZK_ERR_NOT_IMPLEMENTED ||
                                     verify_e == DOGECOIN_ZK_ERR_DELEGATED) ? "DELEGATED" :
                                    "ERROR";
                                client->nodegroup->log_write_cb("[zk-commit] ZK verification %s at height=%d txpos=%u mode=%u err=%d\n",
                                    verify_status, pindex->height, i, (unsigned)matched_mode, (int)verify_e);

                                /* Reveal succeeds when the proof verified in-process, OR
                                   verification was delegated and the on-chain commit matched.
                                   When the binding check ran AND came back as a mismatch we
                                   refuse to log Reveal validated regardless of verify_e — a
                                   binding mismatch means the proof was lifted from another
                                   funding tx and replayed under this commit, which is the one
                                   thing this SPV-side check exists to catch.  When the binding
                                   check was skipped (legacy payload, decode failure, or the
                                   cached TX_C wasn't available) we fall back to the previous
                                   behaviour so v0 / pre-binding payloads still validate. */
                                if ((verify_e == DOGECOIN_ZK_OK ||
                                     verify_e == DOGECOIN_ZK_ERR_NOT_IMPLEMENTED ||
                                     verify_e == DOGECOIN_ZK_ERR_DELEGATED) &&
                                    zk_binding_state >= 0) {
                                    client->nodegroup->log_write_cb("[zk-commit] Reveal validated: TX_R=%s commit=%s payload_len=%zu mode=%u height=%d\n",
                                        txr_txid_hex, commit_hex, zk_payload_len, (unsigned)matched_mode, pindex->height);
                                } else if (zk_binding_state < 0) {
                                    client->nodegroup->log_write_cb("[zk-commit] Reveal REJECTED (tx_binding mismatch): TX_R=%s commit=%s payload_len=%zu mode=%u height=%d\n",
                                        txr_txid_hex, commit_hex, zk_payload_len, (unsigned)matched_mode, pindex->height);
                                }

                                /* Release the cached TX_C buffer we stashed before
                                 * spv_zk_remove_pending freed the hash-table entry. */
                                if (matched_txc_raw) dogecoin_free(matched_txc_raw);
                            } else {
                                client->nodegroup->log_write_cb("[zk-commit] Unmatched at height=%d txpos=%u commit=%s payload_len=%zu source=carrier_scriptsig txr_txid=%s\n",
                                                                 pindex->height, i, commit_hex, zk_payload_len, txr_txid_hex);
                            }
                        }
                        dogecoin_free(zk_payload);
                    }
                }
#endif /* USE_ZK_CARRIER */
                
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
        client->nodegroup->log_write_cb("Got %d headers (took %d s) from node %d [%us elapsed]\n", amount_of_headers, now - client->last_headersrequest_time, node->nodeid, spv_elapsed(client));

        /* Parallel genesis headers mode — buffer into the owning segment. */
        if (client->par_hdr && client->par_hdr->active) {
            par_hdr_recv(client, node, buf, amount_of_headers);
            return;
        }

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
        client->nodegroup->log_write_cb("Chaintip at height %d [%us elapsed]\n", chaintip->height, spv_elapsed(client));

        if (client->header_message_processed && client->header_message_processed(client, node, chaintip) == false)
            return;

        if (amount_of_headers == MAX_HEADERS_RESULTS && ((node->state & NODE_BLOCKSYNC) != NODE_BLOCKSYNC))
        {
            time_t lasttime = chaintip->header.timestamp;
            client->nodegroup->log_write_cb("chain size: %d, last time %s", chaintip->height, ctime(&lasttime));
            dogecoin_net_spv_node_request_headers_or_blocks(node, false);
        }
        else if (client->compact_filters_enabled && client->cfilter_state &&
                 !client->cfilter_state->awaiting_response &&
                 /* CF sync not yet complete: cfheaders or cfilters behind chain tip */
                 (client->cfilter_state->cfheaders_tip_height < (uint32_t)chaintip->height ||
                  client->cfilter_state->filters_tip_height  < client->cfilter_state->cfheaders_tip_height) &&
                 /* Not already in a live parallel cfilter download */
                 !(client->cfilter_state->par_num_workers > 0 &&
                   client->cfilter_state->filters_tip_height < client->cfilter_state->cfheaders_tip_height) &&
                 chaintip->height > 0 &&
                 chaintip->height >= node->bestknownheight - 5) {
            /* Headers are at tip — find a BIP157-capable peer (NODE_COMPACT_FILTERS) */
            dogecoin_node *cf_node = NULL;
            for (unsigned int ni = 0; ni < (unsigned int)client->nodegroup->nodes->len; ni++) {
                dogecoin_node *n = (dogecoin_node *)vector_idx(client->nodegroup->nodes, ni);
                if ((n->state & NODE_CONNECTED) && (n->services & DOGECOIN_NODE_COMPACT_FILTERS)) {
                    cf_node = n;
                    break;
                }
            }
            if (cf_node) {
                client->nodegroup->log_write_cb("[bip157] headers synced to tip (height=%d), sending getcfcheckpt to node %d (compact-filters peer)\n",
                                                chaintip->height, cf_node->nodeid);
                dogecoin_spv_request_cfcheckpt(client, cf_node);
            } else {
                client->nodegroup->log_write_cb("[bip157] headers at tip (height=%d) but no NODE_COMPACT_FILTERS peer connected\n",
                                                chaintip->height);
            }
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

    /* ================================================================ */
    /* BIP157: cfilter response handler                                 */
    /* ================================================================ */
    if (strcmp(hdr->command, DOGECOIN_MSG_CFILTER) == 0)
    {
        if (client->nodegroup && client->nodegroup->log_write_cb)
            client->nodegroup->log_write_cb("[bip157] received cfilter from node %d\n", node->nodeid);

        if (!client->compact_filters_enabled || !client->cfilter_state) {
            if (client->nodegroup && client->nodegroup->log_write_cb)
                client->nodegroup->log_write_cb("[bip157] compact filters not enabled, ignoring cfilter\n");
        } else {
            dogecoin_cfilter_msg cfilter_msg;
            dogecoin_cfilter_msg_init(&cfilter_msg);

            struct const_buffer deser_buf = { buf->p, buf->len };
            if (dogecoin_p2p_msg_cfilter_deser(&cfilter_msg, &deser_buf)) {
                dogecoin_compact_filter_state *cfstate = client->cfilter_state;

                if (client->nodegroup && client->nodegroup->log_write_cb)
                    client->nodegroup->log_write_cb("[bip157] cfilter type=%u data_len=%u\n",
                        cfilter_msg.filter_type,
                        (unsigned int)(cfilter_msg.filter_data ? cfilter_msg.filter_data->len : 0));

                if (cfilter_msg.filter_data) {
                    dogecoin_bool parallel = (cfstate->par_num_workers > 1);

                    /* Determine the height this cfilter corresponds to. */
                    uint32_t filter_height;
                    cf_par_buf *par_buf = NULL;

                    if (parallel) {
                        /* Per-node height tracking: validate node has an active batch */
                        if (node->cf_batch_end == 0 ||
                            node->cf_cur_height > node->cf_batch_end) {
                            /* Stale or unassigned — drop */
                            goto cfilter_handler_done;
                        }
                        filter_height = node->cf_cur_height;
                        node->cf_cur_height++;

                        /* Find the buffer for this node */
                        uint8_t pi;
                        for (pi = 0; pi < cfstate->par_num_workers; pi++) {
                            if (cfstate->par_bufs[pi].node_id == node->nodeid) {
                                par_buf = &cfstate->par_bufs[pi];
                                break;
                            }
                        }
                        if (!par_buf) goto cfilter_handler_done;
                    } else {
                        if (cfstate->filters_tip_height >= cfstate->cfheaders_tip_height)
                            goto cfilter_handler_done;
                        filter_height = cfstate->filters_tip_height + 1;
                    }

                    /*
                     * filter_headers[i] = filter header for block at height (cfheaders_base_height + i).
                     * For block at height h:
                     *   vec_idx     = h - cfheaders_base_height
                     *   expected_fh = filter_headers[vec_idx]
                     *   prev_fh     = filter_headers[vec_idx - 1]  (or genesis_filter_header when vec_idx == 0)
                     */
                    uint256_t prev_fh;
                    uint32_t base = cfstate->cfheaders_base_height;
                    if (filter_height <= base || cfstate->filter_headers->len == 0) {
                        memcpy(prev_fh, cfstate->genesis_filter_header, 32);
                    } else {
                        uint32_t prev_idx = filter_height - base - 1;
                        if (prev_idx < cfstate->filter_headers->len) {
                            memcpy(prev_fh, vector_idx(cfstate->filter_headers, prev_idx), 32);
                        } else {
                            memcpy(prev_fh, cfstate->cfheaders_tip_hash, 32);
                        }
                    }

                    uint32_t vec_idx = (filter_height >= base) ? filter_height - base : UINT32_MAX;
                    if (vec_idx < cfstate->filter_headers->len) {
                        uint256_t *expected_fh = (uint256_t *)vector_idx(cfstate->filter_headers, vec_idx);

                        if (dogecoin_compact_filter_validate(cfilter_msg.filter_data, prev_fh, *expected_fh)) {
                            if (parallel) {
                                /* Buffer the validated record; disk flush happens in-order via spv_cf_par_try_flush */
                                uint32_t offset = filter_height - par_buf->batch_start;
                                cf_par_record *rec = &par_buf->records[offset];
                                rec->filter_data = cstr_new_buf(cfilter_msg.filter_data->str,
                                                                cfilter_msg.filter_data->len);
                                memcpy(rec->block_hash, cfilter_msg.block_hash, 32);

                                /* Match watched scripts now (before buffering loses the data reference) */
                                if (cfstate->watched_scripts && cfstate->watched_scripts->len > 0) {
                                    gcs_filter *gcs = gcs_filter_new();
                                    struct const_buffer fbuf = { cfilter_msg.filter_data->str,
                                                                  cfilter_msg.filter_data->len };
                                    if (gcs_filter_deserialize(gcs, cfilter_msg.filter_type,
                                                                cfilter_msg.block_hash, &fbuf)) {
                                        if (gcs_filter_match_any(gcs, cfstate->watched_scripts)) {
                                            if (client->nodegroup && client->nodegroup->log_write_cb)
                                                client->nodegroup->log_write_cb(
                                                    "[bip157] MATCH at height %u\n", filter_height);
                                            uint256_t *matched_hash = dogecoin_calloc(1, sizeof(uint256_t));
                                            memcpy(matched_hash, cfilter_msg.block_hash, sizeof(uint256_t));
                                            vector_add(cfstate->matched_block_hashes, matched_hash);
                                        }
                                    }
                                    gcs_filter_free(gcs);
                                }

                                par_buf->received++;
                                if (par_buf->received == par_buf->batch_end - par_buf->batch_start + 1) {
                                    par_buf->complete = true;
                                    spv_cf_par_try_flush(client);
                                    /* Get next batch for this worker (no-op if all work assigned) */
                                    spv_cf_par_assign(client, node);
                                }
                            } else {
                                /* Sequential mode: write immediately */
                                cfstate->filters_tip_height = filter_height;

                                if (client->cfilters_db)
                                    dogecoin_cfilters_db_write(client->cfilters_db,
                                                               filter_height,
                                                               cfilter_msg.block_hash,
                                                               cfilter_msg.filter_data);

                                /* Match watched scripts */
                                if (cfstate->watched_scripts && cfstate->watched_scripts->len > 0) {
                                    gcs_filter *gcs = gcs_filter_new();
                                    struct const_buffer fbuf = { cfilter_msg.filter_data->str,
                                                                  cfilter_msg.filter_data->len };
                                    if (gcs_filter_deserialize(gcs, cfilter_msg.filter_type,
                                                                cfilter_msg.block_hash, &fbuf)) {
                                        if (gcs_filter_match_any(gcs, cfstate->watched_scripts)) {
                                            if (client->nodegroup && client->nodegroup->log_write_cb)
                                                client->nodegroup->log_write_cb(
                                                    "[bip157] MATCH at height %u\n", filter_height);
                                            uint256_t *matched_hash = dogecoin_calloc(1, sizeof(uint256_t));
                                            memcpy(matched_hash, cfilter_msg.block_hash, sizeof(uint256_t));
                                            vector_add(cfstate->matched_block_hashes, matched_hash);
                                        }
                                    }
                                    gcs_filter_free(gcs);
                                }

                                /* Request next batch when current is consumed */
                                dogecoin_blockindex *cf_tip =
                                    client->headers_db->getchaintip(client->headers_db_ctx);
                                if (cfstate->filters_tip_height >= cfstate->cfheaders_tip_height) {
                                    if (client->nodegroup && client->nodegroup->log_write_cb)
                                        client->nodegroup->log_write_cb(
                                            "[bip157] all filters processed: %u matched blocks [%us elapsed]\n",
                                            (unsigned int)cfstate->matched_block_hashes->len,
                                            spv_elapsed(client));
                                    cfstate->awaiting_response = false;
                                    client->stateflags &= ~SPV_CFILTER_SYNC_FLAG;
                                    if (!client->called_sync_completed && client->sync_completed) {
                                        if (client->smpv_enabled) dogecoin_net_spv_request_mempool(client);
                                        client->sync_completed(client);
                                        client->called_sync_completed = true;
                                    }
                                } else if (cfstate->filters_tip_height >= cfstate->cfilter_batch_end) {
                                    cfstate->awaiting_response = false;
                                    dogecoin_spv_request_cfilters(client, node,
                                        cfstate->filters_tip_height + 1, cf_tip->hash);
                                }
                            }
                        } else {
                            if (client->nodegroup && client->nodegroup->log_write_cb)
                                client->nodegroup->log_write_cb(
                                    "[bip157] filter at height %u FAILED validation\n", filter_height);
                            dogecoin_node_misbehave(node);
                        }
                    }
                }
                cfilter_handler_done:;
            } else {
                if (client->nodegroup && client->nodegroup->log_write_cb)
                    client->nodegroup->log_write_cb("[bip157] failed to deserialize cfilter from node %d\n", node->nodeid);
            }
            dogecoin_cfilter_msg_free(&cfilter_msg);
        }
    }

    /* ================================================================ */
    /* BIP157: cfheaders response handler                               */
    /* ================================================================ */
    if (strcmp(hdr->command, DOGECOIN_MSG_CFHEADERS) == 0)
    {
        if (client->nodegroup && client->nodegroup->log_write_cb)
            client->nodegroup->log_write_cb("[bip157] received cfheaders from node %d\n", node->nodeid);

        if (!client->compact_filters_enabled || !client->cfilter_state) {
            if (client->nodegroup && client->nodegroup->log_write_cb)
                client->nodegroup->log_write_cb("[bip157] compact filters not enabled, ignoring cfheaders\n");
        } else {
            dogecoin_cfheaders_msg cfh_msg;
            dogecoin_cfheaders_msg_init(&cfh_msg);

            struct const_buffer deser_buf = { buf->p, buf->len };
            if (dogecoin_p2p_msg_cfheaders_deser(&cfh_msg, &deser_buf)) {
                dogecoin_compact_filter_state *cfstate = client->cfilter_state;

                if (client->nodegroup && client->nodegroup->log_write_cb)
                    client->nodegroup->log_write_cb("[bip157] cfheaders: type=%u n_hashes=%u\n",
                        cfh_msg.filter_type, (unsigned int)cfh_msg.filter_hashes->len);

                uint256_t prev_header;
                memcpy(prev_header, cfh_msg.prev_filter_header, 32);
                uint32_t height = cfstate->cfheaders_tip_height;

                /* On the first cfheaders batch, prev_filter_header is the filter header
                 * immediately before our starting height — store it for cfilter validation
                 * and persist it so restarts don't need to re-download cfheaders. */
                if (cfstate->filter_headers->len == 0) {
                    memcpy(cfstate->genesis_filter_header, cfh_msg.prev_filter_header, 32);
                    if (client->cfheaders_db)
                        dogecoin_cfheaders_db_write_genesis(client->cfheaders_db,
                                                           cfh_msg.prev_filter_header);
                }

                unsigned int i;
                dogecoin_bool valid = true;

                for (i = 0; i < cfh_msg.filter_hashes->len; i++) {
                    uint256_t *filter_hash = (uint256_t *)vector_idx(cfh_msg.filter_hashes, i);
                    height++;

                    /* filter_header = dbl_sha256(filter_hash || prev_header) */
                    uint8_t combined[64];
                    memcpy(combined, filter_hash, 32);
                    memcpy(combined + 32, prev_header, 32);

                    uint256_t *new_header = dogecoin_calloc(1, sizeof(uint256_t));
                    dogecoin_hash(combined, 64, *new_header);

                    /* Validate against checkpoint if at a boundary.
                     * Dogecoin Core checkpoints are at heights 1000, 2000, ...
                     * cp_idx = height / CFCHECKPT_INTERVAL - 1: 1000→0, 2000→1, etc. */
                    if (cfstate->checkpoints && cfstate->checkpoints->len > 0 &&
                        height > 0 && (height % CFCHECKPT_INTERVAL) == 0) {
                        uint32_t cp_idx = (height / CFCHECKPT_INTERVAL) - 1;
                        if (cp_idx < cfstate->checkpoints->len) {
                            uint256_t *checkpoint = (uint256_t *)vector_idx(cfstate->checkpoints, cp_idx);
                            if (memcmp(*new_header, checkpoint, 32) != 0) {
                                if (client->nodegroup && client->nodegroup->log_write_cb)
                                    client->nodegroup->log_write_cb("[bip157] cfheader at height %u does NOT match checkpoint!\n", height);
                                valid = false;
                                dogecoin_free(new_header);
                                break;
                            }
                        }
                    }

                    vector_add(cfstate->filter_headers, new_header);
                    memcpy(prev_header, *new_header, 32);

                    if (client->cf_export_enabled &&
                        height > 0 && (height % CF_EXPORT_INTERVAL) == 0) {
                        char *hex = utils_uint8_to_hex(*new_header, 32);
                        printf("[cfcheckpt-export] { %u, \"%s\" },\n", height, hex);
                        fflush(stdout);
                    }
                }

                if (valid) {
                    cfstate->cfheaders_tip_height = height;
                    memcpy(cfstate->cfheaders_tip_hash, prev_header, 32);

                    dogecoin_blockindex *tip = client->headers_db->getchaintip(client->headers_db_ctx);
                    cfstate->awaiting_response = false;
                    if (height < (uint32_t)tip->height) {
                        dogecoin_spv_request_cfheaders(client, node, height + 1, tip->hash);
                    } else {
                        if (client->nodegroup && client->nodegroup->log_write_cb)
                            client->nodegroup->log_write_cb("[bip157] all cfheaders received, starting cfilter download\n");

                        dogecoin_headers_db *hdb_cf = (dogecoin_headers_db *)client->headers_db_ctx;
                        uint32_t cf_scan_start = 1;
                        if (hdb_cf && hdb_cf->chainbottom && hdb_cf->chainbottom->height > 0)
                            cf_scan_start = hdb_cf->chainbottom->height;

                        if (client->cf_num_workers > 1) {
                            /* Parallel mode: assign batches to all connected nodes */
                            cfstate->par_num_workers = client->cf_num_workers;
                            cfstate->par_next_height  = cf_scan_start;
                            cfstate->par_flush_height = cf_scan_start;
                            cfstate->filters_tip_height = (cf_scan_start > 1) ? cf_scan_start - 1 : 0;

                            if (!cfstate->par_bufs) {
                                cfstate->par_bufs = (cf_par_buf *)dogecoin_calloc(
                                    cfstate->par_num_workers, sizeof(cf_par_buf));
                                uint8_t pi;
                                for (pi = 0; pi < cfstate->par_num_workers; pi++)
                                    cfstate->par_bufs[pi].node_id = -1;
                            }

                            if (client->nodegroup && client->nodegroup->log_write_cb)
                                client->nodegroup->log_write_cb(
                                    "[bip157-par] assigning %u parallel workers from height %u\n",
                                    (unsigned int)cfstate->par_num_workers, cf_scan_start);

                            unsigned int ni;
                            for (ni = 0; ni < client->nodegroup->nodes->len; ni++) {
                                dogecoin_node *wn = (dogecoin_node *)vector_idx(client->nodegroup->nodes, ni);
                                if (!wn || !(wn->state & NODE_CONNECTED) || !wn->version_handshake)
                                    continue;
                                spv_cf_par_assign(client, wn);
                            }
                        } else {
                            /* Sequential mode: single node, existing path */
                            cfstate->filters_tip_height = (cf_scan_start > 1) ? cf_scan_start - 1 : 0;
                            dogecoin_spv_request_cfilters(client, node, cf_scan_start, tip->hash);
                        }
                    }
                } else {
                    dogecoin_node_misbehave(node);
                    cfstate->awaiting_response = false;
                }
            } else {
                if (client->nodegroup && client->nodegroup->log_write_cb)
                    client->nodegroup->log_write_cb("[bip157] failed to deserialize cfheaders\n");
            }
            dogecoin_cfheaders_msg_free(&cfh_msg);
        }
    }

    /* ================================================================ */
    /* BIP157: cfcheckpt response handler                               */
    /* ================================================================ */
    if (strcmp(hdr->command, DOGECOIN_MSG_CFCHECKPT) == 0)
    {
        if (client->nodegroup && client->nodegroup->log_write_cb)
            client->nodegroup->log_write_cb("[bip157] received cfcheckpt from node %d\n", node->nodeid);

        if (!client->compact_filters_enabled || !client->cfilter_state) {
            if (client->nodegroup && client->nodegroup->log_write_cb)
                client->nodegroup->log_write_cb("[bip157] compact filters not enabled, ignoring cfcheckpt\n");
        } else {
            dogecoin_cfcheckpt_msg cfcp_msg;
            dogecoin_cfcheckpt_msg_init(&cfcp_msg);

            struct const_buffer deser_buf = { buf->p, buf->len };
            if (dogecoin_p2p_msg_cfcheckpt_deser(&cfcp_msg, &deser_buf)) {
                dogecoin_compact_filter_state *cfstate = client->cfilter_state;

                if (client->nodegroup && client->nodegroup->log_write_cb)
                    client->nodegroup->log_write_cb("[bip157] cfcheckpt: type=%u n_checkpoints=%u\n",
                        cfcp_msg.filter_type, (unsigned int)cfcp_msg.filter_headers->len);

                if (cfstate->checkpoints) {
                    vector_free(cfstate->checkpoints, true);
                }
                cfstate->checkpoints = vector_new(cfcp_msg.filter_headers->len, dogecoin_free);

                unsigned int i;
                for (i = 0; i < cfcp_msg.filter_headers->len; i++) {
                    uint256_t *cp = dogecoin_calloc(1, sizeof(uint256_t));
                    memcpy(cp, vector_idx(cfcp_msg.filter_headers, i), 32);
                    vector_add(cfstate->checkpoints, cp);
                }

                if (!dogecoin_cf_validate_checkpoints(client->chainparams, cfstate->checkpoints)) {
                    if (client->nodegroup && client->nodegroup->log_write_cb)
                        client->nodegroup->log_write_cb("[bip157] cfcheckpt FAILED hardcoded validation — misbehaving node %d\n", node->nodeid);
                    dogecoin_node_misbehave(node);
                    dogecoin_cfcheckpt_msg_free(&cfcp_msg);
                    return;
                }

                /* Export checkpoint filter headers directly from cfcheckpt response.
                 * Checkpoints are at heights 999, 1999, 2999 ... (cp_idx * 1000 + 999). */
                /* Export filter headers directly from cfcheckpt response.
                 * Dogecoin Core checkpoints are at heights 1000, 2000, ...
                 * peer_checkpoints[i] = filter header at height (i+1)*CFCHECKPT_INTERVAL. */
                if (client->cf_export_enabled) {
                    printf("[cfcheckpt-export] /* Dogecoin Core cfcheckpt: %u entries */\n",
                           (unsigned int)cfcp_msg.filter_headers->len);
                    for (unsigned int ci = 0; ci < (unsigned int)cfcp_msg.filter_headers->len; ci++) {
                        uint32_t cp_height = (ci + 1) * CFCHECKPT_INTERVAL;
                        uint256_t *fh = (uint256_t *)vector_idx(cfcp_msg.filter_headers, ci);
                        /* P2P bytes are LE; chainparams.c uses big-endian display (same as RPC).
                         * Reverse the 32 bytes before hex-encoding. */
                        uint8_t reversed[32];
                        for (int ri = 0; ri < 32; ri++) reversed[ri] = (*fh)[31 - ri];
                        char *hex = utils_uint8_to_hex(reversed, 32);
                        printf("[cfcheckpt-export] { %u, \"%s\" },\n", cp_height, hex);
                        fflush(stdout);
                    }
                    printf("[cfcheckpt-export] /* end */\n");
                    fflush(stdout);
                }

                dogecoin_blockindex *tip = client->headers_db->getchaintip(client->headers_db_ctx);

                /* Determine where cfheaders download starts.
                 * cf_start_height overrides everything (set via --cf-from-genesis or API).
                 * Otherwise: start at chainbottom (checkpoint-based sync) unless an aux
                 * hash-lookup DB is available, in which case we can go back to genesis. */
                uint32_t cfh_start;
                if (client->cf_start_height > 0) {
                    cfh_start = client->cf_start_height;
                } else if (client->aux_hash_db && client->aux_hash_db_ctx) {
                    /* aux DB covers early heights — download filters from genesis. */
                    cfh_start = 1;
                } else {
                    dogecoin_headers_db *hdb = (dogecoin_headers_db *)client->headers_db_ctx;
                    cfh_start = (hdb && hdb->chainbottom && hdb->chainbottom->height > 0)
                                ? hdb->chainbottom->height : 1;
                }

                /* Use cfheaders already loaded from disk if they are valid and cover
                 * the needed range.  The v2 DB stores genesis_filter_header so we can
                 * validate cfilters without re-downloading all cfheaders. */
                uint8_t gfh_zeros[32];
                memset(gfh_zeros, 0, 32);
                dogecoin_bool genesis_valid =
                    (memcmp(cfstate->genesis_filter_header, gfh_zeros, 32) != 0);
                dogecoin_bool have_loaded =
                    (cfstate->filter_headers->len > 0 &&
                     cfstate->cfheaders_base_height > 0 &&
                     cfstate->cfheaders_base_height <= cfh_start &&
                     cfstate->cfheaders_tip_height >= (cfh_start > 0 ? cfh_start - 1 : 0));

                if (have_loaded && genesis_valid) {
                    uint32_t cfh_resume = cfstate->cfheaders_tip_height + 1;
                    if (cfh_resume > (uint32_t)tip->height) {
                        /* cfheaders already at chain tip: skip directly to cfilters */
                        if (client->nodegroup && client->nodegroup->log_write_cb)
                            client->nodegroup->log_write_cb(
                                "[bip157] cfheaders at tip (base=%u tip=%u), starting cfilters [%us elapsed]\n",
                                cfstate->cfheaders_base_height,
                                cfstate->cfheaders_tip_height, spv_elapsed(client));
                        dogecoin_headers_db *hdb_cf = (dogecoin_headers_db *)client->headers_db_ctx;
                        uint32_t cf_scan_start = 1;
                        if (hdb_cf && hdb_cf->chainbottom && hdb_cf->chainbottom->height > 0)
                            cf_scan_start = hdb_cf->chainbottom->height;
                        cfstate->awaiting_response = false;
                        if (client->cf_num_workers > 1) {
                            cfstate->par_num_workers   = client->cf_num_workers;
                            cfstate->par_next_height   = cf_scan_start;
                            cfstate->par_flush_height  = cf_scan_start;
                            cfstate->filters_tip_height = (cf_scan_start > 1) ? cf_scan_start - 1 : 0;
                            if (!cfstate->par_bufs) {
                                cfstate->par_bufs = (cf_par_buf *)dogecoin_calloc(
                                    cfstate->par_num_workers, sizeof(cf_par_buf));
                                uint8_t pi;
                                for (pi = 0; pi < cfstate->par_num_workers; pi++)
                                    cfstate->par_bufs[pi].node_id = -1;
                            }
                            if (client->nodegroup && client->nodegroup->log_write_cb)
                                client->nodegroup->log_write_cb(
                                    "[bip157-par] assigning %u parallel workers from height %u\n",
                                    (unsigned int)cfstate->par_num_workers, cf_scan_start);
                            unsigned int ni;
                            for (ni = 0; ni < client->nodegroup->nodes->len; ni++) {
                                dogecoin_node *wn = (dogecoin_node *)vector_idx(
                                    client->nodegroup->nodes, ni);
                                if (!wn || !(wn->state & NODE_CONNECTED) ||
                                    !wn->version_handshake)
                                    continue;
                                spv_cf_par_assign(client, wn);
                            }
                        } else {
                            cfstate->filters_tip_height = (cf_scan_start > 1) ? cf_scan_start - 1 : 0;
                            dogecoin_spv_request_cfilters(client, node, cf_scan_start, tip->hash);
                        }
                    } else {
                        /* Resume cfheaders download from where the DB left off */
                        if (client->nodegroup && client->nodegroup->log_write_cb)
                            client->nodegroup->log_write_cb(
                                "[bip157] resuming cfheaders from %u (base=%u disk_tip=%u) [%us elapsed]\n",
                                cfh_resume, cfstate->cfheaders_base_height,
                                cfstate->cfheaders_tip_height, spv_elapsed(client));
                        cfstate->awaiting_response = false;
                        dogecoin_spv_request_cfheaders(client, node, cfh_resume, tip->hash);
                    }
                } else {
                    /* Fresh start: clear any stale loaded data and re-download */
                    if (client->nodegroup && client->nodegroup->log_write_cb)
                        client->nodegroup->log_write_cb(
                            "[bip157] cfheaders fresh start at height %u [%us elapsed]\n",
                            cfh_start, spv_elapsed(client));
                    if (cfstate->filter_headers->len > 0) {
                        vector_free(cfstate->filter_headers, true);
                        cfstate->filter_headers = vector_new(4096, dogecoin_free);
                    }
                    dogecoin_mem_zero(cfstate->cfheaders_tip_hash, sizeof(uint256_t));
                    dogecoin_mem_zero(cfstate->genesis_filter_header, sizeof(uint256_t));
                    cfstate->cfheaders_tip_height  = (cfh_start > 1) ? cfh_start - 1 : 0;
                    cfstate->cfheaders_base_height = cfh_start;
                    if (client->cfheaders_db)
                        dogecoin_cfheaders_db_reset(client->cfheaders_db);
                    cfstate->awaiting_response = false;
                    dogecoin_spv_request_cfheaders(client, node, cfh_start, tip->hash);
                }
            } else {
                if (client->nodegroup && client->nodegroup->log_write_cb)
                    client->nodegroup->log_write_cb("[bip157] failed to deserialize cfcheckpt\n");
            }
            dogecoin_cfcheckpt_msg_free(&cfcp_msg);
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

/* ================================================================ */
/* BIP157: enable/disable compact filter sync                        */
/* ================================================================ */
LIBDOGECOIN_API void dogecoin_spv_enable_compact_filters(dogecoin_spv_client *client, dogecoin_bool enable)
{
    if (!client) return;

    if (enable && !client->compact_filters_enabled) {
        client->cfilter_state = dogecoin_compact_filter_state_new();
        if (client->cfilter_state) {
            client->cfilter_state->enabled = true;
            client->compact_filters_enabled = true;
            if (client->nodegroup && client->nodegroup->log_write_cb)
                client->nodegroup->log_write_cb("[bip157] compact filter sync enabled\n");
        }
        return;
    }

    if (!enable && client->compact_filters_enabled) {
        if (client->nodegroup && client->nodegroup->log_write_cb)
            client->nodegroup->log_write_cb("[bip157] compact filter sync disabled\n");
        if (client->cfilter_state) {
            dogecoin_compact_filter_state_free(client->cfilter_state);
            client->cfilter_state = NULL;
        }
        client->compact_filters_enabled = false;
    }
}

/* ================================================================ */
/* Parallel genesis header download                                  */
/* ================================================================ */

/* Build segments from the chainparams block-header checkpoint array.
 * Segment i covers the open-closed height range (prev_checkpoint, checkpoint[i]].
 * Segment 0 starts from the genesis block hash (height 0).
 * Returns a newly allocated par_hdr_state, or NULL for chains with no checkpoints. */
static par_hdr_state *par_hdr_init(const dogecoin_chainparams *params)
{
    const dogecoin_checkpoint *arr = NULL;
    size_t cnt = 0;
    if (strcmp(params->chainname, "main") == 0) {
        arr = dogecoin_mainnet_checkpoint_array;
        cnt = sizeof(dogecoin_mainnet_checkpoint_array) /
              sizeof(dogecoin_mainnet_checkpoint_array[0]);
    } else if (strcmp(params->chainname, "test") == 0) {
        arr = dogecoin_testnet_checkpoint_array;
        cnt = sizeof(dogecoin_testnet_checkpoint_array) /
              sizeof(dogecoin_testnet_checkpoint_array[0]);
    }
    if (!cnt) return NULL;

    par_hdr_state *s = dogecoin_calloc(1, sizeof(par_hdr_state));
    s->segs = dogecoin_calloc(cnt, sizeof(par_hdr_seg));
    s->num_segs = (uint32_t)cnt;
    s->active = true;

    for (uint32_t i = 0; i < (uint32_t)cnt; i++) {
        par_hdr_seg *seg = &s->segs[i];

        /* stop = checkpoint[i] */
        seg->stop_height = arr[i].height;
        utils_uint256_sethex((char *)arr[i].hash, seg->stop_hash);

        /* start = checkpoint[i-1] (or genesis for first segment) */
        if (i == 0) {
            seg->start_height = 0;
            memcpy(seg->start_hash, params->genesisblockhash, sizeof(uint256_t));
        } else {
            seg->start_height = arr[i - 1].height;
            utils_uint256_sethex((char *)arr[i - 1].hash, seg->start_hash);
        }

        seg->node_id    = -1;
        seg->tip_height = seg->start_height;
        memcpy(seg->tip_hash, seg->start_hash, sizeof(uint256_t));

        seg->cap = 2048;
        seg->buf = dogecoin_malloc((size_t)seg->cap * PAR_HDR_RAW_LEN);
    }
    return s;
}

/* Send a getheaders request to @node for the next batch in @seg. */
static void par_hdr_send_getheaders(dogecoin_node *node, const par_hdr_seg *seg)
{
    vector_t *locators = vector_new(1, free);
    uint256_t *loc = dogecoin_calloc(1, sizeof(uint256_t));
    memcpy(loc, seg->tip_hash, sizeof(uint256_t));
    vector_add(locators, loc);

    cstring *msg = cstr_new_sz(512);
    dogecoin_p2p_msg_getheaders(locators, (uint8_t *)seg->stop_hash, msg);
    vector_free(locators, true);

    cstring *p2p = dogecoin_p2p_message_new(
        node->nodegroup->chainparams->netmagic,
        DOGECOIN_MSG_GETHEADERS, msg->str, msg->len);
    cstr_free(msg, true);
    dogecoin_node_send(node, p2p);
    cstr_free(p2p, true);

    node->state |= NODE_HEADERSYNC;
}

/* Assign the next unassigned segment to @node and send the first getheaders. */
LIBDOGECOIN_API void par_hdr_assign(dogecoin_spv_client *client, dogecoin_node *node)
{
    par_hdr_state *s = client->par_hdr;
    if (!s || !s->active) return;
    if (!(node->state & NODE_CONNECTED) || !node->version_handshake) return;

    /* Skip nodes already working on a segment */
    for (uint32_t i = 0; i < s->num_segs; i++) {
        if (s->segs[i].node_id == (int)node->nodeid) return;
    }

    if (s->next_assign >= s->num_segs) return; /* all assigned */

    par_hdr_seg *seg = &s->segs[s->next_assign];
    seg->node_id = (int)node->nodeid;
    s->next_assign++;

    if (client->nodegroup && client->nodegroup->log_write_cb)
        client->nodegroup->log_write_cb(
            "[par-hdr] assigned node %d to segment %u (heights %u..%u)\n",
            node->nodeid, s->next_assign - 1,
            seg->start_height + 1, seg->stop_height);

    par_hdr_send_getheaders(node, seg);
}

/* Flush completed segments (in order) into the primary headers DB.
 * Returns the number of segments flushed. */
static uint32_t par_hdr_flush(dogecoin_spv_client *client)
{
    par_hdr_state *s = client->par_hdr;
    uint32_t flushed = 0;

    while (s->flush_idx < s->num_segs && s->segs[s->flush_idx].complete &&
           !s->segs[s->flush_idx].flushed) {
        par_hdr_seg *seg = &s->segs[s->flush_idx];

        if (client->nodegroup && client->nodegroup->log_write_cb)
            client->nodegroup->log_write_cb(
                "[par-hdr] flushing segment %u (%u headers, heights %u..%u)\n",
                s->flush_idx, seg->count,
                seg->start_height + 1, seg->stop_height);

        uint32_t bad = 0;
        for (uint32_t j = 0; j < seg->count; j++) {
            struct const_buffer cbuf = {
                (const void *)(seg->buf + (size_t)j * PAR_HDR_RAW_LEN),
                PAR_HDR_RAW_LEN
            };
            dogecoin_bool connected;
            dogecoin_blockindex *pindex =
                client->headers_db->connect_hdr(client->headers_db_ctx, &cbuf, false, &connected);
            if (!connected) {
                if (client->nodegroup && client->nodegroup->log_write_cb)
                    client->nodegroup->log_write_cb(
                        "[par-hdr] flush: header %u in segment %u failed to connect\n",
                        j, s->flush_idx);
                bad++;
            }
            if (pindex && client->header_connected)
                client->header_connected(client);
            dogecoin_free(pindex);
        }

        seg->flushed = true;
        s->flush_idx++;
        flushed++;

        if (bad) break; /* stop flushing if chain broke; caller handles */
    }
    return flushed;
}

/* Called from the DOGECOIN_MSG_HEADERS handler when par_hdr is active.
 * @buf points just past the varint that gave @count. */
static void par_hdr_recv(dogecoin_spv_client *client, dogecoin_node *node,
                         struct const_buffer *buf, uint32_t count)
{
    par_hdr_state *s = client->par_hdr;

    /* Find the segment assigned to this node */
    par_hdr_seg *seg = NULL;
    uint32_t seg_idx = 0;
    for (uint32_t i = 0; i < s->num_segs; i++) {
        if (s->segs[i].node_id == (int)node->nodeid && !s->segs[i].complete) {
            seg = &s->segs[i];
            seg_idx = i;
            break;
        }
    }
    if (!seg) {
        /* Unsolicited response — discard */
        node->state &= ~NODE_HEADERSYNC;
        return;
    }

    /* Buffer each raw 80-byte header */
    for (uint32_t i = 0; i < count; i++) {
        if (buf->len < PAR_HDR_RAW_LEN) break;

        /* Grow buffer if needed */
        if (seg->count >= seg->cap) {
            seg->cap *= 2;
            seg->buf  = dogecoin_realloc(seg->buf, (size_t)seg->cap * PAR_HDR_RAW_LEN);
        }

        memcpy(seg->buf + (size_t)seg->count * PAR_HDR_RAW_LEN, buf->p, PAR_HDR_RAW_LEN);
        seg->count++;

        /* Compute header hash to track tip */
        dogecoin_block_header hdr;
        struct const_buffer hbuf = { seg->buf + (size_t)(seg->count - 1) * PAR_HDR_RAW_LEN,
                                     PAR_HDR_RAW_LEN };
        if (dogecoin_block_header_deserialize(&hdr, &hbuf, client->chainparams, NULL)) {
            dogecoin_block_header_hash(&hdr, (uint8_t *)seg->tip_hash);
            seg->tip_height++;
        }

        buf->p   = (const uint8_t *)buf->p + PAR_HDR_RAW_LEN;
        buf->len -= PAR_HDR_RAW_LEN;
        /* skip tx_count varint (always 0x00 in headers messages) */
        if (buf->len > 0) { buf->p = (const uint8_t *)buf->p + 1; buf->len--; }
    }

    if (client->nodegroup && client->nodegroup->log_write_cb)
        client->nodegroup->log_write_cb(
            "[par-hdr] seg %u: buffered %u, tip_height=%u, stop=%u\n",
            seg_idx, seg->count, seg->tip_height, seg->stop_height);

    if (seg->tip_height >= seg->stop_height) {
        /* Segment complete */
        seg->complete = true;
        seg->node_id  = -1;
        node->state  &= ~NODE_HEADERSYNC;

        if (client->nodegroup && client->nodegroup->log_write_cb)
            client->nodegroup->log_write_cb(
                "[par-hdr] segment %u complete (%u headers)\n", seg_idx, seg->count);

        /* Try to flush as many ordered completed segments as possible */
        par_hdr_flush(client);

        /* Re-assign this node to the next segment */
        par_hdr_assign(client, node);

        /* Check if all segments are done */
        if (s->flush_idx >= s->num_segs) {
            s->active = false;
            dogecoin_blockindex *tip =
                client->headers_db->getchaintip(client->headers_db_ctx);
            if (client->nodegroup && client->nodegroup->log_write_cb)
                client->nodegroup->log_write_cb(
                    "[par-hdr] all segments complete — primary DB height %d\n",
                    tip ? tip->height : -1);
        }
    } else {
        /* More headers needed for this segment */
        par_hdr_send_getheaders(node, seg);
    }
}

/* Release all par_hdr memory. */
LIBDOGECOIN_API void par_hdr_free(dogecoin_spv_client *client)
{
    if (!client || !client->par_hdr) return;
    par_hdr_state *s = client->par_hdr;
    for (uint32_t i = 0; i < s->num_segs; i++)
        dogecoin_free(s->segs[i].buf);
    dogecoin_free(s->segs);
    dogecoin_free(s);
    client->par_hdr = NULL;
}

/* Initialise parallel genesis header download for @client.
 * Builds segments from the chainparams block checkpoint array.
 * Also sets cf_start_height = 1 (scan from genesis after sync) and resets
 * any existing CF databases so they will restart from genesis too.
 * Returns true on success, false if the chain has no checkpoints. */
LIBDOGECOIN_API dogecoin_bool dogecoin_spv_client_enable_genesis_headers(
    dogecoin_spv_client *client)
{
    if (!client || !client->chainparams) return false;
    par_hdr_free(client);
    client->par_hdr = par_hdr_init(client->chainparams);
    if (!client->par_hdr) return false;

    client->cf_start_height = 1;

    /* Reset CF databases — they must re-download from genesis once the primary
     * headers DB covers height 0, so any checkpoint-based records are stale. */
    if (client->cfheaders_db)
        dogecoin_cfheaders_db_reset(client->cfheaders_db);
    if (client->cfilters_db) {
        dogecoin_cfilters_db_free(client->cfilters_db);
        client->cfilters_db = dogecoin_cfilters_db_new(false);
        dogecoin_cfilters_db_load(client->cfilters_db, NULL);
    }
    if (client->cfilter_state) {
        vector_free(client->cfilter_state->filter_headers, true);
        client->cfilter_state->filter_headers = vector_new(8, dogecoin_free);
        memset(client->cfilter_state->genesis_filter_header, 0, 32);
        memset(client->cfilter_state->cfheaders_tip_hash, 0, 32);
        client->cfilter_state->cfheaders_tip_height  = 0;
        client->cfilter_state->cfheaders_base_height = 0;
        client->cfilter_state->filters_tip_height    = 0;
    }
    return true;
}

/* ================================================================ */
/* BIP157: request helper functions                                  */
/* ================================================================ */

/* Find the first block-header checkpoint at height >= target_height and write
 * its hash in P2P (internal LE) byte order to hash_out.
 * Returns the checkpoint height, or 0 if no suitable checkpoint exists. */
static uint32_t cf_find_checkpoint_stop(const dogecoin_chainparams *params,
    uint32_t target_height, uint256_t hash_out)
{
    const dogecoin_checkpoint *arr = NULL;
    size_t cnt = 0;
    if (!params) return 0;
    if (strcmp(params->chainname, "main") == 0) {
        arr = dogecoin_mainnet_checkpoint_array;
        cnt = sizeof(dogecoin_mainnet_checkpoint_array) / sizeof(dogecoin_mainnet_checkpoint_array[0]);
    } else if (strcmp(params->chainname, "test") == 0) {
        arr = dogecoin_testnet_checkpoint_array;
        cnt = sizeof(dogecoin_testnet_checkpoint_array) / sizeof(dogecoin_testnet_checkpoint_array[0]);
    }
    for (size_t i = 0; i < cnt; i++) {
        if (arr[i].height >= target_height) {
            /* chainparams hashes are display-order hex; utils_uint256_sethex reverses to LE */
            utils_uint256_sethex((char *)arr[i].hash, hash_out);
            return arr[i].height;
        }
    }
    return 0;
}

LIBDOGECOIN_API dogecoin_bool dogecoin_spv_request_cfcheckpt(dogecoin_spv_client *client, dogecoin_node *node)
{
    if (!client || !node || !client->cfilter_state) return false;

    dogecoin_blockindex *tip = client->headers_db->getchaintip(client->headers_db_ctx);
    if (!tip) return false;

    dogecoin_getcfcheckpt_msg msg;
    msg.filter_type = GCS_BASIC_FILTER_TYPE;
    memcpy(msg.stop_hash, tip->hash, sizeof(uint256_t));

    cstring *payload = cstr_new_sz(64);
    dogecoin_p2p_msg_getcfcheckpt_ser(&msg, payload);

    cstring *p2p_msg = dogecoin_p2p_message_new(
        node->nodegroup->chainparams->netmagic,
        DOGECOIN_MSG_GETCFCHECKPT,
        payload->str, payload->len);
    cstr_free(payload, true);
    dogecoin_node_send(node, p2p_msg);
    cstr_free(p2p_msg, true);

    client->cfilter_state->awaiting_response = true;
    client->cfilter_state->last_request_time = (uint64_t)time(NULL);

    if (client->nodegroup && client->nodegroup->log_write_cb)
        client->nodegroup->log_write_cb("[bip157] sent getcfcheckpt to node %d\n", node->nodeid);
    return true;
}

LIBDOGECOIN_API dogecoin_bool dogecoin_spv_request_cfheaders(dogecoin_spv_client *client, dogecoin_node *node, uint32_t start_height, const uint256_t stop_hash)
{
    if (!client || !node || !client->cfilter_state) return false;

    dogecoin_blockindex *tip = client->headers_db->getchaintip(client->headers_db_ctx);
    if (!tip) return false;

    uint32_t tip_height = (uint32_t)tip->height;

    /* BIP157: servers reject requests with stop_height - start_height >= MAX_GETCFHEADERS_SIZE.
     * Clamp the stop to one batch of MAX_GETCFHEADERS_SIZE filter headers. */
    uint32_t batch_stop_height = start_height + MAX_GETCFHEADERS_SIZE - 1;
    if (batch_stop_height >= tip_height)
        batch_stop_height = tip_height;

    uint256_t batch_stop_hash;
    if (batch_stop_height == tip_height) {
        /* Last (or only) batch ends exactly at the tip. */
        memcpy(batch_stop_hash, tip->hash, sizeof(uint256_t));
    } else {
        /* Find the block hash at batch_stop_height.
         * Try the in-memory prev chain first; fall back to a file scan. */
        dogecoin_headers_db *hdb = (dogecoin_headers_db *)client->headers_db_ctx;
        if (!dogecoin_headers_db_get_block_hash_at_height(hdb, batch_stop_height, batch_stop_hash)) {
            /* Primary DB miss — try aux hash-lookup DB (genesis headers for filter IBD). */
            dogecoin_bool aux_found = false;
            if (client->aux_hash_db && client->aux_hash_db_ctx) {
                dogecoin_headers_db *aux = (dogecoin_headers_db *)client->aux_hash_db_ctx;
                aux_found = dogecoin_headers_db_get_block_hash_at_height(aux, batch_stop_height, batch_stop_hash);
            }
            if (!aux_found) {
                uint32_t cp_h = cf_find_checkpoint_stop(client->chainparams,
                    batch_stop_height, batch_stop_hash);
                if (cp_h > 0) {
                    if (client->nodegroup && client->nodegroup->log_write_cb)
                        client->nodegroup->log_write_cb(
                            "[bip157] getcfheaders: no hash at %u, using checkpoint %u\n",
                            batch_stop_height, cp_h);
                    batch_stop_height = cp_h;
                } else {
                    if (client->nodegroup && client->nodegroup->log_write_cb)
                        client->nodegroup->log_write_cb(
                            "[bip157] getcfheaders: cannot find hash at height %u, using tip\n",
                            batch_stop_height);
                    memcpy(batch_stop_hash, tip->hash, sizeof(uint256_t));
                    batch_stop_height = tip_height;
                }
            }
        }
    }

    dogecoin_getcfheaders_msg msg;
    msg.filter_type = GCS_BASIC_FILTER_TYPE;
    msg.start_height = start_height;
    memcpy(msg.stop_hash, batch_stop_hash, sizeof(uint256_t));

    cstring *payload = cstr_new_sz(64);
    dogecoin_p2p_msg_getcfheaders_ser(&msg, payload);

    cstring *p2p_msg = dogecoin_p2p_message_new(
        node->nodegroup->chainparams->netmagic,
        DOGECOIN_MSG_GETCFHEADERS,
        payload->str, payload->len);
    cstr_free(payload, true);
    dogecoin_node_send(node, p2p_msg);
    cstr_free(p2p_msg, true);

    client->cfilter_state->awaiting_response = true;
    client->cfilter_state->last_request_time = (uint64_t)time(NULL);
    client->cfilter_state->pending_start_height = start_height;
    memcpy(client->cfilter_state->pending_stop_hash, batch_stop_hash, sizeof(uint256_t));

    if (client->nodegroup && client->nodegroup->log_write_cb)
        client->nodegroup->log_write_cb("[bip157] sent getcfheaders (start=%u stop_height=%u) to node %d [%us elapsed]\n",
            start_height, batch_stop_height, node->nodeid, spv_elapsed(client));
    return true;
}

LIBDOGECOIN_API dogecoin_bool dogecoin_spv_request_cfilters(dogecoin_spv_client *client, dogecoin_node *node, uint32_t start_height, const uint256_t stop_hash)
{
    if (!client || !node || !client->cfilter_state) return false;

    dogecoin_compact_filter_state *cfstate = client->cfilter_state;
    uint32_t cfheaders_tip = cfstate->cfheaders_tip_height;

    /* BIP157: servers reject requests with stop_height - start_height >= MAX_GETCFILTERS_SIZE.
     * Clamp the batch to at most MAX_GETCFILTERS_SIZE cfilters. */
    uint32_t batch_end = start_height + MAX_GETCFILTERS_SIZE - 1;
    if (cfheaders_tip > 0 && batch_end > cfheaders_tip)
        batch_end = cfheaders_tip;

    /* Find the block hash at batch_end. */
    uint256_t batch_stop_hash;
    dogecoin_blockindex *tip = client->headers_db->getchaintip(client->headers_db_ctx);
    if (tip && batch_end == (uint32_t)tip->height) {
        memcpy(batch_stop_hash, tip->hash, sizeof(uint256_t));
    } else {
        dogecoin_headers_db *hdb = (dogecoin_headers_db *)client->headers_db_ctx;
        if (!dogecoin_headers_db_get_block_hash_at_height(hdb, batch_end, batch_stop_hash)) {
            /* Primary DB miss — try aux hash-lookup DB (genesis headers for filter IBD). */
            dogecoin_bool aux_found = false;
            if (client->aux_hash_db && client->aux_hash_db_ctx) {
                dogecoin_headers_db *aux = (dogecoin_headers_db *)client->aux_hash_db_ctx;
                aux_found = dogecoin_headers_db_get_block_hash_at_height(aux, batch_end, batch_stop_hash);
            }
            if (!aux_found) {
                uint32_t cp_h = cf_find_checkpoint_stop(client->chainparams,
                    batch_end, batch_stop_hash);
                if (cp_h > 0) {
                    if (client->nodegroup && client->nodegroup->log_write_cb)
                        client->nodegroup->log_write_cb(
                            "[bip157] getcfilters: no hash at %u, using checkpoint %u\n",
                            batch_end, cp_h);
                    batch_end = cp_h;
                } else {
                    if (client->nodegroup && client->nodegroup->log_write_cb)
                        client->nodegroup->log_write_cb(
                            "[bip157] getcfilters: cannot find hash at height %u, using tip\n",
                            batch_end);
                    memcpy(batch_stop_hash, stop_hash, sizeof(uint256_t));
                    if (tip) batch_end = (uint32_t)tip->height;
                }
            }
        }
    }

    dogecoin_getcfilters_msg msg;
    msg.filter_type = GCS_BASIC_FILTER_TYPE;
    msg.start_height = start_height;
    memcpy(msg.stop_hash, batch_stop_hash, sizeof(uint256_t));

    cstring *payload = cstr_new_sz(64);
    dogecoin_p2p_msg_getcfilters_ser(&msg, payload);

    cstring *p2p_msg = dogecoin_p2p_message_new(
        node->nodegroup->chainparams->netmagic,
        DOGECOIN_MSG_GETCFILTERS,
        payload->str, payload->len);
    cstr_free(payload, true);
    dogecoin_node_send(node, p2p_msg);
    cstr_free(p2p_msg, true);

    cfstate->cfilter_batch_end = batch_end;
    cfstate->awaiting_response = true;
    cfstate->last_request_time = (uint64_t)time(NULL);
    cfstate->pending_start_height = start_height;
    memcpy(cfstate->pending_stop_hash, batch_stop_hash, sizeof(uint256_t));

    if (client->nodegroup && client->nodegroup->log_write_cb)
        client->nodegroup->log_write_cb("[bip157] sent getcfilters (start=%u..%u) to node %d [%us elapsed]\n",
            start_height, batch_end, node->nodeid, spv_elapsed(client));
    return true;
}
