/*
 * Copyright (c) 2024 The Dogecoin Foundation
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

#ifndef __LIBDOGECOIN_SMPV_H__
#define __LIBDOGECOIN_SMPV_H__

#include <stdint.h>
#include <stddef.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/tx.h>

LIBDOGECOIN_BEGIN_DECL

/* Forward declarations */
typedef struct dogecoin_transaction_ dogecoin_transaction;

/* SMPV transaction structure */
typedef struct {
    char* txid;                    /* Transaction ID (hex string) */
    char* raw_hex;                 /* Raw transaction hex */
    dogecoin_tx* decoded_tx;       /* Decoded transaction */
    uint64_t size;                 /* Transaction size in bytes */
    uint64_t timestamp;            /* When transaction was first seen */
    dogecoin_bool is_confirmed;    /* Whether transaction is confirmed */
    uint32_t confirmations;        /* Number of confirmations */
    char* block_hash;              /* Block hash if confirmed */
    uint32_t block_height;         /* Block height if confirmed */

    /* --- per-tx stats (lightweight) --- */
    uint32_t vin_count;            /* number of inputs */
    uint32_t vout_count;           /* number of outputs */
    uint32_t p2pkh_out;            /* #outputs classified as P2PKH */
    uint32_t p2sh_out;             /* #outputs classified as P2SH */
    uint32_t pubkey_out;           /* #outputs classified as P2PK */
    uint32_t multisig_out;         /* #outputs classified as MULTISIG */
    uint32_t opreturn_out;         /* #outputs starting with OP_RETURN */
    uint32_t nonstandard_out;      /* #outputs classified as NONSTANDARD */
    uint64_t total_output_value;   /* sum of vout values (koinu) */
    dogecoin_bool is_coinbase;     /* tx is coinbase */
} dogecoin_smpv_tx;

/* SMPV address watcher structure */
typedef struct {
    char* address;                 /* Dogecoin address being watched */
    uint64_t total_received;       /* Total received in koinu */
    uint64_t total_sent;           /* Total sent in koinu */
    uint64_t balance;              /* Current balance in koinu */
    uint32_t tx_count;             /* Number of transactions */
    dogecoin_bool is_active;       /* Whether watcher is active */
} dogecoin_smpv_watcher;

/* SMPV client structure */
typedef struct {
    const dogecoin_chainparams* chain_params;
    dogecoin_smpv_watcher* watchers;   /* Hash table of watchers */
    dogecoin_smpv_tx* mempool_txs;     /* Hash table of mempool transactions */
    uint32_t watcher_count;
    uint32_t mempool_tx_count;
    dogecoin_bool is_running;
    uint64_t last_update_time;

    /* lightweight running totals (not exposed via new APIs) */
    uint64_t total_bytes;
    uint32_t confirmed_count;
    uint32_t unconfirmed_count;
    uint64_t last_seen_ts;
} dogecoin_smpv_client;

/* Callback function type for transaction notifications */
typedef void (*dogecoin_smpv_tx_callback)(
    const dogecoin_smpv_tx* tx,
    const char* address,
    void* user_data
);

/* Initialize SMPV client */
LIBDOGECOIN_API dogecoin_smpv_client* dogecoin_smpv_client_new(const dogecoin_chainparams* chain_params);

/* Free SMPV client */
LIBDOGECOIN_API void dogecoin_smpv_client_free(dogecoin_smpv_client* client);

/* Add address to watch list */
LIBDOGECOIN_API dogecoin_bool dogecoin_smpv_add_watcher(
    dogecoin_smpv_client* client,
    const char* address
);

/* Remove address from watch list */
LIBDOGECOIN_API dogecoin_bool dogecoin_smpv_remove_watcher(
    dogecoin_smpv_client* client,
    const char* address
);

/* Get watcher for address */
LIBDOGECOIN_API dogecoin_smpv_watcher* dogecoin_smpv_get_watcher(
    const dogecoin_smpv_client* client,
    const char* address
);

/* Start SMPV monitoring */
LIBDOGECOIN_API dogecoin_bool dogecoin_smpv_start(dogecoin_smpv_client* client);

/* Stop SMPV monitoring */
LIBDOGECOIN_API void dogecoin_smpv_stop(dogecoin_smpv_client* client);

/* Process new mempool transaction */
LIBDOGECOIN_API dogecoin_bool dogecoin_smpv_process_tx(
    dogecoin_smpv_client* client,
    const char* raw_tx_hex,
    dogecoin_smpv_tx_callback callback,
    void* user_data
);

/* Get mempool transaction by ID */
LIBDOGECOIN_API dogecoin_smpv_tx* dogecoin_smpv_get_tx(
    const dogecoin_smpv_client* client,
    const char* txid
);

/* Get all transactions for an address */
LIBDOGECOIN_API dogecoin_smpv_tx** dogecoin_smpv_get_address_txs(
    const dogecoin_smpv_client* client,
    const char* address,
    size_t* tx_count
);

/* Check if transaction is relevant to watched addresses */
LIBDOGECOIN_API dogecoin_bool dogecoin_smpv_is_tx_relevant(
    const dogecoin_smpv_client* client,
    const dogecoin_tx* tx,
    char** relevant_address
);

/* Decode raw transaction hex */
LIBDOGECOIN_API dogecoin_tx* dogecoin_smpv_decode_tx(const char* raw_tx_hex);

/* Note: Fee calculation removed - mempool doesn't track fees */

/* Get transaction size */
LIBDOGECOIN_API uint64_t dogecoin_smpv_get_tx_size(const dogecoin_tx* tx);

/* Update transaction status (confirmed/unconfirmed) */
LIBDOGECOIN_API void dogecoin_smpv_update_tx_status(
    dogecoin_smpv_client* client,
    const char* txid,
    dogecoin_bool confirmed,
    const char* block_hash,
    uint32_t block_height
);

/* Get mempool statistics */
LIBDOGECOIN_API void dogecoin_smpv_get_stats(
    const dogecoin_smpv_client* client,
    uint32_t* total_txs,
    uint32_t* watched_addresses
);

/* Free SMPV transaction */
LIBDOGECOIN_API void dogecoin_smpv_tx_free(dogecoin_smpv_tx* tx);

/* Free SMPV watcher */
LIBDOGECOIN_API void dogecoin_smpv_watcher_free(dogecoin_smpv_watcher* watcher);

/* Utility functions */
LIBDOGECOIN_API char* dogecoin_smpv_tx_to_json(const dogecoin_smpv_tx* tx);
LIBDOGECOIN_API char* dogecoin_smpv_watcher_to_json(const dogecoin_smpv_watcher* watcher);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_SMPV_H__
