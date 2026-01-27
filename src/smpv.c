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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stddef.h>
#include <dogecoin/smpv.h>
#include <dogecoin/mem.h>
#include <dogecoin/tx.h>
#include <dogecoin/serialize.h>
#include <dogecoin/hash.h>
#include <dogecoin/cstr.h>

/* Initialize SMPV client */
dogecoin_smpv_client* dogecoin_smpv_client_new(const dogecoin_chainparams* chain_params) {
    if (!chain_params) return NULL;
    dogecoin_smpv_client* client = dogecoin_calloc(1, sizeof(dogecoin_smpv_client));
    if (!client) return NULL;

    client->chain_params = chain_params;
    client->watchers = NULL;
    client->mempool_txs = NULL;
    client->watcher_count = 0;
    client->mempool_tx_count = 0;
    client->is_running = false;
    client->last_update_time = 0;

    /* init new counters */
    client->total_bytes = 0;
    client->confirmed_count = 0;
    client->unconfirmed_count = 0;
    client->last_seen_ts = 0;

    return client;
}

/* Free SMPV client */
void dogecoin_smpv_client_free(dogecoin_smpv_client* client) {
    if (!client) return;
    
    /* Free watchers */
    for (uint32_t i = 0; i < client->watcher_count; i++) {
        if (client->watchers[i].address) {
            dogecoin_free(client->watchers[i].address);
        }
    }
    if (client->watchers) {
        dogecoin_free(client->watchers);
    }
    
    /* Free transactions */
    for (uint32_t i = 0; i < client->mempool_tx_count; i++) {
        if (client->mempool_txs[i].txid) {
            dogecoin_free(client->mempool_txs[i].txid);
        }
        if (client->mempool_txs[i].raw_hex) {
            dogecoin_free(client->mempool_txs[i].raw_hex);
        }
        if (client->mempool_txs[i].decoded_tx) {
            dogecoin_free(client->mempool_txs[i].decoded_tx);
        }
        if (client->mempool_txs[i].block_hash) {
            dogecoin_free(client->mempool_txs[i].block_hash);
        }
    }
    if (client->mempool_txs) {
        dogecoin_free(client->mempool_txs);
    }
    
    dogecoin_free(client);
}

/* Add address to watch list */
dogecoin_bool dogecoin_smpv_add_watcher(
    dogecoin_smpv_client* client,
    const char* address
) {
    if (!client || !address) return false;
    
    /* Check if address is already being watched */
    for (uint32_t i = 0; i < client->watcher_count; i++) {
        if (strcmp(client->watchers[i].address, address) == 0) {
            return true; /* Already watching */
        }
    }
    
    /* Resize watchers array */
    client->watchers = realloc(client->watchers, 
                              (client->watcher_count + 1) * sizeof(dogecoin_smpv_watcher));
    if (!client->watchers) return false;
    
    /* Initialize new watcher */
    dogecoin_smpv_watcher* watcher = &client->watchers[client->watcher_count];
    watcher->address = dogecoin_calloc(1, strlen(address) + 1);
    if (!watcher->address) return false;
    strcpy(watcher->address, address);
    watcher->total_received = 0;
    watcher->total_sent = 0;
    watcher->balance = 0;
    watcher->tx_count = 0;
    watcher->is_active = true;
    
    client->watcher_count++;
    return true;
}

/* Remove address from watch list */
dogecoin_bool dogecoin_smpv_remove_watcher(
    dogecoin_smpv_client* client,
    const char* address
) {
    if (!client || !address) return false;
    
    for (uint32_t i = 0; i < client->watcher_count; i++) {
        if (strcmp(client->watchers[i].address, address) == 0) {
            /* Free the watcher */
            if (client->watchers[i].address) {
                dogecoin_free(client->watchers[i].address);
            }
            
            /* Move remaining watchers */
            for (uint32_t j = i; j < client->watcher_count - 1; j++) {
                client->watchers[j] = client->watchers[j + 1];
            }
            
            client->watcher_count--;
            return true;
        }
    }
    
    return false;
}

/* Get watcher for address */
dogecoin_smpv_watcher* dogecoin_smpv_get_watcher(
    const dogecoin_smpv_client* client,
    const char* address
) {
    if (!client || !address) return NULL;
    
    for (uint32_t i = 0; i < client->watcher_count; i++) {
        if (strcmp(client->watchers[i].address, address) == 0) {
            return &client->watchers[i];
        }
    }
    
    return NULL;
}

/* Start SMPV monitoring */
dogecoin_bool dogecoin_smpv_start(dogecoin_smpv_client* client) {
    if (!client) return false;
    
    client->is_running = true;
    client->last_update_time = time(NULL);
    return true;
}

/* Stop SMPV monitoring */
void dogecoin_smpv_stop(dogecoin_smpv_client* client) {
    if (!client) return;
    
    client->is_running = false;
}

/* Process new mempool transaction */
LIBDOGECOIN_API dogecoin_bool dogecoin_smpv_process_tx(
    dogecoin_smpv_client* client,
    const char* raw_tx_hex,
    dogecoin_smpv_tx_callback callback,
    void* user_data
) {
    if (!client || !raw_tx_hex) return false;

    dogecoin_smpv_tx* smpv_tx = (dogecoin_smpv_tx*)dogecoin_calloc(1, sizeof(dogecoin_smpv_tx));
    if (!smpv_tx) return false;

    /* keep the hex string */
    const size_t raw_len = strlen(raw_tx_hex);
    smpv_tx->raw_hex = (char*)dogecoin_calloc(1, raw_len + 1);
    if (!smpv_tx->raw_hex) { dogecoin_smpv_tx_free(smpv_tx); return false; }
    strcpy(smpv_tx->raw_hex, raw_tx_hex);

    /* hex -> bytes */
    const size_t alloc_bytes = raw_len / 2;
    unsigned char* bin = (unsigned char*)dogecoin_calloc(1, alloc_bytes ? alloc_bytes : 1);
    if (!bin) { dogecoin_smpv_tx_free(smpv_tx); return false; }
    size_t out_len = 0;
    utils_hex_to_bin(raw_tx_hex, bin, raw_len, &out_len);
    if (out_len == 0) { dogecoin_free(bin); dogecoin_smpv_tx_free(smpv_tx); return false; }

    /* txid = dbl-SHA256(bytes) (display LE) */
    uint256_t h;
    dogecoin_dblhash(bin, out_len, h);
    smpv_tx->txid = (char*)dogecoin_calloc(1, 65);
    if (!smpv_tx->txid) { dogecoin_free(bin); dogecoin_smpv_tx_free(smpv_tx); return false; }
    char* hex = utils_uint8_to_hex((const uint8_t*)h, 32);
    if (!hex) { dogecoin_free(bin); dogecoin_smpv_tx_free(smpv_tx); return false; }
    strcpy(smpv_tx->txid, hex);
    utils_reverse_hex(smpv_tx->txid, 64);

    /* base metadata */
    smpv_tx->size          = (uint64_t)out_len;
    smpv_tx->timestamp     = time(NULL);
    smpv_tx->is_confirmed  = false;
    smpv_tx->confirmations = 0;
    smpv_tx->block_hash    = NULL;
    smpv_tx->block_height  = 0;

    /* init per-tx stats */
    smpv_tx->vin_count = smpv_tx->vout_count = 0;
    smpv_tx->p2pkh_out = smpv_tx->p2sh_out = smpv_tx->pubkey_out = 0;
    smpv_tx->multisig_out = smpv_tx->opreturn_out = smpv_tx->nonstandard_out = 0;
    smpv_tx->total_output_value = 0;
    smpv_tx->is_coinbase = false;

    /* best-effort decode */
    smpv_tx->decoded_tx = dogecoin_smpv_decode_tx(raw_tx_hex);
    if (smpv_tx->decoded_tx) {
        dogecoin_tx* tx = smpv_tx->decoded_tx;
        smpv_tx->vin_count  = tx->vin  ? (uint32_t)tx->vin->len  : 0;
        smpv_tx->vout_count = tx->vout ? (uint32_t)tx->vout->len : 0;
        smpv_tx->is_coinbase = dogecoin_tx_is_coinbase(tx);

        if (tx->vout) {
            for (size_t i = 0; i < tx->vout->len; i++) {
                dogecoin_tx_out* o = vector_idx(tx->vout, i);
                if (!o) continue;
                smpv_tx->total_output_value += (uint64_t)o->value;

                if (o->script_pubkey && o->script_pubkey->len > 0) {
                    /* Detect OP_RETURN and OP_FALSE OP_RETURN */
                    vector_t* ops = vector_new(4, dogecoin_script_op_free_cb);
                    dogecoin_bool got_ops = dogecoin_script_get_ops(o->script_pubkey, ops);

                    dogecoin_bool is_opret = false;
                    if (got_ops && ops->len > 0) {
                        dogecoin_script_op* opA = (dogecoin_script_op*)vector_idx(ops, 0);
                        if (opA->op == OP_RETURN) {
                            is_opret = true; /* OP_RETURN <data> */
                        } else if (ops->len > 1) {
                            dogecoin_script_op* opB = (dogecoin_script_op*)vector_idx(ops, 1);
                            if ((opA->op == OP_0) && (opB->op == OP_RETURN)) {
                                is_opret = true; /* OP_FALSE OP_RETURN */
                            }
                        }
                    }

                    if (is_opret) {
                        smpv_tx->opreturn_out++;
                    } else {
                        enum dogecoin_tx_out_type t = dogecoin_script_classify(o->script_pubkey, NULL);
                        switch (t) {
                            case DOGECOIN_TX_PUBKEY:     smpv_tx->pubkey_out++;     break;
                            case DOGECOIN_TX_PUBKEYHASH: smpv_tx->p2pkh_out++;      break;
                            case DOGECOIN_TX_SCRIPTHASH: smpv_tx->p2sh_out++;       break;
                            case DOGECOIN_TX_MULTISIG:   smpv_tx->multisig_out++;   break;
                            default:                     smpv_tx->nonstandard_out++;break;
                        }
                    }

                    if (ops) vector_free(ops, true);
                }
            }
        }
    }

    dogecoin_free(bin);

    /* push to mempool store */
    client->mempool_txs = (dogecoin_smpv_tx*)realloc(
        client->mempool_txs,
        (client->mempool_tx_count + 1) * sizeof(dogecoin_smpv_tx)
    );
    if (!client->mempool_txs) { dogecoin_smpv_tx_free(smpv_tx); return false; }

    client->mempool_txs[client->mempool_tx_count] = *smpv_tx; /* struct copy */
    dogecoin_free(smpv_tx);
    client->mempool_tx_count++;

    /* light rolling counters (internal only) */
    client->total_bytes += (uint64_t)out_len;
    client->last_seen_ts = client->last_update_time = time(NULL);
    if (client->unconfirmed_count < UINT32_MAX) client->unconfirmed_count++;

    /* naive relevance: first watcher */
    char* relevant_address = NULL;
    if (client->watcher_count > 0 && client->watchers[0].address) {
        size_t alen = strlen(client->watchers[0].address);
        relevant_address = (char*)dogecoin_calloc(1, alen + 1);
        if (relevant_address) {
            strcpy(relevant_address, client->watchers[0].address);
            client->watchers[0].tx_count++;
        }
    }

    if (callback) {
        callback(&client->mempool_txs[client->mempool_tx_count - 1],
                 relevant_address,
                 user_data);
    }
    if (relevant_address) dogecoin_free(relevant_address);
    return true;
}

/* Get mempool transaction by ID */
dogecoin_smpv_tx* dogecoin_smpv_get_tx(
    const dogecoin_smpv_client* client,
    const char* txid
) {
    if (!client || !txid) return NULL;
    
    for (uint32_t i = 0; i < client->mempool_tx_count; i++) {
        if (strcmp(client->mempool_txs[i].txid, txid) == 0) {
            return &client->mempool_txs[i];
        }
    }
    
    return NULL;
}

/* Get all transactions for an address */
dogecoin_smpv_tx** dogecoin_smpv_get_address_txs(
    const dogecoin_smpv_client* client,
    const char* address,
    size_t* tx_count
) {
    if (!client || !address || !tx_count) return NULL;
    
    *tx_count = 0;
    /* Simplified implementation - would need proper address matching */
    return NULL;
}

/* Check if transaction is relevant to watched addresses */
dogecoin_bool dogecoin_smpv_is_tx_relevant(
    const dogecoin_smpv_client* client,
    const dogecoin_tx* tx,
    char** relevant_address
) {
    if (!client || !tx || !relevant_address) return false;
    
    /* Simplified implementation - would need proper address matching */
    *relevant_address = NULL;
    return false;
}

/* Decode raw transaction hex */
LIBDOGECOIN_API dogecoin_tx* dogecoin_smpv_decode_tx(const char* raw_tx_hex) {
    if (!raw_tx_hex) return NULL;
    size_t hex_len = strlen(raw_tx_hex);
    if (hex_len < 2 || (hex_len % 2) != 0) return NULL;

    size_t bin_len = hex_len / 2;
    unsigned char* bin = (unsigned char*)dogecoin_calloc(1, bin_len);
    if (!bin) return NULL;

    size_t out_len = 0;
    utils_hex_to_bin(raw_tx_hex, bin, hex_len, &out_len);
    if (out_len == 0) { dogecoin_free(bin); return NULL; }

    dogecoin_tx* tx = dogecoin_tx_new();
    size_t consumed = 0;
    int ok = dogecoin_tx_deserialize(bin, out_len, tx, &consumed);
    dogecoin_free(bin);
    if (!ok) { dogecoin_tx_free(tx); return NULL; }
    return tx;
}

/* Note: Fee calculation removed - mempool doesn't need to track fees
 * since we can't calculate real fees without access to previous outputs. */

/* Get transaction size */
uint64_t dogecoin_smpv_get_tx_size(const dogecoin_tx* tx) {
    if (!tx) return 0;
    
    /* Serialize transaction to get actual size */
    cstring* tx_serialized = cstr_new_sz(1024);
    dogecoin_tx_serialize(tx_serialized, tx);
    uint64_t size = tx_serialized->len;
    cstr_free(tx_serialized, true);
    return size;
}

/* Update transaction status */
LIBDOGECOIN_API void dogecoin_smpv_update_tx_status(
    dogecoin_smpv_client* client,
    const char* txid,
    dogecoin_bool confirmed,
    const char* block_hash,
    uint32_t block_height
) {
    if (!client || !txid) return;

    dogecoin_smpv_tx* tx = dogecoin_smpv_get_tx(client, txid);
    if (!tx) return;

    /* adjust internal counters only on transition */
    if (!tx->is_confirmed && confirmed) {
        if (client->confirmed_count < UINT32_MAX) client->confirmed_count++;
        if (client->unconfirmed_count > 0) client->unconfirmed_count--;
    } else if (tx->is_confirmed && !confirmed) {
        if (client->confirmed_count > 0) client->confirmed_count--;
        if (client->unconfirmed_count < UINT32_MAX) client->unconfirmed_count++;
    }

    tx->is_confirmed = confirmed;
    if (confirmed) {
        tx->confirmations = 1;
        if (block_hash) {
            if (tx->block_hash) dogecoin_free(tx->block_hash);
            tx->block_hash = dogecoin_calloc(1, strlen(block_hash) + 1);
            strcpy(tx->block_hash, block_hash);
        }
        tx->block_height = block_height;
    }
}

/* Get mempool statistics */
void dogecoin_smpv_get_stats(
    const dogecoin_smpv_client* client,
    uint32_t* total_txs,
    uint32_t* watched_addresses
) {
    if (!client) return;
    
    if (total_txs) *total_txs = client->mempool_tx_count;
    if (watched_addresses) *watched_addresses = client->watcher_count;
}

/* Free SMPV transaction */
void dogecoin_smpv_tx_free(dogecoin_smpv_tx* tx) {
    if (!tx) return;
    
    if (tx->txid) dogecoin_free(tx->txid);
    if (tx->raw_hex) dogecoin_free(tx->raw_hex);
    if (tx->decoded_tx) dogecoin_free(tx->decoded_tx);
    if (tx->block_hash) dogecoin_free(tx->block_hash);
    dogecoin_free(tx);
}

/* Free SMPV watcher */
void dogecoin_smpv_watcher_free(dogecoin_smpv_watcher* watcher) {
    if (!watcher) return;
    
    if (watcher->address) dogecoin_free(watcher->address);
    dogecoin_free(watcher);
}

/* Utility functions */
LIBDOGECOIN_API char* dogecoin_smpv_tx_to_json(const dogecoin_smpv_tx* tx) {
    if (!tx) return NULL;

    char* json = dogecoin_calloc(1, 2048);
    snprintf(json, 2048,
        "{\n"
        "  \"txid\": \"%s\",\n"
        "  \"size\": %llu,\n"
        "  \"timestamp\": %llu,\n"
        "  \"confirmed\": %s,\n"
        "  \"confirmations\": %u,\n"
        "  \"vin_count\": %u,\n"
        "  \"vout_count\": %u,\n"
        "  \"is_coinbase\": %s,\n"
        "  \"total_output_value\": %llu,\n"
        "  \"outputs\": {\n"
        "    \"p2pk\": %u,\n"
        "    \"p2pkh\": %u,\n"
        "    \"p2sh\": %u,\n"
        "    \"multisig\": %u,\n"
        "    \"op_return\": %u,\n"
        "    \"nonstandard\": %u\n"
        "  }\n"
        "}",
        tx->txid ? tx->txid : "",
        (unsigned long long)tx->size,
        (unsigned long long)tx->timestamp,
        tx->is_confirmed ? "true" : "false",
        tx->confirmations,
        tx->vin_count,
        tx->vout_count,
        tx->is_coinbase ? "true" : "false",
        (unsigned long long)tx->total_output_value,
        tx->pubkey_out,
        tx->p2pkh_out,
        tx->p2sh_out,
        tx->multisig_out,
        tx->opreturn_out,
        tx->nonstandard_out
    );
    return json;
}

char* dogecoin_smpv_watcher_to_json(const dogecoin_smpv_watcher* watcher) {
    if (!watcher) return NULL;
    
    char* json = dogecoin_calloc(1, 512);
    snprintf(json, 512,
        "{\n"
        "  \"address\": \"%s\",\n"
        "  \"balance\": %llu,\n"
        "  \"tx_count\": %u,\n"
        "  \"active\": %s\n"
        "}",
        watcher->address ? watcher->address : "",
        (unsigned long long)watcher->balance,
        watcher->tx_count,
        watcher->is_active ? "true" : "false"
    );
    return json;
}

