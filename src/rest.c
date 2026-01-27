/*

 The MIT License (MIT)

 Copyright (c) 2024 edtubbs, bluezr
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

#include <dogecoin/rest.h>

#include <dogecoin/blockchain.h>
#include <dogecoin/koinu.h>
#include <dogecoin/headersdb_file.h>
#include <dogecoin/spv.h>
#include <dogecoin/smpv.h>
#include <dogecoin/wallet.h>

#define TIMESTAMP_MAX_LEN 32

#include <stdlib.h>   // qsort
#include <stdint.h>   // uint64_t

static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t*)a, vb = *(const uint64_t*)b;
    return (va > vb) - (va < vb);
}

/**
 * This function is called when an http request is received
 * It handles the request and sends a response
 *
 * @param req the request
 * @param arg the client
 *
 * @return Nothing.
 */
void dogecoin_http_request_cb(struct evhttp_request *req, void *arg) {
    dogecoin_spv_client* client = (dogecoin_spv_client*)arg;
    dogecoin_wallet* wallet = (dogecoin_wallet*)client->sync_transaction_ctx;
    if (!wallet) {
        evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
        return;
    }

    const struct evhttp_uri* uri = evhttp_request_get_evhttp_uri(req);
    const char* path = evhttp_uri_get_path(uri);

    struct evbuffer *evb = NULL;
    evb = evbuffer_new();
    if (!evb) {
        evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
        return;
    }

    if (strcmp(path, "/getBalance") == 0) {
        int64_t balance = dogecoin_wallet_get_balance(wallet);
        char balance_str[32] = {0};
        koinu_to_coins_str(balance, balance_str);
        evbuffer_add_printf(evb, "Wallet balance: %s\n", balance_str);
    } else if (strcmp(path, "/getAddresses") == 0) {
        vector_t* addresses = vector_new(10, dogecoin_free);
        dogecoin_wallet_get_addresses(wallet, addresses);
        for (unsigned int i = 0; i < addresses->len; i++) {
            char* address = vector_idx(addresses, i);
            evbuffer_add_printf(evb, "address: %s\n", address);
        }
        vector_free(addresses, true);
    } else if (strcmp(path, "/getTransactions") == 0) {
        char wallet_total[21];
        dogecoin_mem_zero(wallet_total, 21);
        uint64_t wallet_total_u64 = 0;

        if (HASH_COUNT(wallet->utxos) > 0) {
            dogecoin_utxo* utxo;
            dogecoin_utxo* tmp;
            HASH_ITER(hh, wallet->utxos, utxo, tmp) {
                if (!utxo->spendable) {
                    // For spent UTXOs
                    evbuffer_add_printf(evb, "%s\n", "----------------------");
                    evbuffer_add_printf(evb, "txid:           %s\n", utils_uint8_to_hex(utxo->txid, sizeof(utxo->txid)));
                    evbuffer_add_printf(evb, "vout:           %d\n", utxo->vout);
                    evbuffer_add_printf(evb, "address:        %s\n", utxo->address);
                    evbuffer_add_printf(evb, "script_pubkey:  %s\n", utxo->script_pubkey);
                    evbuffer_add_printf(evb, "amount:         %s\n", utxo->amount);
                    evbuffer_add_printf(evb, "confirmations:  %d\n", utxo->confirmations);
                    evbuffer_add_printf(evb, "height:         %d\n", utxo->height);
                    evbuffer_add_printf(evb, "spendable:      %d\n", utxo->spendable);
                    evbuffer_add_printf(evb, "solvable:       %d\n", utxo->solvable);
                    wallet_total_u64 += coins_to_koinu_str(utxo->amount);
                }
            }
        }

        // Convert and print totals for spent UTXOs.
        koinu_to_coins_str(wallet_total_u64, wallet_total);
        evbuffer_add_printf(evb, "Spent Balance: %s\n", wallet_total);
    } else if (strcmp(path, "/getUTXOs") == 0) {
        char wallet_total[21];
        dogecoin_mem_zero(wallet_total, 21);
        uint64_t wallet_total_u64_unspent = 0;

        dogecoin_utxo* utxo;
        dogecoin_utxo* tmp;

        HASH_ITER(hh, wallet->utxos, utxo, tmp) {
            if (utxo->spendable) {
                // For unspent UTXOs
                evbuffer_add_printf(evb, "----------------------\n");
                evbuffer_add_printf(evb, "Unspent UTXO:\n");
                evbuffer_add_printf(evb, "txid:           %s\n", utils_uint8_to_hex(utxo->txid, sizeof(utxo->txid)));
                evbuffer_add_printf(evb, "vout:           %d\n", utxo->vout);
                evbuffer_add_printf(evb, "address:        %s\n", utxo->address);
                evbuffer_add_printf(evb, "script_pubkey:  %s\n", utxo->script_pubkey);
                evbuffer_add_printf(evb, "amount:         %s\n", utxo->amount);
                evbuffer_add_printf(evb, "confirmations:  %d\n", utxo->confirmations);
                evbuffer_add_printf(evb, "height:         %d\n", utxo->height);
                evbuffer_add_printf(evb, "spendable:      %d\n", utxo->spendable);
                evbuffer_add_printf(evb, "solvable:       %d\n", utxo->solvable);
                wallet_total_u64_unspent += coins_to_koinu_str(utxo->amount);
            }
        }

        // Convert and print totals for unspent UTXOs.
        koinu_to_coins_str(wallet_total_u64_unspent, wallet_total);
        evbuffer_add_printf(evb, "Total Unspent: %s\n", wallet_total);
    } else if (strcmp(path, "/getWallet") == 0) {
        // Get the wallet file
        FILE* file = wallet->dbfile;
        if (file == NULL) {
            evhttp_send_error(req, HTTP_NOTFOUND, "Wallet file not found");
            evbuffer_free(evb);
            return;
        }

        // Get the size of the wallet file
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        rewind(file);

        // Read the wallet file into a buffer
        char* buffer = malloc(file_size);
        if (buffer == NULL) {
            evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
            evbuffer_free(evb);
            return;
        }
        size_t result = fread(buffer, 1, file_size, file);
        if (result != (size_t)file_size) {
            free(buffer);
            evbuffer_free(evb);
            evhttp_send_error(req, HTTP_INTERNAL, "Failed to read wallet file");
            return;
        }

        // Add the buffer to the response buffer
        evbuffer_add(evb, buffer, file_size);

        // Set the Content-Type header to "application/octet-stream" for binary data
        evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/octet-stream");

        // Clean up
        free(buffer);
    } else if (strcmp(path, "/getHeaders") == 0) {
        // Get the headers file
        dogecoin_headers_db* headers_db = (dogecoin_headers_db *)(client->headers_db_ctx);
        FILE* file = headers_db->headers_tree_file;
        if (file == NULL) {
            evhttp_send_error(req, HTTP_NOTFOUND, "Headers file not found");
            evbuffer_free(evb);
            return;
        }

        // Get the size of the headers file
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        rewind(file);

        // Read the headers file into a buffer
        char* buffer = malloc(file_size);
        if (buffer == NULL) {
            evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
            evbuffer_free(evb);
            return;
        }
        size_t result = fread(buffer, 1, file_size, file);
        if (result !=  (size_t)file_size) {
            free(buffer);
            evbuffer_free(evb);
            evhttp_send_error(req, HTTP_INTERNAL, "Failed to read headers file");
            return;
        }

        // Add the buffer to the response buffer
        evbuffer_add(evb, buffer, file_size);

        // Set the Content-Type header to "application/octet-stream" for binary data
        evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/octet-stream");

        // Clean up
        free(buffer);
    } else if (strcmp(path, "/getChaintip") == 0) {
        dogecoin_blockindex* tip = client->headers_db->getchaintip(client->headers_db_ctx);
        evbuffer_add_printf(evb, "Chain tip: %d\n", tip->height);
    } else if (strcmp(path, "/getTimestamp") == 0) {
        dogecoin_blockindex* tip = client->headers_db->getchaintip(client->headers_db_ctx);
        char s[TIMESTAMP_MAX_LEN] = {0};
        time_t t = tip->header.timestamp;
        struct tm *p = localtime(&t);
        strftime(s, sizeof(s), "%F %T", p);
        evbuffer_add_printf(evb, "%s\n", s);
    } else if (strcmp(path, "/getLastBlockInfo") == 0) {
        uint64_t size = client->last_block_size;
        uint64_t tx_count = client->last_block_tx_count;
        uint64_t total_tx_size = client->last_block_total_tx_size;

        evbuffer_add_printf(evb, "Block size: %lu\n", size);
        evbuffer_add_printf(evb, "Tx count: %lu\n", tx_count);
        evbuffer_add_printf(evb, "Total tx size: %lu\n", total_tx_size);
    } else if (strcmp(path, "/getRawTx") == 0) {
        // Return ASCII raw tx by txid: ?txid=<64-hex big-endian>
        const char* query = evhttp_uri_get_query(uri);
        if (!query) { evhttp_send_error(req, HTTP_BADREQUEST, "missing ?txid"); evbuffer_free(evb); return; }

        // extract txid=... up to '&'
        const char* p = strstr(query, "txid=");
        if (!p) { evhttp_send_error(req, HTTP_BADREQUEST, "missing txid param"); evbuffer_free(evb); return; }
        p += 5;
        char txid_hex[65]; size_t n = 0;
        while (p[n] && p[n] != '&' && n < 64) { txid_hex[n] = p[n]; n++; }
        txid_hex[n] = '\0';
        if (n != 64) { evhttp_send_error(req, HTTP_BADREQUEST, "invalid txid length"); evbuffer_free(evb); return; }

        //parse big-endian hex -> bytes, then convert to little-endian for cache compare
        uint8_t txid_be[32]; size_t outlen = 0;
        utils_hex_to_bin(txid_hex, txid_be, 64, &outlen);
        if (outlen != 32) { evhttp_send_error(req, HTTP_BADREQUEST, "invalid txid hex"); evbuffer_free(evb); return; }
        uint8_t txid_le[32];
        for (int i = 0; i < 32; ++i) txid_le[i] = txid_be[31 - i];

        int found = 0;
        for (unsigned int i = 0; i < wallet->vec_wtxes->len; i++) {
            dogecoin_wtx* wtx = vector_idx(wallet->vec_wtxes, i);
            if (!wtx || !wtx->tx) continue;
            if (memcmp(wtx->tx_hash_cache, txid_le, 32) != 0) continue;

            // serialize & hex-encode the tx
            cstring* ser = cstr_new_sz(1024);
            if (!ser) { evhttp_send_error(req, HTTP_INTERNAL, "oom"); evbuffer_free(evb); return; }
            dogecoin_tx_serialize(ser, wtx->tx);
            char* hexout = (char*)malloc(ser->len * 2 + 1);
            if (!hexout) { cstr_free(ser, true); evhttp_send_error(req, HTTP_INTERNAL, "oom"); evbuffer_free(evb); return; }
            utils_bin_to_hex((unsigned char*)ser->str, ser->len, hexout);
            cstr_free(ser, true);

            evbuffer_add_printf(evb, "%s\n", hexout);
            free(hexout);
            found = 1;
            break;
        }

        if (!found) { evhttp_send_error(req, HTTP_NOTFOUND, "tx not found"); evbuffer_free(evb); return; }

    } else if (strcmp(path, "/viewTx") == 0) {
        // Print UTXO-style info for a single tx by txid; optional ?vout=<n> or ?n=<n> to filter
        const char* query = evhttp_uri_get_query(uri);
        if (!query) { evhttp_send_error(req, HTTP_BADREQUEST, "missing ?txid"); evbuffer_free(evb); return; }

        // extract txid
        const char* p = strstr(query, "txid=");
        if (!p) { evhttp_send_error(req, HTTP_BADREQUEST, "missing txid param"); evbuffer_free(evb); return; }
        p += 5;
        char txid_hex[65]; size_t n = 0;
        while (p[n] && p[n] != '&' && n < 64) { txid_hex[n] = p[n]; n++; }
        txid_hex[n] = '\0';
        if (n != 64) { evhttp_send_error(req, HTTP_BADREQUEST, "invalid txid length"); evbuffer_free(evb); return; }

        // parse optional vout / n
        int have_vout = 0, want_vout = 0;
        const char* pv = strstr(query, "vout=");
        if (!pv) pv = strstr(query, "n=");
        if (pv) {
            pv += (pv[1] == 'o') ? 5 : 2; // 'vout='=5, 'n='=2
            char numbuf[16]; size_t k = 0;
            while (pv[k] && pv[k] != '&' && k < sizeof(numbuf) - 1) { numbuf[k] = pv[k]; k++; }
            numbuf[k] = '\0';
            want_vout = atoi(numbuf);
            have_vout = 1;
        }

        // utxo->txid bytes are big-endian (display order)
        uint8_t txid_be[32]; size_t outlen = 0;
        utils_hex_to_bin(txid_hex, txid_be, 64, &outlen);
        if (outlen != 32) { evhttp_send_error(req, HTTP_BADREQUEST, "invalid txid hex"); evbuffer_free(evb); return; }

        int found = 0;
        if (HASH_COUNT(wallet->utxos) > 0) {
            dogecoin_utxo* utxo;
            dogecoin_utxo* tmp;
            HASH_ITER(hh, wallet->utxos, utxo, tmp) {
                if (memcmp(utxo->txid, txid_be, 32) != 0) continue;
                if (have_vout && utxo->vout != want_vout) continue;
                found = 1;
                evbuffer_add_printf(evb, "%s\n", "----------------------");
                evbuffer_add_printf(evb, "txid:           %s\n", utils_uint8_to_hex(utxo->txid, sizeof utxo->txid));
                evbuffer_add_printf(evb, "vout:           %d\n", utxo->vout);
                evbuffer_add_printf(evb, "address:        %s\n", utxo->address);
                evbuffer_add_printf(evb, "script_pubkey:  %s\n", utxo->script_pubkey);
                evbuffer_add_printf(evb, "amount:         %s\n", utxo->amount);
                evbuffer_add_printf(evb, "confirmations:  %d\n", utxo->confirmations);
                evbuffer_add_printf(evb, "height:         %d\n", utxo->height);
                evbuffer_add_printf(evb, "spendable:      %d\n", utxo->spendable);
                evbuffer_add_printf(evb, "solvable:       %d\n", utxo->solvable);
            }
        }

        if (!found) {
            evbuffer_add_printf(evb, "No matching UTXOs for txid\n");
        }

    } else if (strcmp(path, "/stats24h") == 0 || strncmp(path, "/stats", 6) == 0) {
    // params: secs=N (default 86400), blocks=M (optional: use last M blocks instead of time)
    uint32_t window = 86400;
    uint32_t limit_blocks = 0;
    const char* q = evhttp_uri_get_query(uri);
    if (q) {
        const char* p = strstr(q, "secs=");
        if (p) {
            p += 5;
            window = (uint32_t)atoi(p);
            if (window == 0) window = 86400;
        }
        const char* b = strstr(q, "blocks=");
        if (b) {
            b += 7;
            limit_blocks = (uint32_t)atoi(b);
        }
    }

    dogecoin_blockindex* tip = client->headers_db->getchaintip(client->headers_db_ctx);
    uint32_t tip_ts = tip ? tip->header.timestamp : (uint32_t)time(NULL);
    uint32_t cutoff = tip_ts > window ? (tip_ts - window) : 0;

    // if stats ring is empty/short and we're headers-only, nudge block sync to backfill recent blocks
    if ((client->stats_ring_len < (limit_blocks ? (int)limit_blocks : 11)) &&
        ((client->stateflags & SPV_FULLBLOCK_SYNC_FLAG) == 0))
    {
        client->stateflags &= ~SPV_HEADER_SYNC_FLAG;
        client->stateflags |=  SPV_FULLBLOCK_SYNC_FLAG;
        client->oldest_item_of_interest = cutoff;        // aim for the requested window
        dogecoin_net_spv_request_headers(client);        // kick the downloader
    }

    // aggregate from ring, newest -> older until cutoff or block limit hit
    uint64_t sum_txs = 0, sum_outputs = 0, sum_out_value = 0, sum_fees = 0, sum_size = 0;
    uint32_t blocks = 0;
    uint64_t fees_buf[SPV_STATS_RING], fee_kb_buf[SPV_STATS_RING];
    size_t fees_n = 0;
    size_t fee_kb_n = 0;

    for (int i = 0; i < client->stats_ring_len; i++) {
        int idx = (client->stats_ring_head - 1 - i + SPV_STATS_RING) % SPV_STATS_RING;
        spv_block_sample *s = &client->stats_ring[idx];
        if (!limit_blocks) {
            if (s->ts < cutoff) break;                  // time window mode
        } else {
            if (blocks >= limit_blocks) break;          // last-N-blocks mode
        }
        blocks++;
        sum_txs      += s->txs;
        sum_outputs  += s->outputs;
        sum_out_value+= s->out_value;
        sum_fees     += s->fees;
        sum_size     += s->size;
        if (fees_n < SPV_STATS_RING) fees_buf[fees_n++] = s->fees;
        if (s->size > 0 && fee_kb_n < SPV_STATS_RING) {
            fee_kb_buf[fee_kb_n++] = (s->fees * 1024) / s->size;
        }
    }

    double tps = window ? ((double)sum_txs / (double)window) : 0.0;

    // median/avg fee per block (in koinu)
    uint64_t median_fee = 0;
    if (fees_n) {
        qsort(fees_buf, fees_n, sizeof(uint64_t), cmp_u64);
        median_fee = (fees_n & 1) ? fees_buf[fees_n/2]
                                  : (fees_buf[fees_n/2 - 1] + fees_buf[fees_n/2]) / 2;
    }
    uint64_t avg_fee = fees_n ? (sum_fees / fees_n) : 0;

    // avg/median fee per kB (in koinu/kB)
    uint64_t avg_fee_per_kb = 0;
    if (sum_size > 0) {
        avg_fee_per_kb = (sum_fees * 1024) / sum_size;
    }
    uint64_t median_fee_per_kb = 0;
    if (fee_kb_n) {
        qsort(fee_kb_buf, fee_kb_n, sizeof(uint64_t), cmp_u64);
        median_fee_per_kb = (fee_kb_n & 1) ? fee_kb_buf[fee_kb_n/2]
                                          : (fee_kb_n > 0) ? (fee_kb_buf[fee_kb_n/2 - 1] + fee_kb_buf[fee_kb_n/2]) / 2
                                                          : 0;
    }

    // stringify (zero-init to avoid garbage)
    char vol_str[32]        = {0};
    char med_fee_str[32]    = {0};
    char avg_fee_str[32]    = {0};
    char med_fee_kb_str[32] = {0};
    char avg_fee_kb_str[32] = {0};
    koinu_to_coins_str(sum_out_value, vol_str);
    koinu_to_coins_str(median_fee,    med_fee_str);
    koinu_to_coins_str(avg_fee,       avg_fee_str);
    koinu_to_coins_str(median_fee_per_kb, med_fee_kb_str);
    koinu_to_coins_str(avg_fee_per_kb,     avg_fee_kb_str);

    evbuffer_add_printf(evb, "=== Stats (window=%u s) ===\n", window);
    evbuffer_add_printf(evb, "blocks: %u\n", blocks);
    evbuffer_add_printf(evb, "transactions: %llu\n", (unsigned long long)sum_txs);
    evbuffer_add_printf(evb, "tps: %.4f\n", tps);
    evbuffer_add_printf(evb, "volume: %s\n", vol_str);
    evbuffer_add_printf(evb, "volume_koinu: %llu\n", (unsigned long long)sum_out_value);
    evbuffer_add_printf(evb, "median_fee_per_block: %s\n", med_fee_str);
    evbuffer_add_printf(evb, "avg_fee_per_block: %s\n", avg_fee_str);
    evbuffer_add_printf(evb, "outputs: %llu\n", (unsigned long long)sum_outputs);
    evbuffer_add_printf(evb, "bytes: %llu\n", (unsigned long long)sum_size);
    evbuffer_add_printf(evb, "median_fee_per_kb: %s\n", med_fee_kb_str);
    evbuffer_add_printf(evb, "avg_fee_per_kb: %s\n", avg_fee_kb_str);
    } else if (strcmp(path, "/chainStats") == 0) {
        dogecoin_blockindex* tip = client->headers_db->getchaintip(client->headers_db_ctx);

        // headers file size if available
        long headers_bytes = 0;
        {
            dogecoin_headers_db* hdb = (dogecoin_headers_db*)client->headers_db_ctx;
            FILE* hf = hdb ? hdb->headers_tree_file : NULL;
            if (hf) {
                long cur = ftell(hf);
                fseek(hf, 0, SEEK_END);
                headers_bytes = ftell(hf);
                if (cur >= 0) fseek(hf, cur, SEEK_SET);
            }
        }

        char total_out_str[32]  = {0};
        char total_fees_str[32] = {0};
        koinu_to_coins_str(client->stats_out_value_total, total_out_str);
        koinu_to_coins_str(client->stats_fees_total, total_fees_str);

        evbuffer_add_printf(evb, "=== Chain Stats (SPV session) ===\n");
        if (tip) {
            char ts[32] = {0};
            time_t t = tip->header.timestamp;
            struct tm *p = localtime(&t);
            if (p) strftime(ts, sizeof(ts), "%F %T", p);
            evbuffer_add_printf(evb, "tip_height: %d\n", tip->height);
            evbuffer_add_printf(evb, "tip_time: %s\n", ts[0]?ts:"unknown");
            evbuffer_add_printf(evb, "tip_bits: 0x%08x\n", (unsigned int)tip->header.bits);
        }
        evbuffer_add_printf(evb, "headers_bytes: %ld\n", headers_bytes);

        // totals reflect blocks we actually parsed this run
        evbuffer_add_printf(evb, "blocks_total: %llu\n", (unsigned long long)client->stats_blocks_total);
        evbuffer_add_printf(evb, "transactions_total: %llu\n", (unsigned long long)client->stats_txs_total);
        evbuffer_add_printf(evb, "outputs_total: %llu\n", (unsigned long long)client->stats_outputs_total);
        evbuffer_add_printf(evb, "output_value_total: %s\n", total_out_str);
        evbuffer_add_printf(evb, "fees_total: %s\n", total_fees_str);
        evbuffer_add_printf(evb, "block_bytes_total: %llu\n", (unsigned long long)client->stats_block_bytes_total);

        // simple approximate on-disk 'size' visible to SPV
        unsigned long long approx_chain_bytes =
            (unsigned long long)headers_bytes + (unsigned long long)client->stats_block_bytes_total;
        evbuffer_add_printf(evb, "approx_chain_bytes: %llu\n", approx_chain_bytes);

        // uptime seconds since SPV client started
        time_t now = time(NULL);
        unsigned long uptime = client->start_ts && now >= (time_t)client->start_ts
                             ? (unsigned long)(now - (time_t)client->start_ts) : 0UL;
        evbuffer_add_printf(evb, "uptime_sec: %lu\n", uptime);

    } else if (strcmp(path, "/smpvStats") == 0) {
        // Lightweight SMPV status/counters for dashboard
        dogecoin_bool enabled = (client->smpv_enabled && client->smpv_ctx) ? true : false;
        uint32_t mempool_txs = 0, watchers = 0, confirmed = 0, unconfirmed = 0;
        uint64_t total_bytes = 0, last_seen_ts = 0;
        // script-type aggregates across current mempool set
        uint64_t p2pk=0, p2pkh=0, p2sh=0, multisig=0, opret=0, nonstd=0, vout_total=0, coinbase_cnt=0;

        if (enabled) {
            dogecoin_smpv_client* smpv = (dogecoin_smpv_client*)client->smpv_ctx;
            mempool_txs  = smpv->mempool_tx_count;
            watchers     = smpv->watcher_count;
            confirmed    = smpv->confirmed_count;
            unconfirmed  = smpv->unconfirmed_count;
            total_bytes  = smpv->total_bytes;
            last_seen_ts = smpv->last_seen_ts;

            // sum per-tx script classifications
            for (uint32_t i = 0; i < smpv->mempool_tx_count; i++) {
                const dogecoin_smpv_tx* t = &smpv->mempool_txs[i];
                p2pk     += t->pubkey_out;
                p2pkh    += t->p2pkh_out;
                p2sh     += t->p2sh_out;
                multisig += t->multisig_out;
                opret    += t->opreturn_out;
                nonstd   += t->nonstandard_out;
                vout_total += t->vout_count;
                if (t->is_coinbase) coinbase_cnt++;
            }
        }
        const char* last_txid = "";
        uint32_t last_ts = 0;
        dogecoin_smpv_client* smpv = (dogecoin_smpv_client*)client->smpv_ctx;
        if (smpv && smpv->mempool_tx_count > 0) {
            const dogecoin_smpv_tx* last = &smpv->mempool_txs[smpv->mempool_tx_count - 1];
            if (last->txid) last_txid = last->txid;
            if (last->timestamp) last_ts = last->timestamp;
        }
        const unsigned long age = last_ts ? (unsigned long)(time(NULL) - last_ts) : 0;

        evbuffer_add_printf(evb, "=== SMPV ===\n");
        evbuffer_add_printf(evb, "enabled: %d\n", enabled ? 1 : 0);
        evbuffer_add_printf(evb, "mempool_txs: %u\n", mempool_txs);
        evbuffer_add_printf(evb, "watchers: %u\n", watchers);
        evbuffer_add_printf(evb, "confirmed: %u\n", confirmed);
        evbuffer_add_printf(evb, "unconfirmed: %u\n", unconfirmed);
        evbuffer_add_printf(evb, "total_bytes: %llu\n", (unsigned long long)total_bytes);
        evbuffer_add_printf(evb, "last_seen_ts: %llu\n", (unsigned long long)last_seen_ts);
        evbuffer_add_printf(evb, "last_seen_age_sec: %lu\n", age);
        evbuffer_add_printf(evb, "last_seen_txid: %s\n", last_txid);
        // script-type totals
        evbuffer_add_printf(evb, "types_p2pk: %llu\n", (unsigned long long)p2pk);
        evbuffer_add_printf(evb, "types_p2pkh: %llu\n", (unsigned long long)p2pkh);
        evbuffer_add_printf(evb, "types_p2sh: %llu\n", (unsigned long long)p2sh);
        evbuffer_add_printf(evb, "types_multisig: %llu\n", (unsigned long long)multisig);
        evbuffer_add_printf(evb, "types_op_return: %llu\n", (unsigned long long)opret);
        evbuffer_add_printf(evb, "types_nonstandard: %llu\n", (unsigned long long)nonstd);
        evbuffer_add_printf(evb, "types_vout_total: %llu\n", (unsigned long long)vout_total);
        evbuffer_add_printf(evb, "coinbase_txs: %llu\n", (unsigned long long)coinbase_cnt);
    } else if (strncmp(path, "/smpvTx", 7) == 0) {
        // GET /smpvTx?id=<txid>  -> JSON for a single mempool tx
        if (!client->smpv_enabled || !client->smpv_ctx) {
            evhttp_send_error(req, HTTP_BADREQUEST, "SMPV disabled");
            evbuffer_free(evb);
            return;
        }
        const char* q = evhttp_uri_get_query(uri);
        const char* id = NULL;
        if (q) {
            const char* p = strstr(q, "id=");
            if (p) { id = p + 3; }
        }
        if (!id || strlen(id) < 6) {
            evhttp_send_error(req, HTTP_BADREQUEST, "missing or invalid id");
            evbuffer_free(evb);
            return;
        }
        char txid[129] = {0};
        size_t n = 0;
        while (id[n] && id[n] != '&' && n < sizeof(txid)-1) { txid[n] = id[n]; n++; }

        dogecoin_smpv_client* smpv = (dogecoin_smpv_client*)client->smpv_ctx;
        dogecoin_smpv_tx* tx = dogecoin_smpv_get_tx(smpv, txid);
        if (!tx) {
            evhttp_send_error(req, HTTP_NOTFOUND, "tx not found");
            evbuffer_free(evb);
            return;
        }
        char* json = dogecoin_smpv_tx_to_json(tx);
        if (!json) {
            evhttp_send_error(req, HTTP_INTERNAL, "serialization error");
            evbuffer_free(evb);
            return;
        }
        struct evkeyvalq* headers = evhttp_request_get_output_headers(req);
        evhttp_add_header(headers, "Content-Type", "application/json");
        evbuffer_add_printf(evb, "%s", json);
        dogecoin_free(json);
    } else {
        evhttp_send_error(req, HTTP_NOTFOUND, "Not Found");
        evbuffer_free(evb);
        return;
    }

    // Set Content-Type header if not already set
    struct evkeyvalq* headers = evhttp_request_get_output_headers(req);
    if (!evhttp_find_header(headers, "Content-Type")) {
        evhttp_add_header(headers, "Content-Type", "text/plain");
    }

    evhttp_send_reply(req, HTTP_OK, "OK", evb);
    evbuffer_free(evb);
}
