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

#include <dogecoin/sweep.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/bip38.h>
#include <dogecoin/key.h>
#include <dogecoin/address.h>
#include <dogecoin/transaction.h>
#include <dogecoin/koinu.h>
#include <dogecoin/tx.h>
#include <dogecoin/cstr.h>
#include <dogecoin/script.h>
#include <dogecoin/utils.h>
#include <dogecoin/mem.h>
#include <dogecoin/sha2.h>
#include <dogecoin/rmd160.h>
#include <dogecoin/constants.h>
#include <dogecoin/ecc.h>
#ifdef WITH_WALLET
#include <dogecoin/wallet.h>
#endif
#ifdef WITH_NET
#include <dogecoin/net.h>
#endif
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static dogecoin_bool sweep_pubkey_from_privkey(
    const uint8_t* private_key,
    dogecoin_bool compressed,
    dogecoin_pubkey* pubkey_out)
{
    if (!private_key || !pubkey_out) {
        return false;
    }
    dogecoin_pubkey_init(pubkey_out);
    size_t pubkey_len = compressed ? DOGECOIN_ECKEY_COMPRESSED_LENGTH : DOGECOIN_ECKEY_UNCOMPRESSED_LENGTH;
    dogecoin_ecc_get_pubkey(private_key, pubkey_out->pubkey, &pubkey_len, compressed);
    pubkey_out->compressed = compressed;
    return true;
}

static void sweep_secure_free(char* s)
{
    if (!s) {
        return;
    }
    dogecoin_mem_zero(s, strlen(s));
    dogecoin_free(s);
}

static void sweep_paper_wallet_clear_sensitive(dogecoin_paper_wallet* wallet)
{
    if (!wallet) {
        return;
    }
    sweep_secure_free(wallet->private_key_wif);
    wallet->private_key_wif = NULL;
    sweep_secure_free(wallet->private_key_hex);
    wallet->private_key_hex = NULL;
    sweep_secure_free(wallet->encrypted_private_key);
    wallet->encrypted_private_key = NULL;
    sweep_secure_free(wallet->passphrase);
    wallet->passphrase = NULL;
    sweep_secure_free(wallet->address);
    wallet->address = NULL;
}

static void sweep_result_fail(dogecoin_sweep_result* r, const char* msg)
{
    if (!r || !msg) return;
    if (r->error_message) dogecoin_free(r->error_message);
    r->error_message = dogecoin_calloc(1, strlen(msg) + 1);
    if (r->error_message) strcpy(r->error_message, msg);
    r->success = false;
}

/* Sweep txs are small; use a modest heap buffer (not TXHEXMAXLEN) to ease armhf CI. */
#define SWEEP_TX_HEX_BUF_SIZE 65536U

static char* sweep_tx_hex_alloc(void)
{
    return (char*)dogecoin_calloc(1, SWEEP_TX_HEX_BUF_SIZE);
}

static void sweep_options_clear_utxos(dogecoin_sweep_options* options)
{
    size_t i;
    if (!options || !options->utxos) {
        if (options) {
            options->utxo_count = 0;
        }
        return;
    }
    for (i = 0; i < options->utxo_count; i++) {
        if (options->utxos[i].txid) {
            dogecoin_free(options->utxos[i].txid);
        }
        if (options->utxos[i].amount_doge) {
            dogecoin_free(options->utxos[i].amount_doge);
        }
    }
    dogecoin_free(options->utxos);
    options->utxos = NULL;
    options->utxo_count = 0;
}

static void sweep_options_sync_legacy(dogecoin_sweep_options* options)
{
    if (!options) {
        return;
    }
    if (options->utxo_txid) {
        dogecoin_free(options->utxo_txid);
        options->utxo_txid = NULL;
    }
    if (options->utxo_total_doge) {
        dogecoin_free(options->utxo_total_doge);
        options->utxo_total_doge = NULL;
    }
    options->utxo_vout = -1;
    if (options->utxo_count == 0) {
        return;
    }
    options->utxo_txid = dogecoin_calloc(1, strlen(options->utxos[0].txid) + 1);
    options->utxo_total_doge = dogecoin_calloc(1, strlen(options->utxos[0].amount_doge) + 1);
    if (options->utxo_txid && options->utxo_total_doge) {
        strcpy(options->utxo_txid, options->utxos[0].txid);
        strcpy(options->utxo_total_doge, options->utxos[0].amount_doge);
        options->utxo_vout = options->utxos[0].vout;
    }
}

static dogecoin_bool sweep_options_utxo_ok(const dogecoin_sweep_options* o)
{
    size_t i;
    if (!o || o->utxo_count == 0) {
        return false;
    }
    for (i = 0; i < o->utxo_count; i++) {
        const dogecoin_sweep_utxo* u = &o->utxos[i];
        if (!u->txid || !u->txid[0] || u->vout < 0 || !u->amount_doge || !u->amount_doge[0]) {
            return false;
        }
    }
    return true;
}

static uint64_t sweep_options_total_koinu(const dogecoin_sweep_options* options)
{
    uint64_t total = 0;
    size_t i;
    for (i = 0; i < options->utxo_count; i++) {
        total += coins_to_koinu_str(options->utxos[i].amount_doge);
    }
    return total;
}

static size_t sweep_estimate_vsize(size_t input_count)
{
    if (input_count == 0) {
        input_count = 1;
    }
    /* version + varints + N signed P2PKH inputs + 1 P2PKH output + locktime */
    return 10u + input_count * 180u + 34u;
}

static dogecoin_bool sweep_compute_amounts(
    const dogecoin_sweep_options* options,
    uint64_t* fee_koinu_out,
    uint64_t* out_koinu_out,
    char* fee_doge,
    char* out_doge)
{
    uint64_t total_koinu = sweep_options_total_koinu(options);
    size_t est_vsize = sweep_estimate_vsize(options->utxo_count);
    uint64_t fee_koinu = options->fee_per_byte * est_vsize;
    if (fee_koinu < options->min_fee) {
        fee_koinu = options->min_fee;
    }
    if (fee_koinu > options->max_fee) {
        fee_koinu = options->max_fee;
    }
    if (total_koinu <= fee_koinu) {
        return false;
    }
    uint64_t out_koinu = total_koinu - fee_koinu;
    if (!koinu_to_coins_str(fee_koinu, fee_doge)) {
        return false;
    }
    if (!koinu_to_coins_str(out_koinu, out_doge)) {
        return false;
    }
    *fee_koinu_out = fee_koinu;
    *out_koinu_out = out_koinu;
    return true;
}

static void sweep_apply_tx_flags(const dogecoin_sweep_options* options, int txindex)
{
    working_transaction* tx;
    size_t i;
    if (!options) {
        return;
    }
    tx = find_transaction(txindex);
    if (!tx || !tx->transaction) {
        return;
    }
    if (options->locktime) {
        tx->transaction->locktime = options->locktime;
    }
    if (options->use_rbf) {
        for (i = 0; i < tx->transaction->vin->len; i++) {
            dogecoin_tx_in* vin = vector_idx(tx->transaction->vin, i);
            vin->sequence = 0xfffffffd;
        }
    }
}

/* Full P2PKH scriptPubKey hex: 6 + 40 + 4 hex chars + NUL (see transaction_tests.c). */
#define SWEEP_SCRIPTPUBKEY_HEX_LEN (40 + 6 + 4 + 1)

static char* sweep_script_pubkey_from_wallet(const dogecoin_paper_wallet* wallet)
{
    char* script;
    if (!wallet || !wallet->address) {
        return NULL;
    }
    script = dogecoin_calloc(1, SWEEP_SCRIPTPUBKEY_HEX_LEN);
    if (!script) {
        return NULL;
    }
    if (!dogecoin_p2pkh_address_to_pubkey_hash(wallet->address, script)) {
        dogecoin_free(script);
        return NULL;
    }
    return script;
}

static dogecoin_bool sweep_wallet_get_wif(
    const dogecoin_paper_wallet* wallet,
    char* wif_out,
    size_t wif_size)
{
    return dogecoin_paper_wallet_get_wif(wallet, wif_out, wif_size);
}

static dogecoin_bool sweep_build_unsigned_tx(
    const dogecoin_sweep_options* options,
    const char* fee_doge,
    const char* out_doge,
    int* txindex_out)
{
    char dest_copy[P2PKHLEN];
    char total_copy[64];
    size_t i;
    int txindex;

    strncpy(dest_copy, options->destination_address, sizeof(dest_copy) - 1);
    dest_copy[sizeof(dest_copy) - 1] = '\0';
    if (!koinu_to_coins_str(sweep_options_total_koinu(options), total_copy)) {
        return false;
    }

    /* Working-transaction table is global; clear stale entries from prior API use. */
    remove_all();

    txindex = start_transaction();
    for (i = 0; i < options->utxo_count; i++) {
        if (!add_utxo(txindex, options->utxos[i].txid, options->utxos[i].vout)) {
            clear_transaction(txindex);
            return false;
        }
    }
    if (!add_output(txindex, dest_copy, (char*)out_doge)) {
        clear_transaction(txindex);
        return false;
    }
    if (!finalize_transaction(txindex, dest_copy, (char*)fee_doge, total_copy, NULL)) {
        clear_transaction(txindex);
        return false;
    }
    sweep_apply_tx_flags(options, txindex);
    *txindex_out = txindex;
    return true;
}

static dogecoin_bool sweep_sign_txindex(
    int txindex,
    const dogecoin_paper_wallet* const* wallets,
    size_t wallet_count,
    char* hexbuf,
    size_t hexbuf_cap)
{
    working_transaction* tx;
    size_t vin_cnt;
    size_t i;

    if (!wallets || wallet_count == 0 || !hexbuf) {
        return false;
    }

    tx = find_transaction(txindex);
    if (!tx || !tx->transaction) {
        return false;
    }
    vin_cnt = tx->transaction->vin->len;

    if (wallet_count == 1) {
        char wif[PRIVKEYWIFLEN];
        char* script_pubkey;
        if (!sweep_wallet_get_wif(wallets[0], wif, sizeof(wif))) {
            return false;
        }
        script_pubkey = sweep_script_pubkey_from_wallet(wallets[0]);
        if (!script_pubkey) {
            return false;
        }
        if (!sign_transaction_ex(txindex, script_pubkey, wif, hexbuf, hexbuf_cap)) {
            dogecoin_free(script_pubkey);
            return false;
        }
        dogecoin_free(script_pubkey);
        return true;
    }

    if (wallet_count != vin_cnt) {
        return false;
    }

    for (i = 0; i < vin_cnt; i++) {
        char wif[PRIVKEYWIFLEN];
        char* script_pubkey;
        if (!sweep_wallet_get_wif(wallets[i], wif, sizeof(wif))) {
            return false;
        }
        script_pubkey = sweep_script_pubkey_from_wallet(wallets[i]);
        if (!script_pubkey) {
            return false;
        }
        if (!sign_indexed_raw_transaction_ex(
                txindex, (int)i, script_pubkey, 1, wif, hexbuf, hexbuf_cap)) {
            dogecoin_free(script_pubkey);
            return false;
        }
        dogecoin_free(script_pubkey);
    }
    return true;
}

static dogecoin_bool sweep_fill_result_from_hex(
    dogecoin_sweep_result* result,
    const dogecoin_sweep_options* options,
    const char* hexbuf,
    int hexlen,
    uint64_t out_koinu,
    uint64_t fee_koinu)
{
    dogecoin_tx* stx;
    uint8_t* bindata;
    size_t binlen;
    uint256_t txhash;
    char txidhex[65];

    stx = dogecoin_tx_new();
    if (!stx) {
        return false;
    }
    bindata = dogecoin_malloc((size_t)hexlen / 2 + 1);
    if (!bindata) {
        dogecoin_tx_free(stx);
        return false;
    }
    binlen = 0;
    utils_hex_to_bin(hexbuf, bindata, (size_t)hexlen, &binlen);
    if (!dogecoin_tx_deserialize(bindata, binlen, stx, NULL)) {
        dogecoin_free(bindata);
        dogecoin_tx_free(stx);
        return false;
    }
    dogecoin_free(bindata);
    dogecoin_tx_hash(stx, txhash);
    dogecoin_tx_free(stx);

    utils_bin_to_hex((unsigned char*)txhash, sizeof(txhash), txidhex);
    utils_reverse_hex(txidhex, 64);
    txidhex[64] = '\0';

    result->transaction_hex = dogecoin_calloc(1, (size_t)hexlen + 1);
    result->transaction_id = dogecoin_calloc(1, strlen(txidhex) + 1);
    result->destination_address = dogecoin_calloc(1, strlen(options->destination_address) + 1);
    if (!result->transaction_hex || !result->transaction_id || !result->destination_address) {
        if (result->transaction_hex) {
            dogecoin_free(result->transaction_hex);
        }
        if (result->transaction_id) {
            dogecoin_free(result->transaction_id);
        }
        if (result->destination_address) {
            dogecoin_free(result->destination_address);
        }
        result->transaction_hex = NULL;
        result->transaction_id = NULL;
        result->destination_address = NULL;
        return false;
    }
    memcpy(result->transaction_hex, hexbuf, (size_t)hexlen + 1);
    strcpy(result->transaction_id, txidhex);
    strcpy(result->destination_address, options->destination_address);
    result->amount_swept = out_koinu;
    result->fee_paid = fee_koinu;
    result->success = true;
    return true;
}

static dogecoin_sweep_result* sweep_wallets_impl(
    const dogecoin_paper_wallet* const* wallets,
    size_t wallet_count,
    const dogecoin_sweep_options* options)
{
    dogecoin_sweep_result* result = dogecoin_sweep_result_new();
    char fee_doge[64];
    char out_doge[64];
    uint64_t fee_koinu = 0;
    uint64_t out_koinu = 0;
    int txindex = 0;
    char* hexbuf = NULL;
    int hexlen;
    size_t i;

    if (!result) {
        return NULL;
    }
    if (!wallets || wallet_count == 0 || !options) {
        sweep_result_fail(result, "Invalid wallet or options");
        return result;
    }
    for (i = 0; i < wallet_count; i++) {
        if (!dogecoin_paper_wallet_is_valid(wallets[i])) {
            sweep_result_fail(result, "Invalid paper wallet");
            return result;
        }
    }
    if (!options->destination_address) {
        sweep_result_fail(result, "No destination address specified");
        return result;
    }
    if (!sweep_options_utxo_ok(options)) {
        sweep_result_fail(result,
            "No UTXO specified: use dogecoin_sweep_options_set_utxo or add_utxo");
        return result;
    }
    if (wallet_count > 1 && options->utxo_count != wallet_count) {
        sweep_result_fail(result, "Multi-wallet sweep requires one UTXO per wallet");
        return result;
    }
    if (!sweep_compute_amounts(options, &fee_koinu, &out_koinu, fee_doge, out_doge)) {
        sweep_result_fail(result, "Fee exceeds input value or amount conversion failed");
        return result;
    }
    if (!sweep_build_unsigned_tx(options, fee_doge, out_doge, &txindex)) {
        sweep_result_fail(result, "Building unsigned sweep transaction failed");
        return result;
    }
    hexbuf = sweep_tx_hex_alloc();
    if (!hexbuf) {
        clear_transaction(txindex);
        sweep_result_fail(result, "out of memory");
        return result;
    }
    if (!sweep_sign_txindex(txindex, wallets, wallet_count, hexbuf, SWEEP_TX_HEX_BUF_SIZE)) {
        clear_transaction(txindex);
        dogecoin_free(hexbuf);
        sweep_result_fail(result, "Signing sweep transaction failed");
        return result;
    }
    hexlen = (int)strlen(hexbuf);
    if (hexlen <= 0) {
        clear_transaction(txindex);
        dogecoin_free(hexbuf);
        sweep_result_fail(result, "Signed transaction hex is empty");
        return result;
    }
    if (!sweep_fill_result_from_hex(result, options, hexbuf, hexlen, out_koinu, fee_koinu)) {
        clear_transaction(txindex);
        dogecoin_free(hexbuf);
        sweep_result_fail(result, "out of memory");
        return result;
    }
    dogecoin_free(hexbuf);
    clear_transaction(txindex);
    return result;
}

/* Initialize a paper wallet structure */
dogecoin_paper_wallet* dogecoin_paper_wallet_new(void) {
    dogecoin_paper_wallet* wallet = dogecoin_calloc(1, sizeof(dogecoin_paper_wallet));
    if (!wallet) return NULL;
    
    wallet->private_key_wif = NULL;
    wallet->private_key_hex = NULL;
    wallet->encrypted_private_key = NULL;
    wallet->passphrase = NULL;
    wallet->address = NULL;
    wallet->compressed = false;
    wallet->is_encrypted = false;
    wallet->chain_params = NULL;
    
    return wallet;
}

/* Free a paper wallet structure */
void dogecoin_paper_wallet_free(dogecoin_paper_wallet* wallet) {
    if (!wallet) return;

    sweep_paper_wallet_clear_sensitive(wallet);

    dogecoin_free(wallet);
}

/* Initialize a sweep result structure */
dogecoin_sweep_result* dogecoin_sweep_result_new(void) {
    dogecoin_sweep_result* result = dogecoin_calloc(1, sizeof(dogecoin_sweep_result));
    if (!result) return NULL;
    
    result->success = false;
    result->error_message = NULL;
    result->transaction_hex = NULL;
    result->transaction_id = NULL;
    result->amount_swept = 0;
    result->fee_paid = 0;
    result->destination_address = NULL;
    
    return result;
}

/* Free a sweep result structure */
void dogecoin_sweep_result_free(dogecoin_sweep_result* result) {
    if (!result) return;
    
    if (result->error_message) {
        dogecoin_free(result->error_message);
    }
    if (result->transaction_hex) {
        dogecoin_free(result->transaction_hex);
    }
    if (result->transaction_id) {
        dogecoin_free(result->transaction_id);
    }
    if (result->destination_address) {
        dogecoin_free(result->destination_address);
    }
    
    dogecoin_free(result);
}

/* Initialize sweep options with defaults */
dogecoin_sweep_options* dogecoin_sweep_options_new(const dogecoin_chainparams* chain_params) {
    dogecoin_sweep_options* options = dogecoin_calloc(1, sizeof(dogecoin_sweep_options));
    if (!options) return NULL;
    
    options->destination_address = NULL;
    options->fee_per_byte = DOGECOIN_SWEEP_DEFAULT_FEE_PER_BYTE;
    options->min_fee = DOGECOIN_SWEEP_DEFAULT_MIN_FEE;
    options->max_fee = DOGECOIN_SWEEP_DEFAULT_MAX_FEE;
    options->use_rbf = false;
    options->locktime = 0;
    options->chain_params = chain_params;
    options->utxos = NULL;
    options->utxo_count = 0;
    options->utxo_txid = NULL;
    options->utxo_vout = -1;
    options->utxo_total_doge = NULL;
    
    return options;
}

/* Free sweep options */
void dogecoin_sweep_options_free(dogecoin_sweep_options* options) {
    if (!options) return;
    
    if (options->destination_address) {
        dogecoin_free(options->destination_address);
    }
    sweep_options_clear_utxos(options);
    if (options->utxo_txid) {
        dogecoin_free(options->utxo_txid);
    }
    if (options->utxo_total_doge) {
        dogecoin_free(options->utxo_total_doge);
    }
    
    dogecoin_free(options);
}

/* Set paper wallet from WIF private key */
dogecoin_bool dogecoin_paper_wallet_set_wif(
    dogecoin_paper_wallet* wallet,
    const char* wif_private_key,
    const dogecoin_chainparams* chain_params
) {
    if (!wallet || !wif_private_key || !chain_params) return false;

    sweep_paper_wallet_clear_sensitive(wallet);
    
    uint8_t private_key[DOGECOIN_ECKEY_PKEY_LENGTH];
    dogecoin_bool compressed = true;
    if (!dogecoin_bip38_wif_to_private_key(wif_private_key, chain_params, private_key, &compressed)) {
        return false;
    }

    dogecoin_pubkey pubkey;
    if (!sweep_pubkey_from_privkey(private_key, compressed, &pubkey)) {
        dogecoin_mem_zero(private_key, sizeof(private_key));
        return false;
    }

    char address[P2PKHLEN];
    if (!dogecoin_pubkey_getaddr_p2pkh(&pubkey, chain_params, address)) {
        dogecoin_mem_zero(private_key, sizeof(private_key));
        return false;
    }
    dogecoin_mem_zero(private_key, sizeof(private_key));
    
    /* Set wallet properties */
    wallet->private_key_wif = dogecoin_calloc(1, strlen(wif_private_key) + 1);
    if (!wallet->private_key_wif) return false;
    strcpy(wallet->private_key_wif, wif_private_key);
    
    wallet->address = dogecoin_calloc(1, strlen(address) + 1);
    if (!wallet->address) {
        sweep_secure_free(wallet->private_key_wif);
        wallet->private_key_wif = NULL;
        return false;
    }
    strcpy(wallet->address, address);
    
    wallet->compressed = compressed;
    wallet->is_encrypted = false;
    wallet->chain_params = chain_params;
    
    return true;
}

/* Set paper wallet from hex private key */
dogecoin_bool dogecoin_paper_wallet_set_hex(
    dogecoin_paper_wallet* wallet,
    const char* hex_private_key,
    dogecoin_bool compressed,
    const dogecoin_chainparams* chain_params
) {
    if (!wallet || !hex_private_key || !chain_params) return false;

    sweep_paper_wallet_clear_sensitive(wallet);
    
    /* Convert hex to bytes */
    uint8_t private_key[DOGECOIN_ECKEY_PKEY_LENGTH];
    size_t private_key_len;
    utils_hex_to_bin(hex_private_key, private_key, strlen(hex_private_key), &private_key_len);
    if (private_key_len != DOGECOIN_ECKEY_PKEY_LENGTH) {
        return false;
    }
    
    dogecoin_pubkey pubkey;
    if (!sweep_pubkey_from_privkey(private_key, compressed, &pubkey)) {
        dogecoin_mem_zero(private_key, sizeof(private_key));
        return false;
    }
    
    char address[P2PKHLEN];
    if (!dogecoin_pubkey_getaddr_p2pkh(&pubkey, chain_params, address)) {
        dogecoin_mem_zero(private_key, sizeof(private_key));
        return false;
    }

    dogecoin_mem_zero(private_key, sizeof(private_key));

    /* Set wallet properties */
    wallet->private_key_hex = dogecoin_calloc(1, strlen(hex_private_key) + 1);
    if (!wallet->private_key_hex) return false;
    strcpy(wallet->private_key_hex, hex_private_key);
    
    wallet->address = dogecoin_calloc(1, strlen(address) + 1);
    if (!wallet->address) {
        sweep_secure_free(wallet->private_key_hex);
        wallet->private_key_hex = NULL;
        return false;
    }
    strcpy(wallet->address, address);
    
    wallet->compressed = compressed;
    wallet->is_encrypted = false;
    wallet->chain_params = chain_params;
    
    return true;
}

/* Set paper wallet from BIP38 encrypted private key */
dogecoin_bool dogecoin_paper_wallet_set_encrypted(
    dogecoin_paper_wallet* wallet,
    const char* encrypted_private_key,
    const char* passphrase,
    const dogecoin_chainparams* chain_params
) {
    if (!wallet || !encrypted_private_key || !passphrase || !chain_params) return false;

    sweep_paper_wallet_clear_sensitive(wallet);
    
    /* Decrypt private key (Dogecoin-mainnet BIP38 semantics). */
    uint8_t private_key[DOGECOIN_ECKEY_PKEY_LENGTH];
    dogecoin_bool compressed;
    if (!dogecoin_bip38_decrypt_ex(
            encrypted_private_key,
            passphrase,
            BIP38_ADDRESS_MATCH_MAINNET,
            private_key,
            &compressed)) {
        return false;
    }

    dogecoin_pubkey pubkey;
    if (!sweep_pubkey_from_privkey(private_key, compressed, &pubkey)) {
        dogecoin_mem_zero(private_key, sizeof(private_key));
        return false;
    }

    char address[P2PKHLEN];
    if (!dogecoin_pubkey_getaddr_p2pkh(&pubkey, chain_params, address)) {
        dogecoin_mem_zero(private_key, sizeof(private_key));
        return false;
    }

    if (!dogecoin_bip38_verify_address_hash(encrypted_private_key, address)) {
        dogecoin_mem_zero(private_key, sizeof(private_key));
        return false;
    }

    /* Set wallet properties */
    wallet->encrypted_private_key = dogecoin_calloc(1, strlen(encrypted_private_key) + 1);
    if (!wallet->encrypted_private_key) {
        dogecoin_mem_zero(private_key, sizeof(private_key));
        return false;
    }
    strcpy(wallet->encrypted_private_key, encrypted_private_key);

    wallet->passphrase = dogecoin_calloc(1, strlen(passphrase) + 1);
    if (!wallet->passphrase) {
        sweep_secure_free(wallet->encrypted_private_key);
        dogecoin_mem_zero(private_key, sizeof(private_key));
        return false;
    }
    strcpy(wallet->passphrase, passphrase);

    wallet->address = dogecoin_calloc(1, strlen(address) + 1);
    if (!wallet->address) {
        sweep_secure_free(wallet->encrypted_private_key);
        sweep_secure_free(wallet->passphrase);
        dogecoin_mem_zero(private_key, sizeof(private_key));
        return false;
    }
    strcpy(wallet->address, address);
    
    wallet->compressed = compressed;
    wallet->is_encrypted = true;
    wallet->chain_params = chain_params;

    dogecoin_mem_zero(private_key, sizeof(private_key));
    return true;
}

/* Get the address from a paper wallet */
dogecoin_bool dogecoin_paper_wallet_get_address(
    const dogecoin_paper_wallet* wallet,
    char* address_out,
    size_t address_size
) {
    if (!wallet || !address_out || !wallet->address) return false;
    
    if (strlen(wallet->address) >= address_size) return false;
    
    strcpy(address_out, wallet->address);
    return true;
}

/* Get the private key from a paper wallet */
dogecoin_bool dogecoin_paper_wallet_get_private_key(
    const dogecoin_paper_wallet* wallet,
    uint8_t* private_key_out
) {
    if (!wallet || !private_key_out) return false;
    
    if (wallet->private_key_hex) {
        /* Convert hex to bytes */
        size_t private_key_len;
        utils_hex_to_bin(wallet->private_key_hex, private_key_out, strlen(wallet->private_key_hex), &private_key_len);
        return (private_key_len == DOGECOIN_ECKEY_PKEY_LENGTH);
    } else if (wallet->encrypted_private_key && wallet->passphrase) {
        /* Decrypt private key */
        dogecoin_bool compressed;
        return dogecoin_bip38_decrypt(wallet->encrypted_private_key, wallet->passphrase, private_key_out, &compressed);
    } else if (wallet->private_key_wif) {
        /* Decode WIF to get private key */
        dogecoin_key key;
        if (!wallet->chain_params) {
            return false;
        }
        if (!dogecoin_privkey_decode_wif(wallet->private_key_wif, wallet->chain_params, &key)) {
            return false;
        }
        memcpy(private_key_out, key.privkey, DOGECOIN_ECKEY_PKEY_LENGTH);
        dogecoin_privkey_cleanse(&key);
        return true;
    }

    return false;
}

/* Get the WIF private key from a paper wallet */
dogecoin_bool dogecoin_paper_wallet_get_wif(
    const dogecoin_paper_wallet* wallet,
    char* wif_out,
    size_t wif_size
) {
    if (!wallet || !wif_out) return false;
    
    if (wallet->private_key_wif) {
        if (strlen(wallet->private_key_wif) >= wif_size) return false;
        strcpy(wif_out, wallet->private_key_wif);
        return true;
    }
    
    /* Convert from other formats */
    uint8_t private_key[DOGECOIN_ECKEY_PKEY_LENGTH];
    if (!dogecoin_paper_wallet_get_private_key(wallet, private_key)) {
        return false;
    }
    
    size_t wif_len = wif_size;
    if (!dogecoin_bip38_private_key_to_wif(
            private_key,
            wallet->chain_params,
            wallet->compressed,
            wif_out,
            &wif_len)) {
        dogecoin_mem_zero(private_key, sizeof(private_key));
        return false;
    }
    dogecoin_mem_zero(private_key, sizeof(private_key));
    return true;
}

/* Check if a paper wallet is valid */
dogecoin_bool dogecoin_paper_wallet_is_valid(const dogecoin_paper_wallet* wallet) {
    if (!wallet) return false;
    
    /* Check if we have at least one private key format */
    if (!wallet->private_key_wif && !wallet->private_key_hex && !wallet->encrypted_private_key) {
        return false;
    }
    
    /* Check if we have an address */
    if (!wallet->address) return false;

    if (wallet->private_key_wif && !wallet->chain_params) {
        return false;
    }
    
    /* Try to get private key to verify it's valid */
    uint8_t private_key[DOGECOIN_ECKEY_PKEY_LENGTH];
    if (!dogecoin_paper_wallet_get_private_key(wallet, private_key)) {
        return false;
    }

    dogecoin_mem_zero(private_key, sizeof(private_key));
    return true;
}

/* Sweep a paper wallet to a destination address */
dogecoin_sweep_result* dogecoin_sweep_paper_wallet(
    const dogecoin_paper_wallet* wallet,
    const dogecoin_sweep_options* options
) {
  const dogecoin_paper_wallet* wallets[1];
  if (!wallet) {
    dogecoin_sweep_result* result = dogecoin_sweep_result_new();
    if (result) {
      sweep_result_fail(result, "Invalid wallet or options");
    }
    return result;
  }
  wallets[0] = wallet;
  return sweep_wallets_impl(wallets, 1, options);
}

dogecoin_sweep_result* dogecoin_sweep_multiple_paper_wallets(
    const dogecoin_paper_wallet* wallets,
    size_t wallet_count,
    const dogecoin_sweep_options* options
) {
    const dogecoin_paper_wallet** wptrs;
    dogecoin_sweep_result* result;
    size_t i;

    if (!wallets || !options) {
        result = dogecoin_sweep_result_new();
        if (result) {
            sweep_result_fail(result, "Invalid wallets or options");
        }
        return result;
    }
    if (wallet_count == 0) {
        result = dogecoin_sweep_result_new();
        if (result) {
            sweep_result_fail(result, "No paper wallets specified");
        }
        return result;
    }
    if (wallet_count == 1) {
        return dogecoin_sweep_paper_wallet(&wallets[0], options);
    }

    wptrs = (const dogecoin_paper_wallet**)dogecoin_calloc(wallet_count, sizeof(dogecoin_paper_wallet*));
    if (!wptrs) {
        result = dogecoin_sweep_result_new();
        if (result) {
            sweep_result_fail(result, "out of memory");
        }
        return result;
    }
    for (i = 0; i < wallet_count; i++) {
        wptrs[i] = &wallets[i];
    }
    result = sweep_wallets_impl(wptrs, wallet_count, options);
    dogecoin_free(wptrs);
    return result;
}

uint64_t dogecoin_sweep_estimate_fee(
    const dogecoin_paper_wallet* wallet,
    const dogecoin_sweep_options* options
) {
    (void)wallet;
    if (!options) return 0;
    size_t est_vsize = sweep_estimate_vsize(options->utxo_count ? options->utxo_count : 1);
    uint64_t fee_koinu = options->fee_per_byte * est_vsize;
    if (fee_koinu < options->min_fee) fee_koinu = options->min_fee;
    if (fee_koinu > options->max_fee) fee_koinu = options->max_fee;
    return fee_koinu;
}

dogecoin_bool dogecoin_sweep_get_balance(
    const char* address,
    const dogecoin_chainparams* chain_params,
    uint64_t* balance_out
) {
    if (!address || !balance_out) {
        return false;
    }
#ifdef WITH_WALLET
    (void)chain_params;
    *balance_out = dogecoin_get_balance((char*)address);
    return true;
#else
    (void)chain_params;
    *balance_out = 0;
    return false;
#endif
}

dogecoin_transaction* dogecoin_sweep_create_transaction(
    const dogecoin_paper_wallet* wallet,
    const dogecoin_sweep_options* options
) {
    (void)wallet;
    if (!options || !options->destination_address || !sweep_options_utxo_ok(options)) return NULL;

    char fee_doge[64];
    char out_doge[64];
    uint64_t fee_koinu = 0;
    uint64_t out_koinu = 0;
    if (!sweep_compute_amounts(options, &fee_koinu, &out_koinu, fee_doge, out_doge)) return NULL;

    int txindex = 0;
    if (!sweep_build_unsigned_tx(options, fee_doge, out_doge, &txindex)) return NULL;

    char* hexbuf = sweep_tx_hex_alloc();
    if (!hexbuf) {
        clear_transaction(txindex);
        return NULL;
    }
    int hexlen = get_raw_transaction_ex(txindex, hexbuf, SWEEP_TX_HEX_BUF_SIZE);
    if (hexlen <= 0) {
        clear_transaction(txindex);
        dogecoin_free(hexbuf);
        return NULL;
    }

    dogecoin_tx* tx = dogecoin_tx_new();
    if (!tx) {
        clear_transaction(txindex);
        dogecoin_free(hexbuf);
        return NULL;
    }
    uint8_t* bindata = dogecoin_malloc((size_t)hexlen / 2 + 1);
    if (!bindata) {
        dogecoin_tx_free(tx);
        clear_transaction(txindex);
        dogecoin_free(hexbuf);
        return NULL;
    }
    size_t binlen = 0;
    utils_hex_to_bin(hexbuf, bindata, (size_t)hexlen, &binlen);
    dogecoin_free(hexbuf);
    if (!dogecoin_tx_deserialize(bindata, binlen, tx, NULL)) {
        dogecoin_free(bindata);
        dogecoin_tx_free(tx);
        clear_transaction(txindex);
        return NULL;
    }
    dogecoin_free(bindata);
    clear_transaction(txindex);
    return tx;
}

dogecoin_bool dogecoin_sweep_sign_transaction(
    dogecoin_transaction* transaction,
    const dogecoin_paper_wallet* wallet
) {
    if (!transaction || !wallet || !dogecoin_paper_wallet_is_valid(wallet)) return false;

    remove_all();

    cstring* ser = cstr_new_sz(1024);
    if (!ser) return false;
    dogecoin_tx_serialize(ser, transaction);
    char* hex = dogecoin_malloc(ser->len * 2 + 1);
    if (!hex) {
        cstr_free(ser, true);
        return false;
    }
    utils_bin_to_hex((unsigned char*)ser->str, ser->len, hex);
    cstr_free(ser, true);

    int txidx = store_raw_transaction(hex);
    dogecoin_free(hex);
    if (txidx <= 0) return false;

    char* signedbuf = sweep_tx_hex_alloc();
    if (!signedbuf) {
        clear_transaction(txidx);
        return false;
    }
    {
        const dogecoin_paper_wallet* wallets[1];
        wallets[0] = wallet;
        if (!sweep_sign_txindex(txidx, wallets, 1, signedbuf, SWEEP_TX_HEX_BUF_SIZE)) {
            clear_transaction(txidx);
            dogecoin_free(signedbuf);
            return false;
        }
    }
    uint8_t* bindata = dogecoin_malloc(strlen(signedbuf) / 2 + 1);
    if (!bindata) {
        clear_transaction(txidx);
        dogecoin_free(signedbuf);
        return false;
    }
    size_t binlen = 0;
    utils_hex_to_bin(signedbuf, bindata, strlen(signedbuf), &binlen);
    dogecoin_free(signedbuf);
    dogecoin_tx* signed_tx = dogecoin_tx_new();
    if (!signed_tx) {
        dogecoin_free(bindata);
        clear_transaction(txidx);
        return false;
    }
    if (!dogecoin_tx_deserialize(bindata, binlen, signed_tx, NULL)) {
        dogecoin_free(bindata);
        dogecoin_tx_free(signed_tx);
        clear_transaction(txidx);
        return false;
    }
    dogecoin_free(bindata);
    dogecoin_tx_copy(transaction, signed_tx);
    dogecoin_tx_free(signed_tx);
    clear_transaction(txidx);
    return true;
}

dogecoin_bool dogecoin_sweep_broadcast_transaction(
    const dogecoin_transaction* transaction,
    const dogecoin_chainparams* chain_params,
    char* transaction_id_out,
    size_t transaction_id_size
) {
    if (!transaction || !chain_params) {
        return false;
    }
#ifdef WITH_NET
    dogecoin_bool ok = broadcast_tx(chain_params, (dogecoin_tx*)transaction, NULL, 10, 15, false);
    if (ok && transaction_id_out && transaction_id_size >= 65) {
        uint256_t txhash;
        dogecoin_tx_hash((dogecoin_tx*)transaction, txhash);
        utils_bin_to_hex((unsigned char*)txhash, sizeof(txhash), transaction_id_out);
        utils_reverse_hex(transaction_id_out, 64);
        transaction_id_out[64] = '\0';
    }
    return ok;
#else
    (void)transaction_id_out;
    (void)transaction_id_size;
    return false;
#endif
}

dogecoin_bool dogecoin_sweep_validate_transaction(
    const dogecoin_transaction* transaction,
    const dogecoin_paper_wallet* wallet,
    const dogecoin_sweep_options* options
) {
    size_t i;
    dogecoin_bool dest_found;
    int is_mainnet;
    uint64_t outsum;
    uint64_t fee_koinu;
    uint64_t out_koinu;
    char fee_doge[64];
    char out_doge[64];

    if (!transaction || !wallet || !options || !options->destination_address) {
        return false;
    }
    if (!dogecoin_paper_wallet_is_valid(wallet)) {
        return false;
    }

    for (i = 0; i < transaction->vin->len; i++) {
        dogecoin_tx_in* vin = vector_idx(transaction->vin, i);
        if (!vin->script_sig || vin->script_sig->len == 0) {
            return false;
        }
    }

    if (sweep_options_utxo_ok(options) && transaction->vin->len != options->utxo_count) {
        return false;
    }

    is_mainnet = (options->destination_address[0] == 'D');
    dest_found = false;
    for (i = 0; i < transaction->vout->len; i++) {
        dogecoin_tx_out* o = vector_idx(transaction->vout, i);
        char addr[P2PKHLEN];
        dogecoin_mem_zero(addr, sizeof(addr));
        if (dogecoin_tx_out_pubkey_hash_to_p2pkh_address(o, addr, is_mainnet) &&
            strcmp(addr, options->destination_address) == 0) {
            dest_found = true;
            break;
        }
    }
    if (!dest_found) {
        return false;
    }

    if (sweep_options_utxo_ok(options)) {
        if (!sweep_compute_amounts(options, &fee_koinu, &out_koinu, fee_doge, out_doge)) {
            return false;
        }
        outsum = 0;
        for (i = 0; i < transaction->vout->len; i++) {
            dogecoin_tx_out* o = vector_idx(transaction->vout, i);
            outsum += (uint64_t)o->value;
        }
        if (outsum != out_koinu) {
            return false;
        }
    }

    if (options->use_rbf) {
        for (i = 0; i < transaction->vin->len; i++) {
            dogecoin_tx_in* vin = vector_idx(transaction->vin, i);
            if (vin->sequence != 0xfffffffd) {
                return false;
            }
        }
    }

    if (options->locktime && transaction->locktime != options->locktime) {
        return false;
    }

    return true;
}

dogecoin_bool dogecoin_sweep_get_stats(
    const dogecoin_transaction* transaction,
    const dogecoin_sweep_options* options,
    uint64_t* input_count_out,
    uint64_t* output_count_out,
    uint64_t* total_input_value_out,
    uint64_t* total_output_value_out,
    uint64_t* fee_out
) {
    uint64_t insum = 0;
    uint64_t outsum = 0;
    size_t i;

    if (!transaction) {
        return false;
    }
    if (options && sweep_options_utxo_ok(options)) {
        insum = sweep_options_total_koinu(options);
    }
    for (i = 0; i < transaction->vout->len; i++) {
        dogecoin_tx_out* o = vector_idx(transaction->vout, i);
        outsum += (uint64_t)o->value;
    }
    if (input_count_out) {
        *input_count_out = transaction->vin->len;
    }
    if (output_count_out) {
        *output_count_out = transaction->vout->len;
    }
    if (total_input_value_out) {
        *total_input_value_out = insum;
    }
    if (total_output_value_out) {
        *total_output_value_out = outsum;
    }
    if (fee_out) {
        *fee_out = (insum > 0 && outsum <= insum) ? insum - outsum : 0;
    }
    return true;
}

/* Setter functions */
dogecoin_bool dogecoin_sweep_options_set_destination(
    dogecoin_sweep_options* options,
    const char* destination_address
) {
    if (!options || !destination_address) return false;
    
    if (options->destination_address) {
        dogecoin_free(options->destination_address);
    }
    
    options->destination_address = dogecoin_calloc(1, strlen(destination_address) + 1);
    if (!options->destination_address) return false;
    
    strcpy(options->destination_address, destination_address);
    return true;
}

dogecoin_bool dogecoin_sweep_options_set_fee(
    dogecoin_sweep_options* options,
    uint64_t fee_per_byte,
    uint64_t min_fee,
    uint64_t max_fee
) {
    if (!options) return false;
    if (min_fee > max_fee) return false;
    
    options->fee_per_byte = fee_per_byte;
    options->min_fee = min_fee;
    options->max_fee = max_fee;
    
    return true;
}

void dogecoin_sweep_options_set_rbf(
    dogecoin_sweep_options* options,
    dogecoin_bool use_rbf
) {
    if (options) {
        options->use_rbf = use_rbf;
    }
}

void dogecoin_sweep_options_set_locktime(
    dogecoin_sweep_options* options,
    uint32_t locktime
) {
    if (options) {
        options->locktime = locktime;
    }
}

static dogecoin_bool sweep_options_append_utxo(
    dogecoin_sweep_options* options,
    const char* txid_hex,
    int vout,
    const char* amount_doge)
{
    dogecoin_sweep_utxo* grown;
    dogecoin_sweep_utxo* entry;

    if (!options || !txid_hex || !amount_doge || vout < 0) {
        return false;
    }

    grown = (dogecoin_sweep_utxo*)dogecoin_realloc(
        options->utxos, (options->utxo_count + 1) * sizeof(dogecoin_sweep_utxo));
    if (!grown) {
        return false;
    }
    options->utxos = grown;
    entry = &options->utxos[options->utxo_count];
    memset(entry, 0, sizeof(*entry));
    entry->txid = dogecoin_calloc(1, strlen(txid_hex) + 1);
    entry->amount_doge = dogecoin_calloc(1, strlen(amount_doge) + 1);
    if (!entry->txid || !entry->amount_doge) {
        if (entry->txid) {
            dogecoin_free(entry->txid);
        }
        if (entry->amount_doge) {
            dogecoin_free(entry->amount_doge);
        }
        return false;
    }
    strcpy(entry->txid, txid_hex);
    strcpy(entry->amount_doge, amount_doge);
    entry->vout = vout;
    options->utxo_count++;
    sweep_options_sync_legacy(options);
    return true;
}

dogecoin_bool dogecoin_sweep_options_set_utxo(
    dogecoin_sweep_options* options,
    const char* txid_hex,
    int vout,
    const char* total_input_doge)
{
    if (!options || !txid_hex || !total_input_doge || vout < 0) {
        return false;
    }
    sweep_options_clear_utxos(options);
    return sweep_options_append_utxo(options, txid_hex, vout, total_input_doge);
}

dogecoin_bool dogecoin_sweep_options_add_utxo(
    dogecoin_sweep_options* options,
    const char* txid_hex,
    int vout,
    const char* amount_doge)
{
    return sweep_options_append_utxo(options, txid_hex, vout, amount_doge);
}

size_t dogecoin_sweep_options_utxo_count(const dogecoin_sweep_options* options)
{
    if (!options) {
        return 0;
    }
    return options->utxo_count;
}

uint64_t dogecoin_sweep_fee_per_kb_to_per_byte(uint64_t fee_per_kb)
{
    return fee_per_kb / 1000;
}

/* Getter functions */
const char* dogecoin_sweep_result_get_error(const dogecoin_sweep_result* result) {
    return result ? result->error_message : NULL;
}

const char* dogecoin_sweep_result_get_transaction_hex(const dogecoin_sweep_result* result) {
    return result ? result->transaction_hex : NULL;
}

const char* dogecoin_sweep_result_get_transaction_id(const dogecoin_sweep_result* result) {
    return result ? result->transaction_id : NULL;
}

uint64_t dogecoin_sweep_result_get_amount_swept(const dogecoin_sweep_result* result) {
    return result ? result->amount_swept : 0;
}

uint64_t dogecoin_sweep_result_get_fee_paid(const dogecoin_sweep_result* result) {
    return result ? result->fee_paid : 0;
}

const char* dogecoin_sweep_result_get_destination_address(const dogecoin_sweep_result* result) {
    return result ? result->destination_address : NULL;
}

