/*

 The MIT License (MIT)

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

/*
 * Mainnet sweep API driver (libdogecoin).
 *
 * Exercises the full public sweep API end-to-end against real mainnet UTXOs:
 *   - dogecoin_paper_wallet_set_wif / dogecoin_paper_wallet_set_encrypted (BIP38)
 *   - dogecoin_sweep_options_new / set_destination / set_fee / set_rbf / add_utxo
 *   - dogecoin_sweep_create_transaction / dogecoin_sweep_sign_transaction
 *   - dogecoin_sweep_validate_transaction / dogecoin_sweep_get_stats
 *   - dogecoin_sweep_broadcast_transaction (transmits over the p2p network)
 *
 * It is intentionally a thin, scriptable wrapper so the mainnet end-to-end
 * test (contrib/mainnet_bip38_sweep_test.sh) can transmit a real sweep via
 * the sweep API and capture evidence in the committed log file.
 *
 * Build (from repo root, after ./configure && make):
 *   gcc contrib/examples/mainnet_sweep_driver.c .libs/libdogecoin.a \
 *       $(pkg-config --libs libevent) -lpthread -Iinclude -Iinclude/dogecoin \
 *       -o mainnet_sweep_driver
 *
 * Usage:
 *   mainnet_sweep_driver \
 *     --wif <WIF> | --bip38 <6P...> --passphrase <pass> \
 *     --dest <D...> [--fee-per-kb <koinu>] [--min-fee <koinu>] \
 *     [--max-fee <koinu>] [--rbf] [--no-broadcast] \
 *     --utxo <txid>:<vout>:<amount_doge> [--utxo ...]
 */

#include <dogecoin/chainparams.h>
#include <dogecoin/ecc.h>
#include <dogecoin/bip38.h>
#include <dogecoin/sweep.h>
#include <dogecoin/tx.h>
#include <dogecoin/cstr.h>
#include <dogecoin/utils.h>
#include <dogecoin/mem.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_UTXOS 64

static void usage(const char* prog) {
    fprintf(stderr,
        "usage: %s (--wif WIF | --bip38 6P... --passphrase PASS) --dest ADDR\n"
        "          [--fee-per-kb KOINU] [--min-fee KOINU] [--max-fee KOINU]\n"
        "          [--rbf] [--no-broadcast] --utxo TXID:VOUT:AMOUNT_DOGE [--utxo ...]\n",
        prog);
}

int main(int argc, char** argv) {
    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;
    const char* wif = NULL;
    const char* bip38 = NULL;
    const char* passphrase = NULL;
    const char* dest = NULL;
    const char* encrypt_bip38 = NULL; /* passphrase: encrypt the WIF key then reload via BIP38 */
    uint64_t fee_per_kb = 1000000ULL; /* 0.01 DOGE/kB default for mainnet relay */
    uint64_t min_fee = 100000ULL;
    uint64_t max_fee = 100000000ULL;
    int use_rbf = 0;
    int do_broadcast = 1;
    const char* utxo_args[MAX_UTXOS];
    size_t utxo_count = 0;
    int rc = 1;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--wif") == 0 && i + 1 < argc) {
            wif = argv[++i];
        } else if (strcmp(argv[i], "--bip38") == 0 && i + 1 < argc) {
            bip38 = argv[++i];
        } else if (strcmp(argv[i], "--passphrase") == 0 && i + 1 < argc) {
            passphrase = argv[++i];
        } else if (strcmp(argv[i], "--dest") == 0 && i + 1 < argc) {
            dest = argv[++i];
        } else if (strcmp(argv[i], "--encrypt-bip38") == 0 && i + 1 < argc) {
            encrypt_bip38 = argv[++i];
        } else if (strcmp(argv[i], "--fee-per-kb") == 0 && i + 1 < argc) {
            fee_per_kb = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--min-fee") == 0 && i + 1 < argc) {
            min_fee = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--max-fee") == 0 && i + 1 < argc) {
            max_fee = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--rbf") == 0) {
            use_rbf = 1;
        } else if (strcmp(argv[i], "--no-broadcast") == 0) {
            do_broadcast = 0;
        } else if (strcmp(argv[i], "--utxo") == 0 && i + 1 < argc) {
            if (utxo_count >= MAX_UTXOS) {
                fprintf(stderr, "too many UTXOs (max %d)\n", MAX_UTXOS);
                return 1;
            }
            utxo_args[utxo_count++] = argv[++i];
        } else {
            fprintf(stderr, "unknown/incomplete argument: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    if (!dest || utxo_count == 0 || (!wif && !(bip38 && passphrase))) {
        usage(argv[0]);
        return 1;
    }

    dogecoin_ecc_start();

    dogecoin_paper_wallet* wallet = dogecoin_paper_wallet_new();
    dogecoin_sweep_options* opt = NULL;
    dogecoin_transaction* tx = NULL;
    if (!wallet) {
        fprintf(stderr, "failed to allocate paper wallet\n");
        goto done;
    }

    if (wif) {
        printf("[driver] loading paper wallet from WIF\n");
        if (!dogecoin_paper_wallet_set_wif(wallet, wif, chain)) {
            fprintf(stderr, "[driver] dogecoin_paper_wallet_set_wif failed\n");
            goto done;
        }
    } else {
        printf("[driver] loading paper wallet from BIP38 encrypted key\n");
        if (!dogecoin_paper_wallet_set_encrypted(wallet, bip38, passphrase, chain)) {
            fprintf(stderr, "[driver] dogecoin_paper_wallet_set_encrypted failed\n");
            goto done;
        }
    }

    if (!dogecoin_paper_wallet_is_valid(wallet)) {
        fprintf(stderr, "[driver] paper wallet is not valid\n");
        goto done;
    }

    /*
     * Optional BIP38 round trip: encrypt the loaded key (dogecoin_bip38_encrypt),
     * print the 6P... key, then reload the wallet from it
     * (dogecoin_paper_wallet_set_encrypted -> BIP38 decrypt) so the sweep that
     * follows is driven by a key that round-tripped through the full BIP38 API.
     */
    if (wif && encrypt_bip38) {
        uint8_t priv[32];
        char addr[128];
        char enckey[128];
        size_t enclen = sizeof(enckey);
        memset(priv, 0, sizeof(priv));
        memset(addr, 0, sizeof(addr));
        memset(enckey, 0, sizeof(enckey));
        if (!dogecoin_paper_wallet_get_private_key(wallet, priv) ||
            !dogecoin_paper_wallet_get_address(wallet, addr, sizeof(addr))) {
            fprintf(stderr, "[driver] could not extract key/address for BIP38 encrypt\n");
            goto done;
        }
        if (!dogecoin_bip38_encrypt(priv, encrypt_bip38, addr, true, enckey, &enclen)) {
            dogecoin_mem_zero(priv, sizeof(priv));
            fprintf(stderr, "[driver] dogecoin_bip38_encrypt failed\n");
            goto done;
        }
        dogecoin_mem_zero(priv, sizeof(priv));
        printf("[driver] BIP38 encrypted key: %s\n", enckey);
        printf("[driver] BIP38 passphrase: %s\n", encrypt_bip38);
        dogecoin_paper_wallet_free(wallet);
        wallet = dogecoin_paper_wallet_new();
        if (!wallet) {
            fprintf(stderr, "[driver] failed to reallocate paper wallet\n");
            goto done;
        }
        printf("[driver] reloading paper wallet from BIP38 encrypted key\n");
        if (!dogecoin_paper_wallet_set_encrypted(wallet, enckey, encrypt_bip38, chain)) {
            fprintf(stderr, "[driver] dogecoin_paper_wallet_set_encrypted (round trip) failed\n");
            goto done;
        }
        if (!dogecoin_paper_wallet_is_valid(wallet)) {
            fprintf(stderr, "[driver] round-tripped paper wallet is not valid\n");
            goto done;
        }
        printf("[driver] BIP38 round trip OK; sweeping with decrypted key\n");
    }

    {
        char addr[128];
        memset(addr, 0, sizeof(addr));
        if (dogecoin_paper_wallet_get_address(wallet, addr, sizeof(addr))) {
            printf("[driver] source address: %s\n", addr);
        }
    }

    opt = dogecoin_sweep_options_new(chain);
    if (!opt) {
        fprintf(stderr, "[driver] dogecoin_sweep_options_new failed\n");
        goto done;
    }
    if (!dogecoin_sweep_options_set_destination(opt, dest)) {
        fprintf(stderr, "[driver] set_destination failed\n");
        goto done;
    }
    dogecoin_sweep_options_set_fee(
        opt, dogecoin_sweep_fee_per_kb_to_per_byte(fee_per_kb), min_fee, max_fee);
    dogecoin_sweep_options_set_rbf(opt, use_rbf ? true : false);

    for (i = 0; (size_t)i < utxo_count; i++) {
        char buf[256];
        char* txid;
        char* vout_s;
        char* amount;
        int vout;
        strncpy(buf, utxo_args[i], sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        txid = strtok(buf, ":");
        vout_s = strtok(NULL, ":");
        amount = strtok(NULL, ":");
        if (!txid || !vout_s || !amount) {
            fprintf(stderr, "[driver] bad --utxo format: %s\n", utxo_args[i]);
            goto done;
        }
        vout = atoi(vout_s);
        if (!dogecoin_sweep_options_add_utxo(opt, txid, vout, amount)) {
            fprintf(stderr, "[driver] add_utxo failed for %s\n", utxo_args[i]);
            goto done;
        }
        printf("[driver] added UTXO %s:%d amount=%s DOGE\n", txid, vout, amount);
    }
    printf("[driver] configured %zu UTXO(s)\n", dogecoin_sweep_options_utxo_count(opt));

    tx = dogecoin_sweep_create_transaction(wallet, opt);
    if (!tx) {
        fprintf(stderr, "[driver] dogecoin_sweep_create_transaction failed\n");
        goto done;
    }
    printf("[driver] unsigned sweep transaction created\n");

    if (!dogecoin_sweep_sign_transaction(tx, wallet)) {
        fprintf(stderr, "[driver] dogecoin_sweep_sign_transaction failed\n");
        goto done;
    }
    printf("[driver] sweep transaction signed\n");

    if (!dogecoin_sweep_validate_transaction(tx, wallet, opt)) {
        fprintf(stderr, "[driver] dogecoin_sweep_validate_transaction failed\n");
        goto done;
    }
    printf("[driver] sweep transaction validated\n");

    {
        uint64_t nin = 0, nout = 0, vin = 0, vout = 0, fee = 0;
        if (dogecoin_sweep_get_stats(tx, opt, &nin, &nout, &vin, &vout, &fee)) {
            printf("[driver] stats: inputs=%" PRIu64 " outputs=%" PRIu64
                   " total_in=%" PRIu64 " koinu total_out=%" PRIu64
                   " koinu fee=%" PRIu64 " koinu\n",
                   nin, nout, vin, vout, fee);
        }
    }

    {
        cstring* s = cstr_new_sz(1024);
        dogecoin_tx_serialize(s, tx);
        char* hex = dogecoin_char_vla(s->len * 2 + 1);
        utils_bin_to_hex((unsigned char*)s->str, s->len, hex);
        printf("[driver] signed sweep tx hex: %s\n", hex);
        free(hex);
        cstr_free(s, true);
    }

    if (do_broadcast) {
        char txid_out[128];
        memset(txid_out, 0, sizeof(txid_out));
        printf("[driver] broadcasting via dogecoin_sweep_broadcast_transaction...\n");
        if (dogecoin_sweep_broadcast_transaction(tx, chain, txid_out, sizeof(txid_out))) {
            printf("[driver] BROADCAST OK txid=%s\n", txid_out);
            rc = 0;
        } else {
            fprintf(stderr, "[driver] broadcast failed\n");
            rc = 2;
        }
    } else {
        printf("[driver] skipping broadcast (--no-broadcast)\n");
        rc = 0;
    }

done:
    if (tx) dogecoin_tx_free(tx);
    if (opt) dogecoin_sweep_options_free(opt);
    if (wallet) dogecoin_paper_wallet_free(wallet);
    dogecoin_ecc_stop();
    return rc;
}
