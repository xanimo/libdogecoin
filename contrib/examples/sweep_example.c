/*
 * Paper-wallet sweep example (libdogecoin).
 *
 * The app supplies UTXO data from an indexer; libdogecoin builds and signs.
 *
 * Build (from repo root, after ./configure && make):
 *   gcc contrib/examples/sweep_example.c .libs/libdogecoin.a -Iinclude/dogecoin -o sweep_example
 *
 * Windows (MSVC, after CMake build):
 *   cl.exe contrib/examples/sweep_example.c /I"include\dogecoin" /link "build\Debug\dogecoin.lib" ...
 */

#include <dogecoin/libdogecoin.h>
#include <dogecoin/bip38.h>
#include <dogecoin/sweep.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/ecc.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static void print_sweep_result(const dogecoin_sweep_result* result)
{
    if (!result) {
        printf("  (null result)\n");
        return;
    }
    if (!result->success) {
        printf("  sweep failed: %s\n",
               result->error_message ? result->error_message : "unknown");
        return;
    }
    printf("  txid: %s\n", result->transaction_id);
    printf("  swept: %" PRIu64 " koinu, fee: %" PRIu64 " koinu\n",
           result->amount_swept, result->fee_paid);
    printf("  hex (first 80 chars): %.80s...\n", result->transaction_hex);
}

static dogecoin_bool sweep_wif_example(const dogecoin_chainparams* chain)
{
    dogecoin_paper_wallet* wallet;
    dogecoin_sweep_options* opt;
    dogecoin_sweep_result* result;
    dogecoin_bool ok;

    printf("\n--- WIF paper wallet sweep ---\n");

    wallet = dogecoin_paper_wallet_new();
    if (!wallet) {
        return false;
    }

    /* Replace with your paper wallet WIF and real UTXO from your indexer. */
    ok = dogecoin_paper_wallet_set_wif(wallet, "YOUR_WIF_HERE", chain);
    if (!ok) {
        printf("  Set YOUR_WIF_HERE to a valid WIF to run this example.\n");
        dogecoin_paper_wallet_free(wallet);
        return true; /* skip demo, not a hard failure */
    }

    opt = dogecoin_sweep_options_new(chain);
    dogecoin_sweep_options_set_destination(opt, "D_DESTINATION_ADDRESS");
    dogecoin_sweep_options_set_fee(
        opt, dogecoin_sweep_fee_per_kb_to_per_byte(1000000ULL), 1000, 5000000);
    dogecoin_sweep_options_set_utxo(
        opt,
        "b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074",
        1,
        "12.0");

    result = dogecoin_sweep_paper_wallet(wallet, opt);
    print_sweep_result(result);
    dogecoin_sweep_result_free(result);
    dogecoin_sweep_options_free(opt);
    dogecoin_paper_wallet_free(wallet);
    return true;
}

static dogecoin_bool sweep_bip38_example(const dogecoin_chainparams* chain)
{
    dogecoin_paper_wallet* wallet;
    dogecoin_sweep_options* opt;
    dogecoin_sweep_result* result;

    printf("\n--- BIP38 encrypted key sweep ---\n");

    wallet = dogecoin_paper_wallet_new();
    if (!wallet) {
        return false;
    }

    /* Replace with scanned 6P… key, passphrase, and indexer UTXO data. */
    if (!dogecoin_paper_wallet_set_encrypted(
            wallet, "6P_YOUR_ENCRYPTED_KEY", "your-passphrase", chain)) {
        printf("  Set 6P… key and passphrase to run this example.\n");
        dogecoin_paper_wallet_free(wallet);
        return true;
    }

    opt = dogecoin_sweep_options_new(chain);
    dogecoin_sweep_options_set_destination(opt, "D_DESTINATION_ADDRESS");
    dogecoin_sweep_options_set_fee(opt, 1000, 1000, 1000000);
    dogecoin_sweep_options_add_utxo(
        opt,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        0,
        "50.0");
    dogecoin_sweep_options_add_utxo(
        opt,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        1,
        "50.0");

    result = dogecoin_sweep_paper_wallet(wallet, opt);
    print_sweep_result(result);
    dogecoin_sweep_result_free(result);
    dogecoin_sweep_options_free(opt);
    dogecoin_paper_wallet_free(wallet);
    return true;
}

int main(void)
{
    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    dogecoin_ecc_start();

    printf("libdogecoin sweep example\n");
    printf("See doc/sweep.md for integration details.\n");

    sweep_wif_example(chain);
    sweep_bip38_example(chain);

    dogecoin_ecc_stop();
    return 0;
}
