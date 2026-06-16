/*

 The MIT License (MIT)

 Copyright (c) 2024-2026 The Dogecoin Foundation

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

/**
 * @file threadsafe.h
 *
 * @brief Thread-safe routing helpers shared by the libdogecoin CLI tools.
 *
 * The CLI sources are compiled twice: once into the legacy binaries
 * (`such`, `sendtx`, `spvnode`) and once into thread-safe binaries
 * (`such_ts`, `sendtx_ts`, `spvnode_ts`) compiled with `-DDOGECOIN_TS=1`.
 *
 * In the `-DDOGECOIN_TS` build each helper routes through the matching `_ts`
 * library API so the resulting binary exercises the thread-safe contexts and
 * per-object mutexes documented in doc/thread_safety.md; otherwise it calls the
 * plain API. The two builds are otherwise identical.
 *
 * Operations whose `_ts` variant shares the exact signature of the plain API
 * (the direct `dogecoin_tx` create/free calls) are routed with a compile-time
 * rename so the CLI sources keep using the canonical public names rather than
 * having every call site rewritten. Operations whose `_ts` variant takes an
 * extra context argument or has a distinct lifecycle are routed through small,
 * explicit `cli_*` wrappers that inject the context for the caller.
 */

#ifndef __LIBDOGECOIN_THREADSAFE_H__
#define __LIBDOGECOIN_THREADSAFE_H__

#include <stdio.h>

#include <dogecoin/dogecoin.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/eckey.h>
#include <dogecoin/transaction.h>
#include <dogecoin/tx.h>
#include <dogecoin/wallet.h>

#ifdef DOGECOIN_TS
#define DOGECOIN_CLI_TS_LABEL "thread-safe"
#else
#define DOGECOIN_CLI_TS_LABEL "single-threaded"
#endif

/* Thread-safe context lifecycle */

/**
 * @brief Start the CLI thread-safe context for a tool.
 *
 * In the `_ts` build this creates a thread-safe libdogecoin context (a
 * refcount-mutex guarded object), announces the mode and returns the held
 * context for the tool to thread through `_ts` object constructors. In the
 * legacy build it is a no-op that returns NULL.
 *
 * @param tool The name of the CLI tool, used in the announcement.
 * @param testnet Whether the context targets testnet.
 *
 * @return The held thread-safe context in the `_ts` build, otherwise NULL.
 */
static inline dogecoin_ctx* cli_ts_context_start(const char* tool, dogecoin_bool testnet)
{
#ifdef DOGECOIN_TS
    dogecoin_ctx* ctx = dogecoin_ctx_new_ts(testnet, false);
    printf("%s: thread-safe mode %s\n", tool,
           dogecoin_ctx_is_thread_safe(ctx) ? "enabled" : "unavailable");
    return ctx;
#else
    (void)tool;
    (void)testnet;
    return NULL;
#endif
}

/**
 * @brief Release the CLI thread-safe context created by cli_ts_context_start().
 *
 * In the legacy build this is a no-op.
 *
 * @param ctx The context to release.
 *
 * @return Nothing.
 */
static inline void cli_ts_context_finish(dogecoin_ctx* ctx)
{
#ifdef DOGECOIN_TS
    dogecoin_ctx_release(ctx);
#else
    (void)ctx;
#endif
}

/* Transaction builder: dogecoin_tx_new_ts()/dogecoin_tx_free_ts() share the exact
 * signature of the plain create/free calls so they are routed with a compile-time
 * rename. This lets the CLI sources keep calling the canonical dogecoin_tx_new()/
 * dogecoin_tx_free() names while the _ts build transparently exercises the
 * mutex-bearing variants. The renames are only in effect under -DDOGECOIN_TS;
 * the legacy build uses the plain API unchanged. */
#ifdef DOGECOIN_TS
#define dogecoin_tx_new dogecoin_tx_new_ts
#define dogecoin_tx_free dogecoin_tx_free_ts
#endif

/* Transaction registry: the CLI builds transactions through the index-based
 * transaction API which operates on the per-thread default transaction context.
 * The _ts wrappers below therefore target that same default context so registry
 * lookups stay consistent with the rest of the index-based API. */

/**
 * @brief Start a new working transaction in the registry.
 *
 * @return The index of the new working transaction.
 */
static inline int cli_start_transaction(void)
{
#ifdef DOGECOIN_TS
    return start_transaction_ts(dogecoin_transaction_context_default());
#else
    return start_transaction();
#endif
}

/**
 * @brief Find a working transaction by index.
 *
 * @param idx The index of the working transaction to find.
 *
 * @return The working transaction, or NULL if not found.
 */
static inline working_transaction* cli_find_transaction(int idx)
{
#ifdef DOGECOIN_TS
    return find_transaction_ts(dogecoin_transaction_context_default(), idx);
#else
    return find_transaction(idx);
#endif
}

/**
 * @brief Remove (and free) a working transaction from the registry.
 *
 * @param working_tx The working transaction to remove.
 *
 * @return Nothing.
 */
static inline void cli_remove_transaction(working_transaction* working_tx)
{
#ifdef DOGECOIN_TS
    remove_transaction_ts(dogecoin_transaction_context_default(), working_tx);
#else
    remove_transaction(working_tx);
#endif
}

/**
 * @brief Remove (and free) all working transactions from the registry.
 *
 * @return Nothing.
 */
static inline void cli_remove_all(void)
{
#ifdef DOGECOIN_TS
    remove_all_ts(dogecoin_transaction_context_default());
#else
    remove_all();
#endif
}

/**
 * @brief Count the working transactions currently in the registry.
 *
 * @return The number of working transactions.
 */
static inline int cli_get_transaction_count(void)
{
#ifdef DOGECOIN_TS
    return get_transaction_count_ts(dogecoin_transaction_context_default());
#else
    return get_transaction_count();
#endif
}

/* Index-based transaction mutation/serialization: the CLI mutates and serializes
 * working transactions through the index-based API. In the _ts build the working
 * transaction is mutex-bearing (created via dogecoin_tx_new_ts() inside
 * new_transaction_ts), and the _ts index variants route every mutation through
 * the thread-safe transaction primitives and serialize under the per-transaction
 * mutex. In the legacy build the lock is absent (thread_safe == 0) and the
 * wrappers reduce to the plain index API. */

/**
 * @brief Store a raw (hex) transaction into the working transaction at an index.
 *
 * @param txindex The index of the working transaction to populate.
 * @param hexadecimal_transaction The raw transaction encoded as hex.
 *
 * @return 1 on success, 0 on failure.
 */
static inline int cli_save_raw_transaction(int txindex, const char* hexadecimal_transaction)
{
#ifdef DOGECOIN_TS
    return save_raw_transaction_ts(dogecoin_transaction_context_default(), txindex, hexadecimal_transaction);
#else
    return save_raw_transaction(txindex, hexadecimal_transaction);
#endif
}

/**
 * @brief Add a UTXO input to the working transaction at an index.
 *
 * @param txindex The index of the working transaction to mutate.
 * @param hex_utxo_txid The hex txid of the UTXO to spend.
 * @param vout The output index of the UTXO to spend.
 *
 * @return 1 on success, 0 on failure.
 */
static inline int cli_add_utxo(int txindex, char* hex_utxo_txid, int vout)
{
#ifdef DOGECOIN_TS
    return add_utxo_ts(dogecoin_transaction_context_default(), txindex, hex_utxo_txid, vout);
#else
    return add_utxo(txindex, hex_utxo_txid, vout);
#endif
}

/**
 * @brief Add an output to the working transaction at an index.
 *
 * @param txindex The index of the working transaction to mutate.
 * @param destinationaddress The destination address for the output.
 * @param amount The output amount.
 *
 * @return 1 on success, 0 on failure.
 */
static inline int cli_add_output(int txindex, char* destinationaddress, char* amount)
{
#ifdef DOGECOIN_TS
    return add_output_ts(dogecoin_transaction_context_default(), txindex, destinationaddress, amount);
#else
    return add_output(txindex, destinationaddress, amount);
#endif
}

/**
 * @brief Finalize the working transaction at an index, applying fee and change.
 *
 * @param txindex The index of the working transaction to finalize.
 * @param destinationaddress The destination address.
 * @param subtractedfee The fee to subtract.
 * @param out_dogeamount_for_verification The total amount for verification.
 * @param changeaddress The change address.
 *
 * @return The finalized raw transaction as hex, or NULL on failure.
 */
static inline char* cli_finalize_transaction(int txindex, char* destinationaddress, char* subtractedfee,
                                             char* out_dogeamount_for_verification, char* changeaddress)
{
#ifdef DOGECOIN_TS
    return finalize_transaction_ts(dogecoin_transaction_context_default(), txindex, destinationaddress,
                                   subtractedfee, out_dogeamount_for_verification, changeaddress);
#else
    return finalize_transaction(txindex, destinationaddress, subtractedfee,
                                out_dogeamount_for_verification, changeaddress);
#endif
}

/**
 * @brief Serialize the working transaction at an index to raw hex.
 *
 * @param txindex The index of the working transaction to serialize.
 *
 * @return The raw transaction as hex, or NULL on failure.
 */
static inline char* cli_get_raw_transaction(int txindex)
{
#ifdef DOGECOIN_TS
    return get_raw_transaction_ts(dogecoin_transaction_context_default(), txindex);
#else
    return get_raw_transaction(txindex);
#endif
}

/**
 * @brief Clear (remove and free) the working transaction at an index.
 *
 * clear_transaction removes (and frees) the working transaction, so it is
 * routed through the thread-safe registry rather than holding the per-object
 * lock it is about to destroy.
 *
 * @param txindex The index of the working transaction to clear.
 *
 * @return Nothing.
 */
static inline void cli_clear_transaction(int txindex)
{
#ifdef DOGECOIN_TS
    clear_transaction_ts(dogecoin_transaction_context_default(), txindex);
#else
    clear_transaction(txindex);
#endif
}

/* eckey: the key is a standalone object (never added to a registry), so the
 * _ts build exercises the eckey context lifecycle with a throwaway context. */

/**
 * @brief Create an eckey object from a private key string.
 *
 * In the `_ts` build the key is built through a throwaway eckey context to
 * exercise the thread-safe eckey context lifecycle.
 *
 * @param private_key The private key string.
 *
 * @return The new eckey object, or NULL on failure.
 */
static inline eckey* cli_eckey_from_privkey(char* private_key)
{
#ifdef DOGECOIN_TS
    dogecoin_eckey_context* kctx = dogecoin_eckey_context_new();
    eckey* key = new_eckey_from_privkey_ts(kctx, private_key);
    dogecoin_eckey_context_free(kctx);
    return key;
#else
    return new_eckey_from_privkey(private_key);
#endif
}

/* Wallet */

/**
 * @brief Initialize a wallet, binding it to the thread-safe context in the
 * `_ts` build.
 *
 * @param ctx The thread-safe context (used only in the `_ts` build).
 * @param chain The chain parameters.
 * @param address The wallet address.
 * @param name The wallet name.
 * @param opts The wallet options.
 *
 * @return The initialized wallet, or NULL on failure.
 */
static inline dogecoin_wallet* cli_wallet_init(dogecoin_ctx* ctx, const dogecoin_chainparams* chain,
                                               const char* address, const char* name,
                                               const dogecoin_wallet_opts* opts)
{
#ifdef DOGECOIN_TS
    return dogecoin_wallet_init_ts(ctx, chain, address, name, opts);
#else
    (void)ctx;
    return dogecoin_wallet_init(chain, address, name, opts);
#endif
}

/**
 * @brief Allocate a new wallet, enabling thread-safe mode in the `_ts` build.
 *
 * @param ctx The thread-safe context (used only in the `_ts` build).
 * @param params The chain parameters.
 *
 * @return The new wallet, or NULL on failure.
 */
static inline dogecoin_wallet* cli_wallet_new(dogecoin_ctx* ctx, const dogecoin_chainparams* params)
{
    dogecoin_wallet* wallet = dogecoin_wallet_new(params);
#ifdef DOGECOIN_TS
    if (wallet) dogecoin_wallet_enable_thread_safe(wallet, ctx);
#else
    (void)ctx;
#endif
    return wallet;
}

/**
 * @brief Free a wallet allocated through the CLI wallet helpers.
 *
 * @param wallet The wallet to free.
 *
 * @return Nothing.
 */
static inline void cli_wallet_free(dogecoin_wallet* wallet)
{
#ifdef DOGECOIN_TS
    dogecoin_wallet_free_ts(wallet);
#else
    dogecoin_wallet_free(wallet);
#endif
}

#endif /* __LIBDOGECOIN_THREADSAFE_H__ */
