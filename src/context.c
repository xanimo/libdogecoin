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

#include <dogecoin/libdogecoin.h>
#include <dogecoin/mem.h>
#include <dogecoin/random.h>

#include "secp256k1/include/secp256k1.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

struct dogecoin_transaction_context* dogecoin_transaction_context_new(void);
void dogecoin_transaction_context_free(struct dogecoin_transaction_context* ctx);
struct dogecoin_eckey_context* dogecoin_eckey_context_new(void);
void dogecoin_eckey_context_free(struct dogecoin_eckey_context* ctx);

/**
 * @brief Returns the platform mutex size used to guard the refcount.
 *
 * Selects the size of the underlying critical section (Windows) or
 * pthread mutex (POSIX) that backs the context reference-count lock.
 *
 * @return The number of bytes to allocate for the refcount lock.
 */
static size_t dogecoin_refcount_lock_size(void)
{
#ifdef _WIN32
    return sizeof(CRITICAL_SECTION);
#else
    return sizeof(pthread_mutex_t);
#endif
}

/**
 * @brief Releases every owned subsystem held by a context.
 *
 * Frees the transaction, eckey, RNG and secp256k1 sub-contexts as well as the
 * refcount lock, and resets the pointers to NULL. Does not free the context
 * structure itself.
 *
 * @param ctx The context whose members should be released. May be NULL.
 *
 * @return Nothing.
 */
static void dogecoin_context_cleanup(dogecoin_context* ctx)
{
    if (!ctx) return;
    if (ctx->tx_ctx) dogecoin_transaction_context_free(ctx->tx_ctx);
    if (ctx->key_ctx) dogecoin_eckey_context_free(ctx->key_ctx);
    if (ctx->rng_state) free_fast_random_context((struct fast_random_context*)ctx->rng_state);
    if (ctx->ecc_ctx) secp256k1_context_destroy((secp256k1_context*)ctx->ecc_ctx);
    if (ctx->refcount_lock) {
#ifdef _WIN32
        DeleteCriticalSection((CRITICAL_SECTION*)ctx->refcount_lock);
#else
        pthread_mutex_destroy((pthread_mutex_t*)ctx->refcount_lock);
#endif
        dogecoin_free(ctx->refcount_lock);
    }
    ctx->tx_ctx = NULL;
    ctx->key_ctx = NULL;
    ctx->rng_state = NULL;
    ctx->ecc_ctx = NULL;
    ctx->refcount_lock = NULL;
}

/**
 * @brief Clears the last-error state stored on a context.
 *
 * @param ctx The context whose error code and message should be reset. May be NULL.
 *
 * @return Nothing.
 */
static void dogecoin_context_zero_error(dogecoin_context* ctx)
{
    if (!ctx) return;
    ctx->error_code = 0;
    ctx->last_error[0] = '\0';
}

/**
 * @brief Allocates and initializes a new stateless libdogecoin context.
 *
 * Creates the per-context secp256k1 context (seeded with fresh randomness), the
 * fast RNG state, and the transaction and eckey sub-contexts, and initializes
 * the refcount lock with an initial reference count of 1.
 *
 * @param testnet    Selects testnet chain parameters when true, mainnet otherwise.
 * @param enable_net Records whether networking is intended for this context.
 *
 * @return A pointer to the new context, or NULL on allocation/initialization failure.
 */
dogecoin_context* dogecoin_context_new(dogecoin_bool testnet, dogecoin_bool enable_net)
{
    dogecoin_context* ctx = (dogecoin_context*)dogecoin_calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    ctx->chain_params = testnet ? &dogecoin_chainparams_test : &dogecoin_chainparams_main;
    ctx->enable_net = enable_net ? 1 : 0;
    ctx->refcount = 1;
    ctx->refcount_lock = dogecoin_calloc(1, dogecoin_refcount_lock_size());
    if (!ctx->refcount_lock) {
        fprintf(stderr, "CTXNEW FAIL: refcount_lock alloc\n");
        dogecoin_free(ctx);
        return NULL;
    }
#ifdef _WIN32
    InitializeCriticalSection((CRITICAL_SECTION*)ctx->refcount_lock);
#else
    if (pthread_mutex_init((pthread_mutex_t*)ctx->refcount_lock, NULL) != 0) {
        fprintf(stderr, "CTXNEW FAIL: pthread_mutex_init\n");
        dogecoin_free(ctx->refcount_lock);
        ctx->refcount_lock = NULL;
        dogecoin_free(ctx);
        return NULL;
    }
#endif
    ctx->ecc_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx->ecc_ctx) {
        fprintf(stderr, "CTXNEW FAIL: secp256k1_context_create\n");
        dogecoin_context_cleanup(ctx);
        dogecoin_free(ctx);
        return NULL;
    }
    union {
        uint256_t u256;
        uint8_t bytes[32];
    } randomization_seed;
    if (!dogecoin_random_bytes(randomization_seed.bytes, sizeof(randomization_seed.bytes), 0) ||
        !secp256k1_context_randomize((secp256k1_context*)ctx->ecc_ctx, randomization_seed.bytes)) {
        fprintf(stderr, "CTXNEW FAIL: random_bytes/randomize\n");
        dogecoin_mem_zero(randomization_seed.bytes, sizeof(randomization_seed.bytes));
        dogecoin_context_cleanup(ctx);
        dogecoin_free(ctx);
        return NULL;
    }
    const uint256_t* rng_init_seed = (const uint256_t*)&randomization_seed.u256;
    ctx->rng_state = init_fast_random_context(false, rng_init_seed);
    dogecoin_mem_zero(randomization_seed.bytes, sizeof(randomization_seed.bytes));
    ctx->tx_ctx = dogecoin_transaction_context_new();
    ctx->key_ctx = dogecoin_eckey_context_new();
    if (!ctx->rng_state || !ctx->tx_ctx || !ctx->key_ctx) {
        fprintf(stderr, "CTXNEW FAIL: rng=%p tx=%p key=%p\n",
                (void*)ctx->rng_state, (void*)ctx->tx_ctx, (void*)ctx->key_ctx);
        dogecoin_context_cleanup(ctx);
        dogecoin_free(ctx);
        return NULL;
    }
    dogecoin_context_zero_error(ctx);
    return ctx;
}

/**
 * @brief Atomically increments the reference count of a context.
 *
 * Acquires an additional owning reference; each call must be balanced by a
 * matching dogecoin_context_release().
 *
 * @param ctx The context to retain. No-op if NULL or uninitialized.
 *
 * @return Nothing.
 */
void dogecoin_context_acquire(dogecoin_context* ctx)
{
    if (!ctx) return;
    if (!ctx->refcount_lock) return;
#ifdef _WIN32
    EnterCriticalSection((CRITICAL_SECTION*)ctx->refcount_lock);
#else
    pthread_mutex_lock((pthread_mutex_t*)ctx->refcount_lock);
#endif
    ctx->refcount++;
#ifdef _WIN32
    LeaveCriticalSection((CRITICAL_SECTION*)ctx->refcount_lock);
#else
    pthread_mutex_unlock((pthread_mutex_t*)ctx->refcount_lock);
#endif
}

/**
 * @brief Atomically decrements the reference count and frees on zero.
 *
 * Drops one owning reference. When the final reference is released the context's
 * subsystems are cleaned up and the structure is freed.
 *
 * @param ctx The context to release. No-op if NULL or uninitialized.
 *
 * @return Nothing.
 */
void dogecoin_context_release(dogecoin_context* ctx)
{
    dogecoin_bool should_free = false;
    if (!ctx) return;
    if (!ctx->refcount_lock) return;
#ifdef _WIN32
    EnterCriticalSection((CRITICAL_SECTION*)ctx->refcount_lock);
#else
    pthread_mutex_lock((pthread_mutex_t*)ctx->refcount_lock);
#endif
    if (ctx->refcount > 0) ctx->refcount--;
    if (ctx->refcount == 0) should_free = true;
#ifdef _WIN32
    LeaveCriticalSection((CRITICAL_SECTION*)ctx->refcount_lock);
#else
    pthread_mutex_unlock((pthread_mutex_t*)ctx->refcount_lock);
#endif
    if (!should_free) return;
    dogecoin_context_cleanup(ctx);
    dogecoin_free(ctx);
}

/**
 * @brief Returns the chain parameters bound to a context.
 *
 * @param ctx The context to query. May be NULL.
 *
 * @return The chain parameters, or NULL if ctx is NULL.
 */
const dogecoin_chainparams* dogecoin_context_get_chainparams(const dogecoin_context* ctx)
{
    return ctx ? ctx->chain_params : NULL;
}

/**
 * @brief Returns the per-context transaction sub-context.
 *
 * @param ctx The context to query. May be NULL.
 *
 * @return The transaction context, or NULL if ctx is NULL.
 */
struct dogecoin_transaction_context* dogecoin_context_get_transaction_context(dogecoin_context* ctx)
{
    return ctx ? ctx->tx_ctx : NULL;
}

/**
 * @brief Returns the per-context eckey sub-context.
 *
 * @param ctx The context to query. May be NULL.
 *
 * @return The eckey context, or NULL if ctx is NULL.
 */
struct dogecoin_eckey_context* dogecoin_context_get_eckey_context(dogecoin_context* ctx)
{
    return ctx ? ctx->key_ctx : NULL;
}

/**
 * @brief Returns the opaque per-context secp256k1 context.
 *
 * @param ctx The context to query. May be NULL.
 *
 * @return The secp256k1 context pointer, or NULL if ctx is NULL.
 */
void* dogecoin_context_get_ecc_context(dogecoin_context* ctx)
{
    return ctx ? ctx->ecc_ctx : NULL;
}

/**
 * @brief Returns the opaque per-context fast RNG state.
 *
 * @param ctx The context to query. May be NULL.
 *
 * @return The RNG state pointer, or NULL if ctx is NULL.
 */
void* dogecoin_context_get_rng_state(dogecoin_context* ctx)
{
    return ctx ? ctx->rng_state : NULL;
}

/**
 * @brief Records an error code and message on a context.
 *
 * Stores the supplied code and copies the message (truncated to fit) into the
 * context's last-error buffer for later retrieval.
 *
 * @param ctx  The context to update. No-op if NULL.
 * @param code The numeric error code to store.
 * @param msg  The error message, or NULL to clear the message.
 *
 * @return Nothing.
 */
void dogecoin_context_set_error(dogecoin_context* ctx, int code, const char* msg)
{
    if (!ctx) return;
    ctx->error_code = code;
    if (!msg) {
        ctx->last_error[0] = '\0';
        return;
    }
    strncpy(ctx->last_error, msg, sizeof(ctx->last_error) - 1);
    ctx->last_error[sizeof(ctx->last_error) - 1] = '\0';
}

/**
 * @brief Returns the last error code recorded on a context.
 *
 * @param ctx The context to query. May be NULL.
 *
 * @return The stored error code, or 0 if ctx is NULL.
 */
int dogecoin_context_get_error_code(const dogecoin_context* ctx)
{
    return ctx ? ctx->error_code : 0;
}

/**
 * @brief Returns the last error message recorded on a context.
 *
 * @param ctx The context to query. May be NULL.
 *
 * @return The stored error message, or an empty string if ctx is NULL.
 */
const char* dogecoin_context_get_error(const dogecoin_context* ctx)
{
    if (!ctx) return "";
    return ctx->last_error;
}

/**
 * @brief Generates a private/public keypair using a context's chain.
 *
 * Produces a WIF-encoded private key and matching P2PKH address for the chain
 * selected by the context. When wif or addr is NULL the required buffer sizes
 * are returned via wif_size/addr_size without generating output. On buffer
 * overflow the required sizes are written and an error is recorded on the
 * context.
 *
 * @param ctx       The context selecting the chain. Receives error state on failure.
 * @param wif       Destination buffer for the WIF key, or NULL to query the size.
 * @param wif_size  In/out: capacity of wif on input, bytes needed on output.
 * @param addr      Destination buffer for the address, or NULL to query the size.
 * @param addr_size In/out: capacity of addr on input, bytes needed on output.
 *
 * @return true on success, false on invalid arguments, generation failure, or
 *         insufficient buffer capacity.
 */
int dogecoin_generate_keypair_ex(dogecoin_context* ctx, char* wif, size_t* wif_size, char* addr, size_t* addr_size)
{
    if (!ctx || !wif_size || !addr_size) {
        dogecoin_context_set_error(ctx, -1, "invalid arguments");
        return false;
    }

    const dogecoin_bool is_testnet = (ctx->chain_params != &dogecoin_chainparams_main);
    char tmp_wif[PRIVKEYWIFLEN] = {0};
    char tmp_addr[P2PKHLEN] = {0};
    if (!generatePrivPubKeypair(tmp_wif, tmp_addr, is_testnet)) {
        dogecoin_context_set_error(ctx, -2, "key generation failed");
        return false;
    }

    size_t wif_need = strlen(tmp_wif) + 1;
    size_t addr_need = strlen(tmp_addr) + 1;
    dogecoin_context_zero_error(ctx);
    if (!wif || !addr) {
        *wif_size = wif_need;
        *addr_size = addr_need;
        return true;
    }
    if (*wif_size < wif_need || *addr_size < addr_need) {
        *wif_size = wif_need;
        *addr_size = addr_need;
        dogecoin_context_set_error(ctx, -3, "output buffer too small");
        return false;
    }

    memcpy(wif, tmp_wif, wif_need);
    memcpy(addr, tmp_addr, addr_need);
    *wif_size = wif_need;
    *addr_size = addr_need;
    return true;
}

/* Short-form alias API: dogecoin_ctx_*
 * These are thin aliases over dogecoin_context_* that match the API surface
 * documented in doc/thread_safety.md. dogecoin_ctx_new_ts() additionally
 * marks the context as thread-safe so dependent subsystems can opt into
 * per-object locking when wired through the context. */

/**
 * @brief Creates a thread-compatible context (short-form alias).
 *
 * Equivalent to dogecoin_context_new() and leaves the context untagged so
 * subsystems use their default (non-_ts) single-owner behavior.
 *
 * @param testnet    Selects testnet chain parameters when true, mainnet otherwise.
 * @param enable_net Records whether networking is intended for this context.
 *
 * @return A pointer to the new context, or NULL on failure.
 */
dogecoin_ctx* dogecoin_ctx_new(dogecoin_bool testnet, dogecoin_bool enable_net)
{
    dogecoin_ctx* ctx = dogecoin_context_new(testnet, enable_net);
    if (ctx) ctx->thread_safe = 0;
    return ctx;
}

/**
 * @brief Creates a thread-safe-tagged context (short-form alias).
 *
 * Equivalent to dogecoin_context_new() but marks the context as thread-safe so
 * dependent subsystems select per-object locking via dogecoin_ctx_is_thread_safe().
 *
 * @param testnet    Selects testnet chain parameters when true, mainnet otherwise.
 * @param enable_net Records whether networking is intended for this context.
 *
 * @return A pointer to the new thread-safe context, or NULL on failure.
 */
dogecoin_ctx* dogecoin_ctx_new_ts(dogecoin_bool testnet, dogecoin_bool enable_net)
{
    dogecoin_ctx* ctx = dogecoin_context_new(testnet, enable_net);
    if (ctx) ctx->thread_safe = 1;
    return ctx;
}

/**
 * @brief Retains a context reference (short-form alias).
 *
 * @param ctx The context to retain. No-op if NULL.
 *
 * @return Nothing.
 */
void dogecoin_ctx_acquire(dogecoin_ctx* ctx)
{
    dogecoin_context_acquire(ctx);
}

/**
 * @brief Releases a context reference (short-form alias).
 *
 * @param ctx The context to release. No-op if NULL.
 *
 * @return Nothing.
 */
void dogecoin_ctx_release(dogecoin_ctx* ctx)
{
    dogecoin_context_release(ctx);
}

/**
 * @brief Reports whether a context was tagged thread-safe.
 *
 * @param ctx The context to query. May be NULL.
 *
 * @return Nonzero if the context was created via dogecoin_ctx_new_ts(), 0 otherwise.
 */
int dogecoin_ctx_is_thread_safe(const dogecoin_ctx* ctx)
{
    return ctx ? ctx->thread_safe : 0;
}
