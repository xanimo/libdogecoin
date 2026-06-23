/*

 The MIT License (MIT)

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

#include <assert.h>

#include <dogecoin/base58.h>
#include <dogecoin/eckey.h>
#include <dogecoin/key.h>
#include <dogecoin/mem.h>
#include <dogecoin/utils.h>

static dogecoin_eckey_context* default_eckey_context(void) {
    static DOGECOIN_THREAD_LOCAL dogecoin_eckey_context default_ctx = {0};
    return &default_ctx;
}

/* ---- internal registry helpers; caller MUST hold ctx->lock ----
 * Raw uthash operations with no locking, so the public _ts entry points and the
 * composed start/free paths take the lock once and stay deadlock-free on the
 * non-recursive mutex. */

/* Dispose of a key already unlinked from the registry: defer if a find_eckey_ts()
   holder still references it, otherwise cleanse and free now. Defined below with
   the lifetime helpers it depends on. Caller MUST hold ctx->lock. */
static void dispose_unlinked_eckey_locked(dogecoin_eckey_context* ctx, eckey* key);

static void add_eckey_locked(dogecoin_eckey_context* ctx, eckey *key) {
    eckey* key_old;
    HASH_FIND_INT(ctx->keys, &key->idx, key_old);
    if (key_old == NULL) {
        HASH_ADD_INT(ctx->keys, idx, key);
        return;
    }
    /* With monotonic, never-reused ids (see new_eckey_ts) a collision is
       impossible for keys minted by new_eckey_ts()/start_key_ts(). Reaching here
       means a caller supplied a colliding idx directly. The previous code
       HASH_REPLACE'd and freed the displaced key -- destroying a live key AND,
       because dogecoin_key_free() does not cleanse, leaving its private-key bytes
       in freed heap. Keep the existing key and decline the colliding insert; the
       caller retains ownership of `key`. (Real removals still go through
       remove_eckey_locked -> dispose_unlinked_eckey_locked, which preserves the
       refcount-safe deferred delete and destroy_eckey_locked()'s cleanse.) */
    (void)key_old;
}

static eckey* find_eckey_locked(dogecoin_eckey_context* ctx, int idx) {
    eckey* key;
    HASH_FIND_INT(ctx->keys, &idx, key);
    return key;
}

/* ---- lifetime side-table helpers; caller MUST hold ctx->lock ----
 * The refcount/pending_delete state lives outside the eckey struct so the public
 * eckey layout never changes. A record is created lazily the first time an entry
 * is retained, and dropped as soon as it is no longer needed. */
static eckey_lifetime* find_lifetime_locked(dogecoin_eckey_context* ctx, eckey* key) {
    eckey_lifetime* lt;
    HASH_FIND_PTR(ctx->lifetimes, &key, lt);
    return lt;
}

static eckey_lifetime* get_or_create_lifetime_locked(dogecoin_eckey_context* ctx, eckey* key) {
    eckey_lifetime* lt = find_lifetime_locked(ctx, key);
    if (lt) return lt;
    lt = (eckey_lifetime*)dogecoin_calloc(1, sizeof(*lt));
    if (!lt) return NULL;
    lt->key = key;
    HASH_ADD_PTR(ctx->lifetimes, key, lt);
    return lt;
}

static void drop_lifetime_locked(dogecoin_eckey_context* ctx, eckey_lifetime* lt) {
    if (!lt) return;
    HASH_DEL(ctx->lifetimes, lt);
    dogecoin_free(lt);
}

/* Free the key material and the entry itself. Caller MUST hold ctx->lock and
   must have already unlinked the entry from the registry and dropped its
   lifetime record. */
static void destroy_eckey_locked(eckey* key) {
    dogecoin_privkey_cleanse(&key->private_key);
    dogecoin_pubkey_cleanse(&key->public_key);
    dogecoin_key_free(key);
}

/* Dispose of a key that is already unlinked from ctx->keys. If a find_eckey_ts()
   holder still references it, mark its lifetime pending_delete so the last
   release_eckey_locked() performs the cleanse+free; otherwise do it now. */
static void dispose_unlinked_eckey_locked(dogecoin_eckey_context* ctx, eckey* key) {
    eckey_lifetime* lt = find_lifetime_locked(ctx, key);
    if (lt && lt->refcount > 0) {
        /* A holder from find_eckey_ts() is still using it; defer the free to the
           last release. The entry is already out of the registry. */
        lt->pending_delete = 1;
        return;
    }
    drop_lifetime_locked(ctx, lt);
    destroy_eckey_locked(key);
}

static void remove_eckey_locked(dogecoin_eckey_context* ctx, eckey* key) {
    HASH_DEL(ctx->keys, key); /* unlink so no new finder can reach it */
    dispose_unlinked_eckey_locked(ctx, key);
}

/* Drop a reference taken by find_eckey_ts(). Caller MUST hold ctx->lock. Frees
   the entry if it was removed while referenced and this was the last ref. */
static void release_eckey_locked(dogecoin_eckey_context* ctx, eckey* key) {
    if (!key) return;
    eckey_lifetime* lt = find_lifetime_locked(ctx, key);
    if (!lt) return;
    if (lt->refcount > 0) lt->refcount--;
    if (lt->refcount == 0) {
        int pending = lt->pending_delete;
        drop_lifetime_locked(ctx, lt);
        if (pending) destroy_eckey_locked(key);
    }
}

dogecoin_eckey_context* dogecoin_eckey_context_new(void) {
    dogecoin_eckey_context* ctx =
        (dogecoin_eckey_context*)dogecoin_calloc(1, sizeof(dogecoin_eckey_context));
    if (!ctx) return NULL;
#if defined(_WIN32) || defined(DOGECOIN_HAVE_THREADS)
    /* With a threading runtime, a failed mutex init is a real error. Without
       one (e.g. OP-TEE/enclave builds), dogecoin_mutex_init() returns false by
       design and the lock no-ops; the context is still valid, so don't treat
       that as a construction failure. */
    if (!dogecoin_mutex_init(&ctx->lock)) {
        dogecoin_free(ctx);
        return NULL;
    }
#else
    (void)dogecoin_mutex_init(&ctx->lock); /* no-op; lock stays uninitialized */
#endif
    return ctx;
}

void dogecoin_eckey_context_free(dogecoin_eckey_context* ctx) {
    if (!ctx) return;
    eckey* current;
    eckey* tmp;
    dogecoin_mutex_lock(&ctx->lock);
    HASH_ITER(hh, ctx->keys, current, tmp) {
#ifndef NDEBUG
        /* Guard rail (debug builds): freeing a context while a find_eckey_ts()
           reference is still outstanding indicates a missing release_eckey_ts()
           and would otherwise leak the deferred-delete entry. */
        eckey_lifetime* lt = find_lifetime_locked(ctx, current);
        assert(!lt || lt->refcount == 0);
#endif
        remove_eckey_locked(ctx, current);
    }
    /* Any lifetime records still present here are orphans (refcount == 0 and not
       tied to a live registry entry); drop them so the context frees cleanly. */
    {
        eckey_lifetime* lt_cur;
        eckey_lifetime* lt_tmp;
        HASH_ITER(hh, ctx->lifetimes, lt_cur, lt_tmp) {
            drop_lifetime_locked(ctx, lt_cur);
        }
    }
    dogecoin_mutex_unlock(&ctx->lock);
    dogecoin_mutex_destroy(&ctx->lock);
    dogecoin_free(ctx);
}

/**
 * @brief This function instantiates a new working eckey,
 * but does not add it to the hash table.
 *
 * @return A pointer to the new working eckey.
 */
eckey* new_eckey(dogecoin_bool is_testnet) {
    return new_eckey_ts(default_eckey_context(), is_testnet);
}

eckey* new_eckey_ts(dogecoin_eckey_context* ctx, dogecoin_bool is_testnet) {
    if (!ctx) return NULL;
    eckey* key = (struct eckey*)dogecoin_calloc(1, sizeof *key);
    dogecoin_privkey_init(&key->private_key);
    assert(dogecoin_privkey_is_valid(&key->private_key) == 0);
    dogecoin_privkey_gen(&key->private_key);
    assert(dogecoin_privkey_is_valid(&key->private_key)==1);
    dogecoin_pubkey_init(&key->public_key);
    dogecoin_pubkey_from_key(&key->private_key, &key->public_key);
    assert(dogecoin_pubkey_is_valid(&key->public_key) == 1);
    strcpy(key->public_key_hex, utils_uint8_to_hex((const uint8_t *)&key->public_key, 33));
    uint8_t pkeybase58c[34];
    const dogecoin_chainparams* chain = is_testnet ? &dogecoin_chainparams_test : &dogecoin_chainparams_main;
    pkeybase58c[0] = chain->b58prefix_secret_address;
    pkeybase58c[33] = 1; /* always use compressed keys */
    memcpy_safe(&pkeybase58c[1], &key->private_key, DOGECOIN_ECKEY_PKEY_LENGTH);
    if (dogecoin_base58_encode_check(pkeybase58c, sizeof(pkeybase58c), key->private_key_wif, sizeof(key->private_key_wif)) == 0) { dogecoin_key_free(key); return NULL; }
    if (!dogecoin_pubkey_getaddr_p2pkh(&key->public_key, chain, (char*)&key->address)) { dogecoin_key_free(key); return NULL; }
    dogecoin_mutex_lock(&ctx->lock);
    key->idx = (int)++ctx->next_idx; /* never-reused id; see dogecoin_eckey_context.next_idx */
    dogecoin_mutex_unlock(&ctx->lock);
    return key;
}

/**
 * @brief This function instantiates a new working eckey,
 * but does not add it to the hash table.
 *
 * @return A pointer to the new working eckey.
 */
eckey* new_eckey_from_privkey(char* private_key) {
    return new_eckey_from_privkey_ts(default_eckey_context(), private_key);
}

eckey* new_eckey_from_privkey_ts(dogecoin_eckey_context* ctx, char* private_key) {
    if (!ctx || !private_key) return NULL;
    eckey* key = (struct eckey*)dogecoin_calloc(1, sizeof *key);
    dogecoin_privkey_init(&key->private_key);
    const dogecoin_chainparams* chain = chain_from_b58_prefix(private_key);
    if (!dogecoin_privkey_decode_wif(private_key, chain, &key->private_key)) { dogecoin_key_free(key); return NULL; }
    assert(dogecoin_privkey_is_valid(&key->private_key)==1);
    dogecoin_pubkey_init(&key->public_key);
    dogecoin_pubkey_from_key(&key->private_key, &key->public_key);
    assert(dogecoin_pubkey_is_valid(&key->public_key) == 1);
    strcpy(key->public_key_hex, utils_uint8_to_hex((const uint8_t *)&key->public_key, 33));
    uint8_t pkeybase58c[34];
    pkeybase58c[0] = chain->b58prefix_secret_address;
    pkeybase58c[33] = 1; /* always use compressed keys */
    memcpy_safe(&pkeybase58c[1], &key->private_key, DOGECOIN_ECKEY_PKEY_LENGTH);
    if (dogecoin_base58_encode_check(pkeybase58c, sizeof(pkeybase58c), key->private_key_wif, sizeof(key->private_key_wif)) == 0) { dogecoin_key_free(key); return NULL; }
    if (!dogecoin_pubkey_getaddr_p2pkh(&key->public_key, chain, (char*)&key->address)) { dogecoin_key_free(key); return NULL; }
    dogecoin_mutex_lock(&ctx->lock);
    key->idx = (int)++ctx->next_idx; /* never-reused id; see dogecoin_eckey_context.next_idx */
    dogecoin_mutex_unlock(&ctx->lock);
    return key;
}

/**
 * @brief This function takes a pointer to an existing working
 * eckey object and adds it to the hash table.
 *
 * @param key The pointer to the working eckey.
 *
 * @return Nothing.
 */
void add_eckey(eckey *key) {
    add_eckey_ts(default_eckey_context(), key);
}

void add_eckey_ts(dogecoin_eckey_context* ctx, eckey *key) {
    if (!ctx || !key) return;
    dogecoin_mutex_lock(&ctx->lock);
    add_eckey_locked(ctx, key);
    dogecoin_mutex_unlock(&ctx->lock);
}

/**
 * @brief This function takes an index and returns the working
 * eckey associated with that index in the hash table.
 *
 * @param idx The index of the target working eckey.
 *
 * @return The pointer to the working eckey associated with
 * the provided index.
 */
eckey* find_eckey(int idx) {
    /* Legacy lookup on the thread-local default context, which is never shared
       across threads. Return a borrowed pointer without retaining so the
       default context's entries keep no lifetime record per the documented
       invariant (see eckey_lifetime); the legacy callers of this API have no
       release_eckey_ts() pairing. */
    dogecoin_eckey_context* ctx = default_eckey_context();
    if (!ctx) return NULL;
    dogecoin_mutex_lock(&ctx->lock);
    eckey* key = find_eckey_locked(ctx, idx);
    dogecoin_mutex_unlock(&ctx->lock);
    return key;
}

eckey* find_eckey_ts(dogecoin_eckey_context* ctx, int idx) {
    if (!ctx) return NULL;
    dogecoin_mutex_lock(&ctx->lock);
    eckey* key = find_eckey_locked(ctx, idx);
    if (key) {
        /* retain under the registry lock; the lifetime record is created lazily */
        eckey_lifetime* lt = get_or_create_lifetime_locked(ctx, key);
        if (lt) {
            lt->refcount++;
        } else {
            key = NULL; /* allocation failed; do not hand out an unretained ref */
        }
    }
    dogecoin_mutex_unlock(&ctx->lock);
    return key;
}

/* Release a reference obtained from find_eckey_ts(). Every successful (non-NULL)
   find_eckey_ts() must be paired with exactly one call here once the caller is
   done dereferencing the returned entry. */
void release_eckey_ts(dogecoin_eckey_context* ctx, eckey* key) {
    if (!ctx || !key) return;
    dogecoin_mutex_lock(&ctx->lock);
    release_eckey_locked(ctx, key);
    dogecoin_mutex_unlock(&ctx->lock);
}

int with_eckey_ts(dogecoin_eckey_context* ctx, int idx, void (*fn)(eckey* key, void* arg), void* arg) {
    if (!ctx || !fn) return 0;
    dogecoin_mutex_lock(&ctx->lock);
    eckey* key = find_eckey_locked(ctx, idx);
    if (key) fn(key, arg);
    dogecoin_mutex_unlock(&ctx->lock);
    return key != NULL;
}

/**
 * @brief This function removes the specified working eckey
 * from the hash table and frees the keys in memory.
 *
 * @param key The pointer to the eckey to remove.
 *
 * @return Nothing.
 */
void remove_eckey(eckey* key) {
    remove_eckey_ts(default_eckey_context(), key);
}

void remove_eckey_ts(dogecoin_eckey_context* ctx, eckey* key) {
    if (!ctx || !key) return;
    dogecoin_mutex_lock(&ctx->lock);
    remove_eckey_locked(ctx, key);
    dogecoin_mutex_unlock(&ctx->lock);
}

/**
 * @brief This function frees the memory allocated
 * for an eckey.
 *
 * @param eckey The pointer to the eckey to be freed.
 *
 * @return Nothing.
 */
void dogecoin_key_free(eckey* eckey)
{
    dogecoin_free(eckey);
}

/**
 * @brief This function creates a new key, places it in
 * the hash table, and returns the index of the new key,
 * starting from 1 and incrementing each subsequent call.
 *
 * @param is_testnet
 *
 * @return The index of the new key.
 */
int start_key(dogecoin_bool is_testnet) {
    return start_key_ts(default_eckey_context(), is_testnet);
}

int start_key_ts(dogecoin_eckey_context* ctx, dogecoin_bool is_testnet) {
    if (!ctx) return -1;
    /* Build the key without the lock (the EC work touches no registry state),
       then assign the index and insert under a single lock acquisition so the
       HASH_COUNT()->HASH_ADD() allocation is atomic. new_eckey_ts assigns a
       provisional idx; we overwrite it here under the same lock as the insert. */
    eckey* key = new_eckey_ts(ctx, is_testnet);
    if (!key) return -1;
    /* new_eckey_ts() already minted a unique, never-reused idx under the lock.
       Just insert it (re-minting here would burn a second counter value). */
    dogecoin_mutex_lock(&ctx->lock);
    add_eckey_locked(ctx, key);
    int index = key->idx;
    dogecoin_mutex_unlock(&ctx->lock);
    return index;
}
