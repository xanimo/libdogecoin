/*

 The MIT License (MIT)

 Copyright (c) 2023 bluezr
 Copyright (c) 2023 The Dogecoin Foundation

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

#ifndef __LIBDOGECOIN_ECKEY_H__
#define __LIBDOGECOIN_ECKEY_H__

#include <dogecoin/dogecoin.h>
#include <dogecoin/key.h>
#include <dogecoin/uthash.h>

LIBDOGECOIN_BEGIN_DECL

/* hashmap functions */
typedef struct eckey {
    int idx;
    dogecoin_key private_key;
    char private_key_wif[PRIVKEYWIFLEN];
    dogecoin_pubkey public_key;
    char public_key_hex[PUBKEYHEXLEN];
    char address[P2PKHLEN];
    UT_hash_handle hh;
} eckey;

/* Per-entry lifetime bookkeeping for the _ts retain-under-lock model. Kept in a
   side table (keyed by the eckey pointer) rather than inside eckey itself so the
   public eckey struct layout/ABI stays unchanged. Both fields are guarded by the
   owning dogecoin_eckey_context->lock. refcount counts outstanding holders handed
   out by find_eckey_ts(); pending_delete marks an entry unlinked from the registry
   but not yet freed because a holder is still using it. Entries in the thread-local
   default context never get a lifetime record (they are never retained). */
typedef struct eckey_lifetime {
    eckey* key; /* hash key: the live eckey pointer */
    int refcount;
    int pending_delete;
    UT_hash_handle hh;
} eckey_lifetime;

typedef struct dogecoin_eckey_context {
    eckey* keys;
    eckey_lifetime* lifetimes; /* side table guarding _ts refcounts, keyed by key ptr */
    dogecoin_mutex_t lock; /* guards the registry roots above; no-op for the
                              zero-initialized per-thread default context */
    uint32_t next_idx;     /* monotonic id source, guarded by lock. Never reused:
                              deriving ids from HASH_COUNT()+1 recycled an id after
                              any removal, so a later start_key could mint the id of
                              a still-live key and evict it via HASH_REPLACE -- which
                              freed the displaced key WITHOUT cleansing it, leaving
                              private-key bytes in freed heap. Zero-initialized;
                              first minted id is 1. */
} dogecoin_eckey_context;

// instantiates a new eckey
LIBDOGECOIN_API eckey* new_eckey(dogecoin_bool is_testnet);
LIBDOGECOIN_API eckey* new_eckey_ts(dogecoin_eckey_context* ctx, dogecoin_bool is_testnet);

LIBDOGECOIN_API eckey* new_eckey_from_privkey(char* key);
LIBDOGECOIN_API eckey* new_eckey_from_privkey_ts(dogecoin_eckey_context* ctx, char* key);

// adds eckey structure to hash table
LIBDOGECOIN_API void add_eckey(eckey *key);
LIBDOGECOIN_API void add_eckey_ts(dogecoin_eckey_context* ctx, eckey *key);

// find eckey from the hash table
LIBDOGECOIN_API eckey* find_eckey(int idx);
/* THREAD-SAFE variant - returns an entry with a reference held under the
   registry lock; pair every successful (non-NULL) call with exactly one
   release_eckey_ts(). */
LIBDOGECOIN_API eckey* find_eckey_ts(dogecoin_eckey_context* ctx, int idx);
/* Release a reference obtained from find_eckey_ts(). */
LIBDOGECOIN_API void release_eckey_ts(dogecoin_eckey_context* ctx, eckey* key);
/* Callback-under-lock convenience: looks up idx and, if found, invokes fn(key,
   arg) while the registry lock is held, so the entry cannot be removed/freed
   for the duration of the callback and no retain/release bookkeeping is needed.
   fn must not call back into the same context (the lock is non-recursive).
   Returns 1 if an entry was found and fn was invoked, 0 otherwise. */
LIBDOGECOIN_API int with_eckey_ts(dogecoin_eckey_context* ctx, int idx, void (*fn)(eckey* key, void* arg), void* arg);

// remove eckey from the hash table
LIBDOGECOIN_API void remove_eckey(eckey *key);
LIBDOGECOIN_API void remove_eckey_ts(dogecoin_eckey_context* ctx, eckey *key);

LIBDOGECOIN_API void dogecoin_key_free(eckey* eckey);

// instantiates and adds key to the hash table
LIBDOGECOIN_API int start_key(dogecoin_bool is_testnet);
LIBDOGECOIN_API int start_key_ts(dogecoin_eckey_context* ctx, dogecoin_bool is_testnet);

LIBDOGECOIN_API dogecoin_eckey_context* dogecoin_eckey_context_new(void);
LIBDOGECOIN_API void dogecoin_eckey_context_free(dogecoin_eckey_context* ctx);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_ECKEY_H__
