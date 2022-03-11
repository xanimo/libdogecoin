/*

 The MIT License (MIT)

 Copyright (c) 2016 Jonas Schnelli
 Copyright (c) 2022 bluezr
 Copyright (c) 2022 The Dogecoin Foundation

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

#ifndef __LIBDOGECOIN_WALLET_H__
#define __LIBDOGECOIN_WALLET_H__

LIBDOGECOIN_BEGIN_DECL

#include <dogecoin/dogecoin.h>
#include <dogecoin/blockchain.h>
#include <dogecoin/bip32.h>
#include <dogecoin/buffer.h>
#include <dogecoin/tx.h>

#include <stdint.h>
#include <stddef.h>

/** single key/value record */
typedef struct dogecoin_wallet {
    FILE *dbfile;
    dogecoin_hdnode* masterkey;
    uint32_t next_childindex; //cached next child index
    const dogecoin_chainparams* chain;
    uint32_t bestblockheight;
    vector* spends;
    /* use binary trees for in-memory mapping for wtxs, keys */
    void* wtxes_rbtree;
    void* hdkeys_rbtree;
} dogecoin_wallet;

typedef struct dogecoin_wtx_ {
    uint256 tx_hash_cache;
    uint32_t height;
    dogecoin_tx* tx;
} dogecoin_wtx;

typedef struct dogecoin_wallet_hdnode_ {
    uint160 pubkeyhash;
    dogecoin_hdnode *hdnode;
} dogecoin_wallet_hdnode;

typedef struct dogecoin_output_ {
    uint32_t i;
    dogecoin_wtx* wtx;
} dogecoin_output;

/** wallet transaction (wtx) functions */
LIBDOGECOIN_API dogecoin_wtx* dogecoin_wallet_wtx_new();
LIBDOGECOIN_API void dogecoin_wallet_wtx_free(dogecoin_wtx* wtx);
LIBDOGECOIN_API void dogecoin_wallet_wtx_serialize(cstring* s, const dogecoin_wtx* wtx);
LIBDOGECOIN_API dogecoin_bool dogecoin_wallet_wtx_deserialize(dogecoin_wtx* wtx, struct const_buffer* buf);
/** ------------------------------------ */

/** wallet hdnode (wallet_hdnode) functions */
LIBDOGECOIN_API dogecoin_wallet_hdnode* dogecoin_wallet_hdnode_new();
LIBDOGECOIN_API void dogecoin_wallet_hdnode_free(dogecoin_wallet_hdnode* whdnode);
LIBDOGECOIN_API void dogecoin_wallet_hdnode_serialize(cstring* s, const dogecoin_chainparams *params, const dogecoin_wallet_hdnode* whdnode);
LIBDOGECOIN_API dogecoin_bool dogecoin_wallet_hdnode_deserialize(dogecoin_wallet_hdnode* whdnode, const dogecoin_chainparams *params, struct const_buffer* buf);
/** ------------------------------------ */

/** wallet outputs (prev wtx + n) functions */
LIBDOGECOIN_API dogecoin_output* dogecoin_wallet_output_new();
LIBDOGECOIN_API void dogecoin_wallet_output_free(dogecoin_output* output);
/** ------------------------------------ */

LIBDOGECOIN_API dogecoin_wallet* dogecoin_wallet_new(const dogecoin_chainparams *params);
LIBDOGECOIN_API void dogecoin_wallet_free(dogecoin_wallet* wallet);

/** load the wallet, sets masterkey, sets next_childindex */
LIBDOGECOIN_API dogecoin_bool dogecoin_wallet_load(dogecoin_wallet* wallet, const char* file_path, int *error, dogecoin_bool *created);

/** writes the wallet state to disk */
LIBDOGECOIN_API dogecoin_bool dogecoin_wallet_flush(dogecoin_wallet* wallet);

/** set the master key of new created wallet
 consuming app needs to ensure that we don't override exiting masterkeys */
LIBDOGECOIN_API void dogecoin_wallet_set_master_key_copy(dogecoin_wallet* wallet, dogecoin_hdnode* masterkey);

/** derives the next child hdnode (memory is owned by the wallet) */
LIBDOGECOIN_API dogecoin_wallet_hdnode* dogecoin_wallet_next_key(dogecoin_wallet* wallet);

/** writes all available addresses (P2PKH) to the addr_out vector */
LIBDOGECOIN_API void dogecoin_wallet_get_addresses(dogecoin_wallet* wallet, vector* addr_out);

/** searches after a hdnode by given P2PKH (base58(hash160)) address */
LIBDOGECOIN_API dogecoin_wallet_hdnode* dogecoin_wallet_find_hdnode_byaddr(dogecoin_wallet* wallet, const char* search_addr);

/** adds transaction to the wallet (hands over memory management) */
LIBDOGECOIN_API dogecoin_bool dogecoin_wallet_add_wtx_move(dogecoin_wallet* wallet, dogecoin_wtx* wtx);

/** looks if a key with the hash160 (SHA256/RIPEMD) exists */
LIBDOGECOIN_API dogecoin_bool dogecoin_wallet_have_key(dogecoin_wallet* wallet, uint160 hash160);

/** gets credit from given transaction */
LIBDOGECOIN_API int64_t dogecoin_wallet_get_balance(dogecoin_wallet* wallet);

/** gets credit from given transaction */
LIBDOGECOIN_API int64_t dogecoin_wallet_wtx_get_credit(dogecoin_wallet* wallet, dogecoin_wtx* wtx);

/** checks if a transaction outpoint is owned by the wallet */
LIBDOGECOIN_API dogecoin_bool dogecoin_wallet_txout_is_mine(dogecoin_wallet* wallet, dogecoin_tx_out* tx_out);

/** checks if a transaction outpoint is owned by the wallet */
LIBDOGECOIN_API void dogecoin_wallet_add_to_spent(dogecoin_wallet* wallet, dogecoin_wtx* wtx);
LIBDOGECOIN_API dogecoin_bool dogecoin_wallet_is_spent(dogecoin_wallet* wallet, uint256 hash, uint32_t n);
LIBDOGECOIN_API dogecoin_bool dogecoin_wallet_get_unspent(dogecoin_wallet* wallet, vector* unspents);

/** checks a transaction or relevance to the wallet */
LIBDOGECOIN_API void dogecoin_wallet_check_transaction(void *ctx, dogecoin_tx *tx, unsigned int pos, dogecoin_blockindex *pindex);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_WALLET_H__
