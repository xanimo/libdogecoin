/*

 The MIT License (MIT)

 Copyright (c) 2016 Libbtc Developers
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

#ifndef __LIBDOGECOIN_BLOCKCHAIN_H__
#define __LIBDOGECOIN_BLOCKCHAIN_H__

#include <dogecoin/dogecoin.h>
#include <dogecoin/block.h>
#include <dogecoin/tx.h>

LIBDOGECOIN_BEGIN_DECL

/**
 * The block index is a data structure that stores the hash and header of each block in the blockchain.
 */
typedef struct dogecoin_blockindex {
    uint32_t height;
    uint256 hash;
    dogecoin_block_header header;
    struct dogecoin_blockindex* prev;
} dogecoin_blockindex;

typedef struct dogecoin_txid_ {
    uint32_t height;
    uint256 hash;
    dogecoin_tx* tx;
} dogecoin_txid;

typedef struct dogecoin_txdb_ {
    FILE *file;
    const dogecoin_chainparams* chain;
    struct dogecoin_blockindex* tip;
    vector *vec_txns;
    void* txns_rbtree;
} dogecoin_txdb;

dogecoin_txid* dogecoin_txid_new();
void dogecoin_txid_free(dogecoin_txid* txid);


dogecoin_txdb* dogecoin_txdb_new(const dogecoin_chainparams *params);
void dogecoin_txdb_free(dogecoin_txdb* txdb);
dogecoin_bool dogecoin_txdb_create(dogecoin_txdb* txdb, const char* file_path, int *error);
dogecoin_bool dogecoin_txdb_load(dogecoin_txdb* txdb, const char* file_path, int *error, dogecoin_bool *created);
dogecoin_bool dogecoin_txdb_flush(dogecoin_txdb* txdb);
dogecoin_bool dogecoin_txdb_write_record(dogecoin_txdb *txdb, const cstring* record, uint8_t record_type);
void dogecoin_txdb_add_txid_intern_move(dogecoin_txdb *txdb, const dogecoin_txid *txid);
void dogecoin_add_transaction(void *ctx, dogecoin_tx *tx, unsigned int pos, dogecoin_txid *txid);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_BLOCKCHAIN_H__
