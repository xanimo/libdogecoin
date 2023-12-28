/*

 The MIT License (MIT)

 Copyright (c) 2016 The Bitcoin Core developers
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

#ifndef __LIBDOGECOIN_BLOCK_ENCODING_H__
#define __LIBDOGECOIN_BLOCK_ENCODING_H__

#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

#include <dogecoin/block.h>
#include <dogecoin/serialize.h>

struct dogecoin_tx_mempool {
    dogecoin_tx* tx;
};

struct dogecoin_block_tx_request {
    uint256 blockhash;
    vector indexes;
};

struct dogecoin_block_txns {
    uint256 blockhash;
    vector txn;
};

struct dogecoin_prefilled_tx {
    uint16_t index;
    dogecoin_tx tx;
};

typedef enum read_status_ {
    READ_STATUS_OK,
    READ_STATUS_INVALID, // Invalid object, peer is sending bogus crap
    READ_STATUS_FAILED, // Failed to process object
} read_status;

struct dogecoin_block_header_and_short_txids {
    uint64_t short_txid_k0, short_txid_k1;
    uint64_t nonce;
    void (*fill_short_txid_selector)(struct dogecoin_block_header_and_short_txids);
    const int short_txids_length;
    vector short_txids;
    vector prefilled_txns;
    dogecoin_block_header header;
    uint64_t (*get_short_id)(struct dogecoin_block_header_and_short_txids, const uint256* txhash);
    size_t (*block_tx_count)(struct dogecoin_block_header_and_short_txids);
};

struct partially_downloaded_block {
    vector tx_available;
    struct dogecoin_tx_mempool* pool;
    dogecoin_block_header header;
    read_status (*init_data)(struct dogecoin_block_header_and_short_txids* cmpctblock);
    dogecoin_bool (*is_tx_available)(size_t index);
    read_status (*fill_block)(dogecoin_auxpow_block* block, vector* vtx_missing);
};

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_BLOCK_ENCODING_H__
