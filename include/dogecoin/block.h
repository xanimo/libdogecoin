/*

 The MIT License (MIT)

 Copyright (c) 2016 Thomas Kerin
 Copyright (c) 2016 libbtc developers
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

#ifndef __LIBDOGECOIN_BLOCK_H__
#define __LIBDOGECOIN_BLOCK_H__

#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

#include <dogecoin/buffer.h>
#include <dogecoin/cstr.h>
#include <dogecoin/crypto/hash.h>
#include <dogecoin/tx.h>

typedef struct dogecoin_block_header_ {
    int32_t version;
    uint256 prev_block;
    uint256 merkle_root;
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
} dogecoin_block_header;

typedef struct merkle_branch_ {
    uint256 hashes;
    uint32_t sidemask;
} merkle_branch;

typedef struct auxpow_block_header_ {
    dogecoin_tx parent_coinbase;
    uint256 parent_hash;
    uint256 coinbase_branch;
    uint256 blockchain_branch;
    dogecoin_block_header parent_header;
} auxpow_block_header;

typedef struct auxpow_block_ {
    dogecoin_block_header block_header;
    auxpow_block_header aux_data;
    dogecoin_tx txns[];
} auxpow_block;

/* Creating a new block header object. */
LIBDOGECOIN_API dogecoin_block_header* dogecoin_block_header_new();
/* A macro that is used to free the memory allocated for the `dogecoin_block_header` struct. */
LIBDOGECOIN_API void dogecoin_block_header_free(dogecoin_block_header* header);

// TODO
LIBDOGECOIN_API int calcLength(char buf, int offset);

LIBDOGECOIN_API int32_t dogecoin_get_block_header_version(struct const_buffer* buffer);

LIBDOGECOIN_API int dogecoin_get_block_header_prev_block(struct const_buffer* buffer);

LIBDOGECOIN_API int dogecoin_get_block_header_merkle_root(struct const_buffer* buffer);

LIBDOGECOIN_API int dogecoin_get_block_header_timestamp(struct const_buffer* buffer);

LIBDOGECOIN_API int dogecoin_get_block_header_bits(struct const_buffer* buffer);

LIBDOGECOIN_API int32_t dogecoin_get_block_header_nonce(struct const_buffer* buffer);

LIBDOGECOIN_API int dogecoin_get_block_header_coinbase_txn(struct const_buffer* buffer);

LIBDOGECOIN_API int dogecoin_get_block_header_block_hash(struct const_buffer* buffer);

LIBDOGECOIN_API int dogecoin_get_block_header_coinbase_branch(struct const_buffer* buffer);

LIBDOGECOIN_API int dogecoin_get_block_header_blockchain_branch(struct const_buffer* buffer);

LIBDOGECOIN_API int dogecoin_get_block_header_parent_block(struct const_buffer* buffer);

LIBDOGECOIN_API int dogecoin_get_block_header_txn_count(struct const_buffer* buffer);

LIBDOGECOIN_API int dogecoin_get_block_header_txns(struct const_buffer* buffer);
// END TODO

/* Deserializing a block header from a buffer. */
LIBDOGECOIN_API int dogecoin_block_header_deserialize(dogecoin_block_header* header, struct const_buffer* buf);
/* A function that serializes a block header into a cstring. */
LIBDOGECOIN_API void dogecoin_block_header_serialize(cstring* s, const dogecoin_block_header* header);
/* A macro that is used to copy the contents of the `src` block header into the `dest` block header. */
LIBDOGECOIN_API void dogecoin_block_header_copy(dogecoin_block_header* dest, const dogecoin_block_header* src);
/* This is a macro that is used to hash the contents of the `dogecoin_block_header` struct. */
LIBDOGECOIN_API dogecoin_bool dogecoin_block_header_hash(dogecoin_block_header* header, uint256 hash);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_BLOCK_H__
