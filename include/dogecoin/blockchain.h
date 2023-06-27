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
#include <dogecoin/uthash.h>

LIBDOGECOIN_BEGIN_DECL

/**
 * The block index is a data structure that stores the hash and header of each block in the blockchain.
 */
typedef struct dogecoin_blockindex {
    int index;
    uint32_t height;
    uint256 hash;
    dogecoin_block_header header;
    struct dogecoin_blockindex* prev;
    UT_hash_handle hh;
} dogecoin_blockindex;

DISABLE_WARNING_PUSH
DISABLE_WARNING(-Wunused-variable)
static dogecoin_blockindex *block_indices = NULL;
DISABLE_WARNING_POP

// instantiates a new dogecoin_blockindex
LIBDOGECOIN_API dogecoin_blockindex* new_dogecoin_blockindex();

// adds dogecoin_blockindex structure to hash table
LIBDOGECOIN_API void add_dogecoin_blockindex(dogecoin_blockindex *block);

// find dogecoin_blockindex from the hash table
LIBDOGECOIN_API dogecoin_blockindex* find_dogecoin_blockindex(int index);

// remove dogecoin_blockindex from the hash table
LIBDOGECOIN_API void remove_dogecoin_blockindex(dogecoin_blockindex *block);

LIBDOGECOIN_API void dogecoin_blockindex_free(dogecoin_blockindex *block);

// remove all block indicies from hash table
LIBDOGECOIN_API void remove_all_blockindices();

// instantiates and adds index to the hash table
LIBDOGECOIN_API int start_dogecoin_blockindex();

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_BLOCKCHAIN_H__
