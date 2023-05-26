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

#ifndef __LIBDOGECOIN_CONSENSUS_H__
#define __LIBDOGECOIN_CONSENSUS_H__

#include <stdint.h>

#include <dogecoin/block.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/tx.h>
#include <dogecoin/utils.h>
#include <dogecoin/vector.h>

LIBDOGECOIN_BEGIN_DECL

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 4000000;
/** The maximum allowed weight for a block, see BIP 141 (network rule) */
static const unsigned int MAX_BLOCK_WEIGHT = 4000000;
/** The maximum allowed size for a block excluding witness data, in bytes (network rule) */
static const unsigned int MAX_BLOCK_BASE_SIZE = 1000000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const int64_t MAX_BLOCK_SIGOPS_COST = 80000;

/** Flags for nSequence and nLockTime locks */
enum {
    /* Interpret sequence numbers as relative lock-time constraints. */
    LOCKTIME_VERIFY_SEQUENCE = (1 << 0),

    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

/** Merkle functions */
uint256* compute_merkle_root(const vector* leaves, dogecoin_bool* mutated);
vector* compute_merkle_branch(const vector* leaves, uint32_t position);
uint256* compute_merkle_root_from_branch(const uint256* leaf, const vector* branch, uint32_t position);

/*
 * Compute the Merkle root of the transactions in a block.
 * *mutated is set to true if a duplicated subtree was found.
 */
uint256* block_merkle_root(const dogecoin_block* block, dogecoin_bool* mutated);

/*
 * Compute the Merkle branch for the tree of transactions in a block, for a
 * given position.
 * This can be verified using compute_merkle_root_from_branch.
 */
vector* block_merkle_branch(const dogecoin_block* block, uint32_t position);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_CONSENSUS_H__