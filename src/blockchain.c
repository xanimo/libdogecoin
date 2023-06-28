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

#include <assert.h>

#include <dogecoin/blockchain.h>
#include <dogecoin/mem.h>
#include <dogecoin/utils.h>

/**
 * @brief This function instantiates a new working dogecoin_blockindex,
 * but does not add it to the hash table.
 * 
 * @return A pointer to the new working dogecoin_blockindex. 
 */
dogecoin_blockindex* new_dogecoin_blockindex() {
    dogecoin_blockindex* blockindex = (dogecoin_blockindex*)dogecoin_calloc(1, sizeof *blockindex);
    return blockindex;
}

/**
 * @brief This function takes a pointer to an existing working
 * dogecoin_blockindex object and adds it to the hash table.
 * 
 * @param index The pointer to the working dogecoin_blockindex.
 * 
 * @return Nothing.
 */
void add_dogecoin_blockindex(dogecoin_blockindex *block) {
    dogecoin_blockindex* block_old;
    HASH_FIND_INT(block_indices, &block->index, block_old);
    if (block_old) {
        HASH_REPLACE_INT(block_indices, index, block, block_old);
    } else {
        HASH_ADD_INT(block_indices, index, block);
    }
    dogecoin_free(block_old);
}

/**
 * @brief This function takes an index and returns the working
 * dogecoin_blockindex associated with that index in the hash table.
 * 
 * @param index The index of the target working dogecoin_blockindex.
 * 
 * @return The pointer to the working dogecoin_blockindex associated with
 * the provided index.
 */
dogecoin_blockindex* find_dogecoin_blockindex(int index) {
    dogecoin_blockindex* block;
    HASH_FIND_INT(block_indices, &index, block);
    return block;
}

/**
 * @brief This function removes the specified working dogecoin_blockindex
 * from the hash table and frees the block_indices in memory.
 * 
 * @param index The pointer to the dogecoin_blockindex to remove.
 * 
 * @return Nothing.
 */
void remove_dogecoin_blockindex(dogecoin_blockindex* block) {
    HASH_DEL(block_indices, block); /* delete it (block_indices advances to next) */
    dogecoin_blockindex_free(block);
}

/**
 * @brief This function frees the memory allocated
 * for an dogecoin_blockindex.
 * 
 * @param dogecoin_blockindex The pointer to the dogecoin_blockindex to be freed.
 * 
 * @return Nothing.
 */
void dogecoin_blockindex_free(dogecoin_blockindex* block)
{
    dogecoin_free(block);
}

/**
 * @brief This function removes all working block indicies from
 * the hash table.
 * 
 * @return Nothing. 
 */
void remove_all_blockindices() {
    struct dogecoin_blockindex* block;
    struct dogecoin_blockindex *tmp;

    HASH_ITER(hh, block_indices, block, tmp) {
        dogecoin_blockindex_free(block);
    }
}

/**
 * @brief This function creates a new dogecoin_blockindex, places it in
 * the hash table, and returns the index of the new dogecoin_blockindex,
 * starting from 1 and incrementing each subsequent call.
 * 
 * @param is_testnet
 * 
 * @return The index of the new dogecoin_blockindex.
 */
int start_dogecoin_blockindex() {
    dogecoin_blockindex* block = new_dogecoin_blockindex();
    block->index = HASH_COUNT(block_indices) + 1;
    add_dogecoin_blockindex(block);
    int index = block->index;
    return index;
}
