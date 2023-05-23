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

#include <dogecoin/pow.h>
#include <dogecoin/utils.h>
#include <dogecoin/validation.h>

const inline int32_t get_chainid(int32_t version) {
    return version >> 16;
}

const inline dogecoin_bool is_auxpow(int32_t version) {
    return (version & VERSION_AUXPOW) == 256;
}

const inline dogecoin_bool is_legacy(int32_t version) {
    return version == 1
        // Dogecoin: We have a random v2 block with no AuxPoW, treat as legacy
        || (version == 2 && get_chainid(version) == 0);
}

dogecoin_bool check_auxpow(dogecoin_auxpow_block block, dogecoin_chainparams* params) {
    /* Except for legacy blocks with full version 1, ensure that
       the chain ID is correct.  Legacy blocks are not allowed since
       the merge-mining start, which is checked in AcceptBlockHeader
       where the height is known.  */
    if (!is_legacy(block.header->version) && params->strict_id && get_chainid(block.header->version) != params->auxpow_id)
        return error("%s : block does not have our chain ID"
                     " (got %d, expected %d, full nVersion %d)",
                     __func__, get_chainid(block.header->version),
                     params->auxpow_id, block.header->version);

    /* If there is no auxpow, just check the block hash.  */
    if (!block.header->auxpow) {
        if (is_auxpow(block.header->version))
            return error("%s : no auxpow on block with auxpow version", __func__);

        uint256 auxpow_hash;
        dogecoin_get_auxpow_hash(block.header->version, auxpow_hash);
        if (!check_pow(auxpow_hash, block.header->bits, params))
            return error("%s : non-AUX proof of work failed", __func__);

        return true;
    }

    /* We have auxpow.  Check it.  */

    if (!is_auxpow(block.header->version))
        // printf("auxpow on block with non-auxpow version\n");
        return error("%s : auxpow on block with non-auxpow version", __func__);

    uint256* block_header_hash;
    dogecoin_block_header_hash(block.header, block_header_hash);
    if (!block.header->auxpow->check(block_header_hash, get_chainid(block.header->version), params))
        return error("%s : AUX POW is not valid", __func__);
    // uint256 parent_auxpow_hash;
    // dogecoin_block_header* header_copy = dogecoin_block_header_new();
    // dogecoin_block_header_copy(header_copy, block.parent_header);
    // unsigned char* parent_header = dogecoin_uchar_vla(80);
    // dogecoin_mem_zero(parent_header, 80);
    // parent_header = concat(parent_header, utils_uint8_to_hex(&block.parent_header->version, 4));
    // parent_header = concat(parent_header, utils_uint8_to_hex(&block.parent_header->prev_block, 32));
    // parent_header = concat(parent_header, utils_uint8_to_hex(&block.parent_header->merkle_root, 32));
    // parent_header = concat(parent_header, utils_uint8_to_hex(&block.parent_header->timestamp, 4));
    // parent_header = concat(parent_header, utils_uint8_to_hex(&block.parent_header->bits, 4));
    // parent_header = concat(parent_header, utils_uint8_to_hex(&block.parent_header->nonce, 4));
    // printf("parent_header: %s\n", parent_header);
    // dogecoin_block_header_scrypt_hash(header_copy, parent_auxpow_hash);
    // printf("parent_auxpow_hash: %s\n", utils_uint8_to_hex(parent_auxpow_hash, 32));
    // printf("block parent hash:  %s\n", utils_uint8_to_hex(block.parent_hash, 32));
    // dogecoin_get_auxpow_hash(parent_header, parent_auxpow_hash);
    // printf("parent_auxpow_hash: %s\n", utils_uint8_to_hex(parent_auxpow_hash, 32));
    // printf("block parent hash:  %s\n", utils_uint8_to_hex(block.parent_hash, 32));
    // printf("block.aux_merkle_branch: %s\n", utils_uint8_to_hex(block.aux_merkle_branch, 32));
    // printf("block.parent_coinbase_merkle:  %s\n", utils_uint8_to_hex(block.parent_coinbase_merkle, 32));
    // if (!check_pow(block.parent_hash, block.header->bits, params))
    //     printf("AUX pow failed!\n");
        // return false;
        // return error("%s : AUX proof of work failed", __func__);

    return true;
}
